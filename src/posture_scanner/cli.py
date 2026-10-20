import argparse
import ipaddress
import json
import re
import sys
from importlib.resources import files
from pathlib import Path

import boto3
import jsonschema
from botocore.exceptions import BotoCoreError

from .checks import evaluate
from .collector import Collector
from .models import FAMILIES, SEVERITIES, Inventory, exit_code
from .reporting import make_report, utc_now, write_reports


def load_inventory(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    schema = json.loads(files("posture_scanner").joinpath("data/inventory.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(raw)
    raw.pop("schema_version")
    inventory = Inventory(**raw)
    # Reject "complete" snapshots with missing family or region coverage.
    covered = {entry["family"] for entry in inventory.coverage}
    if set(FAMILIES) - covered:
        raise ValueError("Inventory must explicitly declare coverage for all four check families")
    sg_regions = {
        entry["scope"] for entry in inventory.coverage if entry["family"] == "security_groups"
    }
    if set(inventory.regions) - sg_regions:
        raise ValueError("Every requested region needs security-group coverage")
    unknown = set()
    if any(
        any(b[key] is None for key in ("account_block", "bucket_block", "grants", "policy_public"))
        for b in inventory.buckets
    ):
        unknown.add("s3_public")
    if any(u["mfa_devices"] is None or u["console_password"] is None for u in inventory.users):
        unknown.add("iam_mfa")
    partial = {c["family"] for c in inventory.coverage if c["status"] != "complete"}
    if unknown - partial:
        raise ValueError("Unknown observations must be declared as incomplete coverage")
    for group in inventory.security_groups:
        if group["region"] not in inventory.regions:
            raise ValueError("Security-group region is outside declared scope")
        for rule in group["IpPermissions"] + group["IpPermissionsEgress"]:
            if rule["IpProtocol"] in ("tcp", "udp", "6", "17"):
                if rule["FromPort"] > rule["ToPort"]:
                    raise ValueError("Port range is reversed")
            for field, key, version in (("IpRanges", "CidrIp", 4), ("Ipv6Ranges", "CidrIpv6", 6)):
                for source in rule.get(field, []):
                    if ipaddress.ip_network(source[key], strict=False).version != version:
                        raise ValueError("CIDR is in the wrong address family")
    return inventory


def region_name(value):
    if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", value):
        raise argparse.ArgumentTypeError("Use an AWS region name such as us-east-1")
    return value


def parser():
    root = argparse.ArgumentParser(
        description="Read-only AWS posture checks with local JSON, Markdown and HTML reports."
    )
    sub = root.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("demo", "Scan the included fictional inventory without AWS access"),
        ("snapshot", "Review a schema-validated local inventory"),
        ("scan", "Read metadata from your authorised AWS account"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--output", type=Path, default=Path("reports") / name)
        command.add_argument("--fail-on", choices=(*SEVERITIES, "none"), default="high")
        if name == "snapshot":
            command.add_argument("--input", type=Path, required=True)
        if name == "scan":
            command.add_argument("--profile", help="Existing AWS CLI/SSO profile")
            command.add_argument(
                "--regions",
                nargs="+",
                type=region_name,
                required=True,
                help="EC2 regions to check; S3 buckets and IAM are account-wide",
            )
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    started = utc_now()
    try:
        if args.command == "scan":
            try:
                session = boto3.Session(profile_name=args.profile)
                inventory = Collector(session, args.regions).collect()
            except BotoCoreError as error:
                inventory = Inventory(regions=args.regions)
                inventory.errors.append(
                    {
                        "family": "identity",
                        "operation": "initialise_session",
                        "resource": "caller",
                        "code": type(error).__name__,
                        "message": "AWS session could not be established.",
                    }
                )
                inventory.coverage = [
                    {
                        "family": family,
                        "scope": "requested",
                        "status": "not_run",
                        "resources_discovered": 0,
                    }
                    for family in FAMILIES
                ]
        else:
            source = (
                files("posture_scanner").joinpath("data/demo.json")
                if args.command == "demo"
                else args.input
            )
            inventory = load_inventory(source)
        report = make_report(inventory, evaluate(inventory), args.command, started)
        schema = json.loads(
            files("posture_scanner").joinpath("data/report.schema.json").read_text()
        )
        jsonschema.Draft202012Validator(schema).validate(report)
        paths = write_reports(report, args.output)
    except (OSError, ValueError, jsonschema.ValidationError) as error:
        print(
            f"Cannot complete scan: {type(error).__name__}. Check input schema and output path.",
            file=sys.stderr,
        )
        return 2
    print(f"{report['mode']} | coverage={report['status']} | findings={report['summary']['total']}")
    for path in paths:
        print(path)
    return exit_code(report, args.fail_on)
