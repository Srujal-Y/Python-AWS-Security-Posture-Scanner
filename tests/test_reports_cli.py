import json
from importlib.resources import files

import jsonschema
import pytest
from botocore.exceptions import ProfileNotFound

from posture_scanner.checks import evaluate
from posture_scanner.cli import load_inventory, main
from posture_scanner.models import FAMILIES, Inventory, exit_code
from posture_scanner.reporting import html_report, make_report, markdown, write_reports


def report_for(demo):
    return make_report(demo, evaluate(demo), "demo", "2026-01-01T00:00:00+00:00")


def test_report_contract_and_thresholds(demo):
    report = report_for(demo)
    schema = json.loads(files("posture_scanner").joinpath("data/report.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(report)
    assert report["summary"]["total"] == sum(
        count for key, count in report["summary"].items() if key != "total"
    )
    assert exit_code(report, "critical") == 1
    assert exit_code(report, "none") == 0
    report["status"] = "partial"
    assert exit_code(report, "none") == 2


def test_empty_inventory_is_never_a_complete_assessment():
    report = make_report(Inventory(regions=["us-east-1"]), [], "scan", "start")
    assert report["status"] == "partial"


def test_absent_region_coverage_is_partial(demo):
    demo.regions.append("ap-south-1")
    assert report_for(demo)["status"] == "partial"


def test_denied_reads_produce_partial_even_when_no_findings(demo):
    demo.errors = [
        {
            "family": "iam_mfa",
            "operation": "list_users",
            "resource": "users",
            "code": "AccessDenied",
            "message": "Incomplete",
        }
    ]
    report = make_report(demo, [], "scan", "start")
    assert report["status"] == "partial"
    assert exit_code(report) == 2


def test_html_and_markdown_escape_untrusted_resource_metadata(demo):
    report = report_for(demo)
    payload = '<script>alert("x")</script>|[x](https://example.com)'
    report["findings"][0]["resource"] = payload
    report["findings"][0]["evidence"]["payload"] = payload
    rendered = html_report(report)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "default-src 'none'" in rendered
    text = markdown(report)
    # Raw JSON evidence is inside an indented code block; surrounding prose is escaped.
    assert all(line.startswith("    ") for line in text.splitlines() if "<script>" in line)
    assert "&#124;&#91;x&#93;" in text


def test_report_files_can_be_replaced_without_temporary_files(demo, tmp_path):
    report = report_for(demo)
    paths = write_reports(report, tmp_path)
    write_reports(report, tmp_path)
    assert len(paths) == 3
    assert {p.name for p in tmp_path.iterdir()} == {"report.json", "report.md", "report.html"}
    assert json.loads((tmp_path / "report.json").read_text()) == report


@pytest.mark.parametrize("threshold,expected", [("high", 1), ("none", 0)])
def test_demo_cli_never_initialises_aws(monkeypatch, tmp_path, threshold, expected):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline command attempted to initialise AWS")

    monkeypatch.setattr("posture_scanner.cli.boto3.Session", forbidden)
    assert main(["demo", "--output", str(tmp_path), "--fail-on", threshold]) == expected
    report = json.loads((tmp_path / "report.json").read_text())
    assert "SYNTHETIC DEMO" in report["review_note"]


def test_profile_failure_still_writes_incomplete_report(monkeypatch, tmp_path):
    def unavailable(**kwargs):
        raise ProfileNotFound(profile="missing")

    monkeypatch.setattr("posture_scanner.cli.boto3.Session", unavailable)
    assert (
        main(
            [
                "scan",
                "--profile",
                "missing",
                "--regions",
                "us-east-1",
                "--output",
                str(tmp_path),
                "--fail-on",
                "none",
            ]
        )
        == 2
    )
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["errors"][0]["code"] == "ProfileNotFound"
    assert {c["family"] for c in report["coverage"]} == set(FAMILIES)
    assert all(c["status"] == "not_run" for c in report["coverage"])


def test_snapshot_cli_labels_input_as_unverified(demo_raw, tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(demo_raw), encoding="utf-8")
    assert (
        main(
            [
                "snapshot",
                "--input",
                str(source),
                "--output",
                str(tmp_path / "out"),
                "--fail-on",
                "none",
            ]
        )
        == 0
    )
    report = json.loads((tmp_path / "out/report.json").read_text())
    assert "not independently verified" in report["review_note"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(account_id="bad"),
        lambda d: d["coverage"].clear(),
        lambda d: d["coverage"].pop(),
        lambda d: d["users"][0].update(mfa_devices=-1),
        lambda d: d["users"][0].update(mfa_devices=None),
        lambda d: d["security_groups"][1]["IpPermissions"][0].pop("ToPort"),
        lambda d: d["security_groups"][1]["IpPermissions"][0].update(ToPort=10),
        lambda d: d["security_groups"][1]["IpPermissions"][0]["Ipv6Ranges"][0].update(
            CidrIpv6="0.0.0.0/0"
        ),
        lambda d: d["security_groups"][0].update(region="ap-south-1"),
        lambda d: d["policies"][0]["document"].update(Statement=None),
        lambda d: d["policies"][0]["document"]["Statement"].update(NotAction="iam:*"),
    ],
)
def test_invalid_snapshots_are_rejected(demo_raw, tmp_path, mutation):
    mutation(demo_raw)
    source = tmp_path / "input.json"
    source.write_text(json.dumps(demo_raw), encoding="utf-8")
    with pytest.raises((ValueError, jsonschema.ValidationError)):
        load_inventory(source)
    assert main(["snapshot", "--input", str(source), "--output", str(tmp_path / "out")]) == 2
    assert not (tmp_path / "out/report.json").exists()


def test_partial_snapshot_never_passes_gate(demo_raw, tmp_path):
    demo_raw["users"][0]["mfa_devices"] = None
    demo_raw["coverage"][1]["status"] = "partial"
    source = tmp_path / "input.json"
    source.write_text(json.dumps(demo_raw), encoding="utf-8")
    assert (
        main(
            [
                "snapshot",
                "--input",
                str(source),
                "--output",
                str(tmp_path / "out"),
                "--fail-on",
                "none",
            ]
        )
        == 2
    )


def test_invalid_region_fails_before_aws_access():
    with pytest.raises(SystemExit) as error:
        main(["scan", "--regions", "wrong"])
    assert error.value.code == 2


def test_output_io_error_returns_operational_failure(tmp_path):
    output = tmp_path / "file"
    output.write_text("occupied")
    assert main(["demo", "--output", str(output)]) == 2
