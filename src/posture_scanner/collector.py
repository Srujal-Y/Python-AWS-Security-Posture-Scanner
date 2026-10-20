"""AWS inventory collection. Every AWS operation in this module is read-only."""

import json
from urllib.parse import unquote

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from .models import FAMILIES, Inventory

SDK_CONFIG = Config(
    retries={"mode": "standard", "total_max_attempts": 4},
    connect_timeout=5,
    read_timeout=15,
    user_agent_extra="aws-posture-scanner/1.0.0",
)
EMPTY_BLOCK = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}


class Collector:
    def __init__(self, session, regions):
        self.session = session
        self.inventory = Inventory(regions=list(dict.fromkeys(regions)))
        self.clients = {}
        self.family = "identity"

    def client(self, service, region=None):
        region = region or self.inventory.regions[0]
        key = service, region
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=SDK_CONFIG)
        return self.clients[key]

    def error(self, operation, resource, error):
        code = (
            error.response.get("Error", {}).get("Code", type(error).__name__)
            if isinstance(error, ClientError)
            else type(error).__name__
        )
        self.inventory.errors.append(
            {
                "family": self.family,
                "operation": operation,
                "resource": resource,
                "code": code,
                "message": "AWS metadata could not be read. Check permission, credentials, region and connectivity; this scope is incomplete.",
            }
        )

    def read(self, client, operation, resource, absent=(), **kwargs):
        try:
            return getattr(client, operation)(**kwargs)
        except ClientError as error:
            if error.response["Error"]["Code"] in absent:
                return {}
            self.error(operation, resource, error)
        except BotoCoreError as error:
            self.error(operation, resource, error)
        return None

    def items(self, client, operation, key, resource, **kwargs):
        """Yield earlier pages even if a later page fails; record that failure."""
        try:
            if client.can_paginate(operation):
                pages = client.get_paginator(operation).paginate(**kwargs)
            else:
                pages = [getattr(client, operation)(**kwargs)]
            for page in pages:
                yield from page.get(key, [])
        except (ClientError, BotoCoreError) as error:
            self.error(operation, resource, error)

    def run_scope(self, family, scope, callback):
        self.family = family
        errors_before = len(self.inventory.errors)
        count = 0
        try:
            count = callback()
        except (ClientError, BotoCoreError) as error:
            self.error("create_client_or_collect", scope, error)
        self.inventory.coverage.append(
            {
                "family": family,
                "scope": scope,
                "status": "partial" if len(self.inventory.errors) > errors_before else "complete",
                "resources_discovered": count,
            }
        )

    def collect(self):
        identity = self.read(self.client("sts"), "get_caller_identity", "caller")
        if identity is None:
            self.inventory.coverage = [
                {
                    "family": family,
                    "scope": "requested",
                    "status": "not_run",
                    "resources_discovered": 0,
                }
                for family in FAMILIES
            ]
            return self.inventory
        self.inventory.account_id = identity["Account"]
        self.inventory.partition = identity["Arn"].split(":")[1]
        self.run_scope("s3_public", "all-account-buckets", self.s3)
        self.run_scope("iam_mfa", "global", self.mfa)
        self.run_scope("iam_policy", "global", self.policies)
        for region in self.inventory.regions:
            self.run_scope("security_groups", region, lambda r=region: self.security_groups(r))
        return self.inventory

    def s3(self):
        inventory = self.inventory
        account_block = self.read(
            self.client("s3control"),
            "get_public_access_block",
            inventory.account_id,
            absent=("NoSuchPublicAccessBlockConfiguration",),
            AccountId=inventory.account_id,
        )
        account_block = (
            None
            if account_block is None
            else account_block.get("PublicAccessBlockConfiguration", EMPTY_BLOCK.copy())
        )
        discovery = self.client("s3")
        buckets = list(self.items(discovery, "list_buckets", "Buckets", "account-buckets"))
        for bucket in buckets:
            name = bucket["Name"]
            location = self.read(
                discovery,
                "get_bucket_location",
                name,
                Bucket=name,
                ExpectedBucketOwner=inventory.account_id,
            )
            if location is None:
                continue
            region = location.get("LocationConstraint") or "us-east-1"
            region = "eu-west-1" if region == "EU" else region
            s3 = self.client("s3", region)
            args = {"Bucket": name, "ExpectedBucketOwner": inventory.account_id}
            block = self.read(
                s3,
                "get_public_access_block",
                name,
                absent=("NoSuchPublicAccessBlockConfiguration",),
                **args,
            )
            acl = self.read(s3, "get_bucket_acl", name, **args)
            policy = self.read(
                s3,
                "get_bucket_policy_status",
                name,
                absent=("NoSuchBucketPolicy",),
                **args,
            )
            inventory.buckets.append(
                {
                    "name": name,
                    "region": region,
                    "account_block": account_block,
                    "bucket_block": None
                    if block is None
                    else block.get("PublicAccessBlockConfiguration", EMPTY_BLOCK.copy()),
                    "grants": None if acl is None else acl.get("Grants", []),
                    "policy_public": None
                    if policy is None
                    else policy.get("PolicyStatus", {}).get("IsPublic", False),
                }
            )
        return len(buckets)

    def mfa(self):
        iam = self.client("iam")
        users = list(self.items(iam, "list_users", "Users", "iam-users"))
        for user in users:
            before = len(self.inventory.errors)
            devices = list(
                self.items(
                    iam, "list_mfa_devices", "MFADevices", user["Arn"], UserName=user["UserName"]
                )
            )
            count = len(devices) if len(self.inventory.errors) == before else None
            profile = self.read(
                iam,
                "get_login_profile",
                user["Arn"],
                absent=("NoSuchEntity",),
                UserName=user["UserName"],
            )
            self.inventory.users.append(
                {
                    "arn": user["Arn"],
                    "mfa_devices": count,
                    "console_password": None if profile is None else "LoginProfile" in profile,
                }
            )
        return len(users)

    def add_policy(self, arn, source, document):
        if isinstance(document, str):
            try:
                document = json.loads(unquote(document))
            except (ValueError, TypeError):
                self.error("decode_policy", arn, ValueError())
                return
        if not isinstance(document, dict) or "Statement" not in document:
            self.error("decode_policy", arn, ValueError())
            return
        self.inventory.policies.append({"arn": arn, "source": source, "document": document})

    def policies(self):
        iam = self.client("iam")
        count = 0
        for policy in self.items(
            iam,
            "list_policies",
            "Policies",
            "attached-managed-policies",
            Scope="All",
            OnlyAttached=True,
            PolicyUsageFilter="PermissionsPolicy",
        ):
            count += 1
            response = self.read(
                iam,
                "get_policy_version",
                policy["Arn"],
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"],
            )
            if response is not None:
                self.add_policy(
                    policy["Arn"], "attached-managed", response["PolicyVersion"]["Document"]
                )
        for kind, plural in (("user", "Users"), ("role", "Roles"), ("group", "Groups")):
            name_key = kind.title() + "Name"
            for entity in self.items(
                iam, "list_" + plural.lower(), plural, "iam-" + plural.lower()
            ):
                args = {name_key: entity[name_key]}
                for name in self.items(
                    iam, f"list_{kind}_policies", "PolicyNames", entity["Arn"], **args
                ):
                    count += 1
                    arn = entity["Arn"] + "/inline-policy/" + name
                    response = self.read(iam, f"get_{kind}_policy", arn, PolicyName=name, **args)
                    if response is not None:
                        self.add_policy(arn, "inline-" + kind, response["PolicyDocument"])
        return count

    def security_groups(self, region):
        groups = list(
            self.items(
                self.client("ec2", region), "describe_security_groups", "SecurityGroups", region
            )
        )
        for group in groups:
            self.inventory.security_groups.append(
                {
                    **group,
                    "region": region,
                    "arn": f"arn:{self.inventory.partition}:ec2:{region}:{self.inventory.account_id}:security-group/{group['GroupId']}",
                }
            )
        return len(groups)
