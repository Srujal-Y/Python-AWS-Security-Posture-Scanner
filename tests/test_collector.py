import json
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import Mock
from urllib.parse import quote

import boto3
import pytest
from botocore.exceptions import EndpointConnectionError, NoCredentialsError
from botocore.stub import Stubber

from posture_scanner.checks import evaluate
from posture_scanner.collector import EMPTY_BLOCK, SDK_CONFIG, Collector
from posture_scanner.reporting import make_report

ACCOUNT = "111122223333"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/test"
POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/test"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
USER = {
    "Path": "/",
    "UserName": "test",
    "UserId": "AIDA00000000000000000",
    "Arn": USER_ARN,
    "CreateDate": NOW,
}
ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


@pytest.fixture
def collector():
    session = boto3.Session(aws_access_key_id="testing", aws_secret_access_key="testing")
    return Collector(session, ["us-east-1"])


def test_full_collection_uses_read_metadata_and_default_policy_version(collector):
    """Exercise the entire collector with botocore-validated service responses."""
    with ExitStack() as stack:
        stubs = {}
        for service in ("sts", "s3control", "s3", "iam", "ec2"):
            stubs[service] = stack.enter_context(Stubber(collector.client(service)))
        stubs["sts"].add_response(
            "get_caller_identity",
            {
                "Account": ACCOUNT,
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/scanner",
                "UserId": "AIDA00000000000000001",
            },
            {},
        )
        stubs["s3control"].add_response(
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration": EMPTY_BLOCK,
            },
            {"AccountId": ACCOUNT},
        )
        stubs["s3"].add_response("list_buckets", {"Buckets": [{"Name": "fictional-bucket"}]}, {})
        args = {"Bucket": "fictional-bucket", "ExpectedBucketOwner": ACCOUNT}
        stubs["s3"].add_response("get_bucket_location", {}, args)
        stubs["s3"].add_client_error(
            "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", expected_params=args
        )
        stubs["s3"].add_response("get_bucket_acl", {"Grants": []}, args)
        stubs["s3"].add_response(
            "get_bucket_policy_status", {"PolicyStatus": {"IsPublic": True}}, args
        )
        iam = stubs["iam"]
        iam.add_response("list_users", {"Users": [USER], "IsTruncated": False}, {})
        iam.add_response(
            "list_mfa_devices", {"MFADevices": [], "IsTruncated": False}, {"UserName": "test"}
        )
        iam.add_response(
            "get_login_profile",
            {
                "LoginProfile": {
                    "UserName": "test",
                    "CreateDate": NOW,
                }
            },
            {"UserName": "test"},
        )
        iam.add_response(
            "list_policies",
            {
                "Policies": [
                    {
                        "Arn": POLICY_ARN,
                        "DefaultVersionId": "v3",
                    }
                ],
                "IsTruncated": False,
            },
            {"Scope": "All", "OnlyAttached": True, "PolicyUsageFilter": "PermissionsPolicy"},
        )
        iam.add_response(
            "get_policy_version",
            {
                "PolicyVersion": {
                    "Document": quote(json.dumps(ADMIN)),
                    "VersionId": "v3",
                    "IsDefaultVersion": True,
                }
            },
            {"PolicyArn": POLICY_ARN, "VersionId": "v3"},
        )
        iam.add_response("list_users", {"Users": [USER], "IsTruncated": False}, {})
        iam.add_response(
            "list_user_policies",
            {"PolicyNames": ["Inline"], "IsTruncated": False},
            {"UserName": "test"},
        )
        iam.add_response(
            "get_user_policy",
            {"UserName": "test", "PolicyName": "Inline", "PolicyDocument": json.dumps(ADMIN)},
            {"UserName": "test", "PolicyName": "Inline"},
        )
        iam.add_response("list_roles", {"Roles": [], "IsTruncated": False}, {})
        iam.add_response("list_groups", {"Groups": [], "IsTruncated": False}, {})
        stubs["ec2"].add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0123456789abcdef0",
                        "IpPermissions": [
                            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            },
            {},
        )
        inventory = collector.collect()
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    assert not inventory.errors
    assert all(c["status"] == "complete" for c in inventory.coverage)
    assert inventory.account_id == ACCOUNT
    assert inventory.buckets[0]["region"] == "us-east-1"
    assert inventory.buckets[0]["bucket_block"] == EMPTY_BLOCK
    assert inventory.policies[0]["document"] == ADMIN
    assert inventory.policies[1]["source"] == "inline-user"
    assert len(evaluate(inventory)) == 5


def test_later_pagination_failure_retains_earlier_discovery(collector):
    collector.family = "iam_mfa"
    with Stubber(collector.client("iam")) as stub:
        stub.add_response(
            "list_users", {"Users": [USER], "IsTruncated": True, "Marker": "next"}, {}
        )
        stub.add_client_error("list_users", "AccessDenied", expected_params={"Marker": "next"})
        rows = list(collector.items(collector.client("iam"), "list_users", "Users", "users"))
        stub.assert_no_pending_responses()
    assert rows == [USER]
    assert collector.inventory.errors[0]["code"] == "AccessDenied"


def test_mfa_pagination_counts_all_devices_and_missing_profile_is_known_absent(collector):
    with Stubber(collector.client("iam")) as stub:
        stub.add_response("list_users", {"Users": [USER], "IsTruncated": False}, {})
        device = {"UserName": "test", "SerialNumber": "serial-one", "EnableDate": NOW}
        stub.add_response(
            "list_mfa_devices",
            {
                "MFADevices": [device],
                "IsTruncated": True,
                "Marker": "next",
            },
            {"UserName": "test"},
        )
        stub.add_response(
            "list_mfa_devices",
            {
                "MFADevices": [{**device, "SerialNumber": "serial-two"}],
                "IsTruncated": False,
            },
            {"UserName": "test", "Marker": "next"},
        )
        stub.add_client_error(
            "get_login_profile", "NoSuchEntity", expected_params={"UserName": "test"}
        )
        collector.run_scope("iam_mfa", "global", collector.mfa)
    assert collector.inventory.users == [
        {"arn": USER_ARN, "mfa_devices": 2, "console_password": False}
    ]
    assert not collector.inventory.errors


def test_denied_mfa_is_unknown_not_a_missing_device(collector):
    with Stubber(collector.client("iam")) as stub:
        stub.add_response("list_users", {"Users": [USER], "IsTruncated": False}, {})
        stub.add_client_error(
            "list_mfa_devices",
            "AccessDenied",
            service_message="SENSITIVE ERROR DETAIL",
            expected_params={"UserName": "test"},
        )
        stub.add_client_error(
            "get_login_profile", "AccessDenied", expected_params={"UserName": "test"}
        )
        collector.run_scope("iam_mfa", "global", collector.mfa)
    assert collector.inventory.users[0]["mfa_devices"] is None
    assert collector.inventory.users[0]["console_password"] is None
    assert not evaluate(collector.inventory)
    assert collector.inventory.coverage[0]["status"] == "partial"
    assert "SENSITIVE ERROR DETAIL" not in json.dumps(collector.inventory.errors)


def test_s3_location_failure_does_not_claim_complete_bucket_coverage(collector):
    collector.inventory.account_id = ACCOUNT
    with Stubber(collector.client("s3control")) as account, Stubber(collector.client("s3")) as s3:
        account.add_client_error(
            "get_public_access_block", "AccessDenied", expected_params={"AccountId": ACCOUNT}
        )
        s3.add_response("list_buckets", {"Buckets": [{"Name": "fictional-bucket"}]}, {})
        s3.add_client_error(
            "get_bucket_location",
            "AccessDenied",
            expected_params={
                "Bucket": "fictional-bucket",
                "ExpectedBucketOwner": ACCOUNT,
            },
        )
        collector.run_scope("s3_public", "all-account-buckets", collector.s3)
    assert collector.inventory.buckets == []
    assert collector.inventory.coverage[0]["resources_discovered"] == 1
    assert collector.inventory.coverage[0]["status"] == "partial"


def test_s3_legacy_eu_region_and_unknown_observations(collector):
    collector.inventory.account_id = ACCOUNT
    with ExitStack() as stack:
        account = stack.enter_context(Stubber(collector.client("s3control")))
        discovery = stack.enter_context(Stubber(collector.client("s3")))
        regional = stack.enter_context(Stubber(collector.client("s3", "eu-west-1")))
        account.add_client_error(
            "get_public_access_block",
            "NoSuchPublicAccessBlockConfiguration",
            expected_params={"AccountId": ACCOUNT},
        )
        discovery.add_response("list_buckets", {"Buckets": [{"Name": "fictional-bucket"}]}, {})
        args = {"Bucket": "fictional-bucket", "ExpectedBucketOwner": ACCOUNT}
        discovery.add_response("get_bucket_location", {"LocationConstraint": "EU"}, args)
        regional.add_client_error("get_public_access_block", "AccessDenied", expected_params=args)
        regional.add_client_error("get_bucket_acl", "AccessDenied", expected_params=args)
        regional.add_client_error(
            "get_bucket_policy_status", "NoSuchBucketPolicy", expected_params=args
        )
        collector.run_scope("s3_public", "all-account-buckets", collector.s3)
    bucket = collector.inventory.buckets[0]
    assert bucket["region"] == "eu-west-1"
    assert bucket["account_block"] == EMPTY_BLOCK
    assert bucket["bucket_block"] is None
    assert bucket["grants"] is None
    assert bucket["policy_public"] is False
    assert collector.inventory.coverage[0]["status"] == "partial"


def test_security_group_pagination_and_partition(collector):
    collector.inventory.account_id = ACCOUNT
    collector.inventory.partition = "aws-us-gov"
    with Stubber(collector.client("ec2")) as stub:
        stub.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [{"GroupId": "sg-111"}],
                "NextToken": "page2",
            },
            {},
        )
        stub.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [{"GroupId": "sg-222"}],
            },
            {"NextToken": "page2"},
        )
        assert collector.security_groups("us-east-1") == 2
    assert collector.inventory.security_groups[1]["arn"].startswith("arn:aws-us-gov:")


def test_failed_identity_skips_all_scopes(collector):
    with Stubber(collector.client("sts")) as stub:
        stub.add_client_error("get_caller_identity", "ExpiredToken", expected_params={})
        inventory = collector.collect()
    assert all(c["status"] == "not_run" for c in inventory.coverage)
    assert set(collector.clients) == {("sts", "us-east-1")}
    assert make_report(inventory, [], "scan", "start")["status"] == "partial"


def test_sdk_errors_are_recorded_without_raw_messages(collector):
    client = Mock()
    client.get_metadata.side_effect = NoCredentialsError()
    assert collector.read(client, "get_metadata", "resource") is None
    assert collector.inventory.errors[0]["code"] == "NoCredentialsError"
    client.can_paginate.return_value = False
    client.get_metadata.side_effect = EndpointConnectionError(endpoint_url="sensitive-endpoint")
    assert list(collector.items(client, "get_metadata", "Items", "resource")) == []
    assert "sensitive-endpoint" not in json.dumps(collector.inventory.errors)


def test_non_paginated_operation_supported(collector):
    client = Mock()
    client.can_paginate.return_value = False
    client.get_metadata.return_value = {"Items": [1, 2]}
    assert list(collector.items(client, "get_metadata", "Items", "resource")) == [1, 2]


def test_scope_client_initialisation_error_is_partial(collector):
    callback = Mock(side_effect=NoCredentialsError())
    collector.run_scope("iam_policy", "global", callback)
    assert collector.inventory.coverage[0]["status"] == "partial"


@pytest.mark.parametrize("document", ["invalid-json", {}, [], None])
def test_malformed_policy_documents_record_error(collector, document):
    collector.family = "iam_policy"
    collector.add_policy(POLICY_ARN, "attached-managed", document)
    assert not collector.inventory.policies
    assert collector.inventory.errors[0]["code"] == "ValueError"


def test_sdk_has_bounded_standard_retries_and_timeouts():
    assert SDK_CONFIG.retries == {"mode": "standard", "total_max_attempts": 4}
    assert SDK_CONFIG.connect_timeout == 5
    assert SDK_CONFIG.read_timeout == 15
