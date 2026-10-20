from copy import deepcopy

import pytest

from posture_scanner.checks import (
    check_mfa,
    check_policy,
    check_s3,
    check_security_group,
    effective_block,
    evaluate,
)
from posture_scanner.models import sorted_findings


def test_demo_expected_findings_and_rank(demo):
    rows = sorted_findings(evaluate(demo))
    assert len(rows) == 13
    assert [row["severity"] for row in rows] == (
        ["critical"] * 2 + ["high"] * 7 + ["medium"] * 3 + ["low"]
    )
    assert len({f["id"] for f in rows}) == 13
    assert not any("blocked-acl" in f["resource"] for f in rows)
    assert not any("ExplicitDeny" in f["resource"] for f in rows)


@pytest.mark.parametrize("scope", ["account_block", "bucket_block"])
def test_ignore_public_acls_suppresses_existing_grant(demo, scope):
    bucket = deepcopy(demo.buckets[1])
    bucket[scope]["IgnorePublicAcls"] = True
    assert check_s3(bucket, "aws") == []


@pytest.mark.parametrize("scope", ["account_block", "bucket_block"])
def test_block_public_acls_does_not_suppress_existing_grant(demo, scope):
    bucket = deepcopy(demo.buckets[1])
    bucket[scope]["BlockPublicAcls"] = True
    assert check_s3(bucket, "aws")[0].check_id == "S3_PUBLIC_ACL"


def test_policy_write_block_is_distinct_from_restrict_existing_policy(demo):
    bucket = deepcopy(demo.buckets[0])
    bucket["bucket_block"]["BlockPublicPolicy"] = True
    assert len(check_s3(bucket, "aws")) == 1
    bucket["account_block"]["RestrictPublicBuckets"] = True
    assert check_s3(bucket, "aws") == []


def test_unknown_control_is_not_assumed_disabled(demo):
    bucket = deepcopy(demo.buckets[0])
    bucket["account_block"] = None
    finding = check_s3(bucket, "aws")[0]
    assert finding.severity == "medium"
    assert finding.confidence == "review_required"
    assert effective_block(bucket, "RestrictPublicBuckets") is None
    bucket["bucket_block"]["RestrictPublicBuckets"] = True
    assert effective_block(bucket, "RestrictPublicBuckets") is True
    assert check_s3(bucket, "aws") == []


def test_authenticated_users_acl_is_also_public(demo):
    bucket = deepcopy(demo.buckets[1])
    bucket["grants"][0]["Grantee"]["URI"] = (
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    )
    assert len(check_s3(bucket, "aws")) == 1


@pytest.mark.parametrize(
    "devices,console,severity",
    [
        (1, True, None),
        (None, True, None),
        (0, True, "high"),
        (0, False, "medium"),
        (0, None, "medium"),
    ],
)
def test_mfa_enrollment_and_console_context(devices, console, severity):
    findings = check_mfa({"arn": "arn:user", "mfa_devices": devices, "console_password": console})
    assert ([f.severity for f in findings] or [None]) == [severity]


def policy(statement):
    return {"arn": "arn:policy", "source": "attached-managed", "document": {"Statement": statement}}


@pytest.mark.parametrize(
    "statement,severity",
    [
        ({"Effect": "Allow", "Action": "*", "Resource": "*"}, "critical"),
        ({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}, "high"),
        ({"Effect": "Allow", "Action": "IAM:CREATE*KEY", "Resource": "*"}, "high"),
        ({"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}, None),
        ({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::example/*"}, "medium"),
        ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, "high"),
        ({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:excluded"}, "high"),
        ({"Effect": "Deny", "Action": "*", "Resource": "*"}, None),
        (
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            },
            "medium",
        ),
    ],
)
def test_policy_semantics(statement, severity):
    rows = check_policy(policy(statement))
    assert ([f.severity for f in rows] or [None]) == [severity]
    assert all(row.confidence == "review_required" for row in rows)


def test_unconditional_deny_all_suppresses_but_partial_deny_does_not():
    allow = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    deny = {"Effect": "Deny", "Action": "*", "Resource": "*"}
    assert check_policy(policy([allow, deny])) == []
    deny["Action"] = "iam:*"
    assert check_policy(policy([allow, deny]))[0].severity == "medium"


def test_each_broad_statement_has_distinct_stable_identity():
    statements = [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
        {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
    ]
    findings = check_policy(policy(statements))
    rows = sorted_findings(findings + findings)
    assert len(rows) == 2
    assert rows == sorted_findings(check_policy(policy(statements)))


@pytest.mark.parametrize(
    "protocol,start,end,cidr,severity",
    [
        ("tcp", 22, 22, "0.0.0.0/0", "high"),
        ("6", 20, 25, "::/0", "high"),
        ("tcp", 443, 443, "0.0.0.0/0", "medium"),
        ("tcp", 0, 65535, "::/0", "critical"),
        ("udp", 0, 65535, "0.0.0.0/0", "critical"),
        ("icmp", -1, -1, "::/0", "low"),
        ("-1", None, None, "0.0.0.0/0", "critical"),
        ("tcp", 22, 22, "10.0.0.0/8", None),
        ("tcp", 22, 22, "192.0.2.0/24", None),
    ],
)
def test_security_group_sources_ports_and_protocol_aliases(
    demo, protocol, start, end, cidr, severity
):
    group = deepcopy(demo.security_groups[0])
    field, key = ("Ipv6Ranges", "CidrIpv6") if ":" in cidr else ("IpRanges", "CidrIp")
    group["IpPermissions"] = [
        {"IpProtocol": protocol, "FromPort": start, "ToPort": end, field: [{key: cidr}]}
    ]
    group["IpPermissionsEgress"] = []
    rows = check_security_group(group)
    assert ([f.severity for f in rows] or [None]) == [severity]


def test_egress_only_unrestricted_is_flagged(demo):
    group = deepcopy(demo.security_groups[0])
    group["IpPermissions"] = []
    assert check_security_group(group)[0].severity == "low"
    group["IpPermissionsEgress"][0].update(IpProtocol="tcp", FromPort=443, ToPort=443)
    assert check_security_group(group) == []


def test_rule_order_does_not_change_finding_ids(demo):
    original = sorted_findings(check_security_group(demo.security_groups[2]))
    demo.security_groups[2]["IpPermissions"].reverse()
    assert original == sorted_findings(check_security_group(demo.security_groups[2]))
