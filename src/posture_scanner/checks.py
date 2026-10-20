"""Pure checks: no AWS calls, mutations, credential handling or report I/O."""

import fnmatch
import ipaddress

from .models import Finding

PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}
SENSITIVE_PORTS = {
    21,
    22,
    23,
    135,
    139,
    445,
    1433,
    1521,
    2375,
    2376,
    3306,
    3389,
    5432,
    5900,
    6379,
    9200,
    9300,
    11211,
    27017,
}
SENSITIVE_ACTIONS = {
    "iam:passrole",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:attachuserpolicy",
    "iam:attachrolepolicy",
    "iam:attachgrouppolicy",
    "iam:putuserpolicy",
    "iam:putrolepolicy",
    "iam:putgrouppolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:updateassumerolepolicy",
    "sts:assumerole",
    "s3:putbucketpolicy",
    "s3:deletebucketpolicy",
    "kms:putkeypolicy",
    "secretsmanager:getsecretvalue",
}


def values(value):
    return value if isinstance(value, list) else [value] if value is not None else []


def effective_block(bucket, key):
    """True wins across scopes; an unknown scope cannot be assumed disabled."""
    controls = [bucket.get("account_block"), bucket.get("bucket_block")]
    if any(control is not None and control.get(key, False) for control in controls):
        return True
    if any(control is None for control in controls):
        return None
    return False


def check_s3(bucket, partition):
    resource = f"arn:{partition}:s3:::{bucket['name']}"
    grants = [
        grant
        for grant in bucket.get("grants") or []
        if grant.get("Grantee", {}).get("URI") in PUBLIC_GROUPS
    ]
    acl_block = effective_block(bucket, "IgnorePublicAcls")
    policy_block = effective_block(bucket, "RestrictPublicBuckets")
    findings = []
    common = {
        "account_public_access_block": bucket.get("account_block"),
        "bucket_public_access_block": bucket.get("bucket_block"),
        "scope_note": "Bucket/account configuration only; organisation controls and object ACLs are not evaluated.",
    }
    if grants and acl_block is not True:
        write = any(g["Permission"] in ("WRITE", "WRITE_ACP", "FULL_CONTROL") for g in grants)
        findings.append(
            Finding(
                "S3_PUBLIC_ACL",
                "s3_public",
                resource,
                bucket["region"],
                "Bucket ACL contains public grants",
                "high" if write or acl_block is False else "medium",
                "A global ACL grant may permit unintended bucket access. Public does not prove network reachability or object access.",
                "Review the grants, remove unintended global grantees, and enable IgnorePublicAcls and BlockPublicAcls at the appropriate scopes.",
                {**common, "public_grants": grants, "ignore_public_acls": acl_block},
                "review_required" if acl_block is None else "configuration",
            )
        )
    if bucket.get("policy_public") is True and policy_block is not True:
        findings.append(
            Finding(
                "S3_PUBLIC_POLICY",
                "s3_public",
                resource,
                bucket["region"],
                "S3 classifies the bucket policy as public",
                "high" if policy_block is False else "medium",
                "The bucket policy is classified as public by S3 and the observed controls do not establish that public access is restricted.",
                "Review bucket-policy principals and conditions; remove unintended public access and enable RestrictPublicBuckets and BlockPublicPolicy where appropriate.",
                {**common, "is_public": True, "restrict_public_buckets": policy_block},
                "review_required" if policy_block is None else "configuration",
            )
        )
    return findings


def check_mfa(user):
    if user["mfa_devices"] is None or user["mfa_devices"] > 0:
        return []
    console = user["console_password"]
    return [
        Finding(
            "IAM_USER_NO_MFA",
            "iam_mfa",
            user["arn"],
            "global",
            "IAM user has no registered MFA device",
            "high" if console is True else "medium",
            "An unprotected console password increases account takeover risk. MFA enrollment alone does not enforce MFA for access-key API requests.",
            "For human access, prefer federation/Identity Center with enforced MFA. If this IAM user remains, register MFA and enforce it through access policy; replace workload users with roles.",
            {"console_password": console, "registered_mfa_devices": 0},
        )
    ]


def check_policy(policy):
    document = policy["document"]
    statements = values(document.get("Statement"))
    denies = [s for s in statements if s.get("Effect") == "Deny"]
    if any(
        "*" in values(s.get("Action"))
        and "*" in values(s.get("Resource"))
        and not s.get("Condition")
        for s in denies
    ):
        return []
    findings = []
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue
        actions = [str(action).lower() for action in values(statement.get("Action"))]
        resources = values(statement.get("Resource"))
        broad_resource = "*" in resources or bool(statement.get("NotResource"))
        global_action = "*" in actions
        service_wildcard = any(a.endswith(":*") for a in actions)
        sensitive = sorted(
            {
                action
                for action in SENSITIVE_ACTIONS
                if any(fnmatch.fnmatchcase(action, pattern) for pattern in actions)
            }
        )
        reasons = []
        if global_action:
            reasons.append("All actions are allowed by this statement")
        if service_wildcard:
            reasons.append("An entire service action namespace is allowed")
        if statement.get("NotAction"):
            reasons.append("Allow with NotAction grants actions beyond the listed exclusions")
        if statement.get("NotResource"):
            reasons.append("Allow with NotResource grants access beyond the listed exclusions")
        if sensitive and broad_resource:
            reasons.append("Sensitive actions apply across a broad resource scope")
        if not reasons:
            continue
        contextual = bool(statement.get("Condition")) or bool(denies)
        severity = "critical" if global_action and broad_resource and not contextual else "high"
        if not global_action and not broad_resource and not statement.get("NotAction"):
            severity = "medium"
        if contextual and severity == "high":
            severity = "medium"
        findings.append(
            Finding(
                "IAM_BROAD_POLICY",
                "iam_policy",
                policy["arn"],
                "global",
                "Broad Allow statement requires least-privilege review",
                severity,
                "This statement is a policy-risk candidate, not proof of effective permission. Conditions, explicit denies, permission boundaries, SCPs and session policies may constrain it.",
                "Replace broad grants with the actions and resources the workload needs. Review the statement in its attached identity context, including conditions, denies and organisational controls, before changing it.",
                {
                    "statement_index": index,
                    "sid": statement.get("Sid"),
                    "reasons": reasons,
                    "action": statement.get("Action"),
                    "not_action": statement.get("NotAction"),
                    "resource": statement.get("Resource"),
                    "not_resource": statement.get("NotResource"),
                    "condition": statement.get("Condition", {}),
                    "document_has_denies": bool(denies),
                    "source": policy["source"],
                    "sensitive_actions_matched": sensitive,
                },
                "review_required",
                str(index),
            )
        )
    return findings


def universal_sources(rule):
    result = []
    for entries, key in (("IpRanges", "CidrIp"), ("Ipv6Ranges", "CidrIpv6")):
        for entry in rule.get(entries, []):
            network = ipaddress.ip_network(entry[key], strict=False)
            if network.prefixlen == 0:
                result.append(str(network))
    return sorted(set(result))


def check_security_group(group):
    findings = []
    for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
        for rule in group.get(key, []):
            sources = universal_sources(rule)
            if not sources:
                continue
            protocol = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}.get(
                str(rule["IpProtocol"]), str(rule["IpProtocol"])
            )
            start, end = rule.get("FromPort"), rule.get("ToPort")
            all_ports = protocol == "-1" or (
                protocol in ("tcp", "udp") and start == 0 and end == 65535
            )
            if direction == "egress" and not all_ports:
                continue
            sensitive = (
                sorted(p for p in SENSITIVE_PORTS if start is not None and start <= p <= end)
                if protocol in ("tcp", "udp")
                else []
            )
            severity = (
                "low"
                if direction == "egress"
                else "critical"
                if all_ports
                else "high"
                if sensitive
                else "low"
                if protocol in ("icmp", "icmpv6")
                else "medium"
            )
            evidence = {
                "direction": direction,
                "protocol": protocol,
                "from_port": start,
                "to_port": end,
                "cidrs": sources,
                "sensitive_ports": sensitive,
                "vpc_id": group.get("VpcId"),
                "group_name": group.get("GroupName"),
            }
            # Canonical rule identity survives changes in AWS list ordering.
            qualifier = f"{direction}|{protocol}|{start}|{end}|{','.join(sources)}"
            findings.append(
                Finding(
                    "SG_OPEN_INGRESS" if direction == "ingress" else "SG_UNRESTRICTED_EGRESS",
                    "security_groups",
                    group["arn"],
                    group["region"],
                    "Security group permits universal-source ingress"
                    if direction == "ingress"
                    else "Security group permits unrestricted outbound traffic",
                    severity,
                    "This rule permits traffic at the security-group layer. Actual internet reachability depends on attachments, addresses, routes, NACLs and listening services.",
                    "Replace universal CIDRs with approved source ranges or security-group references. For intentional public web ingress, document the owner and justification. Restrict outbound traffic to required destinations and protocols.",
                    evidence,
                    qualifier=qualifier,
                )
            )
    return findings


def evaluate(inventory):
    findings = []
    for bucket in inventory.buckets:
        findings.extend(check_s3(bucket, inventory.partition))
    for user in inventory.users:
        findings.extend(check_mfa(user))
    for policy in inventory.policies:
        findings.extend(check_policy(policy))
    for group in inventory.security_groups:
        findings.extend(check_security_group(group))
    return findings
