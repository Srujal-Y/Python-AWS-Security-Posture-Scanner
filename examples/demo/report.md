# AWS Security Posture Review

SYNTHETIC DEMO: these resources are fictional; this is not an AWS account assessment.

**Status:** complete · **Account:** 111122223333 · **Scan:** fa5de6ec-3703-4356-814b-7111a2588049

Completed: 2026-10-20T09:13:10.209508+00:00

## Severity summary

| Risk level | Findings |
| --- | ---: |
| Critical | 2 |
| High | 7 |
| Medium | 3 |
| Low | 1 |
| Informational | 0 |

## Coverage

| Check family | Scope | Status | Resources discovered |
| --- | --- | --- | ---: |
| s3&#95;public | all-account-buckets | complete | 3 |
| iam&#95;mfa | global | complete | 3 |
| iam&#95;policy | global | complete | 6 |
| security&#95;groups | us-east-1 | complete | 2 |
| security&#95;groups | eu-west-1 | complete | 2 |

## Findings

### CRITICAL — Security group permits universal-source ingress

- **ID:** ecab8b3ef48be632c80d / SG_OPEN_INGRESS
- **Affected resource:** arn:aws:ec2:us-east-1:111122223333:security-group/sg-00000000000000000
- **Region:** us-east-1
- **Assessment:** configuration
- **Risk:** This rule permits traffic at the security-group layer. Actual internet reachability depends on attachments, addresses, routes, NACLs and listening services.
- **Remediation:** Replace universal CIDRs with approved source ranges or security-group references. For intentional public web ingress, document the owner and justification. Restrict outbound traffic to required destinations and protocols.

**Evidence**

    {
      "direction": "ingress",
      "protocol": "-1",
      "from_port": null,
      "to_port": null,
      "cidrs": [
        "0.0.0.0/0"
      ],
      "sensitive_ports": [],
      "vpc_id": "vpc-00000000000000000",
      "group_name": "fictional-group-0"
    }

### CRITICAL — Broad Allow statement requires least-privilege review

- **ID:** 85f6ae44320db79ba471 / IAM_BROAD_POLICY
- **Affected resource:** arn:aws:iam::111122223333:policy/FictionalAdministrator
- **Region:** global
- **Assessment:** review_required
- **Risk:** This statement is a policy-risk candidate, not proof of effective permission. Conditions, explicit denies, permission boundaries, SCPs and session policies may constrain it.
- **Remediation:** Replace broad grants with the actions and resources the workload needs. Review the statement in its attached identity context, including conditions, denies and organisational controls, before changing it.

**Evidence**

    {
      "statement_index": 0,
      "sid": null,
      "reasons": [
        "All actions are allowed by this statement",
        "Sensitive actions apply across a broad resource scope"
      ],
      "action": "*",
      "not_action": null,
      "resource": "*",
      "not_resource": null,
      "condition": {},
      "document_has_denies": false,
      "source": "attached-managed",
      "sensitive_actions_matched": [
        "iam:attachgrouppolicy",
        "iam:attachrolepolicy",
        "iam:attachuserpolicy",
        "iam:createaccesskey",
        "iam:createloginprofile",
        "iam:createpolicyversion",
        "iam:passrole",
        "iam:putgrouppolicy",
        "iam:putrolepolicy",
        "iam:putuserpolicy",
        "iam:setdefaultpolicyversion",
        "iam:updateassumerolepolicy",
        "iam:updateloginprofile",
        "kms:putkeypolicy",
        "s3:deletebucketpolicy",
        "s3:putbucketpolicy",
        "secretsmanager:getsecretvalue",
        "sts:assumerole"
      ]
    }

### HIGH — Security group permits universal-source ingress

- **ID:** c11554d8bdf3275aa1bc / SG_OPEN_INGRESS
- **Affected resource:** arn:aws:ec2:eu-west-1:111122223333:security-group/sg-00000000000000002
- **Region:** eu-west-1
- **Assessment:** configuration
- **Risk:** This rule permits traffic at the security-group layer. Actual internet reachability depends on attachments, addresses, routes, NACLs and listening services.
- **Remediation:** Replace universal CIDRs with approved source ranges or security-group references. For intentional public web ingress, document the owner and justification. Restrict outbound traffic to required destinations and protocols.

**Evidence**

    {
      "direction": "ingress",
      "protocol": "tcp",
      "from_port": 5400,
      "to_port": 5500,
      "cidrs": [
        "0.0.0.0/0"
      ],
      "sensitive_ports": [
        5432
      ],
      "vpc_id": "vpc-00000000000000000",
      "group_name": "fictional-group-2"
    }

### HIGH — Security group permits universal-source ingress

- **ID:** e34a45a01ccee2b151ae / SG_OPEN_INGRESS
- **Affected resource:** arn:aws:ec2:us-east-1:111122223333:security-group/sg-00000000000000001
- **Region:** us-east-1
- **Assessment:** configuration
- **Risk:** This rule permits traffic at the security-group layer. Actual internet reachability depends on attachments, addresses, routes, NACLs and listening services.
- **Remediation:** Replace universal CIDRs with approved source ranges or security-group references. For intentional public web ingress, document the owner and justification. Restrict outbound traffic to required destinations and protocols.

**Evidence**

    {
      "direction": "ingress",
      "protocol": "tcp",
      "from_port": 22,
      "to_port": 22,
      "cidrs": [
        "::/0"
      ],
      "sensitive_ports": [
        22
      ],
      "vpc_id": "vpc-00000000000000000",
      "group_name": "fictional-group-1"
    }

### HIGH — Broad Allow statement requires least-privilege review

- **ID:** a454bfde085b42fa849d / IAM_BROAD_POLICY
- **Affected resource:** arn:aws:iam::111122223333:policy/FictionalNotAction
- **Region:** global
- **Assessment:** review_required
- **Risk:** This statement is a policy-risk candidate, not proof of effective permission. Conditions, explicit denies, permission boundaries, SCPs and session policies may constrain it.
- **Remediation:** Replace broad grants with the actions and resources the workload needs. Review the statement in its attached identity context, including conditions, denies and organisational controls, before changing it.

**Evidence**

    {
      "statement_index": 0,
      "sid": null,
      "reasons": [
        "Allow with NotAction grants actions beyond the listed exclusions"
      ],
      "action": null,
      "not_action": "iam:*",
      "resource": "*",
      "not_resource": null,
      "condition": {},
      "document_has_denies": false,
      "source": "inline-role",
      "sensitive_actions_matched": []
    }

### HIGH — Broad Allow statement requires least-privilege review

- **ID:** da36e7f7476ffd77eb3c / IAM_BROAD_POLICY
- **Affected resource:** arn:aws:iam::111122223333:policy/FictionalPassRole
- **Region:** global
- **Assessment:** review_required
- **Risk:** This statement is a policy-risk candidate, not proof of effective permission. Conditions, explicit denies, permission boundaries, SCPs and session policies may constrain it.
- **Remediation:** Replace broad grants with the actions and resources the workload needs. Review the statement in its attached identity context, including conditions, denies and organisational controls, before changing it.

**Evidence**

    {
      "statement_index": 0,
      "sid": null,
      "reasons": [
        "Sensitive actions apply across a broad resource scope"
      ],
      "action": "iam:PassRole",
      "not_action": null,
      "resource": "*",
      "not_resource": null,
      "condition": {},
      "document_has_denies": false,
      "source": "attached-managed",
      "sensitive_actions_matched": [
        "iam:passrole"
      ]
    }

### HIGH — IAM user has no registered MFA device

- **ID:** 68a22c897ddb5aa586b1 / IAM_USER_NO_MFA
- **Affected resource:** arn:aws:iam::111122223333:user/fictional-operator
- **Region:** global
- **Assessment:** configuration
- **Risk:** An unprotected console password increases account takeover risk. MFA enrollment alone does not enforce MFA for access-key API requests.
- **Remediation:** For human access, prefer federation/Identity Center with enforced MFA. If this IAM user remains, register MFA and enforce it through access policy; replace workload users with roles.

**Evidence**

    {
      "console_password": true,
      "registered_mfa_devices": 0
    }

### HIGH — Bucket ACL contains public grants

- **ID:** 1a02138302db31e234f2 / S3_PUBLIC_ACL
- **Affected resource:** arn:aws:s3:::fictional-public-acl
- **Region:** eu-west-1
- **Assessment:** configuration
- **Risk:** A global ACL grant may permit unintended bucket access. Public does not prove network reachability or object access.
- **Remediation:** Review the grants, remove unintended global grantees, and enable IgnorePublicAcls and BlockPublicAcls at the appropriate scopes.

**Evidence**

    {
      "account_public_access_block": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
      },
      "bucket_public_access_block": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
      },
      "scope_note": "Bucket/account configuration only; organisation controls and object ACLs are not evaluated.",
      "public_grants": [
        {
          "Grantee": {
            "Type": "Group",
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
          },
          "Permission": "WRITE"
        }
      ],
      "ignore_public_acls": false
    }

### HIGH — S3 classifies the bucket policy as public

- **ID:** 18c9c156a196fc77e7a8 / S3_PUBLIC_POLICY
- **Affected resource:** arn:aws:s3:::fictional-public-policy
- **Region:** us-east-1
- **Assessment:** configuration
- **Risk:** The bucket policy is classified as public by S3 and the observed controls do not establish that public access is restricted.
- **Remediation:** Review bucket-policy principals and conditions; remove unintended public access and enable RestrictPublicBuckets and BlockPublicPolicy where appropriate.

**Evidence**

    {
      "account_public_access_block": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
      },
      "bucket_public_access_block": {
        "BlockPublicAcls": false,
        "IgnorePublicAcls": false,
        "BlockPublicPolicy": false,
        "RestrictPublicBuckets": false
      },
      "scope_note": "Bucket/account configuration only; organisation controls and object ACLs are not evaluated.",
      "is_public": true,
      "restrict_public_buckets": false
    }

### MEDIUM — Security group permits universal-source ingress

- **ID:** 79f07c75bf4c0a36b690 / SG_OPEN_INGRESS
- **Affected resource:** arn:aws:ec2:eu-west-1:111122223333:security-group/sg-00000000000000002
- **Region:** eu-west-1
- **Assessment:** configuration
- **Risk:** This rule permits traffic at the security-group layer. Actual internet reachability depends on attachments, addresses, routes, NACLs and listening services.
- **Remediation:** Replace universal CIDRs with approved source ranges or security-group references. For intentional public web ingress, document the owner and justification. Restrict outbound traffic to required destinations and protocols.

**Evidence**

    {
      "direction": "ingress",
      "protocol": "tcp",
      "from_port": 443,
      "to_port": 443,
      "cidrs": [
        "0.0.0.0/0"
      ],
      "sensitive_ports": [],
      "vpc_id": "vpc-00000000000000000",
      "group_name": "fictional-group-2"
    }

### MEDIUM — Broad Allow statement requires least-privilege review

- **ID:** 039026faf115e859cfcb / IAM_BROAD_POLICY
- **Affected resource:** arn:aws:iam::111122223333:policy/FictionalConditionalS3
- **Region:** global
- **Assessment:** review_required
- **Risk:** This statement is a policy-risk candidate, not proof of effective permission. Conditions, explicit denies, permission boundaries, SCPs and session policies may constrain it.
- **Remediation:** Replace broad grants with the actions and resources the workload needs. Review the statement in its attached identity context, including conditions, denies and organisational controls, before changing it.

**Evidence**

    {
      "statement_index": 0,
      "sid": null,
      "reasons": [
        "An entire service action namespace is allowed",
        "Sensitive actions apply across a broad resource scope"
      ],
      "action": "s3:*",
      "not_action": null,
      "resource": "*",
      "not_resource": null,
      "condition": {
        "StringEquals": {
          "aws:PrincipalTag/Team": "review"
        }
      },
      "document_has_denies": false,
      "source": "attached-managed",
      "sensitive_actions_matched": [
        "s3:deletebucketpolicy",
        "s3:putbucketpolicy"
      ]
    }

### MEDIUM — IAM user has no registered MFA device

- **ID:** 8bce8633d01ae205dbc0 / IAM_USER_NO_MFA
- **Affected resource:** arn:aws:iam::111122223333:user/fictional-legacy-workload
- **Region:** global
- **Assessment:** configuration
- **Risk:** An unprotected console password increases account takeover risk. MFA enrollment alone does not enforce MFA for access-key API requests.
- **Remediation:** For human access, prefer federation/Identity Center with enforced MFA. If this IAM user remains, register MFA and enforce it through access policy; replace workload users with roles.

**Evidence**

    {
      "console_password": false,
      "registered_mfa_devices": 0
    }

### LOW — Security group permits unrestricted outbound traffic

- **ID:** 9c19e1f7259f99107be1 / SG_UNRESTRICTED_EGRESS
- **Affected resource:** arn:aws:ec2:us-east-1:111122223333:security-group/sg-00000000000000000
- **Region:** us-east-1
- **Assessment:** configuration
- **Risk:** This rule permits traffic at the security-group layer. Actual internet reachability depends on attachments, addresses, routes, NACLs and listening services.
- **Remediation:** Replace universal CIDRs with approved source ranges or security-group references. For intentional public web ingress, document the owner and justification. Restrict outbound traffic to required destinations and protocols.

**Evidence**

    {
      "direction": "egress",
      "protocol": "-1",
      "from_port": null,
      "to_port": null,
      "cidrs": [
        "0.0.0.0/0"
      ],
      "sensitive_ports": [],
      "vpc_id": "vpc-00000000000000000",
      "group_name": "fictional-group-0"
    }

## Collection errors

None recorded.

## Assessment limits

- This is a configuration review, not a penetration test or proof of internet reachability.
- S3 coverage is bucket ACLs and S3 policy-public status, with observed bucket/account Block Public Access. Object ACLs, access points and organisation-level controls are excluded.
- IAM policy checks inspect attached managed permission policies and user/role/group inline policies. They do not compute effective permissions, trust policies, SCPs, permission boundaries or session policies.
- IAM MFA checks cover IAM users, not the root user, federated identities or Identity Center. Enrollment is distinct from enforcement.
- Security-group checks cover universal IPv4/IPv6 CIDRs and unrestricted egress in explicitly selected regions; routes, NACLs, attachments and combinations of non-universal CIDRs are not evaluated.
