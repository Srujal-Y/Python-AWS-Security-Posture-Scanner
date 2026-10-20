# Check catalogue

Severity is a prioritisation heuristic for human review, not CVSS or a bank's approved risk rating. All findings include evidence and remediation. Intentional public services still require documented review.

## S3 exposure

| Check | Trigger | Severity |
| --- | --- | --- |
| `S3_PUBLIC_ACL` | Bucket ACL contains AllUsers or AuthenticatedUsers grants not suppressed by observed `IgnorePublicAcls` | High with known-unsuppressed grants or public write grants; medium for read grants with unknown controls |
| `S3_PUBLIC_POLICY` | S3 reports `IsPublic=true` and observed `RestrictPublicBuckets` does not establish restriction | High if controls are known false; medium if a control read is unknown |

Bucket and account settings combine using the most restrictive value. A true setting at either scope wins, even when the other scope is unknown. Otherwise an unknown value remains unknown.

`BlockPublicAcls` and `BlockPublicPolicy` prevent certain future public writes. They do not by themselves suppress existing public ACL grants or existing public policies. `IgnorePublicAcls` and `RestrictPublicBuckets` affect existing public access. The scanner uses S3's policy-public classification rather than inventing a partial S3 policy interpreter. See [AWS Block Public Access behaviour](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) and the [public access configuration API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PublicAccessBlockConfiguration.html).

Coverage excludes object ACLs, access points, multi-region access points, directory buckets, organisations' controls and end-to-end data access. ACL findings describe bucket grants; they do not prove that all objects are readable. A private bucket missing preventative controls alone does not produce a finding in this scope.

## IAM MFA

`IAM_USER_NO_MFA` fires only when all MFA-device pages were read and the registered count is zero.

| Context | Severity |
| --- | --- |
| Console login profile exists | High |
| Console profile absent or unreadable | Medium; unreadable profile also causes partial coverage |
| MFA-device read failed | No missing-device assertion; coverage partial |
| At least one device registered | No missing-device finding |

All IAM users are included, even without console passwords. A workload account may legitimately lack an MFA device; review migration to a role rather than blindly enrolling a device. The scanner does not inspect access-key use or enforce MFA. Root, federation and Identity Center are excluded. AWS exposes enrollment through [ListMFADevices](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam/paginator/ListMFADevices.html).

## IAM broad permission policies

`IAM_BROAD_POLICY` examines Allow statements in attached managed **permission** policies and inline user/role/group policies. Boundary-only managed policies, unattached managed policies and role trust policies are excluded.

Candidate patterns:

- `Action: "*"` or service-wide actions such as `s3:*`.
- `Allow` with `NotAction` or `NotResource`.
- Selected sensitive actions against `Resource: "*"` or `NotResource`, including `iam:PassRole`, credential creation, policy attachment/editing, `sts:AssumeRole`, bucket/KMS policy changes and secret retrieval. Case-insensitive action wildcards are matched against the explicit list in `checks.py`.

Global Allow with broad resource scope and no conditions or Deny statements is critical. Other broad grants are generally high; service grants scoped to specific resources are medium. Conditions or Deny statements reduce a high candidate to medium for contextual review. This downgrade does **not** prove a condition or deny is effective. An unconditional explicit Deny of all actions on all resources suppresses findings for that document. Ordinary wildcard-resource read patterns such as `ec2:Describe*` alone are not flagged.

AWS effective permissions depend on policy types and intersections, including explicit denies. The scanner neither simulates permissions nor resolves attachment paths, boundaries, SCPs or sessions. It cannot enumerate every privilege-escalation path, determine whether a condition is trustworthy, or establish exploitability. See [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).

## EC2 security groups

`SG_OPEN_INGRESS` examines `0.0.0.0/0` and `::/0`, including numeric protocol aliases.

| Rule | Severity |
| --- | --- |
| All protocols or all TCP/UDP ports | Critical |
| A range intersects a sensitive port | High |
| Other TCP/UDP ingress, including HTTP/HTTPS | Medium |
| ICMP/ICMPv6 ingress | Low |

Sensitive ports: 21, 22, 23, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5900, 6379, 9200, 9300, 11211 and 27017. This is a documented heuristic, not an exhaustive service inventory.

`SG_UNRESTRICTED_EGRESS` is low severity for universal destinations with all protocols or the full TCP/UDP port range. Restricting egress needs workload context, so narrower outbound rules are not flagged.

Security groups with public HTTP/HTTPS are included for review even when intentional. Prefix lists, group references, multiple CIDRs that collectively cover the internet, workload attachments, public IPs, routes, NACLs and actual listening services are excluded. An unused group can still be flagged. See the [EC2 security-group API response structure](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html).

## Scope and review

Do not interpret zero findings as “secure” or a complete report as regulatory compliance. Read the coverage table and collection errors first, then validate candidates against resource ownership and business intent. The local review workflow is in [OPERATIONS.md](OPERATIONS.md).
