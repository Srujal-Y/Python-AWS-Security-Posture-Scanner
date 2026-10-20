# Python AWS Security Posture Scanner

A read-only Python CLI that turns AWS configuration metadata into a local security review. It checks public S3 exposure, IAM users without MFA, broad IAM permission policies, and open EC2 security-group rules.

Each finding includes a stable ID, affected resource, region, severity, evidence, risk explanation and remediation guidance. JSON supports further analysis; Markdown and a standalone HTML report support human review. There is no dashboard, email integration or automatic remediation.

**Run the demonstration without an AWS account, credentials, Docker or paid services.** The included resources are fictional and every demo report says so.

## Start on Windows

Open PowerShell in this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-build-isolation --no-deps
.\.venv\Scripts\python.exe -m posture_scanner demo --output reports/demo --fail-on none
Start-Process .\reports\demo\report.html
```

Linux/macOS: use `python3 -m venv .venv` and `.venv/bin/python` in place of the Windows Python path. Supported Python versions start at 3.11. The recorded local validation used Python 3.14.2 on Windows.

The demonstration produces **13 findings: 2 critical, 7 high, 3 medium and 1 low**. It also includes protected resources that should produce no finding, including public S3 grants suppressed by account controls, an IAM user with MFA, and an unconditional deny-all policy.

You can open the committed [sample HTML report](examples/demo/report.html), [Markdown report](examples/demo/report.md), or [JSON report](examples/demo/report.json) directly. GitHub displays HTML source; download the HTML file and open it locally to view the formatted report.

## What it checks

| Family | Observations | Important distinction |
| --- | --- | --- |
| Public S3 exposure | Bucket ACL global grants and S3 `IsPublic` policy status; bucket and account Block Public Access | Controls that block new public writes differ from controls that restrict existing public access |
| IAM MFA | Registered MFA devices and console login-profile presence for IAM users | Enrollment does not prove MFA enforcement; workload users need different remediation |
| IAM policies | Attached managed permission policies and user, role and group inline policies | Broad grants are review candidates; the scanner does not calculate effective permissions |
| Security groups | Universal IPv4/IPv6 ingress, sensitive port ranges, all-protocol ingress and unrestricted egress | An open rule does not prove that an attached workload is reachable from the internet |

See the [check catalogue](docs/CHECKS.md) for severity rules, exclusions and AWS references.

## Run against AWS when access is available

Have an account administrator review [the scanner's read-only IAM policy](iam/scanner-read-only-policy.json) and attach it to an authorised scanning role. Use your organisation's normal AWS profile/SSO process. The scanner uses boto3's credential provider chain and stores no credentials in the project.

```powershell
.\.venv\Scripts\python.exe -m posture_scanner scan `
  --profile security-review `
  --regions eu-west-1 me-central-1 `
  --output reports/aws-review
```

EC2 checks run only in the named regions. IAM and general-purpose S3 bucket discovery are account-wide. Run separately with the authorised profile for each account; there is no organisation-wide role traversal.

The scanner only invokes read APIs. It does not provision resources, modify policies, open ports, retrieve object contents, create credentials or send reports. **No live AWS scan has been performed for the included validation evidence.**

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Coverage is complete for the declared scope and no finding meets the chosen failure threshold |
| `1` | Coverage is complete and a finding meets or exceeds the threshold |
| `2` | Collection is incomplete, credentials/input are invalid, or report writing fails |

Default threshold: `--fail-on high`. Other choices: `critical`, `medium`, `low`, `informational`, `none`. `none` disables severity failure but **never** makes partial coverage pass. A default demo run returns `1` because its intentional findings meet the threshold.

“Complete” describes collection coverage for these checks, not a secure account, regulatory compliance or absence of other vulnerabilities. An inaccessible resource is recorded as incomplete; it is never silently treated as safe.

## Review a local inventory

```powershell
.\.venv\Scripts\python.exe -m posture_scanner snapshot `
  --input src/posture_scanner/data/demo.json `
  --output reports/snapshot `
  --fail-on none
```

Snapshots must match the [inventory schema](src/posture_scanner/data/inventory.schema.json), declare all four families and include coverage for every requested EC2 region. Unknown observations must be declared as incomplete. Snapshot metadata is explicitly labelled as unverified. The live command does not export an inventory snapshot.

## Validate the project

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
# Separate network-backed dependency advisory check:
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt --strict --disable-pip --no-deps
```

The verification script runs dependency consistency checks, lint/format checks, tests with branch coverage, package builds and the offline demo. Tests cover AWS responses using botocore Stubber, pagination, denied reads, MFA uncertainty, IAM policy logic, IPv6, report escaping and exit codes. CI runs these checks on Python 3.11 and 3.14 with no AWS credentials.

See [validation evidence](docs/VALIDATION.md) for exactly what was run locally. A configured GitHub workflow is not evidence of a successful hosted CI run.

## Design and operating guides

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Check catalogue and severity decisions](docs/CHECKS.md)
- [Operational runbook and review workflow](docs/OPERATIONS.md)
- [Five-minute interview walkthrough](docs/INTERVIEW.md)
- [Security and data handling](SECURITY.md)

```text
src/posture_scanner/
  collector.py       Read-only AWS metadata collection and coverage
  checks.py          Pure, independently testable detection logic
  models.py          Inventory, stable finding identity and exit policy
  reporting.py       JSON, Markdown and standalone HTML reports
  cli.py             Scan, snapshot and demo commands
  data/              Versioned input/output schemas and fictional inventory
tests/               Detection, AWS stub and CLI/report tests
iam/                 Explicit read-only API permission policy
examples/demo/       Fictional sample outputs
docs/                Design, operations, checks and validation evidence
.github/             Credential-free CI and dependency update configuration
```

This is a portfolio implementation of a scoped posture scanner. Production adoption in a financial institution would additionally require authorised live validation, independent security review, account-specific controls, operational ownership and the institution's own approval process. It makes no claim of affiliation with or certification by a bank.
