# Operator runbook

## Before an authorised live scan

1. Agree on the account, named EC2 regions, owner and review scope. S3 and IAM are account-wide.
2. Have an administrator review `iam/scanner-read-only-policy.json`. It grants only the metadata APIs used by the collector. Some account-wide enumeration needs `Resource: "*"`. The bucket ARN example targets the `aws` partition; adapt it for other partitions.
3. Use a short-lived role/SSO profile through your established AWS credential process. Do not put keys in code, snapshots, command history or repository files.
4. Choose a new output directory in a location appropriate for the sensitivity of IAM policies and network metadata.

The scanner does not create infrastructure and needs no deployed server. A normal authenticated AWS account is needed only for live scans; the offline demo has no AWS requests.

## Run and inspect

```powershell
.\.venv\Scripts\python.exe -m posture_scanner scan `
  --profile security-review `
  --regions eu-west-1 me-central-1 `
  --output reports/review-2026-10-20
$ScanExitCode = $LASTEXITCODE
Get-Content reports/review-2026-10-20/report.json
Write-Host "Scanner exit code: $ScanExitCode"
```

Inspect the exit code before accepting output. A `2` takes precedence over severity and means the result is operationally incomplete. Old output can remain if input validation or file writing fails; check run IDs and timestamps.

For each report:

1. Confirm account, partition, mode, timestamps and the selected regions.
2. Inspect coverage and errors. Investigate `AccessDenied`, expired sessions, throttling or unavailable endpoints; fix authorised access and rerun.
3. Review critical and high findings first, then the remaining findings.
4. Verify resource ownership, business purpose and relevant AWS controls before applying remediation.
5. Record the decision and retain the report under the organisation's evidence policy.

## Review record

The scanner emits evidence; a human records disposition in a local review note or an existing approved case system. Suggested fields:

| Field | Purpose |
| --- | --- |
| Scan ID and finding ID | Link decision to observed evidence |
| Reviewer and review date | Accountability |
| Resource owner | Who can confirm intended configuration |
| Disposition | Confirmed issue / accepted risk / intentional configuration / insufficient evidence |
| Rationale | Business need and compensating controls |
| Agreed action and due date | Owner-approved remediation |
| Verification evidence | New scan ID and manual confirmation after change |

No automated ticketing, suppression store, exception expiry engine, alerting or dashboard is implemented. No finding is automatically fixed.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Demo exits 1 | Expected with its intentional high/critical findings; use `--fail-on none` for a demo smoke test |
| `ProfileNotFound` / `NoCredentialsError` | Select an existing authorised profile or renew the organisation's login session |
| `AccessDenied` | Match the report's operation to the read-only policy; consult the account owner about boundaries/SCPs |
| Partial S3 coverage | Check account-level control access, bucket ownership and per-bucket metadata permissions |
| Partial EC2 region | Confirm the region is enabled and the endpoint and credentials are valid for the partition |
| Snapshot rejected | Validate required fields against the inventory schema; preserve unknown values and declare partial coverage |
| No findings | Confirm complete coverage and understand the check exclusions before drawing conclusions |
| Cannot write reports | Select a writable directory; retain any previous report set separately |

SDK standard retries are bounded; persistent failures are recorded. There is no infinite retry loop.

## First live validation acceptance procedure

This procedure remains pending until an authorised AWS account is available.

1. In an approved sandbox, identify safe existing examples and known configuration issues from each check family. Any deliberately vulnerable fixtures require the account owner's process and are outside the scanner.
2. Compare observed metadata and findings with independent AWS CLI/console reads.
3. Confirm selected regions, bucket regions, attached policy versions and inline policies are covered.
4. Test a role with deliberately missing read permissions. Confirm exit 2 and partial coverage without false safe assertions.
5. Retain sanitised outputs and AWS audit evidence showing only approved read API activity.
6. Have a second reviewer check findings and remediation guidance.

Do not run against an employer's account without their authorisation. Banking production approval requires the institution's own security, data-handling and operational reviews.
