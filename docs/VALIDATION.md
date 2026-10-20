# Validation record

Local validation date: **20 October 2026**. Environment: Windows, Python 3.14.2. This record concerns the source and fictional demo included in this project.

| Check | Observed result |
| --- | --- |
| Dependency consistency (`pip check`) | Passed |
| Ruff lint and formatting | Passed |
| Pytest | **75 passed**, zero failures |
| Combined statement/branch coverage | **97.87%**, above the configured 90% gate |
| Detection module statement and branch coverage | **100%** in this test run |
| Source distribution and universal Python wheel | Built successfully |
| Isolated wheel installation | Passed with pinned runtime dependencies in a separate virtual environment |
| Installed CLI outside the project source directory | Passed; imported package from the isolated environment |
| Offline demo | Complete declared coverage; 13 fictional findings; JSON/Markdown/HTML written |
| Runtime advisory audit on Python 3.14 | No known vulnerabilities reported by pip-audit at the time of the check |
| Live AWS collection | **Not performed: authorised AWS access is not available** |
| Hosted GitHub Actions | **Configured, not run for this new project** |
| Python 3.11 execution | **Configured in CI, not executed locally** |
| Independent bank/security/compliance approval | **Not performed or claimed** |

The compact [machine-readable evidence](../examples/validation/results.json) records test and coverage totals. It contains no live AWS data. The [demo report](../examples/demo/report.md) and its source inventory are fictional.

## What the tests establish

- Expected findings and protected-resource behaviour across the four families.
- S3's distinction between blocking future public writes and suppressing existing public grants.
- Unknown controls and denied MFA reads do not become false safe assertions.
- IAM conditions, Deny statements, NotAction, NotResource and selected sensitive action patterns are treated as documented.
- Universal IPv4 and IPv6 CIDRs, numeric protocols, sensitive port ranges and egress rules are handled.
- Real botocore request/response schemas are exercised with Stubber, including pagination, default managed-policy versions, inline policy reads and SDK failures.
- Schema validation rejects malformed snapshots and missing coverage.
- Severity thresholds and partial-scan exit codes work as documented.
- HTML escapes untrusted fields; Markdown separates escaped prose from JSON code blocks.
- The offline CLI does not initialise a boto3 session.
- Wheel package data contains the required schemas and fictional inventory.

Coverage measures exercised code paths, not detection completeness or production fitness. A mocked API test cannot establish that an actual account grants every required permission or that AWS resources behave exactly like the fixtures.

## Reproduce

```powershell
.\.venv\Scripts\python.exe scripts/verify.py
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt --strict --disable-pip --no-deps
```

The second command needs network access to advisory data. Audit results can change. The Python 3.11-only conditional dependency is covered by the configured Python 3.11 CI audit when that workflow is run.

`reports/junit.xml`, `coverage.xml`, `reports/dependency-audit.json`, `reports/demo/` and `dist/` hold local validation artifacts and are intentionally ignored by Git. The committed examples are explicitly fictional and the compact validation summary omits local machine paths.

Before claiming live validation or operational readiness, follow the acceptance procedure in [OPERATIONS.md](OPERATIONS.md) and retain separately reviewed evidence.
