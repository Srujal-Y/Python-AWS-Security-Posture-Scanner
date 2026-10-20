# Five-minute project walkthrough

## 1. Explain the problem

“AWS exposes configuration across several services. I wanted a small, read-only tool that collects selected metadata and produces an evidence-led review that a person can inspect locally.”

Name the four check families. Explain that the output is a report, with no dashboard or email integration.

## 2. Run the offline demonstration

```powershell
.\.venv\Scripts\python.exe -m posture_scanner demo --output reports/demo --fail-on none
Start-Process .\reports\demo\report.html
```

Explain that all resources in this demonstration are fictional. Show the coverage table, severity totals, one affected resource, the evidence and remediation.

## 3. Explain three decisions

**Incomplete reads must not look safe.** AccessDenied produces explicit collection errors and partial coverage. Exit 2 remains a failure even when severity gating is disabled.

**Security controls need context.** An existing public S3 ACL can be ignored by account settings; an IAM wildcard grant can be constrained by other policies; an open security-group rule does not establish actual reachability. The check catalogue states what each check can establish.

**Rules should be testable independently.** The collector normalises metadata, pure functions evaluate it, and renderers produce schema-validated reports. Botocore Stubber validates SDK request shapes and exercises failures without an AWS account.

## 4. Show engineering evidence

Open a pagination/AccessDenied test, a public-access-block test and the GitHub Actions workflow. Run `.venv/Scripts/python.exe scripts/verify.py` if time permits. Explain stable finding IDs, ranked output, package installation and report escaping.

Describe hosted CI and live AWS validation as pending until they have actually run. Local tests are not evidence of deployment.

## 5. Discuss the next production steps

“The implemented scope is complete and locally tested. Before operational use, I would validate it in an authorised AWS sandbox, have another reviewer assess the detection logic, and agree on account coverage, data retention, ownership and exception handling.”

Possible future extensions: organisation-wide collection through approved roles, root MFA, policy-context analysis, incremental comparison and approved review-system integration. These are future work, not current features.

## Accurate CV wording

> Built a read-only Python/boto3 AWS posture scanner covering public S3 exposure, IAM MFA enrollment, broad permission policies and open security-group rules. Generated severity-ranked JSON, Markdown and HTML findings with resource evidence, risk and remediation guidance; validated detection and failure handling with offline fixtures and mocked AWS APIs.

Do not claim production deployment, bank certification, compliance coverage or a live account assessment without separate evidence.
