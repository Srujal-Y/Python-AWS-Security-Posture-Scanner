# Security and data handling

The scanner reads AWS metadata using the caller's existing boto3 credential configuration. It has no write/remediation API path, credential input form, web server, dashboard, email sender or telemetry integration.

Live reports may expose account identifiers, resource names, network rules, policy statements and business context. Keep them in an approved local location with appropriate filesystem permissions. The scanner does not encrypt or sign them. Report files inherit the destination's filesystem controls.

`reports/`, `.aws/`, `.env`, `credentials` and `live-inventory*.json` are ignored by Git. An ignore rule is not a data-loss prevention control; review staged files before publishing. Only the explicitly fictional `examples/demo/` outputs belong in a public portfolio.

If you find a defect, provide a minimal fictional reproduction and the scanner version. Do not put AWS keys, real account policies or unredacted reports in a public issue. Arrange a private disclosure channel with the repository owner before sharing sensitive details.

Dependencies are pinned for the recorded validation and checked with `pip-audit`; advisory results can change. Dependency updates require rerunning tests and reviewing generated reports. GitHub Actions use fixed commit references, read-only repository permissions and no AWS credentials.

This scanner is a limited configuration review tool. It is not an authorisation system, a compliance certification or a replacement for an organisation's security monitoring.
