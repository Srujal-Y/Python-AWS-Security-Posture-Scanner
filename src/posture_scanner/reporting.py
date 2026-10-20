import html
import json
import os
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .models import FAMILIES, SEVERITIES, sorted_findings

LIMITATIONS = [
    "This is a configuration review, not a penetration test or proof of internet reachability.",
    "S3 coverage is bucket ACLs and S3 policy-public status, with observed bucket/account Block Public Access. Object ACLs, access points and organisation-level controls are excluded.",
    "IAM policy checks inspect attached managed permission policies and user/role/group inline policies. They do not compute effective permissions, trust policies, SCPs, permission boundaries or session policies.",
    "IAM MFA checks cover IAM users, not the root user, federated identities or Identity Center. Enrollment is distinct from enforcement.",
    "Security-group checks cover universal IPv4/IPv6 CIDRs and unrestricted egress in explicitly selected regions; routes, NACLs, attachments and combinations of non-universal CIDRs are not evaluated.",
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def make_report(inventory, findings, mode, started_at):
    rows = sorted_findings(findings)
    counts = Counter(f["severity"] for f in rows)
    covered = {entry["family"] for entry in inventory.coverage}
    sg_regions = {
        entry["scope"] for entry in inventory.coverage if entry["family"] == "security_groups"
    }
    incomplete = (
        inventory.account_id == "unknown"
        or bool(set(FAMILIES) - covered)
        or bool(set(inventory.regions) - sg_regions)
        or bool(inventory.errors)
    ) or any(entry["status"] != "complete" for entry in inventory.coverage)
    return {
        "schema_version": "1.0",
        "scanner_version": __version__,
        "scan_id": str(uuid.uuid4()),
        "mode": mode,
        "started_at": started_at,
        "completed_at": utc_now(),
        "account_id": inventory.account_id,
        "partition": inventory.partition,
        "regions": inventory.regions,
        "status": "partial" if incomplete else "complete",
        "summary": {"total": len(rows), **{s: counts[s] for s in SEVERITIES}},
        "coverage": inventory.coverage,
        "errors": inventory.errors,
        "findings": rows,
        "limitations": LIMITATIONS,
        "review_note": (
            "SYNTHETIC DEMO: these resources are fictional; this is not an AWS account assessment."
            if mode == "demo"
            else "Local metadata snapshot: not independently verified against a live AWS account."
            if mode == "snapshot"
            else "Read-only AWS metadata assessment. Review findings in business and policy context."
        ),
    }


def markdown(report):
    def safe(value):
        escaped = html.escape(str(value)).replace("|", "&#124;").replace("\n", " ")
        return escaped.translate({ord(char): f"&#{ord(char)};" for char in "\\`*_[]"})

    lines = [
        "# AWS Security Posture Review",
        "",
        report["review_note"],
        "",
        f"**Status:** {report['status']} · **Account:** {report['account_id']} · "
        f"**Scan:** {report['scan_id']}",
        "",
        f"Completed: {report['completed_at']}",
        "",
        "## Severity summary",
        "",
        "| Risk level | Findings |",
        "| --- | ---: |",
        *[f"| {s.title()} | {report['summary'][s]} |" for s in SEVERITIES],
        "",
        "## Coverage",
        "",
        "| Check family | Scope | Status | Resources discovered |",
        "| --- | --- | --- | ---: |",
        *[
            f"| {safe(c['family'])} | {safe(c['scope'])} | {safe(c['status'])} | {c['resources_discovered']} |"
            for c in report["coverage"]
        ],
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines += [
            "No findings were produced within the observed scope. Check coverage before interpreting this result.",
            "",
        ]
    for finding in report["findings"]:
        lines += [
            f"### {finding['severity'].upper()} — {safe(finding['issue'])}",
            "",
            f"- **ID:** {finding['id']} / {finding['check_id']}",
            f"- **Affected resource:** {safe(finding['resource'])}",
            f"- **Region:** {safe(finding['region'])}",
            f"- **Assessment:** {finding['confidence']}",
            f"- **Risk:** {safe(finding['risk'])}",
            f"- **Remediation:** {safe(finding['remediation'])}",
            "",
            "**Evidence**",
            "",
            *[
                "    " + line
                for line in json.dumps(
                    finding["evidence"], indent=2, ensure_ascii=True
                ).splitlines()
            ],
            "",
        ]
    lines += ["## Collection errors", ""]
    lines += [
        f"- {safe(e['family'])} / {safe(e['operation'])} / {safe(e['resource'])}: **{safe(e['code'])}** — {safe(e['message'])}"
        for e in report["errors"]
    ] or ["None recorded."]
    lines += ["", "## Assessment limits", "", *["- " + item for item in report["limitations"]], ""]
    return "\n".join(lines)


def html_report(report):
    def esc(value):
        return html.escape(str(value), quote=True)

    cards = "".join(
        f'<div class="metric"><b>{report["summary"][s]}</b><span>{s.title()}</span></div>'
        for s in SEVERITIES
    )
    coverage = "".join(
        f"<tr><td>{esc(c['family'])}</td><td>{esc(c['scope'])}</td>"
        f"<td>{esc(c['status'])}</td><td>{c['resources_discovered']}</td></tr>"
        for c in report["coverage"]
    )
    findings = []
    for f in report["findings"]:
        findings.append(
            f'<article class="{f["severity"]}"><small>{f["severity"].upper()} · {esc(f["check_id"])}</small>'
            f"<h3>{esc(f['issue'])}</h3><p><strong>Affected resource</strong><br><code>{esc(f['resource'])}</code></p>"
            f"<p><strong>Risk</strong><br>{esc(f['risk'])}</p>"
            f"<p><strong>Remediation</strong><br>{esc(f['remediation'])}</p>"
            f"<p>Region: {esc(f['region'])} · Assessment: {esc(f['confidence'])} · ID: {esc(f['id'])}</p>"
            f"<details><summary>Evidence</summary><pre>{esc(json.dumps(f['evidence'], indent=2))}</pre></details></article>"
        )
    errors = "".join(
        f"<li>{esc(e['family'])}: {esc(e['operation'])} — {esc(e['code'])} "
        f"({esc(e['resource'])})</li>"
        for e in report["errors"]
    )
    limits = "".join(f"<li>{esc(item)}</li>" for item in report["limitations"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AWS Security Posture Review</title>
<style>
:root{{font:16px system-ui;color:#1b2a40;background:#f2f5f9}}body{{max-width:1080px;margin:36px auto;padding:24px}}
h1{{font-size:40px;margin-bottom:12px}}h2{{margin-top:38px}}p,li{{line-height:1.6}}small{{letter-spacing:1px}}
.banner{{padding:18px;background:#fff3d6;border-left:5px solid #c48c10}}.metrics{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}
.metric{{flex:1;background:white;padding:18px;border-radius:10px}}.metric b{{display:block;font-size:30px}}.metric span{{color:#53657d}}
article{{padding:24px;background:white;margin:18px 0;border-left:5px solid #8093ad;border-radius:8px;break-inside:avoid}}
.critical{{border-color:#ae163e}}.high{{border-color:#db6620}}.medium{{border-color:#bc9517}}.low{{border-color:#267bb2}}
table{{width:100%;border-collapse:collapse;background:white}}th,td{{text-align:left;padding:12px;border-bottom:1px solid #dee5ef}}
code,pre{{overflow-wrap:anywhere;white-space:pre-wrap;font-size:13px}}pre{{padding:14px;background:#eef2f7}}summary{{cursor:pointer}}
@media print{{body{{margin:0;padding:0;background:white}}.metric{{border:1px solid #ddd}}details{{display:block}}}}
</style></head><body>
<small>READ-ONLY AWS CONFIGURATION REVIEW</small><h1>AWS Security Posture Review</h1>
<p class="banner">{esc(report["review_note"])}</p>
<p><strong>Coverage status: {esc(report["status"]).upper()}</strong> · Account {esc(report["account_id"])}<br>
Completed {esc(report["completed_at"])}<br>Scan ID {esc(report["scan_id"])}</p>
<div class="metrics">{cards}</div>
<h2>Collection coverage</h2><table><thead><tr><th>Check family</th><th>Scope</th><th>Status</th><th>Discovered</th></tr></thead><tbody>{coverage}</tbody></table>
<h2>Findings</h2>{"".join(findings) or "<p>No findings produced. Review coverage before interpreting this result.</p>"}
<h2>Collection errors</h2><ul>{errors or "<li>None recorded.</li>"}</ul>
<h2>Assessment limits</h2><ul>{limits}</ul>
<footer>Local review artifact · no dashboard, network assets, scripts or email integration.</footer>
</body></html>"""


def write_reports(report, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "report.json": json.dumps(report, indent=2, ensure_ascii=True) + "\n",
        "report.md": markdown(report),
        "report.html": html_report(report),
    }
    for name, content in artifacts.items():
        # Replace each artifact atomically so interrupted writes cannot leave truncated JSON.
        handle, temporary = tempfile.mkstemp(dir=output, prefix=".report-", suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
            os.replace(temporary, output / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return [str(output / name) for name in artifacts]
