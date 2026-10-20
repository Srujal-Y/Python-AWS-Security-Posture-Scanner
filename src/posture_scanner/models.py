import hashlib
import json
from dataclasses import asdict, dataclass, field

FAMILIES = ("s3_public", "iam_mfa", "iam_policy", "security_groups")
SEVERITIES = ("critical", "high", "medium", "low", "informational")


@dataclass(frozen=True)
class Finding:
    check_id: str
    family: str
    resource: str
    region: str
    issue: str
    severity: str
    risk: str
    remediation: str
    evidence: dict
    confidence: str = "configuration"
    qualifier: str = ""

    def to_dict(self):
        result = asdict(self)
        qualifier = result.pop("qualifier")
        identity = json.dumps(
            [self.check_id, self.resource, self.region, qualifier], separators=(",", ":")
        )
        result["id"] = hashlib.sha256(identity.encode()).hexdigest()[:20]
        return result


@dataclass
class Inventory:
    account_id: str = "unknown"
    partition: str = "aws"
    regions: list = field(default_factory=list)
    buckets: list = field(default_factory=list)
    users: list = field(default_factory=list)
    policies: list = field(default_factory=list)
    security_groups: list = field(default_factory=list)
    coverage: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self):
        return {"schema_version": "1.0", **asdict(self)}


def sorted_findings(findings):
    rows = {finding.to_dict()["id"]: finding.to_dict() for finding in findings}
    return sorted(
        rows.values(),
        key=lambda f: (SEVERITIES.index(f["severity"]), f["resource"], f["check_id"], f["id"]),
    )


def exit_code(report, fail_on="high"):
    if report["status"] != "complete":
        return 2
    if fail_on == "none":
        return 0
    threshold = SEVERITIES.index(fail_on)
    return int(any(SEVERITIES.index(f["severity"]) <= threshold for f in report["findings"]))
