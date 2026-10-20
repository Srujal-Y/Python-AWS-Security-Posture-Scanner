"""Run local validation with the current Python environment; no AWS calls."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = [
    ["pip", "check"],
    ["ruff", "check", "."],
    ["ruff", "format", "--check", "."],
    [
        "pytest",
        "--cov=posture_scanner",
        "--cov-branch",
        "--cov-report=term-missing",
        "--cov-report=xml",
        "--cov-fail-under=90",
        "--junitxml=reports/junit.xml",
    ],
    ["build", "--no-isolation"],
    ["posture_scanner", "demo", "--output", "reports/demo", "--fail-on", "none"],
]


def main():
    for check in CHECKS:
        print(f"\nRunning: {sys.executable} -m {' '.join(check)}", flush=True)
        result = subprocess.run([sys.executable, "-m", *check], cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
    print("\nLocal validation passed. Live AWS validation is a separate, authorised step.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
