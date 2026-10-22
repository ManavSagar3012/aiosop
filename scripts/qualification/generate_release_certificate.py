#!/usr/bin/env python3
"""Noncertified release readiness draft generator.

Generates RELEASE_READINESS_DRAFT.md with informational Git revision and
selected local static check results. It intentionally refuses to create a
production release certificate and returns a nonzero release-gate exit code.

Usage:
    python scripts/qualification/generate_release_certificate.py

Does not run providers, contact targets or independently verify old reports.
"""

import subprocess
import sys
from datetime import datetime
from pathlib import Path


def run_cmd(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "unknown"


def get_git_sha() -> str:
    return run_cmd(["git", "rev-parse", "--short", "HEAD"])


def get_git_branch() -> str:
    return run_cmd(["git", "rev-parse", "--abbrev-ref", "HEAD"])


def get_pytest_coverage() -> str:
    try:
        # Run pytest with coverage in quiet mode
        result = subprocess.run(
            ["python", "-m", "pytest", "--co", "-q", "--no-cov"],
            capture_output=True,
            text=True,
        )
        # Parse test count from output
        lines = result.stdout.strip().split("\n")
        for line in lines:
            if "test session" in line:
                return line
        return "Tests collected (run for coverage)"
    except Exception as e:
        return f"Could not run tests: {e}"


DELIVERABLE_FILES = [
    "src/ai_osop/reporting/exporters.py",
    "src/ai_osop/mcp/protocol.py",
    "src/ai_osop/core/diff_auth_engine.py",
    "src/ai_osop/safety/self_test.py",
    "src/ai_osop/agents/supervision.py",
    "tests/test_attested_exporters.py",
    "tests/test_finding_validation_corpus.py",
    "tests/test_chaos_matrix.py",
    "tests/test_mcp_manifests_and_lifecycle.py",
    "scripts/qualification/test_self_pentest.py",
    "scripts/qualification/run_competitive_benchmark.py",
]


def get_black_check() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "black", "--check", *DELIVERABLE_FILES],
        capture_output=True,
        text=True,
    )
    return "PASS" if result.returncode == 0 else "FAIL"


def get_flake8_check() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "flake8", "--max-line-length=100", *DELIVERABLE_FILES],
        capture_output=True,
        text=True,
    )
    return "PASS" if result.returncode == 0 else "FAIL"


def get_mypy_check() -> str:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--ignore-missing-imports",
            "-m",
            "ai_osop.reporting.exporters",
            "-m",
            "ai_osop.core.diff_auth_engine",
            "-m",
            "ai_osop.safety.self_test",
            "-m",
            "ai_osop.agents.supervision",
        ],
        capture_output=True,
        text=True,
    )
    return "PASS" if result.returncode == 0 else "FAIL"


def read_qualification_report() -> str:
    report_path = Path("PRODUCTION_READINESS_REPORT.md")
    if report_path.exists():
        content = report_path.read_text(encoding="utf-8")
        # Extract score
        for line in content.split("\n"):
            if "Security Score" in line:
                return line.strip()
        return "Report exists but score not found"
    return "No qualification report found"


def main() -> int:
    """Generate an explicitly noncertified local draft; never mint a certificate.

    Static checks and historical benchmark prose are not current independently
    authenticated target effects, multi-replica qualification or senior signoff.
    """
    print("=" * 60)
    print("AI-OSOP NONCERTIFIED RELEASE READINESS")
    print("=" * 60)
    sha = get_git_sha()
    branch = get_git_branch()
    black = get_black_check()
    flake8 = get_flake8_check()
    mypy = get_mypy_check()
    # Do not copy arbitrary legacy scores/claims into this draft.
    historical_report_present = Path("PRODUCTION_READINESS_REPORT.md").is_file()
    draft = f"""# AI-OSOP release readiness — NONCERTIFIED DRAFT

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**

Generated: {datetime.utcnow().isoformat()}Z
Git SHA (informational): {sha}
Branch (informational): {branch}

## Local static checks (not production qualification)

| Observation | Result |
| --- | --- |
| Selected Black check | {black} |
| Selected Flake8 check | {flake8} |
| Selected MyPy check | {mypy} |
| Historical report present (not independently validated) | {historical_report_present} |

No benchmark score or old report entry is verified by this generator.
Local linting does not qualify a native provider action or target effect.

## Unverified mandatory release requirements

- Independently authenticated, owner-of-record effect evidence for approved
  consequential target actions; signed provider receipts alone are insufficient.
- All 11 configured MCP services' actual authorized transport, execution,
  evidence, revocation and recovery boundaries (not registry initialization).
- Real disposable PostgreSQL joined authorization and cross-process replay,
  rollback, crash/ACK-loss, and multi-replica qualification.
- Substantive PentAGI v2.2.0 feature parity, including providers, knowledge,
  resources, subscriptions and reporting. Previous main sample is historical.
- Independently enrolled senior-signed final release; this tool is NOT a signer.

This draft does not authorize target contact, provider spending, 0027 UNKNOWN
replay, native scanner activation or distribution as a release certificate.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
"""
    output_path = Path("RELEASE_READINESS_DRAFT.md")
    output_path.write_text(draft, encoding="utf-8")
    print(f"Noncertified draft written: {output_path}")
    print(f"Git SHA: {sha}; static checks: Black={black}, Flake8={flake8}, MyPy={mypy}")
    print("NOT PRODUCTION CERTIFIED / NOT READY")
    # Downstream CI must not interpret this entrypoint as release approval.
    return 2


if __name__ == "__main__":
    sys.exit(main())
