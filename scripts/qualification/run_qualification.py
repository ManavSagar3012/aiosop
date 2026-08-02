"""AI-OSOP Qualification Orchestrator

Runs all qualification suites and generates PRODUCTION_QUALIFICATION.md.

Usage:
    python scripts/qualification/run_qualification.py
"""

import asyncio
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

QUALIFICATION_DIR = Path(__file__).parent
PROJECT_DIR = QUALIFICATION_DIR.parent.parent


def run_script(name: str) -> dict:
    """Run a qualification script and capture its output."""
    script_path = QUALIFICATION_DIR / name
    print(f"\n>>> Running {name} ...")
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_DIR),
            timeout=120,
        )
        # Parse simple PASS/FAIL from stdout
        lines = result.stdout.splitlines()
        passed = 0
        failed = 0
        for line in lines:
            if line.startswith("[PASS]"):
                passed += 1
            elif line.startswith("[FAIL]"):
                failed += 1
        return {
            "script": name,
            "returncode": result.returncode,
            "passed": passed,
            "failed": failed,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "script": name,
            "returncode": -1,
            "passed": 0,
            "failed": 0,
            "stdout": "",
            "stderr": "TIMEOUT",
        }
    except Exception as e:
        return {
            "script": name,
            "returncode": -1,
            "passed": 0,
            "failed": 0,
            "stdout": "",
            "stderr": str(e),
        }


def generate_report(results: list[dict]) -> str:
    """Generate PRODUCTION_QUALIFICATION.md."""
    now = datetime.utcnow().isoformat() + "Z"
    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)

    lines = [
        "# AI-OSOP Production Qualification Report",
        "",
        f"**Generated:** {now}",
        f"**Git SHA:** (see RELEASE_CERTIFICATE.md)",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Tests | {total_passed + total_failed} |",
        f"| Passed | {total_passed} |",
        f"| Failed | {total_failed} |",
        (
            f"| Success Rate | {(total_passed / (total_passed + total_failed) * 100):.1f}% |"
            if (total_passed + total_failed) > 0
            else "| Success Rate | N/A |"
        ),
        "",
        "## Suite Results",
        "",
        "| Suite | Status | Passed | Failed |",
        "|-------|--------|--------|--------|",
    ]

    for r in results:
        status = "PASS" if r["returncode"] == 0 else "FAIL"
        lines.append(f"| {r['script']} | {status} | {r['passed']} | {r['failed']} |")

    lines.extend(
        [
            "",
            "## Detailed Output",
            "",
        ]
    )

    for r in results:
        lines.append(f"### {r['script']}")
        lines.append(f"```")
        lines.append(r["stdout"])
        if r["stderr"]:
            lines.append("--- STDERR ---")
            lines.append(r["stderr"])
        lines.append(f"```")
        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "## Certification",
            "",
        ]
    )

    if total_failed == 0 and all(r["returncode"] == 0 for r in results):
        lines.append("**QUALIFICATION PASSED** — All suites passed without failure.")
    else:
        lines.append(
            "**QUALIFICATION CONDITIONAL** — Some suites had failures. Review detailed output above."
        )

    lines.append("")
    return "\n".join(lines)


async def main() -> None:
    print("=" * 60)
    print("AI-OSOP Qualification Orchestrator")
    print("=" * 60)

    scripts = [
        "test_security.py",
        "test_reliability.py",
        "test_scale.py",
    ]

    results = [run_script(s) for s in scripts]

    report = generate_report(results)
    report_path = PROJECT_DIR / "PRODUCTION_QUALIFICATION.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nReport written to: {report_path}")
    print("=" * 60)

    total_failed = sum(r["failed"] for r in results)
    if total_failed > 0 or any(r["returncode"] != 0 for r in results):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
