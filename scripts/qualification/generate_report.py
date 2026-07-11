"""Production Readiness Report Generator

Runs all qualification suites and generates a markdown report.

Usage:
    python scripts/qualification/generate_report.py

Output: PRODUCTION_READINESS_REPORT.md
"""

import asyncio
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SUITES = [
    ("Security", "scripts/qualification/test_security.py"),
    ("Reliability", "scripts/qualification/test_reliability.py"),
    ("Ownership", "scripts/qualification/test_ownership.py"),
    ("Scale", "scripts/qualification/test_scale.py"),
]


async def run_suite(name: str, path: str) -> dict:
    print(f"\nRunning {name} suite...")
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    output = stdout.decode("utf-8", errors="replace")
    # Parse PASS/FAIL from output
    passed = output.count("  PASS")
    failed = output.count("  FAIL")
    errors = output.count("  ERROR")
    return {
        "name": name,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "output": output,
        "exit_code": proc.returncode,
    }


async def main():
    print("=" * 60)
    print("AI-OSOP PRODUCTION READINESS REPORT")
    print("=" * 60)

    results = []
    for name, path in SUITES:
        if Path(path).exists():
            result = await run_suite(name, path)
            results.append(result)
        else:
            print(f"WARNING: {path} not found, skipping")
            results.append(
                {
                    "name": name,
                    "passed": 0,
                    "failed": 0,
                    "errors": 0,
                    "output": "Suite not found",
                    "exit_code": -1,
                }
            )

    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)
    total_errors = sum(r["errors"] for r in results)
    total_tests = total_passed + total_failed + total_errors

    score = int((total_passed / total_tests) * 100) if total_tests > 0 else 0

    report = f"""# AI-OSOP Production Readiness Report

**Generated:** {datetime.utcnow().isoformat()}Z
**Version:** 1.0.0
**Git SHA:** {subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd='.').decode().strip() if Path('.git').exists() else 'unknown'}

## Executive Summary

| Metric | Value |
|--------|-------|
| Security Score | {score}% |
| Total Tests | {total_tests} |
| Passed | {total_passed} |
| Failed | {total_failed} |
| Errors | {total_errors} |
| **Production Ready** | {'YES' if score >= 90 else 'NO (needs work)'} |

## Suite Results

| Suite | Passed | Failed | Errors | Status |
|-------|--------|--------|--------|--------|
"""
    for r in results:
        status = "PASS" if r["exit_code"] == 0 else "FAIL"
        report += f"| {r['name']} | {r['passed']} | {r['failed']} | {r['errors']} | {status} |\n"

    report += "\n## Detailed Output\n\n"
    for r in results:
        report += f"### {r['name']}\n\n```\n{r['output']}\n```\n\n"

    report += """## Recommendations

- **Score >= 90%**: Platform is production-ready.
- **Score 70-89%**: Address failed tests before production.
- **Score < 70%**: Significant work required.

## Next Steps

1. Fix any failed tests above
2. Run self-pentest (`scripts/qualification/test_self_pentest.py`)
3. Review observability dashboards
4. Generate release certificate
"""

    output_path = Path("PRODUCTION_READINESS_REPORT.md")
    output_path.write_text(report, encoding="utf-8")
    print(f"\nReport saved to: {output_path}")

    print("\n" + "=" * 60)
    print(f"OVERALL SCORE: {score}%")
    print(f"PRODUCTION READY: {'YES' if score >= 90 else 'NO'}")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
