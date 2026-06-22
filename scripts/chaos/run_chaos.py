"""Chaos Test Orchestrator

Runs all chaos tests and generates CHAOS_CERTIFICATE.md.

Usage:
    python scripts/chaos/run_chaos.py
"""

import asyncio
import subprocess
import sys
from datetime import datetime
from pathlib import Path

CHAOS_DIR = Path(__file__).parent
PROJECT_DIR = CHAOS_DIR.parent.parent

SCRIPTS = [
    "test_mcp_crash.py",
    "test_redis_kill.py",
    "test_postgres_failover.py",
]


def run_script(name: str) -> dict:
    script_path = CHAOS_DIR / name
    print(f"\n>>> Running {name} ...")
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_DIR),
            timeout=120,
        )
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
        return {"script": name, "returncode": -1, "passed": 0, "failed": 0, "stdout": "", "stderr": "TIMEOUT"}
    except Exception as e:
        return {"script": name, "returncode": -1, "passed": 0, "failed": 0, "stdout": "", "stderr": str(e)}


def generate_certificate(results: list[dict]) -> str:
    now = datetime.utcnow().isoformat() + "Z"
    total_passed = sum(r["passed"] for r in results)
    total_failed = sum(r["failed"] for r in results)

    lines = [
        "# AI-OSOP Chaos Certificate",
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
        f"| Success Rate | {(total_passed / (total_passed + total_failed) * 100):.1f}% |" if (total_passed + total_failed) > 0 else "| Success Rate | N/A |",
        "",
        "## Scenario Results",
        "",
        "| Scenario | Status | Passed | Failed |",
        "|----------|--------|--------|--------|",
    ]

    for r in results:
        status = "PASS" if r["returncode"] == 0 else "FAIL"
        lines.append(f"| {r['script']} | {status} | {r['passed']} | {r['failed']} |")

    lines.extend([
        "",
        "## Resilience Claims",
        "",
        "### MCP Crash Loop",
        "- Circuit breaker opens after 5 consecutive failures",
        "- Execution blocked with `circuit_open` status when breaker is open",
        "- Recovery happens automatically after 30 seconds",
        "- No cascade to other MCP servers",
        "",
        "### Redis Disappearance (5 minutes)",
        "- Warm storage (Postgres) continues serving session state",
        "- JWT validation is independent of Redis",
        "- Active engagements in hot memory are lost (acceptable for 5-min outage)",
        "",
        "### PostgreSQL Failover",
        "- Hot tier (Redis) continues serving active sessions",
        "- Task queue in Redis is independent of Postgres",
        "- New engagements cannot be persisted until Postgres recovers",
        "",
        "## Detailed Output",
        "",
    ])

    for r in results:
        lines.append(f"### {r['script']}")
        lines.append(f"```")
        lines.append(r["stdout"])
        if r["stderr"]:
            lines.append("--- STDERR ---")
            lines.append(r["stderr"])
        lines.append(f"```")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## Certification",
        "",
    ])

    if total_failed == 0 and all(r["returncode"] == 0 for r in results):
        lines.append("**CHAOS CERTIFICATION PASSED** — All resilience scenarios verified.")
    else:
        lines.append("**CHAOS CERTIFICATION CONDITIONAL** — Review failures above.")

    lines.append("")
    return "\n".join(lines)


async def main() -> None:
    print("=" * 60)
    print("AI-OSOP Chaos Test Orchestrator")
    print("=" * 60)

    results = [run_script(s) for s in SCRIPTS]

    cert = generate_certificate(results)
    cert_path = PROJECT_DIR / "CHAOS_CERTIFICATE.md"
    with open(cert_path, "w", encoding="utf-8") as f:
        f.write(cert)

    print(f"\nCertificate written to: {cert_path}")
    print("=" * 60)

    total_failed = sum(r["failed"] for r in results)
    if total_failed > 0 or any(r["returncode"] != 0 for r in results):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
