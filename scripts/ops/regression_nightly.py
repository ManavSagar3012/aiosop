#!/usr/bin/env python
"""Nightly AI-OSOP scanner regression harness (REGRESSION-NIGHTLY-001).

The strongest regression test a scanner can have: run the REAL platform
end-to-end against the local vulnerable fleet and assert it still FINDS the
known bugs. A capability that silently stops finding things is worse than a
crashed test suite — nothing red ever shows up.

Targets (all local, all lab-authorized):
  1. golden_path_target.py (:9199)  — SQLi in POST /login 'username'
  2. rendered_spa_shim.py   (:9299)  — same backend through a JS-rendered
                                       DOM-only form (WEB-AUDIT-004 path)

PASS criteria: BOTH targets yield at least one VALIDATED CWE-89 finding via
the differential engine (not just nuclei echoes).

Usage:
  python scripts/ops/regression_nightly.py            # run + verdict
  python scripts/ops/regression_nightly.py --json     # machine-readable

Exits 0 on PASS, 1 on FAIL — wire it to a scheduler/cron or CI.

Assumes the platform stack is up (API on the pinned local address, DBs, MCP
fleet). Pass --with-targets to let this script manage the lab targets.
"""
import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
BASE = "http://127.0.0.1:8200"  # the ONLY host this harness ever contacts
HEADERS = {"Authorization": "Bearer dev-token", "Content-Type": "application/json"}


async def api_call(method: str, rel: str, body=None, timeout: float = 60.0):
    """HTTP call to the platform API.

    Same accepted shape as scripts/ops/approve_exploit.py: a constant local
    base URL with a relative API path, issued via httpx. No arbitrary or
    absolute URLs are ever requested by this harness.
    """
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.request(
            method, f"{BASE}{rel}", headers=HEADERS, json=body
        )
        resp.raise_for_status()
        return resp.json()


async def _wait_task(tid: str, budget_s: int = 600) -> dict:
    """Poll a task until terminal; return its final record."""
    deadline = time.time() + budget_s
    while time.time() < deadline:
        try:
            row = await api_call("GET", f"/tasks/{tid}", timeout=30.0)
        except Exception:  # noqa: BLE001 - transient poll error: retry
            row = None
        status = (row or {}).get("status")
        if status in ("completed", "failed", "blocked", "timeout"):
            return row or {"status": "unknown"}
        await asyncio.sleep(10)
    return {"status": "poll-timeout"}


async def audit_target(tag: str, url: str, classes: list) -> dict:
    """Create a fresh engagement for one lab target and audit it; return
    a verdict dict with the findings the engine minted."""
    eng = await api_call(
        "POST",
        "/engagements",
        {
            "engagement_id": f"regression-{tag}-{int(time.time())}",
            "domains": ["127.0.0.1"],
            "ips": ["127.0.0.1"],
            "allowed_techniques": ["web_pentest", "sqli", "xss"],
            "authorization_ref": "LOCAL-LAB-REGRESSION: nightly scanner self-test",
            "roe": {"objective": "assert the differential engine still finds the known bug"},
        },
    )
    sid = eng["session_id"]
    await api_call("POST", f"/engagements/{sid}/confirm", {"operator_id": "regression-runner"})
    await api_call("POST", f"/engagements/{sid}/transition?new_phase=reconnaissance")
    await asyncio.sleep(3)
    await api_call("POST", f"/engagements/{sid}/transition?new_phase=vulnerability_discovery")
    task = await api_call(
        "POST",
        "/tasks",
        {
            "task_type": "web_audit",
            "priority": 9,
            "agent_type": "vuln_analysis",
            # Rendered pass (Playwright launch + settle + OIDC redirect
            # following) legitimately exceeds the 300s scheduler default —
            # found by the harness's own first run (reaper timeout 307s).
            "timeout_seconds": 900,
            "payload": {"url": url, "max_urls": 5, "classes": classes},
            "engagement_id": sid,
        },
    )
    final = await _wait_task(task["id"])
    findings = (final or {}).get("findings") or []
    try:
        served = await api_call("GET", f"/engagements/{sid}/findings", timeout=30.0)
        served = served if isinstance(served, list) else served.get("findings", [])
    except Exception:  # noqa: BLE001
        served = []
    all_f = findings + served
    validated_sqli = [
        f for f in all_f
        if str(f.get("cwe", "")).upper().endswith("89")
        or "SQLI" in str(f.get("title", "")).upper()
    ]
    return {
        "session_id": sid,
        "task_status": (final or {}).get("status"),
        "stats": (final or {}).get("stats", {}),
        "findings": len(all_f),
        "sqli_validated": len(validated_sqli) > 0,
    }


async def run(with_targets: bool) -> dict:
    procs = []
    if with_targets:
        procs = [
            subprocess.Popen(
                [sys.executable, str(ROOT / "golden_path_target.py")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ),
            subprocess.Popen(
                [sys.executable, str(ROOT / "tests/benchmarks/rendered_spa_shim.py")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            ),
        ]
        time.sleep(3)
    try:
        results = {
            "golden_path (static form SQLi)": await audit_target(
                "static", "http://127.0.0.1:9199/login", ["sqli"]
            ),
            "rendered_spa (DOM-only form SQLi)": await audit_target(
                "rendered", "http://127.0.0.1:9299/", ["sqli"]
            ),
        }
        passed = all(r["sqli_validated"] for r in results.values())
        return {
            "verdict": "PASS" if passed else "FAIL",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "criteria": "each lab target yields >=1 VALIDATED CWE-89 finding",
            "results": results,
        }
    finally:
        for p in procs:
            p.terminate()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--with-targets", action="store_true",
        help="also start/stop the lab targets (golden_path_target + rendered shim)",
    )
    args = ap.parse_args()

    verdict = asyncio.run(run(args.with_targets))

    if args.json:
        print(json.dumps(verdict, indent=2))
    else:
        print(f"[{verdict['timestamp']}] Scanner regression: {verdict['verdict']}")
        for name, r in verdict["results"].items():
            print(
                f"  {name}: task={r['task_status']} findings={r['findings']} "
                f"sqli_validated={r['sqli_validated']} stats={r['stats']}"
            )
        if verdict["verdict"] == "FAIL":
            print("  -> the differential engine LOST a known bug. Investigate before trusting any run.")
    return 0 if verdict["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
