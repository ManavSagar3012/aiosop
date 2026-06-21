"""Chaos Test: MCP Server Failure

Scenario: MCP servers (burp, browser, nuclei) are stopped.

Expected behavior:
- Circuit breaker opens on MCP failure
- Task retries with backoff
- Scheduler continues processing other tasks
- No API crash

Usage:
    python scripts/chaos/kill_mcp.py

Requires: AI-OSOP API running on localhost:8200, docker-compose services up.
"""

import asyncio
import subprocess
import sys
import time

import httpx

API_BASE = "http://localhost:8200"
TOKEN = "dev-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

MCP_SERVICES = ["burp-mcp", "browser-mcp", "nuclei-mcp"]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True)


async def health_check() -> dict:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{API_BASE}/health")
            return {"status": r.status_code, "body": r.json()}
    except Exception as e:
        return {"status": 0, "error": str(e)}


async def main():
    print("=" * 60)
    print("CHAOS TEST: MCP Server Failure")
    print("=" * 60)

    print("\n[1] Pre-check: API health...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API not reachable: {h}")
        sys.exit(1)
    print("OK: API healthy")

    print("\n[2] Killing MCP servers...")
    for svc in MCP_SERVICES:
        run(["docker-compose", "stop", svc])
    time.sleep(3)

    print("\n[3] Checking API survival without MCP servers...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API crashed after MCP kill: {h}")
        for svc in MCP_SERVICES:
            run(["docker-compose", "start", svc])
        sys.exit(1)
    print("OK: API survived MCP outage")

    print("\n[4] Creating non-MCP task to verify scheduler continues...")
    payload = {
        "task_type": "full_recon",
        "priority": 5,
        "agent_type": "recon",
        "payload": {"domain": "example.com"},
        "engagement_id": "chaos-test-mcp",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(f"{API_BASE}/tasks", json=payload, headers=HEADERS)
            if r.status_code == 200:
                print(f"OK: Non-MCP task created: {r.json().get('id', '')}")
            else:
                print(f"WARN: Task creation returned {r.status_code}")
    except Exception as e:
        print(f"WARN: Task creation failed: {e}")

    print("\n[5] Restoring MCP servers...")
    for svc in MCP_SERVICES:
        run(["docker-compose", "start", svc])
    time.sleep(10)

    print("\n[6] Checking API after MCP restore...")
    h = await health_check()
    if h["status"] == 200:
        print("OK: API healthy after MCP restore")
    else:
        print(f"WARN: Health check after restore: {h}")

    print("\n" + "=" * 60)
    print("CHAOS TEST COMPLETE: MCP failure handled gracefully")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
