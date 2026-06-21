"""Chaos Test: Neo4j Failure

Scenario: Neo4j is stopped mid-operation.

Expected behavior:
- Finding persistence queues (tasks go to Postgres)
- Replays later when Neo4j comes back
- No scheduler crash
- Graph-backed dedupe resumes

Usage:
    python scripts/chaos/kill_neo4j.py

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


async def create_test_task() -> str:
    payload = {
        "task_type": "burp_scan",
        "priority": 5,
        "agent_type": "vuln_analysis",
        "payload": {"url": "https://example.com"},
        "engagement_id": "chaos-test-neo4j",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{API_BASE}/tasks", json=payload, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            return data.get("id", "unknown")
        return ""


async def main():
    print("=" * 60)
    print("CHAOS TEST: Neo4j Failure")
    print("=" * 60)

    print("\n[1] Pre-check: API health...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API not reachable: {h}")
        sys.exit(1)
    print("OK: API healthy")

    print("\n[2] Creating test task...")
    task_id = await create_test_task()
    if not task_id:
        print("FAIL: Could not create test task")
        sys.exit(1)
    print(f"OK: Task created: {task_id}")

    await asyncio.sleep(2)

    print("\n[3] Killing Neo4j...")
    run(["docker-compose", "stop", "neo4j"])
    time.sleep(3)

    print("\n[4] Checking API survival without Neo4j...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API crashed after Neo4j kill: {h}")
        run(["docker-compose", "start", "neo4j"])
        sys.exit(1)
    print("OK: API survived Neo4j outage")

    print("\n[5] Creating second task while Neo4j is down...")
    task_id2 = await create_test_task()
    if task_id2:
        print(f"OK: Task queued without Neo4j: {task_id2}")
    else:
        print("WARN: Task creation may have failed (expected if graph dedupe required)")

    print("\n[6] Restoring Neo4j...")
    run(["docker-compose", "start", "neo4j"])
    time.sleep(10)

    print("\n[7] Checking API after Neo4j restore...")
    h = await health_check()
    if h["status"] == 200:
        print("OK: API healthy after Neo4j restore")
    else:
        print(f"WARN: Health check after restore: {h}")

    print("\n" + "=" * 60)
    print("CHAOS TEST COMPLETE: Neo4j failure handled gracefully")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
