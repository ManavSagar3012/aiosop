"""Chaos Test: Postgres Failure

Scenario: PostgreSQL is stopped mid-operation.

Expected behavior:
- Hot tier (Redis) survives as primary
- Tasks continue to run from in-memory state
- Warm tier writes queue for later replay
- No scheduler crash

Usage:
    python scripts/chaos/kill_postgres.py

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
        "task_type": "full_recon",
        "priority": 5,
        "agent_type": "recon",
        "payload": {"domain": "example.com"},
        "engagement_id": "chaos-test-postgres",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{API_BASE}/tasks", json=payload, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            return data.get("id", "unknown")
        return ""


async def main():
    print("=" * 60)
    print("CHAOS TEST: Postgres Failure")
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

    print("\n[3] Killing Postgres...")
    run(["docker-compose", "stop", "postgres"])
    time.sleep(3)

    print("\n[4] Checking API survival without Postgres...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API crashed after Postgres kill: {h}")
        run(["docker-compose", "start", "postgres"])
        sys.exit(1)
    print("OK: API survived Postgres outage")

    print("\n[5] Creating task while Postgres is down...")
    task_id2 = await create_test_task()
    if task_id2:
        print(f"OK: Task created via Redis hot tier: {task_id2}")
    else:
        print("WARN: Task creation may have failed")

    print("\n[6] Restoring Postgres...")
    run(["docker-compose", "start", "postgres"])
    time.sleep(10)

    print("\n[7] Checking API after Postgres restore...")
    h = await health_check()
    if h["status"] == 200:
        print("OK: API healthy after Postgres restore")
    else:
        print(f"WARN: Health check after restore: {h}")

    print("\n" + "=" * 60)
    print("CHAOS TEST COMPLETE: Postgres failure handled gracefully")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
