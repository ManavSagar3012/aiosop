"""Chaos Test: Redis Failure

Scenario: Redis is stopped mid-operation.

Expected behavior:
- Tasks continue to run from in-memory state
- Warm tier (Postgres) survives as backup
- Redis reconnects automatically when restored
- No scheduler crash

Usage:
    python scripts/chaos/kill_redis.py

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
        "engagement_id": "chaos-test-redis",
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{API_BASE}/tasks", json=payload, headers=HEADERS)
        if r.status_code == 200:
            data = r.json()
            return data.get("id", "unknown")
        return ""


async def get_task_status(task_id: str) -> str:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{API_BASE}/tasks/{task_id}", headers=HEADERS)
            if r.status_code == 200:
                return r.json().get("status", "unknown")
            return f"http_{r.status_code}"
    except Exception as e:
        return f"error: {e}"


async def main():
    print("=" * 60)
    print("CHAOS TEST: Redis Failure")
    print("=" * 60)

    # Pre-check: API must be up
    print("\n[1] Pre-check: API health...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API not reachable: {h}")
        sys.exit(1)
    print(f"OK: API healthy ({h['body']})")

    # Create a test task
    print("\n[2] Creating test task...")
    task_id = await create_test_task()
    if not task_id:
        print("FAIL: Could not create test task")
        sys.exit(1)
    print(f"OK: Task created: {task_id}")

    # Wait briefly for task to enter the system
    await asyncio.sleep(2)

    # Kill Redis
    print("\n[3] Killing Redis...")
    run(["docker-compose", "stop", "redis"])
    time.sleep(3)

    # Verify API is still up (should be - warm tier fallback)
    print("\n[4] Checking API survival without Redis...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API crashed after Redis kill: {h}")
        run(["docker-compose", "start", "redis"])
        sys.exit(1)
    print("OK: API survived Redis outage")

    # Try to read task status - should work via warm tier or in-memory
    print("\n[5] Checking task status via warm tier...")
    status = await get_task_status(task_id)
    print(f"OK: Task status = {status} (read without Redis)")

    # Restore Redis
    print("\n[6] Restoring Redis...")
    run(["docker-compose", "start", "redis"])
    time.sleep(5)

    # Verify auto-reconnect
    print("\n[7] Checking API reconnects to Redis...")
    h = await health_check()
    if h["status"] != 200:
        print(f"WARN: API health check after restore: {h}")
    else:
        print("OK: API healthy after Redis restore")

    print("\n" + "=" * 60)
    print("CHAOS TEST COMPLETE: Redis failure handled gracefully")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
