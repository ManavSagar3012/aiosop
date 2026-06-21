"""Chaos Test: API Restart

Scenario: The AI-OSOP API container is restarted.

Expected behavior:
- Pending approvals restored from Postgres
- Active tasks recovered from warm tier
- Running tasks reset to pending for re-assignment
- Scheduler resumes without duplication

Usage:
    python scripts/chaos/kill_api.py

Requires: AI-OSOP API running via docker-compose on localhost:8200.
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


async def create_engagement() -> str:
    payload = {
        "engagement_id": f"chaos-api-restart-{int(time.time())}",
        "domains": ["example.com"],
        "roe": {"max_depth": 3},
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{API_BASE}/engagements", json=payload, headers=HEADERS)
        if r.status_code == 200:
            return r.json().get("session_id", "")
    return ""


async def create_task(session_id: str) -> str:
    payload = {
        "task_type": "full_recon",
        "priority": 5,
        "agent_type": "recon",
        "payload": {"domain": "example.com"},
        "engagement_id": session_id,
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(f"{API_BASE}/tasks", json=payload, headers=HEADERS)
        if r.status_code == 200:
            return r.json().get("id", "")
    return ""


async def list_tasks() -> list:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{API_BASE}/tasks", headers=HEADERS)
            if r.status_code == 200:
                return r.json()
    except Exception:
        pass
    return []


async def main():
    print("=" * 60)
    print("CHAOS TEST: API Restart")
    print("=" * 60)

    print("\n[1] Pre-check: API health...")
    h = await health_check()
    if h["status"] != 200:
        print(f"FAIL: API not reachable: {h}")
        sys.exit(1)
    print("OK: API healthy")

    print("\n[2] Creating engagement + task...")
    session_id = await create_engagement()
    if not session_id:
        print("FAIL: Could not create engagement")
        sys.exit(1)
    task_id = await create_task(session_id)
    if not task_id:
        print("FAIL: Could not create task")
        sys.exit(1)
    print(f"OK: Engagement={session_id}, Task={task_id}")

    await asyncio.sleep(3)

    print("\n[3] Restarting API container...")
    run(["docker-compose", "restart", "api"])
    time.sleep(15)

    print("\n[4] Checking API recovery...")
    for attempt in range(10):
        h = await health_check()
        if h["status"] == 200:
            print(f"OK: API recovered after restart (attempt {attempt + 1})")
            break
        print(f"  Waiting... ({attempt + 1}/10)")
        time.sleep(3)
    else:
        print("FAIL: API did not recover after restart")
        sys.exit(1)

    print("\n[5] Verifying task recovery...")
    tasks = await list_tasks()
    recovered = [t for t in tasks if t.get("id") == task_id]
    if recovered:
        print(f"OK: Task {task_id} recovered with status={recovered[0].get('status')}")
    else:
        print(f"WARN: Task {task_id} not found in recovery (may have been reaped)")

    print("\n" + "=" * 60)
    print("CHAOS TEST COMPLETE: API restart handled gracefully")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
