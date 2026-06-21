"""Reliability Qualification Tests

Validates:
- Redis restart survival
- Neo4j restart survival
- Postgres restart survival
- API restart recovery
- MCP failure handling

Usage:
    python scripts/qualification/test_reliability.py

Returns exit code 0 if all pass, 1 if any fail.
"""

import asyncio
import subprocess
import sys
import time

import httpx

API_BASE = "http://localhost:8200"
TOKEN = "dev-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, capture_output=True, text=True)


async def health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(f"{API_BASE}/health")
            return r.status_code == 200
    except Exception:
        return False


async def test_redis_restart() -> bool:
    print("  [1] Stopping Redis...")
    run(["docker-compose", "stop", "redis"])
    time.sleep(3)
    print("  [2] Checking API survival...")
    if not await health():
        print("  FAIL: API crashed after Redis stop")
        run(["docker-compose", "start", "redis"])
        return False
    print("  [3] Restoring Redis...")
    run(["docker-compose", "start", "redis"])
    time.sleep(5)
    print("  [4] Checking recovery...")
    if not await health():
        print("  FAIL: API did not recover after Redis restore")
        return False
    print("  PASS: Redis restart handled")
    return True


async def test_neo4j_restart() -> bool:
    print("  [1] Stopping Neo4j...")
    run(["docker-compose", "stop", "neo4j"])
    time.sleep(3)
    print("  [2] Checking API survival...")
    if not await health():
        print("  FAIL: API crashed after Neo4j stop")
        run(["docker-compose", "start", "neo4j"])
        return False
    print("  [3] Restoring Neo4j...")
    run(["docker-compose", "start", "neo4j"])
    time.sleep(10)
    print("  [4] Checking recovery...")
    if not await health():
        print("  FAIL: API did not recover after Neo4j restore")
        return False
    print("  PASS: Neo4j restart handled")
    return True


async def test_postgres_restart() -> bool:
    print("  [1] Stopping Postgres...")
    run(["docker-compose", "stop", "postgres"])
    time.sleep(3)
    print("  [2] Checking API survival...")
    if not await health():
        print("  FAIL: API crashed after Postgres stop")
        run(["docker-compose", "start", "postgres"])
        return False
    print("  [3] Restoring Postgres...")
    run(["docker-compose", "start", "postgres"])
    time.sleep(10)
    print("  [4] Checking recovery...")
    if not await health():
        print("  FAIL: API did not recover after Postgres restore")
        return False
    print("  PASS: Postgres restart handled")
    return True


async def test_api_restart() -> bool:
    print("  [1] Restarting API...")
    run(["docker-compose", "restart", "api"])
    time.sleep(15)
    print("  [2] Checking recovery...")
    for attempt in range(10):
        if await health():
            print(f"  PASS: API recovered after restart (attempt {attempt + 1})")
            return True
        time.sleep(3)
    print("  FAIL: API did not recover after restart")
    return False


async def test_mcp_failure() -> bool:
    print("  [1] Stopping MCP servers...")
    run(["docker-compose", "stop", "burp-mcp", "browser-mcp", "nuclei-mcp"])
    time.sleep(3)
    print("  [2] Checking API survival...")
    if not await health():
        print("  FAIL: API crashed after MCP stop")
        run(["docker-compose", "start", "burp-mcp", "browser-mcp", "nuclei-mcp"])
        return False
    print("  [3] Restoring MCP servers...")
    run(["docker-compose", "start", "burp-mcp", "browser-mcp", "nuclei-mcp"])
    time.sleep(10)
    print("  [4] Checking recovery...")
    if not await health():
        print("  FAIL: API did not recover after MCP restore")
        return False
    print("  PASS: MCP failure handled")
    return True


async def main() -> int:
    print("=" * 60)
    print("RELIABILITY QUALIFICATION SUITE")
    print("=" * 60)

    tests = [
        ("Redis restart", test_redis_restart),
        ("Neo4j restart", test_neo4j_restart),
        ("Postgres restart", test_postgres_restart),
        ("API restart", test_api_restart),
        ("MCP failure", test_mcp_failure),
    ]

    results = []
    for name, test_fn in tests:
        print(f"\n[TEST] {name}")
        try:
            ok = await test_fn()
            results.append((name, ok))
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append((name, False))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed}/{total} passed")
    print("=" * 60)
    for name, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
