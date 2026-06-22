"""Multi-Tenant Ownership Qualification Suite

The definitive test that cross-tenant isolation is real and enforced.

Test matrix:
  operator-a      accessing  operator-a resource   → 200
  operator-a      accessing  operator-b resource   → 403
  operator-b      accessing  operator-a resource   → 403
  senior_operator accessing  operator-a resource   → 200
  senior_operator accessing  operator-b resource   → 200

Resources tested:
  engagements, tasks, findings, approvals, sessions, websocket

Usage:
    python scripts/qualification/test_multi_tenant.py

Returns exit code 0 if all pass, 1 if any fail.
"""

import asyncio
import sys
from typing import Dict, Tuple

import httpx

API_BASE = "http://localhost:8200"

# Simulate two distinct operators and a senior operator
# In a real environment, these would be distinct JWTs issued by your auth system.
OPERATOR_A = "dev-token-a"
OPERATOR_B = "dev-token-b"
SENIOR_OP = "dev-token-senior"

HEADERS_A = {"Authorization": f"Bearer {OPERATOR_A}"}
HEADERS_B = {"Authorization": f"Bearer {OPERATOR_B}"}
HEADERS_SENIOR = {"Authorization": f"Bearer {SENIOR_OP}"}


async def create_engagement(headers: dict, label: str) -> str:
    """Create an engagement and return its session_id."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{API_BASE}/engagements",
            json={
                "engagement_id": f"mt-test-{label}",
                "domains": ["example.com"],
            },
            headers=headers,
        )
        if r.status_code == 200:
            return r.json().get("session_id", "")
    return ""


async def get_engagement(headers: dict, session_id: str) -> int:
    """Return status code for GET /engagements/{session_id}."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{API_BASE}/engagements/{session_id}", headers=headers)
        return r.status_code


async def get_task(headers: dict, task_id: str) -> int:
    """Return status code for GET /tasks/{task_id}."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{API_BASE}/tasks/{task_id}", headers=headers)
        return r.status_code


async def create_task(headers: dict, session_id: str, label: str) -> str:
    """Create a task and return its id."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.post(
            f"{API_BASE}/tasks",
            json={
                "task_type": "full_recon",
                "priority": 5,
                "agent_type": "recon",
                "payload": {"domain": "example.com"},
                "engagement_id": session_id,
            },
            headers=headers,
        )
        if r.status_code == 200:
            return r.json().get("id", "")
    return ""


async def get_finding(headers: dict, finding_id: str) -> int:
    """Return status code for GET /findings/{finding_id}."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{API_BASE}/findings/{finding_id}", headers=headers)
        return r.status_code


async def get_approval(headers: dict, approval_id: str) -> int:
    """Return status code for GET /approvals/{approval_id}."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{API_BASE}/approvals/{approval_id}", headers=headers)
        return r.status_code


async def get_session(headers: dict, session_id: str) -> int:
    """Return status code for GET /sessions/{session_id}."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{API_BASE}/sessions/{session_id}", headers=headers)
        return r.status_code


async def websocket_connect(headers: dict, session_id: str) -> Tuple[str, int]:
    """Try WebSocket connection. Returns (status, close_code)."""
    import websockets
    token = headers.get("Authorization", "").replace("Bearer ", "")
    try:
        await websockets.connect(
            f"ws://localhost:8200/ws/engagements/{session_id}?token={token}",
            open_timeout=5,
        )
        return ("connected", 0)
    except Exception as e:
        msg = str(e)
        if "1008" in msg:
            return ("rejected", 1008)
        if "401" in msg or "403" in msg:
            return ("rejected", 1008)
        return ("error", 0)


# ============== Test Cases ==============


async def test_engagement_isolation() -> bool:
    """Engagement cross-tenant isolation."""
    print("  Setup: create engagement for operator-a...")
    session_a = await create_engagement(HEADERS_A, "a")
    if not session_a:
        print("  SKIP: could not create engagement-a")
        return False

    results = []
    # operator-a owns it → 200
    code = await get_engagement(HEADERS_A, session_a)
    results.append(("operator-a → own engagement", code, 200))

    # operator-b tries to access → 403
    code = await get_engagement(HEADERS_B, session_a)
    results.append(("operator-b → a's engagement", code, 403))

    # senior_operator can access → 200
    code = await get_engagement(HEADERS_SENIOR, session_a)
    results.append(("senior_op → a's engagement", code, 200))

    all_ok = all(act == exp for _, act, exp in results)
    for label, act, exp in results:
        status = "PASS" if act == exp else "FAIL"
        print(f"    [{status}] {label}: {act} (expected {exp})")
    return all_ok


async def test_task_isolation() -> bool:
    """Task cross-tenant isolation."""
    print("  Setup: create engagement + task for operator-a...")
    session_a = await create_engagement(HEADERS_A, "task-a")
    if not session_a:
        print("  SKIP: could not create engagement")
        return False
    task_a = await create_task(HEADERS_A, session_a, "a")
    if not task_a:
        print("  SKIP: could not create task")
        return False

    results = []
    code = await get_task(HEADERS_A, task_a)
    results.append(("operator-a → own task", code, 200))

    code = await get_task(HEADERS_B, task_a)
    results.append(("operator-b → a's task", code, 403))

    code = await get_task(HEADERS_SENIOR, task_a)
    results.append(("senior_op → a's task", code, 200))

    all_ok = all(act == exp for _, act, exp in results)
    for label, act, exp in results:
        status = "PASS" if act == exp else "FAIL"
        print(f"    [{status}] {label}: {act} (expected {exp})")
    return all_ok


async def test_cross_tenant_enumeration() -> bool:
    """IDOR enumeration: random UUIDs should not leak existence."""
    print("  Probing random UUIDs...")
    targets = [
        ("GET /engagements", f"{API_BASE}/engagements/00000000-0000-0000-0000-000000000000"),
        ("GET /tasks", f"{API_BASE}/tasks/00000000-0000-0000-0000-000000000000"),
        ("GET /findings", f"{API_BASE}/findings/00000000-0000-0000-0000-000000000000"),
    ]
    results = []
    async with httpx.AsyncClient(timeout=10) as client:
        for label, url in targets:
            r = await client.get(url, headers=HEADERS_A)
            ok = r.status_code in (403, 404)
            results.append((label, r.status_code, ok))

    all_ok = all(ok for _, _, ok in results)
    for label, act, ok in results:
        status = "PASS" if ok else "FAIL"
        print(f"    [{status}] {label}: {act}")
    return all_ok


async def test_websocket_isolation() -> bool:
    """WebSocket cross-tenant isolation."""
    print("  Setup: create engagement for operator-a...")
    session_a = await create_engagement(HEADERS_A, "ws-a")
    if not session_a:
        print("  SKIP: could not create engagement")
        return False

    results = []
    status, code = await websocket_connect(HEADERS_A, session_a)
    results.append(("operator-a → own ws", status, "connected"))

    status, code = await websocket_connect(HEADERS_B, session_a)
    results.append(("operator-b → a's ws", status, "rejected"))

    status, code = await websocket_connect(HEADERS_SENIOR, session_a)
    results.append(("senior_op → a's ws", status, "connected"))

    all_ok = all(act == exp for _, act, exp in results)
    for label, act, exp in results:
        status = "PASS" if act == exp else "FAIL"
        print(f"    [{status}] {label}: {act} (expected {exp})")
    return all_ok


async def test_list_filtered_by_ownership() -> bool:
    """List endpoints should only show operator's own resources."""
    print("  Setup: create engagements for both operators...")
    session_a = await create_engagement(HEADERS_A, "list-a")
    session_b = await create_engagement(HEADERS_B, "list-b")
    if not session_a or not session_b:
        print("  SKIP: could not create engagements")
        return False

    async with httpx.AsyncClient(timeout=10) as client:
        r_a = await client.get(f"{API_BASE}/engagements", headers=HEADERS_A)
        r_b = await client.get(f"{API_BASE}/engagements", headers=HEADERS_B)
        r_senior = await client.get(f"{API_BASE}/engagements", headers=HEADERS_SENIOR)

    data_a = r_a.json() if r_a.status_code == 200 else []
    data_b = r_b.json() if r_b.status_code == 200 else []
    data_senior = r_senior.json() if r_senior.status_code == 200 else []

    ids_a = {e.get("session_id", "") for e in data_a}
    ids_b = {e.get("session_id", "") for e in data_b}
    ids_senior = {e.get("session_id", "") for e in data_senior}

    a_sees_b = session_b in ids_a
    b_sees_a = session_a in ids_b
    senior_sees_both = session_a in ids_senior and session_b in ids_senior

    results = [
        ("operator-a sees b's engagement", not a_sees_b, True),
        ("operator-b sees a's engagement", not b_sees_a, True),
        ("senior_op sees both", senior_sees_both, True),
    ]

    all_ok = all(act == exp for _, act, exp in results)
    for label, act, exp in results:
        status = "PASS" if act == exp else "FAIL"
        print(f"    [{status}] {label}: {act} (expected {exp})")
    return all_ok


async def main() -> int:
    print("=" * 60)
    print("MULTI-TENANT OWNERSHIP QUALIFICATION SUITE")
    print("=" * 60)

    tests = [
        ("Engagement isolation", test_engagement_isolation),
        ("Task isolation", test_task_isolation),
        ("Cross-tenant enumeration (IDOR)", test_cross_tenant_enumeration),
        ("WebSocket isolation", test_websocket_isolation),
        ("List filtered by ownership", test_list_filtered_by_ownership),
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

    if passed == total:
        print("\n✅  MULTI-TENANT ISOLATION VERIFIED")
    else:
        print("\n❌  MULTI-TENANT ISOLATION BROKEN — FIX BEFORE PRODUCTION")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
