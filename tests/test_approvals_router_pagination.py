"""AIOSOP-SCALE-005: /approvals/pending must be bounded.

The router previously returned every pending approval request with no
limit/offset. This pins the server-side cap + offset pagination.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers import approvals as approvals_router
from ai_osop.core.models import ApprovalRequest


def _approval(
    req_id: str, engagement_id: str = "eng-1", status: str = "pending"
) -> ApprovalRequest:
    return ApprovalRequest(
        id=req_id,
        task_id=f"task-{req_id}",
        agent_id="agent-1",
        action_type="exploit_validation",
        target="http://example.test/",
        payload_summary="Run exploit validation",
        risk_assessment="high",
        evidence=[],
        status=status,
        operator_id="",
        operator_notes="",
        engagement_id=engagement_id,
    )


@pytest.fixture
def app_with_approvals():
    app = FastAPI(title="approvals-test-app")
    app.include_router(approvals_router.router)

    async def _fake_verify_token():
        return {"sub": "op-1", "role": "senior_operator", "claims": {}, "tenant_id": "default"}

    app.dependency_overrides[verify_token] = _fake_verify_token
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
def bound_state(monkeypatch):
    original = dict(state)

    def _bind(orch):
        monkeypatch.setitem(state, "orchestrator", orch)

    yield _bind
    state.clear()
    state.update(original)


def _orchestrator_with(requests):
    orch = SimpleNamespace()
    orch._approval_requests = {r.id: r for r in requests}
    orch._sessions = {}
    return orch


async def test_pending_default_returns_all_small_set(app_with_approvals, bound_state):
    app = app_with_approvals
    reqs = [_approval("apr-1"), _approval("apr-2"), _approval("apr-3")]
    bound_state(_orchestrator_with(reqs))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/approvals/pending")
    assert resp.status_code == 200
    ids = [r["id"] for r in resp.json()]
    assert ids == ["apr-1", "apr-2", "apr-3"]


async def test_pending_excludes_resolved(app_with_approvals, bound_state):
    """Non-pending requests are filtered out before pagination."""
    app = app_with_approvals
    reqs = [_approval("apr-1"), _approval("apr-2", status="approved")]
    bound_state(_orchestrator_with(reqs))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/approvals/pending")
    assert [r["id"] for r in resp.json()] == ["apr-1"]


async def test_pending_paginates(app_with_approvals, bound_state):
    app = app_with_approvals
    reqs = [_approval(f"apr-{i}") for i in range(5)]
    bound_state(_orchestrator_with(reqs))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        r1 = await client.get("/approvals/pending", params={"limit": 2})
        assert [r["id"] for r in r1.json()] == ["apr-0", "apr-1"]
        r2 = await client.get("/approvals/pending", params={"limit": 2, "offset": 2})
        assert [r["id"] for r in r2.json()] == ["apr-2", "apr-3"]


async def test_pending_limits_server_side_cap(app_with_approvals, bound_state):
    """A client asking for more than _MAX_APPROVALS_LIMIT is capped by the
    server (never unbounded)."""
    app = app_with_approvals
    reqs = [_approval(f"apr-{i}") for i in range(10)]
    bound_state(_orchestrator_with(reqs))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/approvals/pending", params={"limit": 10**6})
    assert resp.status_code == 200
    assert len(resp.json()) == 10  # capped at _MAX_APPROVALS_LIMIT (2000)
