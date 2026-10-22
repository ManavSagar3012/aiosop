"""Planner approval API reads are durable and decisions never dispatch agents.

No application database, external provider, or live scan is required.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from jose import jwt

from ai_osop.api.deps import ApprovalDecisionRequest, state
from ai_osop.api.routers import approvals
from ai_osop.core.config import settings
from ai_osop.core.models import ApprovalRequest


def _approval(status="pending", action="planner_inference"):
    return ApprovalRequest(
        id="apr-planner-123", task_id="task-planner-123", engagement_id="eng-123",
        action_type=action, agent_id="planner-runtime", target="flow-123",
        payload_summary="Internal planner proposal", risk_assessment="Human review",
        status=status,
        operator_id="senior-verified" if status == "approved" else None,
        responded_at=datetime.utcnow() if status == "approved" else None,
    )


class Rows:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


class Session:
    def __init__(self, memory):
        self.memory = memory

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def execute(self, query):
        sql = str(query)
        if "FROM approval_requests JOIN tasks" in sql:
            return Rows([self.memory.request.id] if self.memory.request.status == "approved" else [])
        if "FROM tasks" in sql:
            return Rows(self.memory.task)
        if "FROM execution_flows" in sql:
            return Rows(self.memory.flow)
        raise AssertionError(f"Unexpected approval SQL: {sql}")


class Memory:
    def __init__(self, request):
        self.request = request
        self.task = SimpleNamespace(
            status="awaiting_approval", approval_required=True,
            assigned_agent_id="planner-runtime", flow_id="flow-123",
            parent_task_id="objective-123", subtask_id=None,
            payload={
                "_authorization_version": 6, "planner_flow_revision": 10,
                "planner_purpose": "flow_generation",
                "model_api_key": "NOT-TO-BE-EXPOSED",
                **({"approval_id": request.id, "operator_approved": True}
                   if request.status == "approved" else {}),
            },
        )
        self.flow = SimpleNamespace(id="flow-123", status="running", revision=10)

    def _async_session(self):
        return Session(self)

    async def list_pending_approvals(self):
        return [self.request] if self.request.status == "pending" else []

    async def load_approval_request(self, request_id):
        return self.request if request_id == self.request.id else None


@pytest.fixture
def api(monkeypatch):
    memory = Memory(_approval())
    orchestrator = SimpleNamespace(
        session_memory=memory,
        resolve_approval=AsyncMock(return_value={"status": "approved"}),
        _approval_requests={},
    )
    monkeypatch.setattr(approvals.memory_module, "SessionMemory", Memory)
    monkeypatch.setitem(state, "orchestrator", orchestrator)
    access = AsyncMock(return_value=SimpleNamespace())
    monkeypatch.setattr(approvals, "assert_engagement_access", access)
    return memory, orchestrator, access


@pytest.mark.asyncio
async def test_pending_and_lookup_return_safe_durable_version_hints(api):
    memory, _, access = api
    operator = {"sub": "verified-senior", "role": "senior_operator"}
    pending = await approvals.list_pending_approvals(operator)
    assert len(pending) == 1
    view = pending[0]
    assert view["authorization_version"] == 6
    assert view["flow_revision"] == 10
    assert view["flow_revision_current"] is True
    assert view["planner_purpose"] == "flow_generation"
    assert view["parent_task_id"] == "objective-123"
    assert "model_api_key" not in str(view)
    assert "operator_approved" not in str(view)
    lookup = await approvals.get_approval(memory.request.id, operator)
    assert lookup == view
    access.assert_awaited_once_with(operator, "eng-123")


@pytest.mark.asyncio
async def test_stale_flow_hints_do_not_advertise_actionable_review(api):
    memory, _, _ = api
    memory.flow.revision = 11
    pending = await approvals.list_pending_approvals({"sub": "senior", "role": "senior_operator"})
    assert pending[0]["flow_revision_current"] is False
    memory.flow.revision = 10
    memory.flow.status = "paused"
    pending = await approvals.list_pending_approvals({"sub": "senior", "role": "senior_operator"})
    assert pending[0]["flow_revision_current"] is False


@pytest.mark.asyncio
async def test_approved_but_parked_planner_is_listed_for_explicit_resume(api):
    memory, orch, access = api
    memory.request = _approval("approved")
    memory.task.payload.update({
        "approval_id": memory.request.id, "operator_approved": True,
    })
    operator = {"sub": "owner", "role": "operator"}
    ready = await approvals.list_approved_internal_planners("eng-123", operator)
    assert len(ready) == 1
    assert ready[0]["status"] == "approved"
    assert ready[0]["planner_purpose"] == "flow_generation"
    assert ready[0]["flow_revision_current"] is True
    assert ready[0]["authorization_version"] == 6
    assert "NOT-TO-BE-EXPOSED" not in str(ready)
    access.assert_awaited_once_with(operator, "eng-123")
    orch.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_grant_or_terminal_task_is_never_a_resumable_planner(api):
    memory, _, _ = api
    memory.request = _approval("approved")
    operator = {"sub": "senior", "role": "senior_operator"}
    assert await approvals.list_approved_internal_planners("eng-123", operator) == []
    memory.task.payload["approval_id"] = memory.request.id
    memory.task.payload["operator_approved"] = True
    memory.task.status = "running"
    assert await approvals.list_approved_internal_planners("eng-123", operator) == []


@pytest.mark.asyncio
async def test_failed_db_read_never_returns_cached_or_unscoped_planner(api):
    memory, _, _ = api
    memory.list_pending_approvals = AsyncMock(side_effect=OSError("PG unavailable"))
    with pytest.raises(HTTPException) as exc:
        await approvals.list_pending_approvals({"sub": "senior", "role": "senior_operator"})
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_resolution_calls_signed_planner_path_with_jwt_actor_and_fences(api, monkeypatch):
    memory, orch, _ = api
    backend = SimpleNamespace(resolve_internal_approval=AsyncMock(
        return_value=(_approval("approved"), True)))
    monkeypatch.setattr(approvals, "PlannerExecutionStore", lambda _memory: backend)
    operator = {"sub": "verified-senior", "role": "senior_operator"}
    decision = ApprovalDecisionRequest(
        request_id=memory.request.id, decision="approved", notes="Bounded plan only",
        expected_authorization_version=6, expected_flow_revision=10,
    )
    result = await approvals.resolve_approval(memory.request.id, decision, operator)
    assert result.status == "approved"
    backend.resolve_internal_approval.assert_awaited_once_with(
        memory.request.id, "eng-123", "task-planner-123", "approved",
        "verified-senior", actor_role="senior_operator",
        expected_authorization_version=6, expected_flow_revision=10,
        notes="Bounded plan only",
    )
    orch.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_bearer_role_and_identity_are_verified_before_planner_resolution(api, monkeypatch):
    memory, orch, _ = api
    backend = SimpleNamespace(resolve_internal_approval=AsyncMock(
        return_value=(_approval("approved"), True)))
    monkeypatch.setattr(approvals, "PlannerExecutionStore", lambda _memory: backend)
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "isolated-planner-approval-test-secret")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    app = FastAPI()
    app.include_router(approvals.router)

    def auth(role):
        claims = {
            "sub": "verified-senior", "role": role,
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        }
        return {"Authorization": "Bearer " + jwt.encode(
            claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)}

    payload = dict(
        request_id=memory.request.id, decision="approved",
        expected_authorization_version=6, expected_flow_revision=10,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post("/approvals/apr-planner-123/resolve", json=payload)).status_code in {401, 403}
        assert (await client.post(
            "/approvals/apr-planner-123/resolve", json=payload,
            headers=auth("operator"),
        )).status_code == 403
        assert (await client.post(
            "/approvals/apr-planner-123/resolve", json={**payload, "operator_id": "forged"},
            headers=auth("senior_operator"),
        )).status_code == 403
        ok = await client.post(
            "/approvals/apr-planner-123/resolve", json=payload,
            headers=auth("senior_operator"),
        )
        assert ok.status_code == 200
        assert ok.json()["status"] == "approved"
        ready = await client.get(
            "/approvals/planner-ready?engagement_id=eng-123", headers=auth("operator"))
        assert ready.status_code == 200
    backend.resolve_internal_approval.assert_awaited_once()
    assert backend.resolve_internal_approval.await_args.args[4] == "verified-senior"
    orch.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_planner_revoke_or_version_conflict_returns_409_without_generic_dispatch(api, monkeypatch):
    memory, orch, _ = api
    backend = SimpleNamespace(resolve_internal_approval=AsyncMock(
        side_effect=PermissionError("revoked authorization or stale Flow revision")))
    monkeypatch.setattr(approvals, "PlannerExecutionStore", lambda _memory: backend)
    operator = {"sub": "verified-senior", "role": "senior_operator"}
    request = ApprovalDecisionRequest(
        request_id=memory.request.id, decision="approved",
        expected_authorization_version=6, expected_flow_revision=10,
    )
    with pytest.raises(HTTPException) as failure:
        await approvals.resolve_approval(memory.request.id, request, operator)
    assert failure.value.status_code == 409
    assert failure.value.detail == "Approval is no longer actionable"
    orch.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_planner_ready_listing_blocks_cross_tenant_before_database_access(api):
    memory, _, _ = api
    original = approvals.assert_engagement_access

    async def deny(_operator, _engagement):
        raise HTTPException(status_code=403, detail="Not owner")

    approvals.assert_engagement_access = deny
    try:
        with pytest.raises(HTTPException) as failure:
            await approvals.list_approved_internal_planners(
                "eng-unrelated", {"sub": "owner-123", "role": "operator"}
            )
        assert failure.value.status_code == 403
    finally:
        approvals.assert_engagement_access = original


@pytest.mark.asyncio
async def test_generic_approval_resolution_keeps_atomic_orchestrator_path(api):
    memory, orch, _ = api
    memory.request = _approval(action="summarize_context")
    outcome = await approvals.resolve_approval(
        memory.request.id,
        ApprovalDecisionRequest(request_id=memory.request.id, decision="approved"),
        {"sub": "verified-senior", "role": "senior_operator"},
    )
    assert outcome["status"] == "approved"
    orch.resolve_approval.assert_awaited_once_with(
        request_id=memory.request.id, decision="approved",
        operator_id="verified-senior", notes=None,
    )
