"""JWT-scoped approved adaptive planning continuation API: proposals, not agents."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient
from jose import jwt
from pydantic import ValidationError

from ai_osop.api.deps import state
from ai_osop.api.routers import approvals
from ai_osop.core.config import settings
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.orchestrator.planner_resume import AdaptiveResumeDenied


@pytest.fixture
def api(monkeypatch):
    request = SimpleNamespace(
        id="apr-planner-adaptive", engagement_id="eng-adaptive",
        task_id="task-planner", status="approved", action_type="planner_inference",
    )
    memory = SimpleNamespace(load_approval_request=AsyncMock(return_value=request))
    orchestrator = SimpleNamespace(
        session_memory=memory,
        resolve_approval=AsyncMock(side_effect=AssertionError("Generic dispatch forbidden")),
        schedule_task=AsyncMock(side_effect=AssertionError("Agent scheduling forbidden")),
    )
    monkeypatch.setitem(state, "orchestrator", orchestrator)
    monkeypatch.setattr(approvals, "_durable_memory", lambda _memory: True)
    access = AsyncMock(return_value=SimpleNamespace())
    monkeypatch.setattr(approvals, "assert_engagement_access", access)
    proposal = {
        "status": "proposal_ready", "approval_id": request.id,
        "flow_id": "flow-adaptive", "flow_revision": 9,
        "planner_task_id": "task-planner", "review_required": True,
        "execution_started": False,
        "proposal": {"action": "stop", "parameters": {}},
    }
    continuation = AsyncMock(return_value=proposal)
    reader = AsyncMock(return_value=proposal)
    monkeypatch.setattr(approvals, "resume_approved_adaptive_plan", continuation)
    monkeypatch.setattr(approvals, "read_approved_adaptive_proposal", reader)
    # The production API now reads the current signing ledger to attach an
    # authoritative version hint; keep this older isolated HTTP test fixture
    # independent of SQL while preserving the new fail-closed implementation.
    async def signed_hint(_memory, _engagement_id, data):
        return {**data, "authorization_version": 4}
    monkeypatch.setattr(approvals, "_adaptive_version_hint", AsyncMock(side_effect=signed_hint))
    return request, orchestrator, access, continuation, reader, proposal


@pytest.mark.asyncio
async def test_only_senior_verified_identity_reaches_fenced_continuation(api):
    request, orch, access, continuation, _, expected = api
    body = approvals.AdaptiveContinuationRequest(
        request_id=request.id, expected_authorization_version=4, expected_flow_revision=8,
    )
    operator = {"sub": "jwt-senior", "role": "senior_operator"}
    result = await approvals.continue_approved_adaptive_planner(request.id, body, operator)
    assert result == expected
    continuation.assert_awaited_once_with(
        orch,
        request_id=request.id, engagement_id="eng-adaptive",
        actor_id="jwt-senior", actor_role="senior_operator",
        expected_authorization_version=4, expected_flow_revision=8,
    )
    access.assert_awaited_once_with(operator, "eng-adaptive")
    orch.schedule_task.assert_not_awaited()
    orch.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrong_approval_id_is_denied_before_any_model_or_dispatch(api):
    request, orch, _, continuation, _, _ = api
    with pytest.raises(HTTPException) as exc:
        await approvals.continue_approved_adaptive_planner(
            "another-approval",
            approvals.AdaptiveContinuationRequest(
                request_id=request.id, expected_authorization_version=4,
                expected_flow_revision=8,
            ), {"sub": "senior", "role": "senior_operator"},
        )
    assert exc.value.status_code == 400
    continuation.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("exception,status", [
    (AdaptiveResumeDenied("Revoked signed authorization"), 409),
    (ModelBudgetExceeded("Stale planner CAS"), 409),
    (ModelOutcomeUncertain("Remote model might be charged"), 503),
    (OSError("PG receipt unavailable"), 503),
])
async def test_stale_revoked_or_unknown_model_outcome_never_retries_or_dispatches(
    api, exception, status,
):
    request, orch, _, continuation, _, _ = api
    continuation.side_effect = exception
    with pytest.raises(HTTPException) as failure:
        await approvals.continue_approved_adaptive_planner(
            request.id,
            approvals.AdaptiveContinuationRequest(
                request_id=request.id, expected_authorization_version=4,
                expected_flow_revision=8,
            ), {"sub": "senior", "role": "senior_operator"},
        )
    assert failure.value.status_code == status
    assert continuation.await_count == 1
    assert "Remote" not in failure.value.detail
    orch.schedule_task.assert_not_awaited()
    orch.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_settled_proposal_is_read_only_and_engagement_scoped(api):
    request, orch, access, continuation, reader, expected = api
    result = await approvals.get_settled_adaptive_proposal(
        request.id, {"sub": "owner", "role": "operator"},
    )
    assert result == {**expected, "authorization_version": 4}
    reader.assert_awaited_once_with(
        orch, request_id=request.id, engagement_id=request.engagement_id,
    )
    access.assert_awaited_once_with(
        {"sub": "owner", "role": "operator"}, request.engagement_id,
    )
    continuation.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.parametrize("field,value", [
    ("expected_authorization_version", True),
    ("expected_authorization_version", 0),
    ("expected_flow_revision", False),
    ("expected_flow_revision", -1),
])
def test_cannot_coerce_version_hints_or_send_invalid_signer_cas(field, value):
    body = dict(
        request_id="apr-planner-adaptive",
        expected_authorization_version=4,
        expected_flow_revision=8,
    )
    body[field] = value
    with pytest.raises(ValidationError):
        approvals.AdaptiveContinuationRequest(**body)


@pytest.mark.asyncio
async def test_real_http_jwt_senior_only_resume_and_no_headerless_execution(api, monkeypatch):
    request, orch, _, continuation, reader, _ = api
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "isolated-adaptive-worker6-jwt")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    app = FastAPI()
    app.include_router(approvals.router)

    def token(role):
        payload = {
            "sub": "jwt-verified-senior", "role": role,
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        }
        return {"Authorization": "Bearer " + jwt.encode(
            payload, settings.jwt_secret, algorithm=settings.jwt_algorithm,
        )}

    url = f"/approvals/{request.id}/adaptive/continue"
    body = {
        "request_id": request.id,
        "expected_authorization_version": 4, "expected_flow_revision": 8,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post(url, json=body)).status_code in {401, 403}
        assert (await client.post(url, headers=token("operator"), json=body)).status_code == 403
        assert (await client.post(url, headers=token("senior_operator"), json={
            **body, "expected_flow_revision": True,
        })).status_code == 422
        good = await client.post(url, headers=token("senior_operator"), json=body)
        assert good.status_code == 200
        assert good.json()["execution_started"] is False
        # Durable read works for owner authorized operators, never invokes LLM.
        lookup = await client.get(
            f"/approvals/{request.id}/adaptive/proposal", headers=token("operator"),
        )
        assert lookup.status_code == 200
    assert continuation.await_count == 1
    assert continuation.await_args.kwargs["actor_id"] == "jwt-verified-senior"
    reader.assert_awaited_once()
    orch.schedule_task.assert_not_awaited()
