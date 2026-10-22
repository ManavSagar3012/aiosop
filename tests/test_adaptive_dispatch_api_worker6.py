"""Senior JWT/Flow-fenced API confirmation stages no external agent work."""

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
from ai_osop.memory.adaptive_dispatch import AdaptiveDispatchDenied


@pytest.fixture
def api(monkeypatch):
    request = SimpleNamespace(
        id="apr-adaptive-1", engagement_id="eng-a",
        task_id="task-planner-a", status="approved", action_type="planner_inference",
    )
    memory = SimpleNamespace(load_approval_request=AsyncMock(return_value=request))
    orchestrator = SimpleNamespace(
        session_memory=memory,
        schedule_task=AsyncMock(side_effect=AssertionError("No direct agent dispatch")),
        resolve_approval=AsyncMock(side_effect=AssertionError("No generic approval dispatch")),
    )
    receipt = {
        "status": "pending_dispatch_review", "flow_id": "flow-a",
        "flow_revision": 10, "objective_task_id": "task-new",
        "subtask_id": "subtask-new", "approval_required": True,
        "execution_started": False, "dispatch_required": True,
        "target": "example.com",
    }
    admission = AsyncMock(return_value=receipt)
    monkeypatch.setitem(state, "orchestrator", orchestrator)
    monkeypatch.setattr(approvals, "_durable_memory", lambda _memory: True)
    monkeypatch.setattr(approvals, "assert_engagement_access", AsyncMock())
    monkeypatch.setattr(approvals, "confirm_adaptive_followup", admission)
    return request, orchestrator, admission, receipt


def body(**changes):
    return approvals.AdaptiveFollowupRequest(**{
        "request_id": "apr-adaptive-1",
        "expected_authorization_version": 4,
        "expected_flow_revision": 9,
        "confirmed_target": "example.com", "confirm_execution": True,
        **changes,
    })


@pytest.mark.asyncio
async def test_verified_senior_confirm_only_prepares_approval_required_flow_plan(api):
    approval, orchestrator, admission, receipt = api
    response = await approvals.prepare_confirmed_adaptive_followup(
        approval.id, body(), operator={"sub": "jwt-senior", "role": "senior_operator"},
    )
    assert response == receipt
    admission.assert_awaited_once_with(
        orchestrator.session_memory,
        request_id=approval.id, engagement_id=approval.engagement_id,
        actor_id="jwt-senior", actor_role="senior_operator",
        expected_authorization_version=4, expected_flow_revision=9,
        confirmed_target="example.com", confirm_execution=True,
    )
    orchestrator.schedule_task.assert_not_awaited()
    orchestrator.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("request_id,confirm,status", [
    ("another-id", True, 400),
    ("apr-adaptive-1", False, 422),
])
async def test_missing_confirmation_or_mismatched_id_never_reaches_admission(api, request_id, confirm, status):
    approval, orch, admission, _ = api
    with pytest.raises(HTTPException) as error:
        await approvals.prepare_confirmed_adaptive_followup(
            request_id, body(confirm_execution=confirm),
            operator={"sub": "jwt-senior", "role": "senior_operator"},
        )
    assert error.value.status_code == status
    admission.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.parametrize("field,value", [
    ("expected_authorization_version", 0),
    ("expected_authorization_version", True),
    ("expected_flow_revision", -1),
    ("expected_flow_revision", False),
    ("confirm_execution", "true"),
    ("confirm_execution", 1),
    ("confirmed_target", ""),
])
def test_user_supplied_consent_and_fences_are_strictly_validated(field, value):
    with pytest.raises(ValidationError):
        body(**{field: value})


@pytest.mark.asyncio
async def test_revocation_or_wrong_scope_returns_409_no_dispatch(api):
    approval, orch, admission, _ = api
    admission.side_effect = AdaptiveDispatchDenied("signed ROE revoked")
    with pytest.raises(HTTPException) as error:
        await approvals.prepare_confirmed_adaptive_followup(
            approval.id, body(),
            operator={"sub": "jwt-senior", "role": "senior_operator"},
        )
    assert error.value.status_code == 409
    assert "revoked" not in error.value.detail
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_jwt_required_and_regular_operator_cannot_prepare_followup(api, monkeypatch):
    approval, orch, admission, _ = api
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "isolated-adaptive-dispatch-jwt")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    app = FastAPI()
    app.include_router(approvals.router)

    def bearer(role):
        return {"Authorization": "Bearer " + jwt.encode({
            "sub": "verified-senior", "role": role,
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        }, settings.jwt_secret, algorithm=settings.jwt_algorithm)}

    uri = f"/approvals/{approval.id}/adaptive/prepare-followup"
    request = body().model_dump()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post(uri, json=request)).status_code in {401, 403}
        assert (await client.post(uri, headers=bearer("operator"), json=request)).status_code == 403
        assert (await client.post(uri, headers=bearer("senior_operator"), json={
            **request, "confirm_execution": False,
        })).status_code == 422
        accepted = await client.post(uri, headers=bearer("senior_operator"), json=request)
        assert accepted.status_code == 200
        assert accepted.json()["execution_started"] is False
        assert accepted.json()["approval_required"] is True
    assert admission.await_count == 1
    assert admission.await_args.kwargs["actor_id"] == "verified-senior"
    orch.schedule_task.assert_not_awaited()
