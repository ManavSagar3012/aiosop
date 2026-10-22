"""Approval evidence must bind to the authenticated operator, not HTTP input."""

from types import SimpleNamespace
from unittest.mock import AsyncMock
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt
from pydantic import ValidationError
from fastapi import HTTPException

from ai_osop.api.deps import ApprovalDecisionRequest, state
from ai_osop.api.routers import approvals
from ai_osop.core.config import settings


@pytest.fixture
def approval_api(monkeypatch):
    request = SimpleNamespace(engagement_id="eng-approved", action_type="summarize_context")
    orchestrator = SimpleNamespace(
        _approval_requests={"apr-one": request},
        resolve_approval=AsyncMock(return_value={"status": "approved"}),
    )
    monkeypatch.setitem(state, "orchestrator", orchestrator)
    access = AsyncMock()
    monkeypatch.setattr(approvals, "assert_engagement_access", access)
    return orchestrator, access


@pytest.mark.asyncio
async def test_approval_actor_comes_from_verified_bearer_without_client_identity(approval_api):
    orchestrator, access = approval_api
    operator = {"sub": "verified-senior", "role": "senior_operator"}
    result = await approvals.resolve_approval(
        "apr-one", ApprovalDecisionRequest(request_id="apr-one", decision="approved"),
        operator=operator,
    )
    assert result == {"status": "approved"}
    orchestrator.resolve_approval.assert_awaited_once_with(
        request_id="apr-one", decision="approved", operator_id="verified-senior", notes=None,
    )
    access.assert_awaited_once_with(operator, "eng-approved")


@pytest.mark.asyncio
@pytest.mark.parametrize("body,operator,status", [
    ({"request_id": "apr-one", "decision": "approved", "operator_id": "other"},
     {"sub": "verified-senior", "role": "senior_operator"}, 403),
    ({"request_id": "apr-other", "decision": "approved"},
     {"sub": "verified-senior", "role": "senior_operator"}, 400),
    ({"request_id": "apr-one", "decision": "approved"},
     {"sub": "", "role": "senior_operator"}, 403),
])
async def test_forged_approval_identity_is_denied_before_any_decision(
    approval_api, body, operator, status
):
    orchestrator, _ = approval_api
    with pytest.raises(HTTPException) as error:
        await approvals.resolve_approval(
            "apr-one", ApprovalDecisionRequest(**body), operator=operator,
        )
    assert error.value.status_code == status
    orchestrator.resolve_approval.assert_not_awaited()


@pytest.mark.asyncio
async def test_legacy_client_identity_only_accepted_if_exactly_verified(approval_api):
    orchestrator, _ = approval_api
    await approvals.resolve_approval(
        "apr-one", ApprovalDecisionRequest(
            request_id="apr-one", decision="rejected", operator_id="verified-senior",
            notes="Out of scope",
        ), operator={"sub": "verified-senior", "role": "senior_operator"},
    )
    assert orchestrator.resolve_approval.await_args.kwargs["operator_id"] == "verified-senior"


@pytest.mark.parametrize("decision", ["modified", "executed", "timeout", "APPROVED"])
def test_unrecognized_approval_decisions_fail_schema_validation(decision):
    with pytest.raises(ValidationError):
        ApprovalDecisionRequest(request_id="apr-one", decision=decision)


@pytest.mark.asyncio
async def test_internal_planner_approval_routes_to_dedicated_durable_path(
    approval_api, monkeypatch
):
    orchestrator, _access = approval_api
    request = SimpleNamespace(
        engagement_id="eng-approved",
        task_id="task-planner-signed",
        action_type="planner_inference",
    )
    orchestrator.session_memory = SimpleNamespace(
        load_approval_request=AsyncMock(return_value=request)
    )
    monkeypatch.setattr(approvals, "_durable_memory", lambda _memory: True)
    accepted = SimpleNamespace(status="approved", operator_id="verified-senior")
    planner = SimpleNamespace(
        resolve_internal_approval=AsyncMock(return_value=(accepted, True))
    )
    monkeypatch.setattr(approvals, "PlannerExecutionStore", lambda memory: planner)

    response = await approvals.resolve_approval(
        "apr-planner-signed",
        ApprovalDecisionRequest(
            request_id="apr-planner-signed", decision="approved",
            expected_authorization_version=3, expected_flow_revision=7,
        ),
        operator={"sub": "verified-senior", "role": "senior_operator"},
    )
    assert response is accepted
    planner.resolve_internal_approval.assert_awaited_once_with(
        "apr-planner-signed", "eng-approved", "task-planner-signed",
        "approved", "verified-senior", actor_role="senior_operator",
        expected_authorization_version=3, expected_flow_revision=7, notes=None,
    )
    orchestrator.resolve_approval.assert_not_awaited()

    with pytest.raises(HTTPException) as error:
        await approvals.resolve_approval(
            "apr-planner-signed",
            ApprovalDecisionRequest(request_id="apr-planner-signed", decision="approved"),
            operator={"sub": "verified-senior", "role": "senior_operator"},
        )
    assert error.value.status_code == 422
    assert planner.resolve_internal_approval.await_count == 1


@pytest.mark.asyncio
async def test_real_http_bearer_verification_binds_approval_actor_and_denies_spoof(
    approval_api, monkeypatch
):
    orchestrator, _ = approval_api
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "isolated-approval-test-secret")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    app = FastAPI()
    app.include_router(approvals.router)

    def bearer(role):
        payload = {
            "sub": "authenticated-senior", "role": role,
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        }
        return {"Authorization": "Bearer " + jwt.encode(
            payload, settings.jwt_secret, algorithm=settings.jwt_algorithm,
        )}

    url = "/approvals/apr-one/resolve"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        fake = await client.post(url, headers=bearer("senior_operator"), json={
            "request_id": "apr-one", "decision": "approved", "operator_id": "spoofed-senior",
        })
        assert fake.status_code == 403
        unauthorized = await client.post(url, headers=bearer("operator"), json={
            "request_id": "apr-one", "decision": "approved",
        })
        assert unauthorized.status_code == 403
        assert orchestrator.resolve_approval.await_count == 0

        verified = await client.post(url, headers=bearer("senior_operator"), json={
            "request_id": "apr-one", "decision": "approved",
        })
        assert verified.status_code == 200
        assert orchestrator.resolve_approval.await_count == 1
        assert orchestrator.resolve_approval.await_args.kwargs["operator_id"] == "authenticated-senior"
