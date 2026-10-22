"""Owner-scoped Temporal observation never authorizes replay or target success."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state
from ai_osop.api.routers import supervision
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def observer(monkeypatch):
    access = AsyncMock()
    inspect = AsyncMock(return_value={
        "task_id": "task-one", "engagement_id": "eng-one",
        "observation": "found", "provider_status": "completed",
        "verified": True, "safe_to_retry": True,
        "durable_status_changed": True, "external_effect_status": "completed",
        "provider_secrets": "NOT_FOR_CLIENT",
    })
    monkeypatch.setattr(supervision, "_access", access)
    existing = state.get("orchestrator")
    state["orchestrator"] = SimpleNamespace(
        task_scheduler=SimpleNamespace(reconcile_temporal_dispatch=inspect),
    )
    try:
        yield access, inspect
    finally:
        state["orchestrator"] = existing


@pytest.mark.asyncio
async def test_temporal_observation_is_read_only_and_sanitized(observer):
    access, inspect = observer
    response = await supervision.observe_temporal_request(
        "eng-one", "task-one", {"sub": "owner", "role": "senior_operator"},
    )
    access.assert_awaited_once()
    inspect.assert_awaited_once_with("task-one", "eng-one")
    assert response == {
        "task_id": "task-one",
        "observation": "found", "provider_status": "completed",
        "verified": True,
        "safe_to_retry": False,
        "durable_status_changed": False,
        "external_effect_status": "unknown",
    }
    assert "NOT_FOR_CLIENT" not in str(response)


@pytest.mark.asyncio
async def test_foreign_engagement_denial_happens_before_temporal_call(observer):
    access, inspect = observer
    access.side_effect = HTTPException(status_code=403, detail="Not authorized")
    with pytest.raises(HTTPException) as exc:
        await supervision.observe_temporal_request(
            "eng-foreign", "task-one", {"sub": "different", "role": "operator"},
        )
    assert exc.value.status_code == 403
    inspect.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_or_mismatched_provider_reply_is_unknown(observer):
    _, inspect = observer
    for reply in (
        {"task_id": "task-other", "engagement_id": "eng-one", "observation": "found",
         "provider_status": "running"},
        {"task_id": "task-one", "engagement_id": "eng-other", "observation": "found",
         "provider_status": "running"},
        {"task_id": "task-one", "engagement_id": "eng-one", "observation": "successful",
         "provider_status": "terminated"},
        None,
    ):
        inspect.return_value = reply
        receipt = await supervision.observe_temporal_request(
            "eng-one", "task-one", {"sub": "owner", "role": "senior_operator"},
        )
        assert receipt["observation"] == "unknown"
        assert receipt["safe_to_retry"] is False
        assert receipt["external_effect_status"] == "unknown"


@pytest.mark.asyncio
async def test_temporal_provider_disconnect_returns_unknown_not_stopped(observer):
    _, inspect = observer
    inspect.side_effect = ConnectionError("secret upstream hostname")
    reply = await supervision.observe_temporal_request(
        "eng-one", "task-one", {"sub": "owner", "role": "senior_operator"},
    )
    assert reply["observation"] == "unknown"
    assert reply["provider_status"] == "unknown"
    assert "secret" not in str(reply)


@pytest.mark.asyncio
async def test_senior_reconciles_exact_workflow_existence_with_signed_cas(observer):
    access, inspect = observer
    original = state["orchestrator"]
    task = Task(
        id="task-one", engagement_id="eng-one", type="recon",
        agent_type=AgentType.RECON, status="dispatch_unknown",
        payload={"_authorization_version": 4, "target": "authorized.example"},
        result={"reason": "temporal_start_unverified"},
    )
    memory = SimpleNamespace(
        load_task_authoritative=AsyncMock(return_value=task),
        reconcile_temporal_dispatch_observation=AsyncMock(return_value=True),
    )
    state["orchestrator"] = SimpleNamespace(
        session_memory=memory,
        task_scheduler=SimpleNamespace(reconcile_temporal_dispatch=inspect),
    )
    try:
        inspect.return_value = {
            "task_id": "task-one", "engagement_id": "eng-one",
            "observation": "found", "verified": True,
            "workflow_id": "ai-osop-task-one",
            "run_id": "provider-run-123",
            "provider_status": "running",
        }
        result = await supervision.reconcile_temporal_existence(
            "eng-one", "task-one",
            supervision.TemporalExistenceReconciliationRequest(
                expected_authorization_version=4,
            ),
            {"sub": "senior", "role": "senior_operator"},
        )
        assert result["reconciled_workflow_existence"] is True
        assert result["durable_task_status"] == "scheduled"
        assert result["external_effect_status"] == "unknown"
        assert result["safe_to_retry"] is False
        memory.reconcile_temporal_dispatch_observation.assert_awaited_once_with(
            "task-one", "eng-one", "ai-osop-task-one",
            provider_run_id="provider-run-123", provider_status="RUNNING",
        )
    finally:
        state["orchestrator"] = original


@pytest.mark.asyncio
async def test_reconcile_refuses_stale_version_before_provider_call(observer):
    _, inspect = observer
    original = state["orchestrator"]
    memory = SimpleNamespace(
        load_task_authoritative=AsyncMock(return_value=Task(
            id="task-one", engagement_id="eng-one", type="recon",
            agent_type=AgentType.RECON, status="dispatch_unknown",
            payload={"_authorization_version": 5},
            result={"reason": "temporal_start_unverified"},
        )),
        reconcile_temporal_dispatch_observation=AsyncMock(),
    )
    state["orchestrator"] = SimpleNamespace(
        session_memory=memory,
        task_scheduler=SimpleNamespace(reconcile_temporal_dispatch=inspect),
    )
    try:
        with pytest.raises(HTTPException) as err:
            await supervision.reconcile_temporal_existence(
                "eng-one", "task-one",
                supervision.TemporalExistenceReconciliationRequest(
                    expected_authorization_version=4,
                ), {"sub": "senior", "role": "senior_operator"},
            )
        assert err.value.status_code == 409
        inspect.assert_not_awaited()
        memory.reconcile_temporal_dispatch_observation.assert_not_awaited()
    finally:
        state["orchestrator"] = original


@pytest.mark.asyncio
async def test_reconcile_never_writes_unknown_or_unverified_provider_receipt(observer):
    _, inspect = observer
    original = state["orchestrator"]
    memory = SimpleNamespace(
        load_task_authoritative=AsyncMock(return_value=Task(
            id="task-one", engagement_id="eng-one", type="recon",
            agent_type=AgentType.RECON, status="dispatch_unknown",
            payload={"_authorization_version": 4},
            result={"reason": "temporal_start_unverified"},
        )),
        reconcile_temporal_dispatch_observation=AsyncMock(),
    )
    state["orchestrator"] = SimpleNamespace(
        session_memory=memory,
        task_scheduler=SimpleNamespace(reconcile_temporal_dispatch=inspect),
    )
    try:
        inspect.return_value = {
            "task_id": "task-one", "engagement_id": "eng-one",
            "observation": "not_found", "verified": False,
            "workflow_id": "ai-osop-task-one", "provider_status": "unknown",
        }
        response = await supervision.reconcile_temporal_existence(
            "eng-one", "task-one",
            supervision.TemporalExistenceReconciliationRequest(
                expected_authorization_version=4,
            ),
            {"sub": "senior", "role": "senior_operator"},
        )
        assert response["reconciled_workflow_existence"] is False
        assert response["external_effect_status"] == "unknown"
        memory.reconcile_temporal_dispatch_observation.assert_not_awaited()
    finally:
        state["orchestrator"] = original
