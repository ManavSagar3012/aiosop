"""Run only bounded, owner-fenced, no-replay remote status observation."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers import supervision
from ai_osop.memory.supervision_store import SupervisionConflict, SupervisionStore
from ai_osop.orchestrator.orchestrator import Orchestrator

_SID = "eng-owned"
_TASK = "task-owned"
_SERVER = "mock-signed-provider"
_REQUEST = "req-original"


def _claim(status="outcome_unknown"):
    return {
        "server_id": _SERVER,
        "request_id": _REQUEST,
        "engagement_id": _SID,
        "task_id": _TASK,
        "authorization_version": 7,
        "tool_name": "get_health",
        "status": status,
    }


@pytest.fixture
def api(monkeypatch):
    store = SupervisionStore(SimpleNamespace())
    store.assert_access = AsyncMock()
    store.list_mcp_dispatches = AsyncMock(return_value=[_claim()])
    store.get_mcp_dispatch = AsyncMock(return_value=_claim())
    orch = SimpleNamespace(
        supervision_store=store,
        session_memory=SimpleNamespace(),
        reconcile_mcp_dispatch=AsyncMock(
            return_value={
                "status": "unknown",
                "persisted_status": "outcome_unknown",
                "request_id": _REQUEST,
                "safe_to_retry": False,
            }
        ),
    )
    monkeypatch.setitem(state, "orchestrator", orch)
    monkeypatch.setattr(supervision, "assert_engagement_access", AsyncMock())
    app = FastAPI()
    app.include_router(supervision.router)
    app.dependency_overrides[verify_token] = lambda: {
        "sub": "alice",
        "role": "operator",
    }
    return TestClient(app), store, orch


def _url(task=_TASK):
    return f"/supervision/engagements/{_SID}/tasks/{task}/mcp/reconcile-pending"


def test_sweep_observes_only_original_durable_identity_no_target_action(api):
    client, store, orch = api
    reply = client.post(_url(), json={"limit": 6})
    assert reply.status_code == 200, reply.text
    assert reply.json() == {
        "observed": [
            {
                "server_id": _SERVER,
                "request_id": _REQUEST,
                "status": "unknown",
                "persisted_status": "outcome_unknown",
                "safe_to_retry": False,
                "external_effect_status": "unknown",
            }
        ],
        "remaining_unobserved": 0,
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }
    orch.reconcile_mcp_dispatch.assert_awaited_once_with(
        _SID,
        _TASK,
        _SERVER,
        _REQUEST,
    )
    assert store.assert_access.await_count >= 2


def test_sweep_denies_foreign_task_before_remote_provider(api):
    client, store, orch = api
    store.assert_access.side_effect = SupervisionConflict("Foreign task")
    assert client.post(_url(), json={"limit": 2}).status_code == 403
    orch.reconcile_mcp_dispatch.assert_not_awaited()


def test_sweep_rechecks_owner_between_independent_network_observations(api):
    client, store, orch = api
    a, b = _claim(), _claim()
    b["request_id"] = "req-other"
    store.list_mcp_dispatches.return_value = [a, b]
    store.assert_access.side_effect = [None, None, SupervisionConflict("revoked")]
    result = client.post(_url(), json={"limit": 6})
    assert result.status_code == 403
    orch.reconcile_mcp_dispatch.assert_awaited_once()


def test_sweep_refuses_duplicate_or_cross_tenant_inventory(api):
    client, store, orch = api
    store.list_mcp_dispatches.return_value = [_claim(), deepcopy(_claim())]
    assert client.post(_url(), json={"limit": 6}).status_code == 503
    orch.reconcile_mcp_dispatch.assert_not_awaited()
    foreign = _claim()
    foreign["task_id"] = "task-other"
    store.list_mcp_dispatches.return_value = [foreign]
    assert client.post(_url(), json={"limit": 6}).status_code == 503
    orch.reconcile_mcp_dispatch.assert_not_awaited()


def test_sweep_protects_against_provider_forged_success_or_running(api):
    client, store, orch = api
    for status, persisted in (
        ("confirmed_stopped", "outcome_unknown"),
        ("confirmed_finished", "provider_returned"),
        ("running", "outcome_unknown"),
        ("success", "confirmed_finished"),
    ):
        orch.reconcile_mcp_dispatch.return_value = {
            "request_id": _REQUEST,
            "status": status,
            "persisted_status": persisted,
        }
        reply = client.post(_url(), json={"limit": 6})
        assert reply.status_code == 200, reply.text
        assert reply.json()["observed"][0]["status"] == "unknown"
        assert reply.json()["safe_to_retry"] is False


def test_sweep_bounded_limit_prevents_bulk_remote_probing(api):
    client, store, orch = api
    store.list_mcp_dispatches.return_value = [
        {**_claim(), "request_id": f"req-{n}"} for n in range(15)
    ]
    assert client.post(_url(), json={"limit": 9}).status_code == 422
    assert client.post(_url(), json={"limit": 0}).status_code == 422
    assert client.post(_url(), json={"limit": 2}).status_code == 200
    assert orch.reconcile_mcp_dispatch.await_count == 2


@pytest.mark.asyncio
async def test_orchestrator_does_not_present_unpersisted_running_as_provider_state():
    connection = SimpleNamespace(
        reconcile_persisted_status=AsyncMock(
            return_value={"status": "running", "server_id": _SERVER, "request_id": _REQUEST},
        ),
        execute=AsyncMock(),
    )
    store = SimpleNamespace(
        get_mcp_dispatch=AsyncMock(side_effect=[_claim(), _claim("outcome_unknown")]),
    )
    orch = SimpleNamespace(
        supervision_store=store,
        mcp_registry=SimpleNamespace(get_server=lambda _: connection),
    )
    result = await Orchestrator.reconcile_mcp_dispatch(
        orch,
        _SID,
        _TASK,
        _SERVER,
        _REQUEST,
    )
    assert result["status"] == "unknown"
    assert result["reason"] == "running_receipt_not_persisted"
    connection.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_orchestrator_rejects_identity_changed_during_remote_observation():
    claim = _claim()
    forged = {**claim, "task_id": "task-foreign", "status": "confirmed_stopped"}
    connection = SimpleNamespace(
        reconcile_persisted_status=AsyncMock(
            return_value={"status": "confirmed_stopped"},
        )
    )
    orch = SimpleNamespace(
        supervision_store=SimpleNamespace(
            get_mcp_dispatch=AsyncMock(side_effect=[claim, forged]),
        ),
        mcp_registry=SimpleNamespace(get_server=lambda _: connection),
    )
    result = await Orchestrator.reconcile_mcp_dispatch(
        orch,
        _SID,
        _TASK,
        _SERVER,
        _REQUEST,
    )
    assert result == {"status": "unknown", "reason": "receipt_not_persisted"}


@pytest.mark.asyncio
async def test_orchestrator_invalid_provider_response_and_network_outage_stay_unknown():
    claim = _claim()
    connection = SimpleNamespace(
        reconcile_persisted_status=AsyncMock(
            return_value={"status": "confirmed_finished", "request_id": "req-forged"},
        )
    )
    store = SimpleNamespace(get_mcp_dispatch=AsyncMock(return_value=claim))
    orch = SimpleNamespace(
        supervision_store=store,
        mcp_registry=SimpleNamespace(get_server=lambda _: connection),
    )
    outcome = await Orchestrator.reconcile_mcp_dispatch(
        orch,
        _SID,
        _TASK,
        _SERVER,
        _REQUEST,
    )
    assert outcome["status"] == "unknown"
    connection.reconcile_persisted_status.side_effect = TimeoutError("Bearer SECRET")
    outcome = await Orchestrator.reconcile_mcp_dispatch(
        orch,
        _SID,
        _TASK,
        _SERVER,
        _REQUEST,
    )
    assert outcome == {
        "status": "unknown",
        "reason": "remote_observation_unavailable",
    }
    assert "SECRET" not in str(outcome)
