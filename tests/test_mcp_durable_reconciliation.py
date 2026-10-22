"""Orchestrator never treats unpersisted remote status as verified execution."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.orchestrator import Orchestrator


def _claim(status="outcome_unknown"):
    return {
        "engagement_id": "eng-signed",
        "task_id": "task-1",
        "server_id": "mock-provider",
        "request_id": "req-original",
        "tool_name": "passive_query",
        "authorization_version": 3,
        "status": status,
    }


def _instance(*, claimed=True, remote="confirmed_stopped", committed=None, provider=True):
    store = SimpleNamespace(get_mcp_dispatch=AsyncMock(
        side_effect=[_claim() if claimed else None, _claim(committed)] if claimed else [None]
    ))
    connection = SimpleNamespace(
        reconcile_persisted_status=AsyncMock(return_value={"status": remote}),
        execute=AsyncMock(),
    )
    registry = SimpleNamespace(
        get_server=lambda server_id: connection if provider else None
    )
    orch = SimpleNamespace(supervision_store=store, mcp_registry=registry)
    return orch, connection


@pytest.mark.asyncio
async def test_unpersisted_remote_stop_never_presented_confirmed():
    orch, connection = _instance(committed="outcome_unknown")
    result = await Orchestrator.reconcile_mcp_dispatch(
        orch, "eng-signed", "task-1", "mock-provider", "req-original"
    )
    assert result == {"status": "unknown", "reason": "receipt_not_persisted"}
    connection.reconcile_persisted_status.assert_awaited_once()
    connection.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_verified_remote_stop_requires_matching_committed_result():
    orch, connection = _instance(committed="confirmed_stopped")
    result = await Orchestrator.reconcile_mcp_dispatch(
        orch, "eng-signed", "task-1", "mock-provider", "req-original"
    )
    assert result["status"] == result["persisted_status"] == "confirmed_stopped"
    connection.reconcile_persisted_status.assert_awaited_once()
    connection.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_signed_dispatch_or_provider_does_not_issue_target_call():
    missing, connection = _instance(claimed=False)
    result = await Orchestrator.reconcile_mcp_dispatch(
        missing, "eng-signed", "task-1", "mock-provider", "req-fabricated"
    )
    assert result["status"] == "unknown"
    connection.reconcile_persisted_status.assert_not_awaited()

    disconnected, connection = _instance(provider=False)
    result = await Orchestrator.reconcile_mcp_dispatch(
        disconnected, "eng-signed", "task-1", "mock-provider", "req-original"
    )
    assert result["status"] == "not_supported"
    connection.reconcile_persisted_status.assert_not_awaited()
