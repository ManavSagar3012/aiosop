"""Provider status assertions cannot silently cross signed execution identities."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.mcp.protocol import (
    _verified_remote_cancel,
    _verified_remote_status,
)

from tests.test_remote_execution_receipts import known_execution, remote_connection


IDENTITY = {
    "request_id": "req-remote",
    "engagement_id": "eng-live",
    "task_id": "task-allowed",
    "server_id": "scanner",
}


@pytest.mark.parametrize("missing", ["engagement_id", "task_id", "server_id"])
def test_signed_provider_cancellation_requires_complete_identity(missing):
    receipt = {**IDENTITY, "status": "cancelled", "verified": True, "stopped": True}
    assert (
        _verified_remote_cancel(
            receipt, "req-remote", "eng-live", "task-allowed", "scanner",
            require_bound_identity=True,
        )
        == "confirmed_stopped"
    )
    receipt.pop(missing)
    assert (
        _verified_remote_cancel(
            receipt, "req-remote", "eng-live", "task-allowed", "scanner",
            require_bound_identity=True,
        )
        == "unknown"
    )


@pytest.mark.parametrize("changed", ["request_id", "engagement_id", "task_id", "server_id"])
def test_signed_provider_status_rejects_foreign_identity(changed):
    receipt = {**IDENTITY, "status": "completed", "verified": True}
    assert (
        _verified_remote_status(
            receipt, "req-remote", "eng-live", "task-allowed", "scanner",
            require_bound_identity=True,
        )
        == "confirmed_finished"
    )
    receipt[changed] = "foreign"
    assert (
        _verified_remote_status(
            receipt, "req-remote", "eng-live", "task-allowed", "scanner",
            require_bound_identity=True,
        )
        == "unknown"
    )


def test_nested_failed_tool_envelope_cannot_confirm_execution():
    data = {
        "status": "error",
        "request_id": "tool-request",
        "result": {**IDENTITY, "status": "completed", "verified": True},
    }
    assert (
        _verified_remote_status(
            data, "req-remote", "eng-live", "task-allowed", "scanner",
            require_bound_identity=True,
        )
        == "unknown"
    )


@pytest.mark.asyncio
async def test_production_cancellation_propagates_identity_and_rejects_unbound_reply():
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
        remote_response={"request_id": "req-remote", "status": "cancelled",
                         "verified": True, "stopped": True},
    ))
    conn._requires_bound_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "unknown"
    assert conn._session.post.call_args.kwargs["json"] == IDENTITY
    assert conn._executions["req-remote"].outcome == "unknown"


@pytest.mark.asyncio
async def test_production_cancellation_accepts_complete_provider_status():
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1", "mcp_bound_receipts_v1"],
        remote_response={**IDENTITY, "status": "cancelled",
                         "verified": True, "stopped": True},
    ))
    conn._requires_bound_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "confirmed_stopped"
    assert conn._executions["req-remote"].outcome == "confirmed_stopped"


@pytest.mark.asyncio
async def test_persisted_status_requires_full_provider_tuple():
    conn = remote_connection(
        capabilities=["mcp_request_status_v1", "mcp_bound_receipts_v1"],
        remote_response={"request_id": "req-remote", "status": "completed",
                         "verified": True},
    )
    conn._requires_bound_provider_receipt = lambda: True
    conn.set_execution_event_callback(AsyncMock(return_value=True))
    claim = {
        **IDENTITY, "authorization_version": 1, "tool_name": "scan_target",
        "status": "outcome_unknown",
    }
    result = await conn.reconcile_persisted_status(claim)
    assert result["status"] == "unknown"
    assert conn._session.post.call_args.kwargs["json"] == IDENTITY
    assert conn._execution_event_callback.await_args_list[-1].args[2] == "reconciliation_result"
