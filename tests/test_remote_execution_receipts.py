"""Remote stop receipts require real support, scoped identity, and proof."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest, MCPRegistry
from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler

from tests.test_mcp_direct_dispatch_safety import Persistence


@pytest.fixture(autouse=True)
def reset_request_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


def remote_connection(*, capabilities=(), remote_response=None, timeout=False, error=False):
    conn = MCPConnection("scanner", "localhost", 8080)
    conn._initialized = True
    conn._capabilities = list(capabilities)
    conn._tools["scan_target"] = SimpleNamespace(
        name="scan_target", timeout_seconds=5, requires_approval=False,
    )
    response = SimpleNamespace(
        status=200,
        json=AsyncMock(return_value=remote_response or {
            "status": "accepted", "request_id": "req-remote",
        }),
    )
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=response)
    context.__aexit__ = AsyncMock(return_value=False)
    post = MagicMock(return_value=context)
    if timeout:
        post.side_effect = asyncio.TimeoutError()
    elif error:
        post.side_effect = ConnectionError("secret transport credentials")
    conn._session = SimpleNamespace(post=post)
    conn.set_budget_callback(Persistence().consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-allowed")
    return conn


async def known_execution(conn, request_id="req-remote"):
    # Dispatch a previously authorized call; the backend receipt is a response,
    # not proof that an asynchronous scan completed or stopped.
    from ai_osop.mcp.protocol import _RemoteExecution

    conn._executions[request_id] = _RemoteExecution(
        engagement_id="eng-live", task_id="task-allowed",
        tool_name="scan_target", parameters={"url": "https://example.com/a"},
    )
    return conn


@pytest.mark.asyncio
async def test_remote_cancellation_requires_advertised_capability():
    conn = await known_execution(remote_connection())
    result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "not_supported"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_explicit_remote_confirmation_verified_and_idempotent():
    conn = await known_execution(remote_connection(
        capabilities=["mcp_cancel_request_v1"],
        remote_response={"request_id": "req-remote", "status": "cancelled", "verified": True,
                         "stopped": True},
    ))
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)
    first = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    second = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert first["status"] == second["status"] == "confirmed_stopped"
    conn._session.post.assert_called_once()
    assert conn._session.post.call_args.args[0].endswith("/mcp/cancel")
    assert [call.args[2] for call in events.await_args_list] == [
        "cancellation_requested", "cancellation_result",
    ]


@pytest.mark.asyncio
async def test_advertised_cancel_tool_is_used_without_assuming_endpoint():
    conn = await known_execution(remote_connection(
        remote_response={"request_id": "req-cancel-response", "status": "success",
                         "result": {"request_id": "req-remote", "status": "cancelled",
                                    "verified": True, "stopped": True}},
    ))
    conn._tools["cancel_request"] = SimpleNamespace(name="cancel_request")
    receipt = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert receipt["status"] == "confirmed_stopped"
    args = conn._session.post.call_args
    assert args.args[0].endswith("/mcp/execute")
    assert args.kwargs["json"]["tool_name"] == "cancel_request"
    assert args.kwargs["json"]["parameters"] == {"request_id": "req-remote"}


@pytest.mark.parametrize("failure", ["timeout", "error", "accepted", "wrong-request"])
@pytest.mark.asyncio
async def test_cancel_unknown_when_provider_does_not_prove_stop(failure):
    conn = remote_connection(
        capabilities=["mcp_cancel_request_v1"],
        timeout=failure == "timeout", error=failure == "error",
        remote_response={
            "request_id": "wrong" if failure == "wrong-request" else "req-remote",
            "status": "accepted" if failure == "accepted" else "cancelled",
            "verified": True,
        },
    )
    await known_execution(conn)
    result = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "unknown"
    assert "secret" not in str(result)


@pytest.mark.asyncio
async def test_cancellation_requires_matching_attributable_scope_and_approval():
    conn = await known_execution(remote_connection(capabilities=["mcp_cancel_request_v1"]))
    # The task cannot cancel a remote request belonging to another engagement.
    wrong = await conn.request_cancellation("req-remote", "eng-other", "task-allowed")
    assert wrong["status"] == "unknown"
    conn._session.post.assert_not_called()

    # Revoked original target fails closed even if the provider supports stop.
    from ai_osop.core.models import ScopeDefinition
    memory = Persistence(scope=ScopeDefinition(
        engagement_id="eng-live", domains=["elsewhere.example"], authorization_ref="signed-roe",
    ))
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    denied = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert denied["status"] == "denied"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_postrestart_durable_claim_reconciles_status_without_replaying_original_tool():
    conn = remote_connection(
        capabilities=["mcp_request_status_v1"],
        remote_response={
            "request_id": "req-postrestart", "status": "cancelled",
            "verified": True, "stopped": True,
        },
    )
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)
    # The original in-memory _executions map is empty on a restarted worker.
    assert not conn._executions
    claim = {
        "engagement_id": "eng-live",
        "task_id": "task-allowed",
        "server_id": "scanner",
        "request_id": "req-postrestart",
        "tool_name": "scan_target",
        "authorization_version": 2,
        "status": "outcome_unknown",
    }
    result = await conn.reconcile_persisted_status(claim)
    assert result["status"] == "confirmed_stopped"
    conn._session.post.assert_called_once()
    assert conn._session.post.call_args.args[0].endswith("/mcp/request/status")
    assert conn._session.post.call_args.kwargs["json"] == {
        "request_id": "req-postrestart"
    }
    assert [call.args[2] for call in events.await_args_list] == [
        "reconciliation_requested", "reconciliation_result",
    ]
    assert not conn._executions


@pytest.mark.asyncio
async def test_postrestart_status_reconciliation_never_assumes_stop_without_receipt():
    claim = {
        "engagement_id": "eng-live", "task_id": "task-allowed",
        "server_id": "scanner", "request_id": "req-postrestart",
        "tool_name": "scan_target", "authorization_version": 2,
        "status": "outcome_unknown",
    }
    without_support = remote_connection()
    assert (await without_support.reconcile_persisted_status(claim))["status"] == "not_supported"
    without_support._session.post.assert_not_called()

    conn = remote_connection(
        capabilities=["mcp_request_status_v1"],
        remote_response={
            "request_id": "wrong-id", "status": "cancelled",
            "verified": True, "stopped": True,
        },
    )
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)
    assert (await conn.reconcile_persisted_status(claim))["status"] == "unknown"
    conn._session.post.assert_called_once()

    conn._session.post.reset_mock()
    events.side_effect = [True, False]
    conn._session.post.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={
            "request_id": "req-postrestart", "status": "cancelled",
            "verified": True, "stopped": True,
        }
    )
    assert (await conn.reconcile_persisted_status(claim))["status"] == "unknown"
    assert conn._session.post.call_count == 1

    # A forged original server claim cannot use another provider connection.
    wrong_claim = dict(claim, server_id="other-provider")
    conn._session.post.reset_mock()
    assert (await conn.reconcile_persisted_status(wrong_claim))["status"] == "denied"
    conn._session.post.assert_not_called()

@pytest.mark.asyncio
async def test_tool_metadata_approval_is_rechecked_at_cancel_time():
    from ai_osop.mcp.protocol import _RemoteExecution
    conn = remote_connection(capabilities=["mcp_cancel_request_v1"])
    conn._executions["req-remote"] = _RemoteExecution(
        engagement_id="eng-live", task_id="task-allowed", tool_name="scan_target",
        parameters={"url": "https://example.com"}, requires_approval=True,
    )
    receipt = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert receipt["status"] == "denied"
    assert receipt["reason"] == "approval_required"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_event_writer_failure_blocks_tool_dispatch_before_http():
    conn = remote_connection()
    conn.set_execution_event_callback(AsyncMock(side_effect=ConnectionError("database offline")))
    response = await conn.execute(MCPExecuteRequest(
        request_id="req-live", tool_name="scan_target",
        parameters={"url": "https://example.com"},
    ))
    assert response.status == "audit_unavailable"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_durable_event_phases_for_success_and_ambiguous_transport():
    conn = remote_connection(remote_response={
        "request_id": "req-live", "status": "success", "result": {},
    })
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)
    response = await conn.execute(MCPExecuteRequest(
        request_id="req-live", tool_name="scan_target",
        parameters={"url": "https://example.com"},
    ))
    assert response.status == "success"
    assert [call.args[2] for call in events.await_args_list] == [
        "dispatch_accepted", "execution_started", "execution_finished",
    ]
    events.reset_mock()
    conn._session.post.side_effect = ConnectionError("failed after sending")
    response = await conn.execute(MCPExecuteRequest(
        request_id="req-another", tool_name="scan_target",
        parameters={"url": "https://example.com"},
    ))
    assert response.status == "unknown"
    assert events.await_args_list[-1].args[2] == "execution_unknown"


@pytest.mark.asyncio
async def test_cancel_task_execution_idempotent_control_request():
    registry = MCPRegistry()
    conn = remote_connection(capabilities=["mcp_cancel_request_v1"],
                             remote_response={"status": "cancelled", "request_id": "req-remote",
                                              "verified": True, "stopped": True})
    await known_execution(conn)
    registry._servers["scanner"] = conn
    registry.set_budget_callback(conn._budget_callback)
    receipt = await registry.cancel_task_execution("task-allowed", "eng-live", "control-one")
    assert receipt["status"] == "confirmed_stopped"
    repeated = await registry.cancel_task_execution("task-allowed", "eng-live", "control-one")
    assert repeated == receipt
    conn._session.post.assert_called_once()


@pytest.mark.asyncio
async def test_reconcile_requires_provider_capability_and_never_guesses():
    conn = await known_execution(remote_connection())
    receipt = await conn.reconcile_execution("req-remote", "eng-live", "task-allowed")
    assert receipt["status"] == "not_supported"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_provider_status_confirmed_finished_only_with_matching_verified_id():
    conn = await known_execution(remote_connection(
        capabilities=["mcp_request_status_v1"],
        remote_response={"request_id": "req-remote", "status": "completed", "verified": True},
    ))
    receipt = await conn.reconcile_execution("req-remote", "eng-live", "task-allowed")
    assert receipt["status"] == "confirmed_finished"
    assert conn._executions["req-remote"].outcome == "confirmed_finished"
    assert conn._session.post.call_args.args[0].endswith("/mcp/request/status")
    conn._session.post.reset_mock()
    stop = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert stop["status"] == "unknown"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("status,verified,request_id", [
    ("cancelled", False, "req-remote"),
    ("cancelled", True, "wrong-request"),
    ("accepted", True, "req-remote"),
])
async def test_status_reconciliation_denies_unverified_stop(status, verified, request_id):
    conn = await known_execution(remote_connection(
        capabilities=["mcp_request_status_v1"],
        remote_response={"request_id": request_id, "status": status,
                         "stopped": True, "verified": verified},
    ))
    receipt = await conn.reconcile_execution("req-remote", "eng-live", "task-allowed")
    assert receipt["status"] == "unknown"


@pytest.mark.asyncio
async def test_reconciliation_promotes_timeout_only_after_remote_stop_proof():
    conn = await known_execution(remote_connection(capabilities=[
        "mcp_cancel_request_v1", "mcp_request_status_v1",
    ], timeout=True))
    cancelled = await conn.request_cancellation("req-remote", "eng-live", "task-allowed")
    assert cancelled["status"] == "unknown"
    response = conn._session.post.return_value.__aenter__.return_value
    response.json.return_value = {
        "request_id": "req-remote", "status": "cancelled",
        "stopped": True, "verified": True,
    }
    conn._session.post.side_effect = None
    reconciled = await conn.reconcile_execution("req-remote", "eng-live", "task-allowed")
    assert reconciled["status"] == "confirmed_stopped"
    assert conn._cancel_receipts["req-remote"]["status"] == "confirmed_stopped"


@pytest.mark.asyncio
async def test_provider_status_tool_used_only_when_advertised():
    conn = await known_execution(remote_connection(
        remote_response={"status": "success", "result": {
            "request_id": "req-remote", "verified": True, "status": "running",
        }},
    ))
    conn._tools["get_request_status"] = SimpleNamespace(name="get_request_status")
    result = await conn.reconcile_execution("req-remote", "eng-live", "task-allowed")
    assert result["status"] == "running"
    assert conn._session.post.call_args.args[0].endswith("/mcp/execute")
    assert conn._session.post.call_args.kwargs["json"]["tool_name"] == "get_request_status"


@pytest.mark.asyncio
async def test_task_reconciliation_reports_mixed_provider_status_as_unknown():
    registry = MCPRegistry()
    supported = await known_execution(remote_connection(capabilities=["mcp_request_status_v1"],
                           remote_response={"request_id": "req-remote", "verified": True,
                                            "status": "completed"}))
    unsupported = await known_execution(remote_connection())
    unsupported.server_id = "other"
    registry._servers = {"scanner": supported, "other": unsupported}
    registry.set_budget_callback(supported._budget_callback)
    outcome = await registry.reconcile_task_execution("task-allowed", "eng-live", "recon-1")
    assert outcome["status"] == "unknown"
    assert {rec["status"] for rec in outcome["executions"]} == {
        "not_supported", "confirmed_finished",
    }


@pytest.mark.asyncio
async def test_temporal_cancel_only_confirms_actual_status():
    handle = SimpleNamespace(
        cancel=AsyncMock(),
        describe=AsyncMock(return_value=SimpleNamespace(
            status=SimpleNamespace(name="WORKFLOW_EXECUTION_STATUS_CANCELED"))),
    )
    client = SimpleNamespace(get_workflow_handle=MagicMock(return_value=handle))
    scheduler = TemporalTaskScheduler(client=client)
    receipt = await scheduler.cancel_task_workflow("task-allowed")
    assert receipt["status"] == "confirmed_stopped"
    assert receipt["accepted"] is True and receipt["verified"] is True
    handle.cancel.assert_awaited_once()


@pytest.mark.parametrize("mode", ["pending", "timeout", "transport-error"])
@pytest.mark.asyncio
async def test_temporal_cancel_reports_unknown_or_accepted_only(mode):
    handle = SimpleNamespace(
        cancel=AsyncMock(),
        describe=AsyncMock(return_value=SimpleNamespace(
            status=SimpleNamespace(name="WORKFLOW_EXECUTION_STATUS_RUNNING"))),
    )
    if mode == "timeout":
        handle.cancel.side_effect = asyncio.TimeoutError()
    elif mode == "transport-error":
        handle.cancel.side_effect = ConnectionError("Temporal unreachable")
    scheduler = TemporalTaskScheduler(client=SimpleNamespace(
        get_workflow_handle=MagicMock(return_value=handle),
    ))
    receipt = await scheduler.cancel_task_workflow("task-allowed")
    assert receipt["status"] == (
        "cancellation_requested" if mode == "pending" else "unknown"
    )
    assert receipt["verified"] is False
    assert receipt["accepted"] is (mode == "pending")
