"""Adversarial signed MCP admission races against durable callbacks.

Production MCPConnection.execute / SessionMemory signature checks are used
with deterministic in-memory authority and fake HTTP transport. No database,
MCP server, paid API or assessment target is contacted.
"""

from unittest.mock import AsyncMock

import pytest

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPExecuteRequest
from tests.test_mcp_direct_dispatch_safety import connection
from tests.test_mcp_remote_cancel_fences import _signed_memory


@pytest.fixture(autouse=True)
def _clear_request_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


def _admitted(*, approval=False):
    memory = _signed_memory()
    conn = connection(
        "scan_target",
        approval=approval,
        response={
            "request_id": "req-signed-callback-20261018",
            "status": "success",
            "result": {"synthetic": True},
        },
    )
    conn.set_budget_callback(memory.consume_mcp_tool_budget)
    RequestContext.bind(engagement_id="eng-live", task_id="task-live")
    req = MCPExecuteRequest(
        tool_name="scan_target",
        parameters={"url": "https://example.com", "options": {"mode": "read_only"}},
        request_id="req-signed-callback-20261018",
    )
    return conn, memory, req


@pytest.mark.asyncio
@pytest.mark.parametrize("event_kind", ["dispatch_accepted", "execution_started"])
@pytest.mark.parametrize(
    "revocation",
    ["task_cancelled", "signed_key_revoked", "cross_tenant_task", "engagement_halted"],
)
async def test_revocation_in_durable_callback_never_reaches_mcp_http(event_kind, revocation):
    conn, memory, request = _admitted()
    events = []

    async def callback(engagement, task, kind, metadata):
        assert (engagement, task) == ("eng-live", "task-live")
        events.append(kind)
        if kind == event_kind:
            if revocation == "task_cancelled":
                memory.load_task_authoritative.return_value.status = "cancelled"
            elif revocation == "signed_key_revoked":
                memory.assert_signed_authorization.side_effect = PermissionError(
                    "sensitive-signer-secret"
                )
            elif revocation == "cross_tenant_task":
                memory.load_task_authoritative.return_value.engagement_id = "eng-other"
            else:
                memory.load_session_state.return_value.phase = "halted"
        return True

    conn.set_execution_event_callback(callback)
    response = await conn.execute(request)
    assert response.status == "unknown"
    assert response.request_id == request.request_id
    assert "sensitive-signer-secret" not in str(response.model_dump())
    conn._session.post.assert_not_called()
    assert "dispatch_accepted" in events and "execution_started" in events
    assert "execution_unknown" in events
    assert conn._seen_request_ids[request.request_id] is False

    # An accepted durable claim may represent an unknown previous remote
    # effect and must never be retried under the same request identifier.
    again = await conn.execute(request)
    assert again.status == "duplicate_request"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_operator_approval_revoked_after_durable_claim_denies_remote_send():
    conn, memory, request = _admitted(approval=True)
    memory.load_task_authoritative.return_value.payload["approval_id"] = "apr-current"
    memory.is_task_approved.return_value = True

    async def callback(_engagement, _task, kind, _metadata):
        if kind == "execution_started":
            memory.is_task_approved.return_value = False
        return True

    conn.set_execution_event_callback(callback)
    denied = await conn.execute(request)
    assert denied.status == "unknown"
    assert memory.is_task_approved.await_count == 2
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_signed_callback_store_outage_never_sends_remote_tool():
    conn, memory, request = _admitted()
    events = AsyncMock(side_effect=[True, False, True])
    conn.set_execution_event_callback(events)
    result = await conn.execute(request)
    assert result.status == "audit_unavailable"
    assert memory.load_task_authoritative.await_count == 1
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_approved_command_and_request_identity_cannot_change_during_callback():
    conn, memory, request = _admitted()
    original = request.model_dump()

    async def mutate_caller_request(_engagement, _task, kind, _metadata):
        if kind == "dispatch_accepted":
            request.tool_name = "unauthorized_tool"
            request.parameters["url"] = "https://foreign.invalid/secret"
            request.request_id = "req-stolen-foreign"
        return True

    conn.set_execution_event_callback(mutate_caller_request)
    completed = await conn.execute(request)
    assert completed.status == "success"
    assert completed.request_id == original["request_id"]
    payload = conn._session.post.call_args.kwargs["json"]
    assert payload["tool_name"] == original["tool_name"]
    assert payload["parameters"] == original["parameters"]
    assert payload["request_id"] == original["request_id"]
    assert "foreign.invalid" not in str(payload)
    assert memory.load_task_authoritative.await_count == 2


@pytest.mark.asyncio
async def test_runtime_callback_rotation_denies_send_after_signed_claim():
    conn, _, request = _admitted()

    async def replace_writer(_engagement, _task, kind, _metadata):
        if kind == "execution_started":
            conn.set_execution_event_callback(AsyncMock(return_value=True))
        return True

    conn.set_execution_event_callback(replace_writer)
    response = await conn.execute(request)
    assert response.status == "unknown"
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_current_signed_task_rechecked_after_callback_without_second_budget_charge():
    conn, memory, request = _admitted()
    memory.load_session_state.return_value.roe = {"tool_call_budget_total": 3}
    redis = AsyncMock()
    redis.eval.return_value = 1
    memory._ensure_redis = AsyncMock(return_value=redis)
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)

    result = await conn.execute(request)
    assert result.status == "success"
    assert conn._session.post.call_count == 1
    assert memory.load_task_authoritative.await_count == 2
    redis.eval.assert_awaited_once()
    assert events.await_count == 3
    assert [call.args[2] for call in events.await_args_list] == [
        "dispatch_accepted",
        "execution_started",
        "execution_finished",
    ]
