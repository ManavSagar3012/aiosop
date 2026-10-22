"""Engagement-scoped MCP budget gate; no Redis, sockets or live tool execution."""

import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest, MCPRegistry
from ai_osop.mcp.tool_budget import check_tool_budget


@pytest.fixture(autouse=True)
def clear_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


def mock_connection(server_id="scanner", name="get_status"):
    conn = MCPConnection(server_id=server_id, host="localhost", port=8080)
    conn._initialized = True
    conn._tools[name] = SimpleNamespace(timeout_seconds=5)
    answer = SimpleNamespace(
        status=200,
        json=AsyncMock(
            return_value={
                "request_id": "req-mocked",
                "status": "success",
                "result": {"status": "mocked-only"},
            }
        )
    )
    http_context = MagicMock()
    http_context.__aenter__ = AsyncMock(return_value=answer)
    http_context.__aexit__ = AsyncMock(return_value=False)
    conn._session = SimpleNamespace(post=MagicMock(return_value=http_context))
    return conn


def req(tool_name="get_status"):
    return MCPExecuteRequest(tool_name=tool_name, parameters={"sensitive": "DO_NOT_RECORD"})


@pytest.mark.asyncio
async def test_unconfigured_registry_keeps_original_unlimited_behavior():
    conn = mock_connection()
    registry = MCPRegistry()
    registry._servers[conn.server_id] = conn
    RequestContext.bind(engagement_id="eng-one")

    for _ in range(3):
        response = await registry.execute_tool("scanner", "get_status", {"secret": "DO_NOT_RECORD"})
        assert response.status == "success"
    assert conn._session.post.call_count == 3
    assert conn._budget_callback is None


@pytest.mark.asyncio
async def test_callback_meters_only_once_and_rejects_exhausted_call_before_http():
    RequestContext.bind(engagement_id="eng-one", task_id="task-1")
    spent = 0

    async def consume(engagement_id, tool_name, agent_id=None):
        nonlocal spent
        assert (engagement_id, tool_name, agent_id) == (
            "eng-one",
            "scanner.get_status",
            "agent-unspecified",
        )
        if spent >= 2:
            return False
        spent += 1
        return True

    callback = AsyncMock(side_effect=consume)
    conn = mock_connection()
    registry = MCPRegistry()
    registry._servers["scanner"] = conn
    registry.set_budget_callback(callback)
    assert (await registry.execute_tool("scanner", "get_status", {})).status == "success"
    assert (await registry.execute_tool("scanner", "get_status", {})).status == "success"
    blocked = await registry.execute_tool("scanner", "get_status", {})

    assert blocked.status == "quota_exceeded"
    assert "budget exhausted" in (blocked.error or "").lower()
    assert conn._session.post.call_count == 2
    assert callback.await_count == 3
    assert spent == 2
    # Client-side quota denials must not degrade remote server circuit health.
    assert conn._failure_count == 0


@pytest.mark.asyncio
async def test_async_request_context_keeps_independent_engagement_quotas():
    counters = {}
    lock = asyncio.Lock()

    async def consume(engagement_id, tool_name, agent_id=None):
        assert tool_name == "scanner.get_status"
        async with lock:
            used = counters.get(engagement_id, 0)
            if used >= 1:
                return False
            counters[engagement_id] = used + 1
            return True

    conn = mock_connection()
    conn.set_budget_callback(AsyncMock(side_effect=consume))

    async def call_as(engagement_id):
        RequestContext.bind(engagement_id=engagement_id)
        return (await conn.execute(req())).status

    outcomes = await asyncio.gather(
        call_as("eng-a"),
        call_as("eng-b"),
        call_as("eng-a"),
        call_as("eng-b"),
    )
    assert outcomes == ["success", "success", "quota_exceeded", "quota_exceeded"]
    assert counters == {"eng-a": 1, "eng-b": 1}
    assert conn._session.post.call_count == 2


@pytest.mark.asyncio
async def test_callback_error_is_fail_closed_and_never_leaks_secrets():
    RequestContext.bind(engagement_id="eng-one")
    conn = mock_connection()
    conn.set_budget_callback(AsyncMock(side_effect=RuntimeError("DO_NOT_LEAK_REDIS_URL")))
    denied = await conn.execute(req())
    assert denied.status == "quota_unavailable"
    assert "DO_NOT_LEAK" not in (denied.error or "")
    conn._session.post.assert_not_called()
    assert conn._failure_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, "true", 1, [], {}])
async def test_invalid_callback_return_is_fail_closed(outcome):
    RequestContext.bind(engagement_id="eng-one")
    conn = mock_connection()
    callback = AsyncMock(return_value=outcome)
    conn.set_budget_callback(callback)
    response = await conn.execute(req())
    assert response.status == "quota_unavailable"
    conn._session.post.assert_not_called()
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_callback_timeout_blocks_tool_and_does_not_retry():
    RequestContext.bind(engagement_id="eng-one")
    conn = mock_connection()
    callback = AsyncMock(side_effect=asyncio.TimeoutError())
    conn.set_budget_callback(callback)
    response = await conn.execute(req())
    assert response.status == "quota_unavailable"
    callback.assert_awaited_once()
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_without_engagement_and_bootstrap_active_scan_fail_closed():
    conn = mock_connection(name="scan")
    callback = AsyncMock(return_value=False)
    conn.set_budget_callback(callback)
    missing = await conn.execute(req("scan"))
    assert missing.status == "scope_denied"
    callback.assert_not_called()
    conn._session.post.assert_not_called()

    RequestContext.bind(engagement_id="api-bootstrap")
    response = await conn.execute(req("scan"))
    assert response.status == "scope_denied"
    callback.assert_not_called()
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_direct_connection_provenance_stays_enabled_on_quota_denial():
    RequestContext.bind(engagement_id="eng-a", task_id="task-a")
    provenance = AsyncMock()
    callback = AsyncMock(return_value=False)
    conn = mock_connection()
    conn.set_provenance_callback(provenance)
    conn.set_budget_callback(callback)

    denied = await conn.execute(req())
    await conn._provenance_recorder.drain()
    assert denied.status == "quota_exceeded"
    record = provenance.await_args.args[0]
    assert record["engagement_id"] == "eng-a"
    assert record["task_id"] == "task-a"
    assert record["outcome"] == "error"
    assert record["safe_metadata"]["error_class"] == "QuotaExceeded"
    assert "DO_NOT_RECORD" not in str(record)
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_registry_plumbs_callback_to_existing_future_and_direct_connections():
    callback = AsyncMock(return_value=False)
    registry = MCPRegistry()
    before = mock_connection("before")
    registry._servers["before"] = before
    registry.set_budget_callback(callback)
    assert before._budget_callback is callback

    # Registering a future server may perform a health check, never tool execute.
    with patch.object(MCPConnection, "connect", new_callable=AsyncMock):
        after = await registry.register_server("after", "localhost", 8081)
    assert after._budget_callback is callback
    assert after._session is None
    registry.set_budget_callback(None)
    assert registry._budget_callback is None
    assert before._budget_callback is None
    assert after._budget_callback is None

    RequestContext.bind(engagement_id="eng-one")
    response = await before.execute(req())
    assert response.status == "success"
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_broadcast_uses_same_gate_for_each_server_with_qualified_tool_name():
    RequestContext.bind(engagement_id="eng-broadcast")
    callback = AsyncMock(return_value=False)
    registry = MCPRegistry()
    one = mock_connection(server_id="one")
    two = mock_connection(server_id="two")
    registry._servers.update({"one": one, "two": two})
    registry.set_budget_callback(callback)

    responses = await registry.broadcast_execute("get_status", {"secret": "DO_NOT_RECORD"})
    assert {k: v.status for k, v in responses.items()} == {
        "one": "quota_exceeded",
        "two": "quota_exceeded",
    }
    assert callback.await_count == 2
    assert [call.args[1] for call in callback.await_args_list] == ["one.get_status", "two.get_status"]
    one._session.post.assert_not_called()
    two._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_circuit_open_or_unknown_tool_does_not_consume_budget():
    RequestContext.bind(engagement_id="eng-one")
    callback = AsyncMock(return_value=True)
    conn = mock_connection()
    conn.set_budget_callback(callback)
    conn._circuit_open = True
    conn._circuit_opened_at = datetime.utcnow()
    response = await conn.execute(req())
    assert response.status == "circuit_open"
    callback.assert_not_awaited()

    conn._circuit_open = False
    with pytest.raises(Exception, match="not available"):
        await conn.execute(req("not-registered"))
    callback.assert_not_awaited()
    conn._session.post.assert_not_called()


@pytest.mark.asyncio
async def test_explicit_agent_id_is_forwarded_unchanged():
    callback = AsyncMock(return_value=True)
    assert (
        await check_tool_budget(
            callback, "a", "scan", {"engagement_id": "eng-a", "agent_id": "agent-one"}
        )
        is None
    )
    callback.assert_awaited_once_with("eng-a", "a.scan", "agent-one")


@pytest.mark.asyncio
async def test_callback_cancellation_is_propagated_without_http_call():
    RequestContext.bind(engagement_id="eng-one")
    conn = mock_connection()
    conn.set_budget_callback(AsyncMock(side_effect=asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        await conn.execute(req())
    conn._session.post.assert_not_called()
