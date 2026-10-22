"""Original loopback control HTTP cannot smuggle unbounded/ambiguous MCP JSON.

These are local, inert providers. No original tool is dispatched or target
contacted, and a provider HTTP 200 never proves a target-owned effect.
"""

from unittest.mock import AsyncMock, patch

import aiohttp
import pytest
from aiohttp import web

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.mcp.protocol import MCPConnection, MCPInitializeRequest


@pytest.fixture
async def inert_server():
    state = {"body": b"{}", "hits": []}

    async def reply(request):
        state["hits"].append((request.method, request.path))
        return web.Response(body=state["body"], content_type="application/json")

    app = web.Application()
    for path in ("/mcp/initialize", "/mcp/cancel", "/mcp/request/status"):
        app.router.add_post(path, reply)
    app.router.add_get("/mcp/state", reply)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield state, site._server.sockets[0].getsockname()[1]
    finally:
        await runner.cleanup()


_BAD_ENTITIES = {
    "duplicate": b'{"status":"completed","status":"running","verified":true}',
    "nonfinite": b'{"status":"completed","verified":NaN}',
    "overflow": b'{"status":"completed","value":1e9999}',
    "deep": b'{"value":' + b"[" * 30 + b"0" + b"]" * 30 + b"}",
    "oversized": b'{"data":"' + b"x" * (2 * 1024 * 1024) + b'"}',
}


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", sorted(_BAD_ENTITIES))
async def test_original_initialize_stream_denies_ambiguous_or_oversized_manifest(inert_server, bad):
    state, port = inert_server
    state["body"] = _BAD_ENTITIES[bad]
    conn = MCPConnection("inert-server", "127.0.0.1", port)
    async with aiohttp.ClientSession() as session:
        conn._session = session
        # Simulate a previously negotiated manifest. Failed renegotiation
        # must remove it before awaiting untrusted provider response bytes.
        conn._initialized = True
        conn._tools = {"old": object()}
        with pytest.raises(MCPConnectionError):
            await conn.initialize(MCPInitializeRequest(scope={}, session_id="api-bootstrap"))
        assert conn._initialized is False
        assert conn._tools == {}
        assert state["hits"] == [("POST", "/mcp/initialize")]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", sorted(_BAD_ENTITIES))
async def test_original_state_read_denies_ambiguous_or_oversized_json(inert_server, bad):
    state, port = inert_server
    state["body"] = _BAD_ENTITIES[bad]
    conn = MCPConnection("inert-server", "127.0.0.1", port)
    async with aiohttp.ClientSession() as session:
        conn._session = session
        with pytest.raises(ValueError):
            await conn.get_state()
        assert state["hits"] == [("GET", "/mcp/state")]


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", sorted(_BAD_ENTITIES))
@pytest.mark.parametrize("operation", ["reconcile", "stop"])
async def test_original_persisted_control_http200_never_confirms_bad_provider_json(
    inert_server, bad, operation
):
    state, port = inert_server
    state["body"] = _BAD_ENTITIES[bad]
    conn = MCPConnection("inert-server", "127.0.0.1", port)
    conn._capabilities = [
        "mcp_request_status_v1" if operation == "reconcile" else "mcp_cancel_request_v1"
    ]
    events = AsyncMock(return_value=True)
    conn.set_execution_event_callback(events)
    claim = {
        "server_id": "inert-server",
        "engagement_id": "eng-local",
        "task_id": "task-local",
        "request_id": "req-once",
        "authorization_version": 1,
        "status": "outcome_unknown" if operation == "reconcile" else "cancel_requested",
        "tool_name": "inert_metadata",
    }
    # Trusted current signed-authority callback is independent from the
    # untrusted local provider. This test covers its response parsing only.
    with patch(
        "ai_osop.mcp.protocol.check_persisted_reconciliation_authorization",
        new=AsyncMock(return_value=None),
    ):
        async with aiohttp.ClientSession() as session:
            conn._session = session
            if operation == "reconcile":
                result = await conn.reconcile_persisted_status(claim)
            else:
                result = await conn.cancel_persisted_execution(claim)
    assert result["status"] == "unknown"
    assert state["hits"] == [
        ("POST", "/mcp/request/status" if operation == "reconcile" else "/mcp/cancel")
    ]
    assert events.await_count == 2 if operation == "reconcile" else events.await_count == 1
    assert events.await_args.args[3]["status"] == "unknown"
