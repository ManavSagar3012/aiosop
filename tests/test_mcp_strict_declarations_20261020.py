"""Real ephemeral HTTP negotiation rejects implicit READ_ONLY and stale catalogs."""

from copy import deepcopy

import pytest
from aiohttp import web

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.mcp.protocol import MCPConnection, MCPInitializeRequest


SERVER = "inert-mcp-negotiation"
TOOL = {
    "name": "inspect_metadata",
    "description": "Local synthetic metadata only",
    "parameters": [],
    "returns": {},
    "side_effect_class": "READ_ONLY",
    "requires_approval": False,
    "scope_check": True,
}


@pytest.fixture
async def server():
    payload = {
        "server_id": SERVER,
        "version": "1.0.0",
        "status": "ready",
        "capabilities": ["tools"],
        "tools": [deepcopy(TOOL)],
    }
    state = {"payload": payload, "http_status": 200, "initialized": 0, "executed": 0}

    async def health(request):
        return web.json_response({"status": "ready", "server_id": SERVER})

    async def initialize(request):
        state["initialized"] += 1
        return web.json_response(state["payload"], status=state["http_status"])

    async def execute(request):
        state["executed"] += 1
        return web.json_response({"status": "error", "request_id": "no-execution"})

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/mcp/initialize", initialize)
    app.router.add_post("/mcp/execute", execute)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield state, port
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "missing_effect",
        "missing_scope",
        "missing_approval",
        "unscoped",
        "active_no_human",
        "invasive_no_human",
        "duplicate",
        "foreign_id",
        "unready",
        "http500",
    ],
)
async def test_untrusted_native_negotiation_never_enables_tools(server, fault):
    state, port = server
    declaration = state["payload"]
    tool = declaration["tools"][0]
    if fault == "missing_effect":
        tool.pop("side_effect_class")
    elif fault == "missing_scope":
        tool.pop("scope_check")
    elif fault == "missing_approval":
        tool.pop("requires_approval")
    elif fault == "unscoped":
        tool["scope_check"] = False
    elif fault == "active_no_human":
        tool["side_effect_class"] = "RECON_ACTIVE"
    elif fault == "invasive_no_human":
        tool["side_effect_class"] = "INVASIVE_EXPLOIT"
    elif fault == "duplicate":
        declaration["tools"].append(deepcopy(tool))
    elif fault == "foreign_id":
        declaration["server_id"] = "foreign-mcp"
    elif fault == "unready":
        declaration["status"] = "unavailable"
    else:
        state["http_status"] = 500
    conn = MCPConnection(SERVER, "127.0.0.1", port)
    try:
        await conn.connect()
        with pytest.raises(MCPConnectionError):
            await conn.initialize(MCPInitializeRequest(scope={}, session_id="api-bootstrap"))
        assert conn._initialized is False
        assert not conn._tools
        assert state["executed"] == 0
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_good_inert_manifest_then_failed_renegotiation_revokes_old_catalog(server):
    state, port = server
    conn = MCPConnection(SERVER, "127.0.0.1", port)
    try:
        await conn.connect()
        req = MCPInitializeRequest(scope={}, session_id="api-bootstrap")
        first = await conn.initialize(req)
        assert first.status == "ready"
        assert list(conn._tools) == ["inspect_metadata"]
        state["payload"]["tools"][0].pop("side_effect_class")
        with pytest.raises(MCPConnectionError):
            await conn.initialize(req)
        assert conn._initialized is False
        assert not conn._tools
        assert state["initialized"] == 2
        assert state["executed"] == 0
    finally:
        await conn.close()
