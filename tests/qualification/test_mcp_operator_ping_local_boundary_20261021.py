"""Owned localhost transport proofs, never real MCP targets or scanner tools."""

from unittest.mock import patch

import pytest
from aiohttp import web

from ai_osop.mcp.protocol import MCPConnection, MCPRegistry


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["example.internal", "localhost", "127.0.0.2", "[::1]"])
async def test_ping_does_not_construct_bearer_session_or_resolve_nonlocal_host(host):
    connection = MCPConnection("source-map-mcp", host, 8096, auth_token="test-only-secret")
    with patch("ai_osop.mcp.protocol.aiohttp.ClientSession") as session:
        result = await connection.ping()
    session.assert_not_called()
    assert result["status"] == "unverified_nonlocal_transport"
    assert result["runtime_health_verified"] is False
    assert result["independent_target_effect_verified"] is False
    assert "test-only-secret" not in str(result)


@pytest.mark.asyncio
async def test_ping_real_ephemeral_local_health_keeps_transport_unverified_and_does_not_touch_session():
    seen = []

    async def health(request):
        seen.append(request.headers.get("Authorization"))
        return web.json_response({"status": "healthy", "fictional_target_verified": True})

    app = web.Application()
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    try:
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        registry = MCPRegistry()
        conn = await registry.register_server("owned-inert", "127.0.0.1", port, "fixture-bearer")
        existing_session = conn._session
        result = await registry.ping_server("owned-inert")
        assert result["status"] == "healthy"
        assert result["runtime_health_verified"] is False
        assert result["current_authorized_operation_verified"] is False
        assert result["independent_target_effect_verified"] is False
        assert conn._session is existing_session
        # Registration probes once; the later explicit ping probes again.
        assert seen == ["Bearer fixture-bearer", "Bearer fixture-bearer"]
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_ping_exception_is_sanitized_and_does_not_alter_state():
    connection = MCPConnection("owned-inert", "127.0.0.1", 1, auth_token="hidden-key")
    connection._initialized = True
    result = await connection.ping()
    assert result["status"] == "unreachable"
    assert result["error"] == "MCP local diagnostic transport unavailable"
    assert "hidden-key" not in str(result)
    assert connection._initialized is True
    assert connection._session is None
