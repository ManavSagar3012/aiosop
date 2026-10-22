"""All credential-bearing MCP plain-HTTP adapters deny nonnumeric destinations.

No external DNS/network request is made. Real positive test owns an ephemeral
127.0.0.1 HTTP fixture; a handshake is never original Task/target authority.
"""

from unittest.mock import patch

import pytest
from aiohttp import web

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.mcp.protocol import MCPConnection, MCPInitializeRequest, MCPRegistry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server",
    ["burp-mcp", "shodan-mcp", "browser-mcp", "cloud-mcp", "source-map-mcp", "recon-mcp"],
)
@pytest.mark.parametrize("host", ["localhost", "operator-internal.example", "127.0.0.2", "::1"])
async def test_registry_and_direct_credentials_refuse_dns_or_remote_http_before_sending(
    server: str, host: str
) -> None:
    registry = MCPRegistry()
    with patch("ai_osop.mcp.protocol.aiohttp.ClientSession") as session:
        with pytest.raises(MCPConnectionError):
            await registry.register_server(server, host, 18090, "not-a-real-secret")
        session.assert_not_called()
        connection = MCPConnection(server, host, 18090, "not-a-real-secret")
        with pytest.raises(MCPConnectionError):
            await connection.connect()
        session.assert_not_called()
    assert not registry._servers
    assert connection._session is None
    assert connection._initialized is False


@pytest.mark.asyncio
async def test_real_local_server_still_accepts_bearer_for_handshake_only() -> None:
    recorded = []

    async def health(request: web.Request) -> web.Response:
        recorded.append((request.path, request.headers.get("Authorization")))
        return web.json_response({"status": "healthy", "effect_verified": True})

    app = web.Application()
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    registry = MCPRegistry()
    try:
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        connection = await registry.register_server(
            "browser-mcp", "127.0.0.1", port, "owned-fixture"
        )
        assert recorded == [("/health", "Bearer owned-fixture")]
        assert connection._session is not None
        assert connection._initialized is False
        assert connection._tools == {}
    finally:
        await registry.close_all()
        await runner.cleanup()


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "remote-mcp.example", "127.0.0.2"])
async def test_json_only_credentials_do_not_escape_via_remote_mcp_initialize(host: str) -> None:
    conn = MCPConnection("burp-mcp", host, 18090)
    conn._initialized = True
    with patch("ai_osop.mcp.protocol.aiohttp.ClientSession") as session:
        with pytest.raises(MCPConnectionError, match="numeric loopback"):
            await conn.initialize(
                MCPInitializeRequest(
                    scope={},
                    auth_credentials={"secret_label": "fixture-only"},
                    session_id="fixture",
                )
            )
        session.assert_not_called()
    assert conn._initialized is False
    assert conn._tools == {}
