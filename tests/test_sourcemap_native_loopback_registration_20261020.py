"""Never transmit native original-source MCP bearer over unpinned remote HTTP."""

from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host", ["source-map-mcp", "192.0.2.42", "example.invalid", "0.0.0.0", "127.0.0.2"]
)
async def test_source_map_registry_refuses_remote_bearer_before_network(host):
    registry = MCPRegistry()
    with patch.object(MCPConnection, "connect", new_callable=AsyncMock) as connect:
        with pytest.raises(MCPConnectionError, match="loopback"):
            await registry.register_server("source-map-mcp", host, 8096, "secret-native-token")
        connect.assert_not_awaited()
    assert registry._servers == {}


@pytest.mark.asyncio
async def test_direct_source_map_connection_refuses_remote_before_http_session():
    connection = MCPConnection(
        "source-map-mcp", "source-map-mcp", 8096, auth_token="secret-native-token"
    )
    with patch("ai_osop.mcp.protocol.aiohttp.ClientSession") as session:
        with pytest.raises(MCPConnectionError, match="loopback"):
            await connection.connect()
        session.assert_not_called()
    assert connection._session is None


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
async def test_source_map_registry_loopback_retains_existing_registration(host):
    registry = MCPRegistry()
    with patch.object(MCPConnection, "connect", new_callable=AsyncMock) as connect:
        result = await registry.register_server("source-map-mcp", host, 8096, "secret-native-token")
    connect.assert_awaited_once()
    assert result is registry._servers["source-map-mcp"]


@pytest.mark.asyncio
async def test_other_mcp_registry_behavior_unchanged_by_sourcemap_fence():
    registry = MCPRegistry()
    with patch.object(MCPConnection, "connect", new_callable=AsyncMock) as connect:
        registered = await registry.register_server("recon-mcp", "test-recon", 8082)
    connect.assert_awaited_once()
    assert registered.server_id == "recon-mcp"
