"""Native SourceMap credentials must never be sent through hostname resolution."""

import pytest

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.core.config import Settings
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry


def test_source_map_native_default_host_is_numeric_loopback() -> None:
    assert Settings.model_fields["source_map_mcp_host"].default == "127.0.0.1"


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "LOCALHOST", "127.0.0.2", "::1", "example.test"])
async def test_source_map_registry_denies_non_pinned_host_before_transport(host: str) -> None:
    registry = MCPRegistry()
    with pytest.raises(MCPConnectionError, match="loopback"):
        await registry.register_server("source-map-mcp", host, 8096, "secret-bearer")
    assert not registry._servers


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "LOCALHOST", "127.0.0.2", "::1", "example.test"])
async def test_source_map_direct_connection_denies_before_session(host: str) -> None:
    conn = MCPConnection("source-map-mcp", host, 8096, "secret-bearer")
    with pytest.raises(MCPConnectionError, match="loopback"):
        await conn.connect()
    assert conn._session is None
