import pytest
from unittest.mock import AsyncMock, patch

from ai_osop.mcp.protocol import (
    MCPConnection,
    MCPRegistry,
    MCPToolDefinition,
    SideEffectClass,
)


@pytest.mark.asyncio
async def test_mcp_connection_manifests_and_circuit_reset():
    conn = MCPConnection(server_id="test-mcp", host="127.0.0.1", port=8080)
    tool1 = MCPToolDefinition(
        name="test_read_only",
        description="Read only tool",
        parameters=[],
        returns={},
        side_effect_class=SideEffectClass.READ_ONLY,
        version="1.2.0",
        required_permissions=["read:scope"],
    )
    tool2 = MCPToolDefinition(
        name="test_exploit",
        description="Invasive exploit tool",
        parameters=[],
        returns={},
        side_effect_class=SideEffectClass.INVASIVE_EXPLOIT,
        version="2.0.0",
        required_permissions=["exploit:exec"],
    )
    conn._tools = {"test_read_only": tool1, "test_exploit": tool2}

    manifests = conn.get_manifests()
    assert len(manifests) == 2
    assert manifests[0].tool_name == "test_read_only"
    assert manifests[0].side_effect_class == SideEffectClass.READ_ONLY
    assert manifests[0].version == "1.2.0"
    assert manifests[1].tool_name == "test_exploit"
    assert manifests[1].side_effect_class == SideEffectClass.INVASIVE_EXPLOIT

    # Test circuit state trip and reset
    conn._circuit_open = True
    conn._failure_count = 5
    assert conn.get_circuit_state() == "open"

    conn.reset_circuit()
    assert conn.get_circuit_state() == "closed"
    assert conn._failure_count == 0


@pytest.mark.asyncio
async def test_mcp_registry_ping_and_lifecycle():
    registry = MCPRegistry()
    conn = MCPConnection(server_id="scanner-mcp", host="127.0.0.1", port=8081)
    tool = MCPToolDefinition(
        name="scan",
        description="Active recon scan",
        parameters=[],
        returns={},
        side_effect_class=SideEffectClass.RECON_ACTIVE,
    )
    conn._tools = {"scan": tool}
    registry._servers["scanner-mcp"] = conn

    # Check manifest queries
    manifests = registry.get_server_manifests("scanner-mcp")
    assert len(manifests) == 1
    assert manifests[0].side_effect_class == SideEffectClass.RECON_ACTIVE

    all_manifests = registry.get_all_manifests()
    assert "scanner-mcp" in all_manifests

    # Check circuit status
    circuit_status = registry.get_server_circuit_status("scanner-mcp")
    assert circuit_status is not None
    assert circuit_status["circuit_state"] == "closed"
    assert circuit_status["failure_count"] == 0

    # Trip circuit on conn and reset via registry
    conn._circuit_open = True
    assert registry.get_server_circuit_status("scanner-mcp")["circuit_state"] == "open"

    assert registry.reset_circuit("scanner-mcp") is True
    assert registry.get_server_circuit_status("scanner-mcp")["circuit_state"] == "closed"
    assert registry.reset_circuit("unknown-server") is False

    # Ping mock
    with patch.object(
        conn,
        "ping",
        new=AsyncMock(
            return_value={"server_id": "scanner-mcp", "status": "healthy", "latency_ms": 15}
        ),
    ):
        ping_res = await registry.ping_server("scanner-mcp")
        assert ping_res["status"] == "healthy"
        assert ping_res["latency_ms"] == 15
