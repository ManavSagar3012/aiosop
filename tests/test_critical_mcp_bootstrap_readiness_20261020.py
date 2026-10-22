"""Critical MCP startup records real initialization and never grants scanners.

Only inert registry doubles execute. No target, provider, application database,
socket or native scanner is contacted by these bootstrap regression tests.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from ai_osop.api import main
from ai_osop.api.deps import state
from ai_osop.mcp.protocol import MCPInitializeResponse, MCPToolDefinition, SideEffectClass

CRITICAL = {
    "browser-mcp",
    "nuclei-mcp",
    "source-map-mcp",
    "cloud-mcp",
    "turbo-intruder-mcp",
}
ALL = {
    "burp-mcp",
    "recon-mcp",
    "payload-mcp",
    "nuclei-mcp",
    "shodan-mcp",
    "browser-mcp",
    "security-bridge",
    "threat-intel-mcp",
    "source-map-mcp",
    "cloud-mcp",
    "turbo-intruder-mcp",
}


def _declaration(
    server_id: str, *, status: str = "ready", tool_count: int = 1
) -> MCPInitializeResponse:
    return MCPInitializeResponse(
        server_id=server_id,
        version="1.0.0",
        status=status,
        capabilities=["inert_readiness_fixture"],
        tools=[
            MCPToolDefinition(
                name=f"inert_status_{index}",
                description="Only inert fixture: no execution permitted",
                parameters=[],
                returns={"type": "object"},
                side_effect_class=SideEffectClass.READ_ONLY,
                requires_approval=True,
                scope_check=True,
            )
            for index in range(tool_count)
        ],
    )


class InertRegistry:
    """Separates transport registration from source declaration readiness."""

    def __init__(self, *, mode: dict[str, str] | None = None):
        self.mode = mode or {}
        self._servers: dict[str, Any] = {}
        self.register_calls: list[tuple[str, str, int, Any]] = []
        self.init_calls: list[tuple[str, dict, dict, str]] = []
        self.executions: list[str] = []

    async def register_server(self, server_id: str, host: str, port: int, token: Any = None) -> Any:
        self.register_calls.append((server_id, host, port, token))
        if self.mode.get(server_id) == "register_failed":
            raise OSError("PRIVATE-TOKEN: provider connection refused")
        conn = SimpleNamespace(
            server_id=server_id,
            _initialized=False,
            _session=object(),
        )
        self._servers[server_id] = conn
        return conn

    async def initialize_server(
        self,
        server_id: str,
        scope: dict[str, Any],
        credentials: dict[str, Any],
        session_id: str,
    ) -> Any:
        self.init_calls.append((server_id, scope, credentials, session_id))
        mode = self.mode.get(server_id, "ready")
        if mode == "initialize_failed":
            raise RuntimeError("PRIVATE-TOKEN: remote initialization failed")
        if mode == "not_initialized":
            return _declaration(server_id)
        conn = self._servers[server_id]
        conn._initialized = True
        if mode == "missing_session":
            conn._session = None
        if mode == "wrong_server":
            return _declaration("foreign-mcp")
        if mode == "empty_tools":
            return _declaration(server_id, tool_count=0)
        if mode == "unavailable":
            return _declaration(server_id, status="unavailable")
        if mode == "malformed":
            return {"server_id": server_id, "status": "ready"}
        return _declaration(server_id)


@pytest.mark.asyncio
async def test_all_eleven_initialized_without_claiming_any_target_effect(monkeypatch):
    monkeypatch.setattr(main.settings, "environment", "development")
    registry = InertRegistry()
    statuses = await main.register_optional_mcp_servers(registry)
    assert set(statuses) == ALL
    assert {server_id for server_id, value in statuses.items() if value["critical"]} == CRITICAL
    assert {call[0] for call in registry.register_calls} == ALL
    assert {call[0] for call in registry.init_calls} == ALL
    assert all(call[1:] == ({}, {}, "api-bootstrap") for call in registry.init_calls)
    for server_id in CRITICAL:
        assert statuses[server_id] == {
            "critical": True,
            "registered": True,
            "initialized": True,
            "status": "initialized",
            "runtime_health_verified": False,
        }
    for server_id in ALL - CRITICAL:
        assert statuses[server_id] == {
            "critical": False,
            "registered": True,
            "initialized": True,
            "status": "initialized",
            "runtime_health_verified": False,
        }
    assert registry.executions == []


@pytest.mark.asyncio
async def test_source_map_cloud_and_turbo_truthful_unavailable_remain_unready(monkeypatch, caplog):
    monkeypatch.setattr(main.settings, "environment", "development")
    registry = InertRegistry(
        mode={
            "source-map-mcp": "unavailable",
            "cloud-mcp": "initialize_failed",
            "turbo-intruder-mcp": "register_failed",
        }
    )
    health = {"browser-mcp": "unknown", "redis": "healthy"}
    before = state.get("mcp_bootstrap_readiness")
    try:
        await main._bootstrap_mcp_readiness(registry, health)
        assert health["redis"] == "healthy"
        assert health["browser-mcp"] == "initialized"
        assert health["nuclei-mcp"] == "initialized"
        for server_id in ("source-map-mcp", "cloud-mcp", "turbo-intruder-mcp"):
            item = state["mcp_bootstrap_readiness"][server_id]
            assert item["initialized"] is False
            assert item["status"] == "unavailable"
            assert health[server_id] == "unavailable"
        assert state["mcp_bootstrap_readiness"]["source-map-mcp"]["registered"] is True
        assert state["mcp_bootstrap_readiness"]["cloud-mcp"]["registered"] is True
        assert state["mcp_bootstrap_readiness"]["turbo-intruder-mcp"]["registered"] is False
        assert registry.executions == []
        assert "PRIVATE-TOKEN" not in caplog.text
        assert "PRIVATE-TOKEN" not in str(state["mcp_bootstrap_readiness"])
    finally:
        if before is None:
            state.pop("mcp_bootstrap_readiness", None)
        else:
            state["mcp_bootstrap_readiness"] = before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_mode",
    [
        "not_initialized",
        "missing_session",
        "wrong_server",
        "empty_tools",
        "malformed",
        "unavailable",
    ],
)
async def test_trusted_ready_response_alone_does_not_mark_an_unready_connection_initialized(
    monkeypatch, bad_mode
):
    monkeypatch.setattr(main.settings, "environment", "development")
    registry = InertRegistry(mode={"browser-mcp": bad_mode})
    result = await main.register_optional_mcp_servers(registry)
    assert result["browser-mcp"] == {
        "critical": True,
        "registered": True,
        "initialized": False,
        "status": "unavailable",
        "runtime_health_verified": False,
    }
    assert result["source-map-mcp"]["status"] == "initialized"


@pytest.mark.asyncio
@pytest.mark.parametrize("environment", ["production", "prod"])
async def test_production_refuses_partial_critical_bootstrap_and_publishes_no_false_health(
    monkeypatch, environment
):
    monkeypatch.setattr(main.settings, "environment", environment)
    registry = InertRegistry(mode={"source-map-mcp": "unavailable"})
    health = {"browser-mcp": "unknown"}
    before = state.get("mcp_bootstrap_readiness")
    try:
        with pytest.raises(RuntimeError, match="Required critical MCP initialization unavailable"):
            await main._bootstrap_mcp_readiness(registry, health)
        assert {call[0] for call in registry.init_calls} == ALL
        assert health["browser-mcp"] == "initialized"
        assert health["source-map-mcp"] == "unavailable"
        assert state["mcp_bootstrap_readiness"]["source-map-mcp"]["initialized"] is False
        assert not any(value == "healthy" for key, value in health.items() if key in CRITICAL)
    finally:
        if before is None:
            state.pop("mcp_bootstrap_readiness", None)
        else:
            state["mcp_bootstrap_readiness"] = before


@pytest.mark.asyncio
async def test_strict_production_ignores_optional_missing_if_critical_are_initialized(monkeypatch):
    monkeypatch.setattr(main.settings, "environment", "production")
    registry = InertRegistry(mode={"burp-mcp": "register_failed", "payload-mcp": "register_failed"})
    result = await main.register_optional_mcp_servers(registry)
    assert result["burp-mcp"]["status"] == "unavailable"
    assert result["payload-mcp"]["status"] == "unavailable"
    assert all(result[service]["status"] == "initialized" for service in CRITICAL)
