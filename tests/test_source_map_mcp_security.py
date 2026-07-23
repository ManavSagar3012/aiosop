"""Security contracts for the standalone source-map MCP server."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.core.models import ScopeDefinition
from ai_osop.safety.scope import ScopeEnforcer


def _load_server() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "mcp-servers" / "python" / "source_map_mcp.py"
    spec = importlib.util.spec_from_file_location("source_map_mcp_security_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def source_map_server(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    server = _load_server()
    monkeypatch.setattr(server.settings, "api_token", "test-mcp-token")
    return server


def _scope() -> ScopeEnforcer:
    return ScopeEnforcer(
        ScopeDefinition(engagement_id="eng-source-map", domains=["allowed.test"], ips=[])
    )


@pytest.mark.asyncio
async def test_bootstrap_session_cannot_bypass_scope(
    source_map_server: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_map_server.app.state.scope_enforcer = _scope()
    source_map_server.app.state.session_id = "api-bootstrap"
    analyze = AsyncMock(return_value={"sources": [], "secrets": []})
    monkeypatch.setattr(source_map_server, "analyze_sourcemap", analyze)

    response = await source_map_server.mcp_execute(
        source_map_server.MCPExecuteRequest(
            tool_name="fetch_and_parse_sourcemap",
            parameters={"url": "https://outside.test/app.js"},
            request_id="req-bootstrap-bypass",
        ),
        authenticated=None,
    )

    assert response["status"] == "error"
    assert "Out of scope" in response["error"]
    analyze.assert_not_awaited()


@pytest.mark.asyncio
async def test_execute_requires_initialized_scope(source_map_server: ModuleType) -> None:
    if hasattr(source_map_server.app.state, "scope_enforcer"):
        del source_map_server.app.state.scope_enforcer

    response = await source_map_server.mcp_execute(
        source_map_server.MCPExecuteRequest(
            tool_name="fetch_and_parse_sourcemap",
            parameters={"url": "https://allowed.test/app.js"},
            request_id="req-no-scope",
        ),
        authenticated=None,
    )

    assert response == {
        "request_id": "req-no-scope",
        "status": "error",
        "error": "MCP scope has not been initialized",
    }


@pytest.mark.asyncio
async def test_initialize_requires_valid_scope(source_map_server: ModuleType) -> None:
    with pytest.raises(HTTPException) as exc_info:
        await source_map_server.mcp_initialize(
            source_map_server.MCPInitializeRequest(), authenticated=None
        )

    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_authentication_configuration_fails_closed(
    source_map_server: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source_map_server.settings, "api_token", None)
    monkeypatch.delenv("OSOP_API_TOKEN", raising=False)

    with pytest.raises(HTTPException) as exc_info:
        await source_map_server.verify_mcp_token(None)

    assert exc_info.value.status_code == 503
