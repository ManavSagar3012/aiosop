"""Real startup connects to the signed browser MCP with the operator bearer."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api import main


@pytest.mark.asyncio
async def test_browser_mcp_registration_uses_server_bearer_not_anonymous(monkeypatch):
    token = "operator-provisioned-browser-mcp-bearer"
    monkeypatch.setattr(main.settings, "browser_mcp_auth_token", token)
    registry = SimpleNamespace(
        register_server=AsyncMock(), initialize_server=AsyncMock(),
    )
    await main.register_optional_mcp_servers(registry)
    calls = [call.args for call in registry.register_server.await_args_list]
    browser = [call for call in calls if call[0] == "browser-mcp"]
    assert len(browser) == 1
    assert browser[0][3] == token
    assert any(call.args[0] == "browser-mcp" for call in registry.initialize_server.await_args_list)


def test_browser_mcp_token_can_be_injected_only_as_runtime_settings():
    from ai_osop.core.config import Settings

    value = "provisioned-runtime-token-123"
    configured = Settings(_env_file=None, OSOP_BROWSER_MCP_BEARER_TOKEN=value)
    assert configured.browser_mcp_auth_token == value
    assert value not in repr(configured)
