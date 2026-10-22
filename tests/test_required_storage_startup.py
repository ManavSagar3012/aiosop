"""API startup must fail closed when required persistence cannot initialize."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.api.main import app, lifespan


@pytest.mark.asyncio
async def test_database_or_migration_failure_blocks_api_startup():
    with (
        patch("ai_osop.api.main.SessionMemory"),
        patch("ai_osop.api.main.GraphMemory"),
        patch("ai_osop.api.main.VectorMemory"),
        patch("ai_osop.api.main.MCPRegistry"),
        patch("ai_osop.api.main.connect_with_retry", new_callable=AsyncMock) as connect,
    ):
        connect.return_value = False
        with pytest.raises(RuntimeError, match="storage or schema migration unavailable"):
            async with lifespan(app):
                pass
        connect.assert_awaited_once()


@pytest.mark.asyncio
async def test_agent_registration_failure_never_serves_api():
    """A booted Redis/PG connection cannot mask an empty or broken agent fleet."""
    session_memory = MagicMock()
    session_memory._redis.ping = AsyncMock()
    graph_memory = MagicMock()
    vector_memory = MagicMock()
    vector_memory.connect = AsyncMock()
    orchestrator = MagicMock()
    orchestrator.initialize = AsyncMock(side_effect=RuntimeError("agent init failed"))
    with (
        patch("ai_osop.api.main.SessionMemory", return_value=session_memory),
        patch("ai_osop.api.main.GraphMemory", return_value=graph_memory),
        patch("ai_osop.api.main.VectorMemory", return_value=vector_memory),
        patch("ai_osop.api.main.MCPRegistry", return_value=MagicMock()),
        patch("ai_osop.api.main.Orchestrator", return_value=orchestrator),
        patch("ai_osop.api.main.register_optional_mcp_servers", new_callable=AsyncMock),
        patch("ai_osop.api.main.connect_with_retry", new_callable=AsyncMock) as connect,
    ):
        connect.return_value = True
        with pytest.raises(RuntimeError, match="Orchestrator or agent initialization failed"):
            async with lifespan(app):
                pass
        orchestrator.initialize.assert_awaited_once()
