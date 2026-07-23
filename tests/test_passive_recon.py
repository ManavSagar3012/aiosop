from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.passive_recon_agent import PassiveReconAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Asset, Task


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.mcp_registry = AsyncMock()
    ctx.graph_memory = AsyncMock()
    ctx.session_memory = AsyncMock()
    ctx.agent_id = "passive-recon-agent-001"
    ctx.agent_type = AgentType.RECON
    ctx.status = "idle"
    return ctx


@pytest.mark.asyncio
async def test_passive_recon_agent_initialization(mock_ctx):
    agent = PassiveReconAgent(mock_ctx)
    await agent._setup_resources()
    assert agent.agent_type == AgentType.RECON
    assert agent.supports_task_type("passive_recon")
    assert not agent.supports_task_type("full_recon")


@pytest.mark.asyncio
async def test_passive_recon_agent_execution(mock_ctx):
    agent = PassiveReconAgent(mock_ctx)
    await agent._setup_resources()

    # Mock the passive recon MCP adapter
    adapter_mock = AsyncMock()
    adapter_mock.passive_subdomain_discovery.return_value = [
        Asset(
            type="subdomain",
            value="dev.example.com",
            source="passive_recon",
            confidence=0.8,
            engagement_id="eng-123",
        )
    ]
    adapter_mock.shodan_lookup.return_value = [
        Asset(
            type="host",
            value="192.168.1.100",
            source="shodan_passive",
            confidence=0.9,
            engagement_id="eng-123",
        )
    ]
    agent.passive_adapter = adapter_mock

    # Build task
    task = Task(
        id="task-123",
        type="passive_recon",
        priority=5,
        agent_type=AgentType.RECON,
        payload={"domain": "example.com"},
        engagement_id="eng-123",
        status="pending",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["domain"] == "example.com"
    assert result["subdomains_discovered"] == 1
    assert result["hosts_discovered"] == 1

    # Verify assets were persisted to GraphMemory
    assert mock_ctx.graph_memory.add_asset.call_count == 2
