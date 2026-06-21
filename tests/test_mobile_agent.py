from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.experimental.mobile_agent import MobileAnalysisAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "mobile-1"
    ctx.agent_type = AgentType.VULN_ANALYSIS
    ctx.session_id = "test-session"
    ctx.llm_client = AsyncMock()
    ctx.session_memory = AsyncMock()
    ctx.graph_memory = AsyncMock()
    ctx.persona = "test_persona"
    ctx.current_task = None
    ctx.cost_incurred = 0.0
    ctx.audit_callback = AsyncMock()
    ctx.coordination_bus = AsyncMock()
    ctx.mcp_registry = AsyncMock()
    ctx.scope = None
    return ctx


@pytest.fixture
def agent(mock_context):
    return MobileAnalysisAgent(mock_context)


# ──────────────────── tests ────────────────────


@pytest.mark.asyncio
async def test_analyze_deep_links_with_reset(agent) -> None:
    """Deep links containing 'reset' trigger an insecure_deep_link finding."""
    await agent.initialize()

    task = Task(
        id="task-1",
        type="analyze_deep_links",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "bundle_id": "com.example.app",
            "links": [
                "target://home",
                "target://reset_password?token=XYZ",
            ],
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["analyzed_count"] == 2
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "insecure_deep_link"
    assert "Account Takeover" in result["findings"][0]["risk"]


@pytest.mark.asyncio
async def test_analyze_deep_links_no_reset(agent) -> None:
    """Deep links without 'reset' produce no findings."""
    await agent.initialize()

    task = Task(
        id="task-2",
        type="analyze_deep_links",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "bundle_id": "com.example.app",
            "links": ["target://home", "target://profile"],
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["analyzed_count"] == 2
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_intercept_mobile_traffic(agent) -> None:
    """Traffic interception returns success with interception_active flag."""
    await agent.initialize()

    task = Task(
        id="task-3",
        type="intercept_mobile_traffic",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"endpoint": "https://api.example.com/v1/users"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["interception_active"] is True


@pytest.mark.asyncio
async def test_unknown_task_type(agent) -> None:
    """Unknown task type returns an error dict."""
    await agent.initialize()

    task = Task(
        id="task-4",
        type="nonexistent_task",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "error"
    assert "Unknown task type" in result["message"]
