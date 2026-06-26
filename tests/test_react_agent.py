from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.react_agent import ReactSpecialistAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "react-1"
    ctx.agent_type = AgentType.REACT_SPECIALIST
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
    return ReactSpecialistAgent(mock_context)


@pytest.mark.asyncio
async def test_react_agent_analyze_bundle_success(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-1",
        type="analyze_bundle",
        agent_type=AgentType.REACT_SPECIALIST,
        payload={"url": "http://example.com/bundle.js"},
        engagement_id="test-session",
    )

    mock_adapter_instance = AsyncMock()
    mock_adapter_instance.fetch_and_parse_sourcemap.return_value = {
        "secrets": [{"key": "AWS_SECRET_KEY", "file": "src/config.js", "line": 42}],
        "msg": "Sourcemap parsed successfully",
    }

    with patch("ai_osop.adapters.source_map_mcp.SourceMapMCPAdapter") as mock_adapter_cls:
        mock_adapter_cls.return_value = mock_adapter_instance

        result = await agent._execute(task)

        assert result["status"] == "success"
        assert result["findings_count"] == 1
        assert result["msg"] == "Sourcemap parsed successfully"
        mock_adapter_instance.initialize.assert_awaited_once()
        mock_adapter_instance.fetch_and_parse_sourcemap.assert_awaited_once_with(
            "http://example.com/bundle.js"
        )
        assert agent.ctx.coordination_bus.publish.call_count == 1


@pytest.mark.asyncio
async def test_react_agent_analyze_bundle_missing_url(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-2",
        type="analyze_bundle",
        agent_type=AgentType.REACT_SPECIALIST,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "failed"
    assert "target_url is required" in result["error"]


@pytest.mark.asyncio
async def test_react_agent_probe_components(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-3",
        type="probe_components",
        agent_type=AgentType.REACT_SPECIALIST,
        payload={"target": "HomeComponent"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "success"
    assert result["msg"] == "Dynamic component probing initialized."


@pytest.mark.asyncio
async def test_react_agent_unknown_task(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-4",
        type="unknown_task_type",
        agent_type=AgentType.REACT_SPECIALIST,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "failed"
    assert "Unknown task type" in result["error"]
