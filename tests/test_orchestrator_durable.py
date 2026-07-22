import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import EngagementPhase, Orchestrator


@pytest.fixture
def mock_deps():
    return {
        "session_memory": AsyncMock(),
        "graph_memory": AsyncMock(),
        "mcp_registry": MagicMock(),
        "llm_client": AsyncMock(),
        "coordination_bus": AsyncMock(),
    }


@pytest.mark.asyncio
async def test_execute_task_durable_success(mock_deps) -> None:
    # Setup
    orchestrator = Orchestrator(**mock_deps)

    mock_agent = AsyncMock()
    mock_agent.ctx.agent_id = "agent-1"
    mock_agent.ctx.agent_type = AgentType.RECON
    mock_agent.ctx.status = "idle"
    mock_agent.execute_task.return_value = {"status": "success", "data": "found something"}

    orchestrator._agents["agent-1"] = mock_agent

    task = Task(id="task-1", type="recon", agent_type=AgentType.RECON, engagement_id="eng-1")

    # Act
    result = await orchestrator._execute_task_durable(task)

    # Assert
    assert result["status"] == "success"
    assert task.status == "completed"
    mock_agent.execute_task.assert_awaited_once_with(task)


@pytest.mark.asyncio
async def test_execute_task_durable_waits_for_agent(mock_deps) -> None:
    # Setup
    orchestrator = Orchestrator(**mock_deps)

    mock_agent = AsyncMock()
    mock_agent.ctx.agent_id = "agent-1"
    mock_agent.ctx.agent_type = AgentType.RECON
    mock_agent.ctx.status = "busy"  # Initially busy
    mock_agent.execute_task.return_value = {"status": "success"}

    orchestrator._agents["agent-1"] = mock_agent

    task = Task(id="task-1", type="recon", agent_type=AgentType.RECON, engagement_id="eng-1")

    # Background task to make agent idle after 2 seconds
    async def make_idle():
        await asyncio.sleep(2)
        mock_agent.ctx.status = "idle"

    asyncio.create_task(make_idle())

    # Act
    result = await orchestrator._execute_task_durable(task)

    # Assert
    assert result["status"] == "success"
    assert task.status == "completed"


@pytest.mark.asyncio
async def test_execute_task_durable_timeout(mock_deps) -> None:
    # Setup
    orchestrator = Orchestrator(**mock_deps)
    # No agents registered

    task = Task(id="task-1", type="recon", agent_type=AgentType.RECON, engagement_id="eng-1")

    # Mock loop.time to simulate timeout immediately
    loop = asyncio.get_event_loop()
    time_mock = MagicMock(side_effect=[0, 1000])

    with patch.object(loop, "time", time_mock), patch("asyncio.sleep", AsyncMock()):
        # Act
        result = await orchestrator._execute_task_durable(task)

    # Assert
    assert result["status"] == "failed"
    assert "Timeout" in result["error"]
