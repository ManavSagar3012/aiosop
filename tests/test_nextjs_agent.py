from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from ai_osop.agents.base import AgentContext
from ai_osop.agents.experimental.nextjs_agent import NextJSSpecialistAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "nextjs-1"
    ctx.agent_type = AgentType.NEXTJS_SPECIALIST
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


@pytest_asyncio.fixture
async def agent(mock_context):
    instance = NextJSSpecialistAgent(mock_context)
    try:
        yield instance
    finally:
        if instance._running:
            await instance.shutdown()


@pytest.mark.asyncio
async def test_nextjs_agent_audit_server_actions(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-1",
        type="audit_server_actions",
        agent_type=AgentType.NEXTJS_SPECIALIST,
        payload={"url": "https://target.example.com"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "unsupported"
    assert "not implemented" in result["error"]


@pytest.mark.asyncio
async def test_nextjs_agent_test_middleware(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-2",
        type="test_middleware",
        agent_type=AgentType.NEXTJS_SPECIALIST,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "unsupported"
    assert "not implemented" in result["error"]


@pytest.mark.asyncio
async def test_nextjs_agent_unknown_task(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-3",
        type="unknown_task_type",
        agent_type=AgentType.NEXTJS_SPECIALIST,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "failed"
    assert "Unknown task type" in result["error"]
