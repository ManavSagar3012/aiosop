from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.cloud_agent import CloudSpecialistAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "cloud-1"
    ctx.agent_type = AgentType.CLOUD_SPECIALIST
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
    return CloudSpecialistAgent(mock_context)


@pytest.mark.asyncio
async def test_cloud_agent_analyze_iam_success(agent) -> None:
    """MAJ-1 (2026-07-23): the cloud-mcp adapter is a stub (NotImplementedError),
    so _analyze_iam_policy now returns 'skipped' with a clear message instead of
    calling the stub adapter. This test asserts the skip behavior."""
    await agent.initialize()

    task = Task(
        id="task-1",
        type="analyze_iam",
        agent_type=AgentType.CLOUD_SPECIALIST,
        payload={
            "account_id": "123456789012",
            "principal_arn": "arn:aws:iam::123456789012:user/admin",
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    # The stub adapter is now fail-closed: IAM analysis returns 'skipped'
    # with a clear message instead of silently calling a fake adapter.
    assert result["status"] == "skipped"
    assert result["findings_count"] == 0
    assert "stub" in result["msg"].lower() or "credentials" in result["msg"].lower()


@pytest.mark.asyncio
async def test_cloud_agent_probe_metadata(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-2",
        type="probe_metadata",
        agent_type=AgentType.CLOUD_SPECIALIST,
        payload={"url": "http://169.254.169.254/latest/meta-data/"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "success"
    assert "Cloud metadata probing complete" in result["msg"]


@pytest.mark.asyncio
async def test_cloud_agent_unknown_task(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-3",
        type="unknown_task_type",
        agent_type=AgentType.CLOUD_SPECIALIST,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "failed"
    assert "Unknown task type" in result["error"]
