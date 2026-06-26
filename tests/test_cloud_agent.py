import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ai_osop.agents.base import AgentContext
from ai_osop.agents.cloud_agent import CloudSpecialistAgent
from ai_osop.core.config import AgentType
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
    await agent.initialize()

    task = Task(
        id="task-1",
        type="analyze_iam",
        agent_type=AgentType.CLOUD_SPECIALIST,
        payload={"account_id": "123456789012", "principal_arn": "arn:aws:iam::123456789012:user/admin"},
        engagement_id="test-session",
    )

    mock_adapter_instance = AsyncMock()
    mock_adapter_instance.analyze_iam_trust_policies.return_value = {
        "findings": [
            {"role": "arn:aws:iam::123456789012:role/OverprivilegedRole", "issue": "Cross-account assume role allowed"}
        ]
    }
    mock_adapter_instance.discover_privilege_escalation.return_value = {
        "paths": [
            {"target": "admin-policy", "path": "iam:PutUserPolicy"}
        ]
    }

    with patch("ai_osop.adapters.cloud_mcp.CloudMCPAdapter") as mock_adapter_cls:
        mock_adapter_cls.return_value = mock_adapter_instance

        result = await agent._execute(task)

        assert result["status"] == "success"
        assert result["findings_count"] == 2
        assert "complete" in result["msg"]
        mock_adapter_instance.initialize.assert_awaited_once()
        mock_adapter_instance.analyze_iam_trust_policies.assert_awaited_once_with("123456789012")
        mock_adapter_instance.discover_privilege_escalation.assert_awaited_once_with("arn:aws:iam::123456789012:user/admin")
        assert agent.ctx.coordination_bus.publish.call_count == 2


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
    assert "Metadata probing initialized" in result["msg"]


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
