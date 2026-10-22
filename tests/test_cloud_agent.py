from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from ai_osop.agents.base import AgentContext
from ai_osop.agents.experimental.cloud_agent import CloudSpecialistAgent
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


@pytest_asyncio.fixture
async def agent(mock_context):
    instance = CloudSpecialistAgent(mock_context)
    try:
        yield instance
    finally:
        if instance._running:
            await instance.shutdown()


@pytest.mark.asyncio
async def test_cloud_agent_analyze_iam_success(agent) -> None:
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

    mock_adapter_instance = AsyncMock()
    mock_adapter_instance.analyze_iam_trust_policies.return_value = {
        "findings": [
            {
                "role": "arn:aws:iam::123456789012:role/OverprivilegedRole",
                "issue": "Cross-account assume role allowed",
            }
        ]
    }
    mock_adapter_instance.discover_privilege_escalation.return_value = {
        "paths": [{"target": "admin-policy", "path": "iam:PutUserPolicy"}]
    }

    with patch("ai_osop.adapters.cloud_mcp.CloudMCPAdapter") as mock_adapter_cls:
        mock_adapter_cls.return_value = mock_adapter_instance

        result = await agent._execute(task)

        assert result["status"] == "success"
        assert result["findings_count"] == 2
        assert "complete" in result["msg"]
        mock_adapter_instance.initialize.assert_awaited_once()
        mock_adapter_instance.analyze_iam_trust_policies.assert_awaited_once_with("123456789012")
        mock_adapter_instance.discover_privilege_escalation.assert_awaited_once_with(
            "arn:aws:iam::123456789012:user/admin"
        )
        assert agent.ctx.coordination_bus.publish.call_count == 2


@pytest.mark.asyncio
async def test_cloud_agent_local_iac_does_not_promote_to_live_iam(agent) -> None:
    task = Task(
        id="task-local-iac",
        type="scan_local_iac",
        agent_type=AgentType.CLOUD_SPECIALIST,
        payload={},
        engagement_id="test-session",
    )
    adapter = AsyncMock()
    adapter.scan_local_iac.return_value = {
        "findings_count": 1,
        "findings": [{"check_id": "CKV_AWS_1"}],
        "live_cloud_account_verified": False,
        "target_effect_verified": False,
    }
    with patch("ai_osop.adapters.cloud_mcp.CloudMCPAdapter", return_value=adapter):
        result = await agent._execute(task)
    assert result["status"] == "success"
    assert result["live_cloud_account_verified"] is False
    adapter.scan_local_iac.assert_awaited_once_with()
    agent.ctx.coordination_bus.publish.assert_not_called()


@pytest.mark.asyncio
async def test_cloud_iac_accepts_only_current_execution_metadata(agent) -> None:
    task = Task(
        type="scan_local_iac",
        agent_type=AgentType.CLOUD_SPECIALIST,
        engagement_id="test-session",
        payload={"_authorization_version": 7},
    )
    agent.ctx.current_task = task
    execution = task.model_copy(deep=True)
    execution.payload["engagement_id"] = task.engagement_id
    adapter = AsyncMock()
    adapter.scan_local_iac.return_value = {"findings": [], "findings_count": 0}
    with patch("ai_osop.adapters.cloud_mcp.CloudMCPAdapter", return_value=adapter):
        assert (await agent._execute(execution))["status"] == "success"
        execution.payload["_authorization_version"] = 8
        assert (await agent._execute(execution))["status"] == "failed"
    adapter.scan_local_iac.assert_awaited_once()


@pytest.mark.asyncio
async def test_cloud_agent_local_iac_rejects_caller_paths(agent) -> None:
    result = await agent._scan_local_iac({"path": "arbitrary"})
    assert result["status"] == "failed"
    agent.ctx.mcp_registry.execute_tool.assert_not_called()


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
    assert result["status"] == "unsupported"
    assert "not implemented" in result["error"]


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
