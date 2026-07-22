from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.attack_chain_agent import AttackChainAgent
from ai_osop.agents.base import AgentContext
from ai_osop.core.enums import AgentType
from ai_osop.core.models import AttackPath, Task


@pytest.mark.asyncio
async def test_attack_chain_validation_schedules_task():
    # 1. Setup Mocks
    mock_ctx = MagicMock(spec=AgentContext)
    mock_ctx.agent_id = "test-chain-agent"
    mock_ctx.graph_memory = AsyncMock()
    mock_ctx.session_memory = AsyncMock()
    mock_ctx.current_task = MagicMock(spec=Task)
    mock_ctx.current_task.engagement_id = "test-eng"

    agent = AttackChainAgent(mock_ctx)

    # 2. Setup discovered paths
    path = AttackPath(
        id="path-123",
        node_ids=["vuln-1"],
        edge_ids=["chain-1"],
        confidence=0.9,
        risk_score=5.0,
        entry_node_id="vuln-1",
        goal_node_id="vuln-1",
        engagement_id="test-eng",
    )
    agent.discovered_paths = [path]

    # 3. Configure Graph Memory Mock
    mock_ctx.graph_memory.get_node_details.return_value = {
        "type": "Vulnerability",
        "props": {"validated": False},
    }
    mock_ctx.graph_memory.get_endpoint_url_for_vulnerability.return_value = "http://example.com"

    # 4. Execute
    payload = {"path_id": "path-123"}
    result = await agent._validate_chain(payload)

    # 5. Assertions
    assert result["status"] == "success"
    assert result["validation_results"][0]["status"] == "validation_scheduled"

    # Verify task was pushed to orchestrator queue
    mock_ctx.session_memory.push_task_queue.assert_called_once()
    scheduled_task = mock_ctx.session_memory.push_task_queue.call_args[0][1]
    assert scheduled_task["type"] == "validate_exploit"
    assert scheduled_task["payload"]["target"] == "http://example.com"
    assert scheduled_task["payload"]["vulnerability_id"] == "vuln-1"
