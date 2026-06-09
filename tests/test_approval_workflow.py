import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime
from ai_osop.core.models import ApprovalRequest, Task
from ai_osop.orchestrator.orchestrator import Orchestrator

@pytest.fixture
def mock_orchestrator():
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    mcp_registry = AsyncMock()
    llm_client = AsyncMock()
    
    # Need settings
    orch = Orchestrator(session_memory, graph_memory, mcp_registry, llm_client)
    orch.rate_limiter = AsyncMock()
    return orch

@pytest.mark.asyncio
async def test_approval_workflow_success(mock_orchestrator):
    # Setup approval request
    request = ApprovalRequest(
        task_id="task-123",
        agent_id="agent-001",
        action_type="sql_injection",
        target="http://example.com",
        payload_summary="test payload",
        risk_assessment="high",
        engagement_id="eng-001"
    )

    # Coroutine to resolve the approval after a delay
    async def resolve_delayed():
        await asyncio.sleep(0.5)
        await mock_orchestrator.resolve_approval(
            request.id, "approved", "operator-1", "looks good"
        )

    # Schedule resolution
    asyncio.create_task(resolve_delayed())

    # Request approval (should block until resolved)
    result = await mock_orchestrator.request_approval(request)

    assert result.status == "approved"
    assert result.operator_id == "operator-1"
    assert result.operator_notes == "looks good"
