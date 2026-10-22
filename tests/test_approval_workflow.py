import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, SessionState, Task
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
        engagement_id="eng-001",
    )
    mock_orchestrator._sessions["eng-001"] = SessionState(
        session_id="eng-001",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id="eng-001",
            domains=["example.com"],
            authorization_ref="test-roe",
        ),
    )
    mock_orchestrator._tasks["task-123"] = Task(
        id="task-123",
        type="sql_injection",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        engagement_id="eng-001",
        approval_required=True,
        status="awaiting_approval",
    )
    # This test verifies only the persisted approval decision; live execution
    # is exercised by the Temporal/dispatch suites under an explicit scope.
    mock_orchestrator._assign_task = AsyncMock()

    # Coroutine to resolve the approval after a delay
    async def resolve_delayed():
        await asyncio.sleep(0.5)
        await mock_orchestrator.resolve_approval(request.id, "approved", "operator-1", "looks good")

    # Schedule resolution
    asyncio.create_task(resolve_delayed())

    # Request approval (should block until resolved)
    result = await mock_orchestrator.request_approval(request)

    assert result.status == "approved"
    assert result.operator_id == "operator-1"
    assert result.operator_notes == "looks good"
