import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import EngagementPhase, Orchestrator


@pytest.fixture
def mock_orchestrator():
    session_memory = AsyncMock()
    graph_memory = AsyncMock()
    mcp_registry = AsyncMock()
    llm_client = AsyncMock()

    orch = Orchestrator(session_memory, graph_memory, mcp_registry, llm_client)
    orch.rate_limiter = AsyncMock()
    return orch


@pytest.fixture
def dummy_scope():
    return ScopeDefinition(
        engagement_id="test-eng", domains=["example.com"], approval_required_for=["rce"]
    )


@pytest.mark.asyncio
async def test_create_engagement(mock_orchestrator, dummy_scope):
    session = await mock_orchestrator.create_engagement(dummy_scope, {})
    assert session.phase == EngagementPhase.INITIALIZED.value
    assert session.scope.engagement_id == "test-eng"
    assert session.session_id.startswith("eng-")

    mock_orchestrator.session_memory.store_session_state.assert_called_once()
    mock_orchestrator.session_memory.persist_session_state.assert_called_once()


@pytest.mark.asyncio
async def test_transition_phase(mock_orchestrator, dummy_scope):
    # Setup session
    session = SessionState(
        session_id="test-session",
        scope=dummy_scope,
        roe={},
        phase=EngagementPhase.INITIALIZED.value,
        agents={},
        checkpoint_id=None,
        audit_log_position="0",
    )
    mock_orchestrator._sessions["test-session"] = session

    # Transition to recon
    updated_session = await mock_orchestrator.transition_phase(
        "test-session", EngagementPhase.RECONNAISSANCE
    )

    assert updated_session.phase == EngagementPhase.RECONNAISSANCE.value
    mock_orchestrator.session_memory.store_session_state.assert_called()

    # Verify auto-task scheduling for recon
    assert len(mock_orchestrator._tasks) == 1
    task = list(mock_orchestrator._tasks.values())[0]
    assert task.type == "full_recon"
    assert task.payload["domain"] == "example.com"


@pytest.mark.asyncio
async def test_schedule_and_assign_task(mock_orchestrator):
    task = Task(
        type="test_task",
        priority=5,
        agent_type=AgentType.RECON,
        payload={},
        engagement_id="test-session",
    )

    # Mock finding an agent
    mock_agent = AsyncMock()
    mock_agent.ctx.agent_id = "recon-001"
    mock_agent.ctx.agent_type = AgentType.RECON
    mock_agent.ctx.status = "idle"
    mock_agent.execute_task.return_value = {"status": "success"}
    mock_orchestrator._agents["recon-001"] = mock_agent

    scheduled_task = await mock_orchestrator.schedule_task(task)

    # Wait for the background task to execute
    for _ in range(10):
        await asyncio.sleep(0.1)
        if mock_orchestrator._tasks[task.id].status == "completed":
            break

    print(f"DEBUG: Task status: {mock_orchestrator._tasks[task.id].status}")
    assert scheduled_task.assigned_agent_id == "recon-001"
    assert mock_orchestrator._tasks[task.id].status == "completed"
    mock_agent.execute_task.assert_called_once()
