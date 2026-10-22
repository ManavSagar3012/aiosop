"""Emergency stop persists session and task cancellation across restarts."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_halt_persists_warm_state_and_cancels_temporal_tasks():
    session = SessionState(
        session_id="eng-halt",
        scope=ScopeDefinition(
            engagement_id="eng-halt",
            domains=["example.com"],
            authorization_ref="signed-roe",
        ),
    )
    memory = MagicMock()
    memory.store_session_state = AsyncMock()
    memory.persist_session_state = AsyncMock()
    memory.store_task = AsyncMock()
    temporal = MagicMock()
    temporal.cancel_task_workflow = AsyncMock()
    orch = Orchestrator(
        session_memory=memory,
        graph_memory=MagicMock(),
        mcp_registry=MagicMock(),
        llm_client=MagicMock(),
        temporal_scheduler=temporal,
    )
    orch.temporal_enabled = True
    orch._sessions[session.session_id] = session
    task = Task(
        id="task-halt", type="recon", agent_type=AgentType.RECON,
        engagement_id="eng-halt", status="scheduled",
    )
    waiting = Task(
        id="task-wait", type="recon", agent_type=AgentType.RECON,
        engagement_id="eng-halt", status="awaiting_approval",
    )
    unrelated = Task(
        id="task-other", type="recon", agent_type=AgentType.RECON,
        engagement_id="eng-other", status="scheduled",
    )
    orch._tasks = {t.id: t for t in (task, waiting, unrelated)}
    orch._audit_log = AsyncMock()

    await orch.halt_engagement("eng-halt", "operator stop")

    assert session.phase == "halted"
    memory.store_session_state.assert_awaited_once()
    memory.persist_session_state.assert_awaited_once()
    assert {task.status, waiting.status} == {"cancelled"}
    assert unrelated.status == "scheduled"
    assert memory.store_task.await_count == 2
    temporal.cancel_task_workflow.assert_awaited_once_with("task-halt")


@pytest.mark.asyncio
async def test_halt_persists_cancellation_even_if_temporal_unreachable():
    session = SessionState(
        session_id="eng-halt",
        scope=ScopeDefinition(engagement_id="eng-halt", domains=["example.com"]),
    )
    memory = MagicMock()
    memory.store_session_state = AsyncMock()
    memory.persist_session_state = AsyncMock()
    memory.store_task = AsyncMock()
    temporal = MagicMock()
    temporal.cancel_task_workflow = AsyncMock(side_effect=ConnectionError("down"))
    orch = Orchestrator(memory, MagicMock(), MagicMock(), MagicMock(), temporal_scheduler=temporal)
    orch.temporal_enabled = True
    orch._sessions["eng-halt"] = session
    task = Task(id="task-halt", type="recon", agent_type=AgentType.RECON,
                engagement_id="eng-halt", status="scheduled")
    orch._tasks[task.id] = task
    orch._audit_log = AsyncMock()

    await orch.halt_engagement("eng-halt", "stop")

    assert task.status == "cancelled"
    memory.persist_session_state.assert_awaited_once()
    memory.store_task.assert_awaited_once()
