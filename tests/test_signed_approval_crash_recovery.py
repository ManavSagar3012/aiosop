"""Committed human approval resumes once, without rewriting a signed TaskORM."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def prepared():
    task = Task(
        id="task-approved-crash",
        engagement_id="eng-approved-crash",
        type="summarize_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        status="awaiting_approval",
        approval_required=True,
        payload={
            "_authorization_version": 2,
            "operator_approved": True,
            "approval_id": "apr-authoritative-human",
        },
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.claim_local_agent_start = AsyncMock(return_value=True)
    memory.store_hot = AsyncMock()
    memory.store_task = AsyncMock()
    orch = SimpleNamespace(
        temporal_enabled=False,
        session_memory=memory,
        _sessions={},
        _tasks={task.id: task},
        _approval_requests={},
        _busy_agents=set(),
        graph_memory=SimpleNamespace(upsert_task=AsyncMock()),
        coordination_bus=SimpleNamespace(publish=AsyncMock()),
        rate_limiter=SimpleNamespace(acquire=AsyncMock()),
        _find_available_agent=AsyncMock(),
        _release_agent=Mock(),
        _spawn_agent_execution=Mock(),
        _execute_via_agent=AsyncMock(),
    )
    return task, orch, memory


@pytest.mark.asyncio
async def test_approved_parked_task_without_available_agent_keeps_signed_status():
    task, orch, memory = prepared()
    orch._find_available_agent.return_value = None

    await Orchestrator._assign_task(orch, task)
    assert task.status == "awaiting_approval"
    memory.claim_local_agent_start.assert_not_awaited()
    memory.store_task.assert_not_awaited()
    orch.graph_memory.upsert_task.assert_not_awaited()
    orch._spawn_agent_execution.assert_not_called()


@pytest.mark.asyncio
async def test_real_orchestrator_entrypoint_spawns_before_failed_observers():
    task, orch, memory = prepared()
    agent = SimpleNamespace(ctx=SimpleNamespace(agent_id="signed-agent"))
    orch._find_available_agent.return_value = agent
    events = []

    def launched(*_):
        events.append("launched")

    async def graph(_):
        events.append("graph")
        raise OSError("Neo4j down")

    async def notification(*_):
        events.append("bus")
        raise OSError("Redis bus down")

    orch._spawn_agent_execution.side_effect = launched
    orch.graph_memory.upsert_task.side_effect = graph
    orch.coordination_bus.publish.side_effect = notification
    memory.store_hot.side_effect = OSError("Redis hot tier down")

    await Orchestrator._assign_task(orch, task)
    assert events == ["launched", "graph", "bus"]
    assert task.status == "running"
    memory.claim_local_agent_start.assert_awaited_once_with(task, "signed-agent")
    memory.store_task.assert_not_awaited()
    orch._spawn_agent_execution.assert_called_once()
