"""Emergency halt must interrupt active local dispatch, preserving durable cancellation."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.orchestrator import Orchestrator


def _build_orchestrator():
    session_memory = AsyncMock()
    orchestrator = Orchestrator(
        session_memory=session_memory,
        graph_memory=AsyncMock(),
        mcp_registry=MagicMock(),
        llm_client=AsyncMock(),
    )
    orchestrator.temporal_enabled = False
    orchestrator._sessions["eng-owned"] = SessionState(
        session_id="eng-owned",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id="eng-owned",
            domains=["example.com"],
            authorization_ref="signed-roe",
        ),
    )
    return orchestrator


@pytest.mark.asyncio
async def test_halt_cancels_real_running_coroutine_and_keeps_terminal_state() -> None:
    orch = _build_orchestrator()
    started = asyncio.Event()
    hold = asyncio.Event()

    async def run_task(_task):
        started.set()
        await hold.wait()
        return {"status": "success"}

    task = Task(
        id="task-stop-me",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-owned",
        status="running",
        assigned_agent_id="agent-1",
    )
    agent = SimpleNamespace(
        ctx=SimpleNamespace(agent_id="agent-1", agent_type=AgentType.RECON),
        execute_task=AsyncMock(side_effect=run_task),
    )
    orch._tasks[task.id] = task
    orch._agents["agent-1"] = agent
    orch._busy_agents.add("agent-1")

    handle = orch._spawn_agent_execution(agent, task, orch._execute_via_agent)
    await asyncio.wait_for(started.wait(), timeout=1)
    await orch.halt_engagement("eng-owned", "operator emergency stop")

    assert handle.done()
    assert handle.cancelled()
    assert task.status == "cancelled"
    assert orch._sessions["eng-owned"].phase == "halted"
    orch.session_memory.store_task.assert_awaited()
    assert "agent-1" not in orch._busy_agents
    await orch._on_task_success(task, {"status": "success"})
    assert task.status == "cancelled"
    orch.graph_memory.upsert_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_halt_does_not_cancel_another_engagement_dispatch() -> None:
    orch = _build_orchestrator()
    orch._sessions["eng-other"] = SessionState(
        session_id="eng-other",
        phase="reconnaissance",
        scope=ScopeDefinition(engagement_id="eng-other", domains=["example.org"]),
    )
    keep_running = asyncio.Event()
    started = asyncio.Event()

    async def run_other(_task):
        started.set()
        await keep_running.wait()
        return {"status": "success"}

    task = Task(
        id="task-other",
        type="recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-other",
        status="running",
    )
    agent = SimpleNamespace(
        ctx=SimpleNamespace(agent_id="agent-other", agent_type=AgentType.RECON),
        execute_task=AsyncMock(side_effect=run_other),
    )
    orch._tasks[task.id] = task
    orch._agents["agent-other"] = agent
    handle = orch._spawn_agent_execution(agent, task, orch._execute_via_agent)
    await asyncio.wait_for(started.wait(), timeout=1)

    await orch.halt_engagement("eng-owned", "stop owned only")
    assert not handle.done()
    assert task.status == "running"

    keep_running.set()
    await asyncio.wait_for(handle, timeout=1)
