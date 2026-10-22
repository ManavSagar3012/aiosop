"""Local signed Task admission survives non-authoritative observer failures.

All tests are deterministic adapters; no PostgreSQL or remote target runs.
"""

import asyncio
from types import MethodType, SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.task_scheduler import TaskScheduler
from ai_osop.core.exceptions import WorkflowException


def harness(*, signed=True):
    task = Task(
        id="task-local-handoff",
        engagement_id="eng-local-handoff",
        type="full_recon",
        agent_type=AgentType.RECON,
        status="pending",
        payload={
            "target": "example.test",
            **({"_authorization_version": 2} if signed else {}),
        },
    )
    agent = SimpleNamespace(
        ctx=SimpleNamespace(agent_id="agent-local-owner", agent_type=AgentType.RECON, status="idle")
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.claim_local_agent_start = AsyncMock(return_value=True)
    memory.store_hot = AsyncMock()
    memory.store_task = AsyncMock()
    memory.acquire_lock = AsyncMock(return_value=True)
    memory.release_lock = AsyncMock(return_value=True)
    graph = SimpleNamespace(upsert_task=AsyncMock())
    bus = SimpleNamespace(publish=AsyncMock())
    events = []
    spawn = Mock(side_effect=lambda *_: events.append("spawn"))
    orch = SimpleNamespace(
        session_memory=memory,
        temporal_enabled=False,
        temporal_scheduler=None,
        _sessions={},
        _agents={"agent-local-owner": agent},
        _busy_agents=set(),
        graph_memory=graph,
        coordination_bus=bus,
        _spawn_agent_execution=spawn,
        _execute_supervised_agent=AsyncMock(return_value={"status": "failed"}),
        _quarantine_unknown_execution=AsyncMock(),
        _on_task_success=AsyncMock(),
        _on_task_failure=AsyncMock(),
    )
    orch._find_available_agent = MethodType(Orchestrator._find_available_agent, orch)
    orch._release_agent = MethodType(Orchestrator._release_agent, orch)
    return TaskScheduler(orch), task, orch, events, agent


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_observer", ["redis", "graph", "bus"])
async def test_post_claim_observer_failure_cannot_prevent_agent_launch(
    failed_observer,
):
    scheduler, task, orch, events, _ = harness()

    async def graph():
        events.append("graph")
        if failed_observer == "graph":
            raise OSError("graph not available")

    async def publish(*_):
        events.append("bus")
        if failed_observer == "bus":
            raise OSError("bus not available")

    orch.graph_memory.upsert_task.side_effect = graph
    orch.coordination_bus.publish.side_effect = publish
    if failed_observer == "redis":
        orch.session_memory.store_hot.side_effect = OSError("redis not available")

    await scheduler._assign_task(task)
    orch.session_memory.claim_local_agent_start.assert_awaited_once()
    orch._spawn_agent_execution.assert_called_once()
    assert task.status == "running"
    assert events[0] == "spawn"
    orch.session_memory.store_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_task_cancellation_after_pg_claim_cannot_prevent_worker_launch():
    scheduler, task, orch, events, _ = harness()
    orch.session_memory.store_hot.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await scheduler._assign_task(task)
    assert events == ["spawn"]
    orch.session_memory.claim_local_agent_start.assert_awaited_once()
    orch._spawn_agent_execution.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["returned_error", "exception", "mutated_status"])
async def test_signed_running_failure_never_retries_consequential_attempt(failure):
    scheduler, task, orch, _, agent = harness()
    task.status = "running"
    task.assigned_agent_id = agent.ctx.agent_id
    task.retry_count = 1
    scheduler._maybe_retry = AsyncMock()
    scheduler._on_task_failure = AsyncMock()
    if failure == "returned_error":
        orch._execute_supervised_agent.return_value = {"status": "timeout"}
    elif failure == "exception":
        orch._execute_supervised_agent.side_effect = RuntimeError("execution response was lost")
    else:

        async def mutate(_agent, candidate):
            candidate.status = "failed"
            return {"status": "failed"}

        orch._execute_supervised_agent.side_effect = mutate

    await scheduler._execute_via_agent(agent, task)
    scheduler._maybe_retry.assert_not_awaited()
    scheduler._on_task_failure.assert_not_awaited()
    orch._quarantine_unknown_execution.assert_awaited_once_with(task)
    assert task.retry_count == 1


@pytest.mark.asyncio
async def test_unsigned_legacy_failure_retains_existing_retry_policy():
    scheduler, task, orch, _, agent = harness(signed=False)
    task.status = "running"
    task.assigned_agent_id = agent.ctx.agent_id
    scheduler._maybe_retry = AsyncMock(return_value=True)
    orch._execute_supervised_agent.return_value = {"status": "failed"}

    await scheduler._execute_via_agent(agent, task)
    scheduler._maybe_retry.assert_awaited_once()
    orch._quarantine_unknown_execution.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("entrypoint", ["scheduler", "orchestrator"])
async def test_signed_schedule_does_not_project_or_enqueue_denied_pg_snapshot(
    entrypoint,
):
    scheduler, task, orch, _, _ = harness()
    orch._bind_task_authorization = AsyncMock()
    orch.session_memory.load_task_authoritative = AsyncMock(
        return_value=task.model_copy(update={"status": "dispatch_unknown"})
    )
    orch.session_memory.assert_signed_authorization = AsyncMock()
    orch.session_memory.push_task_queue = AsyncMock()
    orch.task_scheduler = scheduler
    orch._tasks = {}
    orch._assign_task = AsyncMock()
    with pytest.raises(WorkflowException, match="snapshot"):
        if entrypoint == "scheduler":
            await scheduler.schedule_task(task)
        else:
            await Orchestrator.schedule_task(orch, task)
    orch.session_memory.store_task.assert_awaited_once()
    orch.session_memory.push_task_queue.assert_not_awaited()
    orch.coordination_bus.publish.assert_not_awaited()
    orch.graph_memory.upsert_task.assert_not_awaited()
    assert orch._tasks == {}
    orch._assign_task.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("entrypoint", ["scheduler", "orchestrator"])
@pytest.mark.parametrize("failure", ["graph_bus", "redis_queue"])
async def test_signed_schedule_proceeds_through_graph_and_bus_outages(
    entrypoint,
    failure,
):
    scheduler, task, orch, _, _ = harness()
    orch._bind_task_authorization = AsyncMock()
    orch.session_memory.load_task_authoritative = AsyncMock(return_value=task)
    orch.session_memory.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=2)
    )
    orch.session_memory.push_task_queue = AsyncMock()
    orch.task_scheduler = scheduler
    orch._tasks = {}
    orch._assign_task = AsyncMock()
    scheduler._assign_task = AsyncMock()
    orch.graph_memory.upsert_task.side_effect = OSError("graph down")
    orch.coordination_bus.publish.side_effect = OSError("bus down")
    if failure == "redis_queue":
        orch.session_memory.push_task_queue.side_effect = OSError("redis down")

    if entrypoint == "scheduler":
        await scheduler.schedule_task(task)
        scheduler._assign_task.assert_awaited_once()
    else:
        await Orchestrator.schedule_task(orch, task)
        orch._assign_task.assert_awaited_once()
    orch.session_memory.store_task.assert_awaited_once()
    orch.session_memory.assert_signed_authorization.assert_awaited_once_with(
        task.engagement_id, expected_version=2
    )
    orch.session_memory.push_task_queue.assert_awaited_once()
