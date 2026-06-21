"""Unit tests for the Reliability sprint: stuck-task reaper + restart recovery."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import Orchestrator


def _orch():
    orch = Orchestrator(AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock())
    orch.rate_limiter = AsyncMock()
    orch._audit_log = AsyncMock()
    orch.graph_memory.upsert_task = AsyncMock()
    return orch


def _fake_agent(agent_id="recon-1", agent_type=AgentType.RECON):
    """An idle agent whose execute_task blocks until released, so we can observe the
    window between selection and completion (P0-1)."""
    agent = MagicMock()
    agent.ctx = MagicMock()
    agent.ctx.agent_id = agent_id
    agent.ctx.agent_type = agent_type
    agent.ctx.status = "idle"
    agent.supports_task_type = MagicMock(return_value=True)
    agent._gate = asyncio.Event()
    agent.calls = []

    async def _execute(task):
        agent.calls.append(task.id)
        await agent._gate.wait()
        return {"status": "success"}

    agent.execute_task = AsyncMock(side_effect=_execute)
    return agent


def _stuck(status="running", age=120, max_retries=0, retry_count=0):
    t = Task(
        type="capture_authenticated_surface",
        priority=5,
        agent_type=AgentType.WORKFLOW,
        payload={},
        engagement_id="e",
        max_retries=max_retries,
        timeout_seconds=1,
    )
    t.status = status
    t.retry_count = retry_count
    when = datetime.utcnow() - timedelta(seconds=age)
    if status == "running":
        t.started_at = when
    else:
        t.created_at = when
    return t


# ----------------------------------------------------------------- Part B: reaper


@pytest.mark.asyncio
async def test_reaper_fails_stuck_running_without_budget():
    orch = _orch()
    t = _stuck(status="running", age=120, max_retries=0)
    orch._tasks[t.id] = t

    n = await orch._reap_stuck_tasks()

    assert n == 1 and t.status == "failed"
    orch.graph_memory.upsert_task.assert_awaited()
    orch._audit_log.assert_awaited()
    assert orch._audit_log.call_args.args[0].event_type == "task_reaped"


@pytest.mark.asyncio
async def test_reaper_recovers_stuck_running_with_budget():
    orch = _orch()
    orch._maybe_retry = AsyncMock(return_value=True)
    t = _stuck(status="running", age=120, max_retries=3, retry_count=0)
    orch._tasks[t.id] = t

    n = await orch._reap_stuck_tasks()

    assert n == 1
    orch._maybe_retry.assert_awaited_once()


@pytest.mark.asyncio
async def test_reaper_fails_stuck_pending():
    orch = _orch()
    t = _stuck(status="pending", age=120, max_retries=0)
    orch._tasks[t.id] = t

    n = await orch._reap_stuck_tasks()

    assert n == 1 and t.status == "failed"


@pytest.mark.asyncio
async def test_reaper_ignores_fresh_and_done_tasks():
    orch = _orch()
    fresh = _stuck(status="running", age=0, max_retries=0)
    done = _stuck(status="completed", age=999)
    orch._tasks[fresh.id] = fresh
    orch._tasks[done.id] = done

    n = await orch._reap_stuck_tasks()

    assert n == 0 and fresh.status == "running"


# ------------------------------------------------------------- Part C: recovery


@pytest.mark.asyncio
async def test_recover_state_resets_running_and_resumes_chain():
    orch = _orch()
    orch.schedule_task = AsyncMock()
    orch._persist_task_dependency = AsyncMock()
    orch.graph_memory.reset_interrupted_tasks = AsyncMock(
        return_value=[{"id": "t1", "type": "map_workflow", "engagement_id": "e"}]
    )
    orch.graph_memory.find_incomplete_chains = AsyncMock(
        return_value=[
            {
                "id": "cap1",
                "type": "capture_authenticated_surface",
                "engagement_id": "e",
                "result_summary": '{"har_path":"/vault/user_a.har","workflow_id":"wf1","user_label":"user_a"}',
            }
        ]
    )
    orch.graph_memory.task_has_spawned = AsyncMock(return_value=False)

    summary = await orch.recover_state()

    assert summary["interrupted_reset"] == 1
    assert summary["chains_resumed"] == 1
    child = orch.schedule_task.call_args.args[0]
    assert child.type == "extract_har_api_inventory"
    assert child.payload["har_path"] == "/vault/user_a.har"
    assert child.dependencies == ["cap1"]
    # interrupted reset emits a task_recovered audit; chain resume emits chain_resumed.
    etypes = {c.args[0].event_type for c in orch._audit_log.call_args_list}
    assert "task_recovered" in etypes and "chain_resumed" in etypes


@pytest.mark.asyncio
async def test_recover_skips_chain_already_spawned():
    orch = _orch()
    orch.schedule_task = AsyncMock()
    orch._persist_task_dependency = AsyncMock()
    orch.graph_memory.reset_interrupted_tasks = AsyncMock(return_value=[])
    orch.graph_memory.find_incomplete_chains = AsyncMock(
        return_value=[
            {
                "id": "cap1",
                "type": "capture_authenticated_surface",
                "engagement_id": "e",
                "result_summary": '{"har_path":"/x.har"}',
            }
        ]
    )
    orch.graph_memory.task_has_spawned = AsyncMock(return_value=True)  # already chained

    summary = await orch.recover_state()

    assert summary["chains_resumed"] == 0
    orch.schedule_task.assert_not_called()


# ---- AIOSOP-AUDIT-2026-06-16: interrupted-task RE-DISPATCH ----


@pytest.mark.asyncio
async def test_recover_redispatches_interrupted_task():
    """A fully-persisted interrupted task is reconstructed and re-dispatched."""
    orch = _orch()
    orch.schedule_task = AsyncMock()
    orch._assign_task = AsyncMock()
    orch.graph_memory.find_incomplete_chains = AsyncMock(return_value=[])
    orch.graph_memory.reset_interrupted_tasks = AsyncMock(
        return_value=[
            {
                "id": "t1",
                "type": "full_recon",
                "engagement_id": "e",
                "agent_type": "recon",
                "payload": '{"target":"example.com"}',
                "priority": 5,
                "max_retries": 3,
                "timeout_seconds": 300,
                "recovery_attempts": 1,
            }
        ]
    )

    summary = await orch.recover_state()

    assert summary["interrupted_reset"] == 1
    assert summary["redispatched"] == 1
    assert summary["failed_over_cap"] == 0
    orch.schedule_task.assert_awaited()
    orch._assign_task.assert_awaited()
    task = orch.schedule_task.call_args.args[0]
    assert task.id == "t1" and task.type == "full_recon"
    assert task.payload["target"] == "example.com"


@pytest.mark.asyncio
async def test_recover_fails_task_over_attempt_cap():
    """A task that has exceeded the recovery cap is failed, not re-dispatched."""
    orch = _orch()
    orch.schedule_task = AsyncMock()
    orch._assign_task = AsyncMock()
    orch.graph_memory.mark_task_status = AsyncMock()
    orch.graph_memory.find_incomplete_chains = AsyncMock(return_value=[])
    orch.graph_memory.reset_interrupted_tasks = AsyncMock(
        return_value=[
            {
                "id": "poison",
                "type": "full_recon",
                "engagement_id": "e",
                "agent_type": "recon",
                "payload": "{}",
                "priority": 5,
                "max_retries": 3,
                "timeout_seconds": 300,
                "recovery_attempts": orch.MAX_RECOVERY_ATTEMPTS + 1,
            }
        ]
    )

    summary = await orch.recover_state()

    assert summary["failed_over_cap"] == 1
    assert summary["redispatched"] == 0
    orch.schedule_task.assert_not_called()
    orch.graph_memory.mark_task_status.assert_awaited_with("poison", "failed")


# ---- P0 concurrency fixes: claim model, non-blocking approval, fresh-approval-on-recovery, single retry ----


@pytest.mark.asyncio
async def test_agent_claimed_synchronously_prevents_double_assign():
    """P0-1: two back-to-back _assign_task calls for the same agent_type with one idle
    agent must not drive that agent concurrently. The 2nd task must be left pending."""
    orch = _orch()
    orch.coordination_bus = AsyncMock()
    agent = _fake_agent(agent_id="recon-1", agent_type=AgentType.RECON)
    orch._agents[agent.ctx.agent_id] = agent

    t1 = Task(
        type="full_recon", priority=5, agent_type=AgentType.RECON, payload={}, engagement_id="e"
    )
    t2 = Task(
        type="full_recon", priority=5, agent_type=AgentType.RECON, payload={}, engagement_id="e"
    )
    orch._tasks[t1.id] = t1
    orch._tasks[t2.id] = t2

    # First assignment claims the (only) idle agent; its execute_task blocks on the gate.
    await orch._assign_task(t1)
    # Second assignment, before the first finishes, must NOT get the same agent.
    await orch._assign_task(t2)
    await asyncio.sleep(0)  # let the dispatched coroutine start execute_task

    assert agent.ctx.agent_id in orch._busy_agents
    assert t1.status == "running" and t1.assigned_agent_id == "recon-1"
    assert t2.status == "pending" and t2.assigned_agent_id is None

    # Release the first task; the claim must be freed in the finally.
    agent._gate.set()
    for _ in range(20):
        await asyncio.sleep(0.01)
        if agent.ctx.agent_id not in orch._busy_agents:
            break
    assert agent.ctx.agent_id not in orch._busy_agents
    # The agent was only ever driven by ONE task concurrently.
    assert agent.calls == [t1.id]


@pytest.mark.asyncio
async def test_approval_required_task_does_not_block_scheduler():
    """P0-3: an approval-required task is parked in awaiting_approval and _assign_task
    returns promptly (no awaiting the full approval timeout); a normal task can still
    be assigned afterwards."""
    orch = _orch()
    orch.coordination_bus = AsyncMock()
    exploit_agent = _fake_agent(agent_id="exp-1", agent_type=AgentType.EXPLOIT_VALIDATION)
    recon_agent = _fake_agent(agent_id="recon-1", agent_type=AgentType.RECON)
    orch._agents[exploit_agent.ctx.agent_id] = exploit_agent
    orch._agents[recon_agent.ctx.agent_id] = recon_agent

    exploit_task = Task(
        type="exploit_validation",
        priority=9,
        agent_type=AgentType.EXPLOIT_VALIDATION,
        approval_required=True,
        payload={"target": "http://x"},
        engagement_id="e",
    )
    recon_task = Task(
        type="full_recon", priority=5, agent_type=AgentType.RECON, payload={}, engagement_id="e"
    )
    orch._tasks[exploit_task.id] = exploit_task
    orch._tasks[recon_task.id] = recon_task

    # Must return promptly (NOT block ~1800s on the approval timeout).
    await asyncio.wait_for(orch._assign_task(exploit_task), timeout=2.0)
    assert exploit_task.status == "awaiting_approval"
    assert exploit_task.assigned_agent_id is None
    # An ApprovalRequest was raised for the operator.
    assert any(r.task_id == exploit_task.id for r in orch._approval_requests.values())
    # The exploit agent was never claimed/driven by the parked task.
    assert exploit_agent.ctx.agent_id not in orch._busy_agents
    assert exploit_agent.calls == []

    # A different task can still be assigned while approval pends.
    await orch._assign_task(recon_task)
    await asyncio.sleep(0)
    assert recon_task.status == "running" and recon_task.assigned_agent_id == "recon-1"
    recon_agent._gate.set()


@pytest.mark.asyncio
async def test_recovered_exploit_task_requires_fresh_approval():
    """P1-2: a previously-approved exploit task reconstructed via the recovery path must
    have its approval stripped so _assign_task's gate re-fires (no autonomous re-run)."""
    orch = _orch()
    orch.coordination_bus = AsyncMock()
    orch.schedule_task = AsyncMock()
    orch._assign_task = AsyncMock()
    orch.graph_memory.find_incomplete_chains = AsyncMock(return_value=[])
    orch.graph_memory.reset_interrupted_tasks = AsyncMock(
        return_value=[
            {
                "id": "exp1",
                "type": "exploit_validation",
                "engagement_id": "e",
                "agent_type": "exploit_validation",
                # Persisted payload carries a STALE approval grant (or could be tampered).
                "payload": '{"target":"http://x","operator_approved":true,"approval_id":"old-apr"}',
                "priority": 9,
                "max_retries": 3,
                "timeout_seconds": 300,
                "recovery_attempts": 0,
            }
        ]
    )

    summary = await orch.recover_state()

    assert summary["redispatched"] == 1
    task = orch.schedule_task.call_args.args[0]
    assert task.type == "exploit_validation"
    assert task.approval_required is True
    # The stale approval must be gone so the gate re-fires.
    assert "operator_approved" not in task.payload
    assert "approval_id" not in task.payload


@pytest.mark.asyncio
async def test_single_retry_owner():
    """P0-2: a failing task is retried exactly once per failure — retry_count increments
    by 1 (the orchestrator's _maybe_retry is the sole retry owner; the agent no longer
    self-schedules a duplicate retry)."""
    orch = _orch()
    orch.coordination_bus = AsyncMock()
    orch._retry_sleep = AsyncMock()  # skip backoff
    orch._assign_task = AsyncMock()  # stop the re-dispatch chain after one retry

    task = Task(
        type="full_recon",
        priority=5,
        agent_type=AgentType.RECON,
        payload={},
        engagement_id="e",
        max_retries=3,
    )
    task.retry_count = 0
    orch._tasks[task.id] = task

    # A single failure feeds _maybe_retry exactly once.
    requeued = await orch._maybe_retry(task, {"status": "failed", "error": "boom"})

    assert requeued is True
    assert task.retry_count == 1  # incremented by 1, not 2
    orch._assign_task.assert_awaited_once()


@pytest.mark.asyncio
async def test_agent_does_not_self_schedule_retry(monkeypatch):
    """P0-2 (agent side): BaseAgent.execute_task no longer pushes a retry onto its
    internal _task_queue on failure — it returns a failure dict for the orchestrator
    to own the retry decision."""
    from ai_osop.agents.base import BaseAgent

    pushed = []

    class _Agent(BaseAgent):
        @property
        def agent_type(self):
            return AgentType.RECON

        async def _setup_resources(self):
            pass

        async def _cleanup_resources(self):
            pass

        async def _execute(self, task):
            raise RuntimeError("boom")

    ctx = MagicMock()
    ctx.agent_id = "recon-1"
    ctx.agent_type = AgentType.RECON
    ctx.rate_limiter = AsyncMock()
    ctx.audit_callback = AsyncMock()
    ctx.session_memory = AsyncMock()
    agent = _Agent(ctx)
    monkeypatch.setattr(agent._task_queue, "put", AsyncMock(side_effect=lambda t: pushed.append(t)))

    task = Task(
        type="full_recon",
        priority=5,
        agent_type=AgentType.RECON,
        payload={},
        engagement_id="e",
        max_retries=3,
    )
    result = await agent.execute_task(task)

    assert result["status"] == "failed"
    assert pushed == []  # no self-scheduled retry requeue
    assert task.retry_count == 0  # agent no longer mutates retry_count
