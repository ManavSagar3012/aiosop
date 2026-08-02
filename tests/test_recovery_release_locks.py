"""Unit tests for RecoveryService.recover_state — agent lock release.

Phase-1 issue #5 fix: when the orchestrator restarts, every agent that was
mid-execution on the prior process left a stale Redis busy-set entry +
``lock:agent:<id>`` lock. These survived until the 30s TTL, shrinking the
agent pool immediately after every restart. recover_state() now releases every
registered agent's claim at the start of recovery.

These tests pin that behaviour with stubs — no Redis, no Neo4j.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.orchestrator.recovery_service import RecoveryService


def _agent(agent_id: str, status: str = "running"):
    """Build a fake agent whose ctx has the fields _release_agent touches."""
    return SimpleNamespace(ctx=SimpleNamespace(agent_id=agent_id, status=status))


def _orch(agents):
    """Build a bare orchestrator shell with the attrs recover_state touches."""
    orch = SimpleNamespace()
    orch._agents = {a.ctx.agent_id: a for a in agents}
    orch._sessions = {}
    orch._tasks = {}

    # session_memory stubs
    sm = SimpleNamespace()
    sm.list_all_sessions = AsyncMock(return_value=[])
    sm.list_pending_approvals = AsyncMock(return_value=[])
    sm.load_all_active_tasks = AsyncMock(return_value=[])
    sm.remove_busy_agent = AsyncMock(return_value=None)
    sm.release_lock = AsyncMock(return_value=None)
    orch.session_memory = sm

    # graph_memory stub
    gm = SimpleNamespace()
    gm.upsert_task = AsyncMock(return_value=None)
    orch.graph_memory = gm

    # dlq stub
    orch.dlq = SimpleNamespace()
    orch.dlq.enqueue = AsyncMock(return_value=None)

    # task_scheduler stub — _release_agent is the only method touched
    ts = SimpleNamespace()
    ts._release_agent = AsyncMock(return_value=None)
    ts._sanitize_external_payload = MagicMock(return_value=None)
    orch.task_scheduler = ts

    # approval_coordinator stub
    ac = SimpleNamespace()
    ac._register_approval = AsyncMock(return_value=None)
    ac._await_approval_outcome = AsyncMock(return_value=None)
    orch.approval_coordinator = ac

    return orch


@pytest.mark.asyncio
async def test_recovery_releases_stale_agent_locks_on_startup():
    """Every registered agent must have its claim released at recovery start."""
    agents = [_agent("agent-a"), _agent("agent-b"), _agent("agent-c")]
    orch = _orch(agents)

    rs = RecoveryService(orch, MagicMock())
    report = await rs.recover_state()

    # _release_agent called once per registered agent.
    assert orch.task_scheduler._release_agent.await_count == 3
    called_ids = {call.args[0] for call in orch.task_scheduler._release_agent.await_args_list}
    assert called_ids == {"agent-a", "agent-b", "agent-c"}
    # Recovery completed without raising.
    assert report == {"engagements": 0, "tasks": 0, "approvals": 0, "exhausted": 0}


@pytest.mark.asyncio
async def test_recovery_continues_when_one_agent_release_fails():
    """A Redis blip releasing ONE agent must not abort recovery for the rest."""
    agents = [_agent("agent-a"), _agent("agent-b"), _agent("agent-c")]
    orch = _orch(agents)
    # Make the second release raise.
    call_count = {"n": 0}

    async def flaky_release(agent_id):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("simulated redis timeout")

    orch.task_scheduler._release_agent = AsyncMock(side_effect=flaky_release)

    rs = RecoveryService(orch, MagicMock())
    report = await rs.recover_state()

    # All three release attempts were made (recovery did not abort).
    assert call_count["n"] == 3
    # Recovery still completed and returned its report.
    assert report == {"engagements": 0, "tasks": 0, "approvals": 0, "exhausted": 0}


@pytest.mark.asyncio
async def test_recovery_skips_agents_without_id():
    """An agent whose ctx.agent_id is None is silently skipped — cannot release
    a lock with no key, and should not crash recovery."""
    agents = [_agent("agent-a"), SimpleNamespace(ctx=SimpleNamespace(agent_id=None, status="running"))]
    orch = _orch([agents[0]])  # only the named agent is in _agents
    # Add the id-less agent directly so it iterates.
    orch._agents["nameless"] = agents[1]

    rs = RecoveryService(orch, MagicMock())
    await rs.recover_state()

    # Only the named agent was released.
    assert orch.task_scheduler._release_agent.await_count == 1
    assert orch.task_scheduler._release_agent.await_args_list[0].args[0] == "agent-a"


@pytest.mark.asyncio
async def test_recovery_release_runs_before_session_restore():
    """The lock-release pass MUST run first, so the agent pool is fully
    available the instant session/task restore completes."""
    agents = [_agent("agent-a")]
    orch = _orch(agents)

    # Track call order: release -> list_sessions -> list_approvals -> load_tasks.
    order: list[str] = []

    async def track_release(agent_id):
        order.append("release")

    orch.task_scheduler._release_agent = AsyncMock(side_effect=track_release)

    async def track_sessions():
        order.append("sessions")
        return []

    orch.session_memory.list_all_sessions = AsyncMock(side_effect=track_sessions)

    async def track_approvals():
        order.append("approvals")
        return []

    orch.session_memory.list_pending_approvals = AsyncMock(side_effect=track_approvals)

    async def track_tasks():
        order.append("tasks")
        return []

    orch.session_memory.load_all_active_tasks = AsyncMock(side_effect=track_tasks)

    rs = RecoveryService(orch, MagicMock())
    await rs.recover_state()

    assert order == ["release", "sessions", "approvals", "tasks"]
