"""Restart-recovery must NOT resurrect tasks of a terminal-phase engagement.

Root cause of live agent-pool starvation: recover_state() re-queued every
non-terminal task across all engagements. A revived abandoned engagement then
regenerated fresh work and starved live engagements. The phase-gate skips
tasks whose engagement is completed/halted.
"""
import asyncio
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.recovery_service import RecoveryService


def _fake_session(eng_id: str, phase: str):
    # recover_state's phase map only reads these three attributes.
    return SimpleNamespace(
        session_id=eng_id, canonical_engagement_id=eng_id, phase=phase
    )


def _make_orch(sessions, tasks):
    orch = SimpleNamespace()
    orch._running = True
    orch._agents = {}
    orch._sessions = {s.session_id: s for s in sessions}
    orch._tasks = {}
    orch.graph_memory = SimpleNamespace(upsert_task=AsyncMock())
    orch.dlq = SimpleNamespace(enqueue=AsyncMock())
    orch.session_memory = SimpleNamespace(
        list_all_sessions=AsyncMock(return_value=[]),
        list_pending_approvals=AsyncMock(return_value=[]),
        load_all_active_tasks=AsyncMock(return_value=tasks),
        store_task=AsyncMock(),
        push_task_queue=AsyncMock(),
    )
    orch.task_scheduler = SimpleNamespace(_release_agent=AsyncMock())
    return orch


async def _run():
    halted = _fake_session("eng-halted", "halted")
    active = _fake_session("eng-active", "reconnaissance")
    t_halt = Task(type="csrf_scan", agent_type=AgentType.WORKFLOW,
                  engagement_id="eng-halted", status="running")
    t_active = Task(type="register", agent_type=AgentType.WORKFLOW,
                    engagement_id="eng-active", status="pending")

    orch = _make_orch([halted, active], [t_halt, t_active])
    svc = RecoveryService(orch, state_machine=SimpleNamespace())
    recovered = await svc.recover_state()

    # terminal-phase task: cancelled, not tracked, not queued
    assert t_halt.status == "cancelled", t_halt.status
    assert t_halt.id not in orch._tasks
    assert recovered["skipped_terminal_phase"] == 1, recovered
    # active-phase task: recovered normally
    assert t_active.id in orch._tasks
    assert recovered["tasks"] == 1, recovered
    orch.session_memory.push_task_queue.assert_awaited()  # only the active one
    assert orch.session_memory.push_task_queue.await_count == 1


def test_terminal_phase_tasks_not_resurrected():
    asyncio.run(_run())


if __name__ == "__main__":
    asyncio.run(_run())
    print("ok")
