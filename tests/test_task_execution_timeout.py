"""Hang guard: agent execution must be time-bounded (benchmark 2026-07-05).

Root cause of 0/372 tasks ever completing: `_execute_via_agent` awaited
`agent.execute_task` with NO timeout, so an agent hung on an unbounded external
call (LLM/MCP/browser) pinned its task at 'running' forever and never released
the agent. These tests pin the guarantee that every execution reaches a terminal
state within the task timeout.
"""
import asyncio
import time
import types

from unittest.mock import AsyncMock, MagicMock

from ai_osop.orchestrator.task_scheduler import TaskScheduler
from ai_osop.core.models import Task, AgentType


def _orch():
    o = MagicMock()
    o.graph_memory.upsert_task = AsyncMock()
    o.session_memory = AsyncMock()
    o.coordination_bus.publish = AsyncMock()
    o.dlq.enqueue = AsyncMock()
    o._audit_log = AsyncMock()
    o._task_handles = {}
    o._tasks = {}
    o._sessions = {}
    return o


class _HangingAgent:
    def __init__(self):
        self.ctx = types.SimpleNamespace(agent_id="agent-x", agent_type=AgentType.RECON)

    async def execute_task(self, task):
        await asyncio.sleep(60)  # never returns within the task timeout


class _FastAgent:
    def __init__(self):
        self.ctx = types.SimpleNamespace(agent_id="agent-y", agent_type=AgentType.RECON)

    async def execute_task(self, task):
        return {"status": "success", "ok": True}


def test_hanging_agent_fails_within_timeout():
    sched = TaskScheduler(_orch())
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e",
                timeout_seconds=1, max_retries=0)
    t0 = time.time()
    asyncio.run(sched._execute_via_agent(_HangingAgent(), task))
    elapsed = time.time() - t0
    assert task.status == "failed", f"expected failed, got {task.status}"
    assert elapsed < 8, f"must not hang; took {elapsed:.1f}s"
    assert "timeout" in str(task.result).lower()


def test_fast_agent_still_completes():
    sched = TaskScheduler(_orch())
    task = Task(type="full_recon", agent_type=AgentType.RECON, engagement_id="e",
                timeout_seconds=30, max_retries=0)
    asyncio.run(sched._execute_via_agent(_FastAgent(), task))
    assert task.status == "completed", f"expected completed, got {task.status}"
