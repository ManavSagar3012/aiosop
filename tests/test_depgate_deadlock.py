"""Regression: a terminally-failed dependency must release its pending dependents.

Root cause (AIOSOP-DEPGATE-DEADLOCK-2026-07-26): `authenticate` depends on
`register`; register failed; the SPAWNED graph edge was never persisted so the
graph-only dependent lookup found nothing, and the trigger only ran on
completion — so `authenticate` stayed 'pending' forever, pinning RECONNAISSANCE
(gated on all WORKFLOW tasks being terminal) and yielding 0 findings.

Run: .venv/Scripts/python.exe tests/test_depgate_deadlock.py
"""
import asyncio
import sys

sys.path.insert(0, "src")

from ai_osop.core.enums import AgentType  # noqa: E402
from ai_osop.core.models import Task  # noqa: E402
from ai_osop.orchestrator.task_scheduler import TaskScheduler  # noqa: E402


class _FakeGraph:
    async def get_task_dependents(self, pid):
        return []  # SPAWNED edge never persisted — the real-world condition


class _FakeSessionMemory:
    async def load_all_active_tasks(self):
        return []


class _FakeOrch:
    def __init__(self, tasks):
        self._tasks = tasks
        self.graph_memory = _FakeGraph()
        self.session_memory = _FakeSessionMemory()


async def _run():
    parent = Task(id="task-reg", type="register", agent_type=AgentType.WORKFLOW,
                  engagement_id="e", status="failed")
    child = Task(id="task-auth", type="authenticate", agent_type=AgentType.WORKFLOW,
                 engagement_id="e", status="pending", dependencies=["task-reg"])
    waiting = Task(id="task-wait", type="authenticate", agent_type=AgentType.WORKFLOW,
                   engagement_id="e", status="pending", dependencies=["task-reg", "task-other"])

    orch = _FakeOrch({t.id: t for t in (parent, child, waiting)})
    sched = TaskScheduler.__new__(TaskScheduler)  # skip heavy __init__
    sched._orch = orch

    assigned = []

    async def _fake_assign(t):
        assigned.append(t.id)
    sched._assign_task = _fake_assign

    await sched._trigger_downstream_tasks(parent)

    # child depends only on the failed parent -> released.
    assert "task-auth" in assigned, "failed dependency did not release its dependent"
    # `waiting` still has a non-terminal dep (task-other) -> must NOT be released.
    assert "task-wait" not in assigned, "released a child with an unsatisfied dependency"
    print("depgate deadlock self-check OK: failed dep releases dependent, partial deps still wait")


if __name__ == "__main__":
    asyncio.run(_run())
