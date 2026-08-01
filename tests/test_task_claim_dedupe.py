"""AIOSOP-TASKCLAIM-001: the same task must dispatch to exactly ONE agent.

_find_available_agent locks the AGENT, not the task. The same task existed as
two objects (in-memory pending scan + a Redis-queue copy, plus the retry path
that re-queues AND re-assigns), so each claimed a different idle agent and ran
concurrently — same identity on the shared browser, all timing out at 180s.
An NX lock keyed by task id serialises dispatch; the loser releases its agent
and drops out. The lock is freed on terminal completion so legit retries run.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler


class _FakeLocks:
    """In-memory NX lock with real set-if-absent semantics (no await between
    check and set, so it is atomic on the single-threaded event loop, exactly
    like Redis SET NX)."""

    def __init__(self):
        self._locks = {}

    async def acquire_lock(self, key, value="locked", ttl_seconds=30, ttl=None):
        if key in self._locks:
            return False
        self._locks[key] = value
        return True

    async def release_lock(self, key, value):
        if self._locks.get(key) == value:
            del self._locks[key]
            return True
        return False


def _fake_agent(agent_id):
    ctx = SimpleNamespace(agent_id=agent_id, agent_type=AgentType.WORKFLOW, status="idle")
    return SimpleNamespace(ctx=ctx)


def _make_scheduler(n_agents=3):
    locks = _FakeLocks()
    sm = SimpleNamespace(
        acquire_lock=locks.acquire_lock,
        release_lock=locks.release_lock,
        add_busy_agent=AsyncMock(),
        remove_busy_agent=AsyncMock(),
        store_task=AsyncMock(),
    )
    orch = SimpleNamespace(
        _agents={f"a{i}": _fake_agent(f"a{i}") for i in range(n_agents)},
        _sessions={},
        _tasks={},
        _task_handles={},
        session_memory=sm,
        graph_memory=SimpleNamespace(upsert_task=AsyncMock()),
        coordination_bus=SimpleNamespace(publish=AsyncMock()),
    )
    sched = TaskScheduler(orch, state_machine=SimpleNamespace())
    return sched, orch


async def _drain(orch):
    if orch._task_handles:
        await asyncio.gather(*list(orch._task_handles.values()))


async def _run():
    sched, orch = _make_scheduler(n_agents=3)

    dispatched = []

    async def fake_exec(agent, task):
        dispatched.append(agent.ctx.agent_id)
        # Mirror the real finally: free the agent AND the task claim.
        await sched._release_agent(agent.ctx.agent_id)
        await sched._release_task_claim(task.id)

    sched._execute_via_agent = fake_exec

    task = Task(type="register", agent_type=AgentType.WORKFLOW,
                engagement_id="eng-x", status="pending", timeout_seconds=180)

    # Two copies of the SAME task id dispatched concurrently (the live bug).
    await asyncio.gather(sched._assign_task(task), sched._assign_task(task))
    await _drain(orch)
    assert len(dispatched) == 1, f"double-dispatch not prevented: {dispatched}"

    # After the winner freed the claim, a legitimate retry must dispatch again.
    orch._task_handles.clear()
    await sched._assign_task(task)
    await _drain(orch)
    assert len(dispatched) == 2, f"claim not released for retry: {dispatched}"

    print("OK: single dispatch under contention, retry allowed after release")


def test_task_claim_dedupe():
    asyncio.run(_run())


def _mk(task_type: str, **kw) -> Task:
    return Task(
        type=task_type,
        priority=5,
        agent_type=kw.pop("agent_type", AgentType.RECON),
        payload={},
        engagement_id="eng-x",
        **kw,
    )


def test_dangerous_markers_force_approval_gate():
    """AIOSOP-APPROVAL-SURFACE-001: every dangerous-class task name variant must be flagged."""
    ts = TaskScheduler.__new__(TaskScheduler)
    for t in (
        "exploit",
        "validate_exploit",
        "exploit_validation",
        "exploit_chain",
        "sqlmap_scan",
        "rce_trigger",
        "shell_upload",
        "sqli_deep",
        "privesc_check",
        "data_exfiltration",
        "backdoor_install",
        "lateral_movement",
    ):
        assert ts._is_dangerous_task(_mk(t)) is True, t


def test_harmless_types_do_not_trigger_gate():
    ts = TaskScheduler.__new__(TaskScheduler)
    for t in ("full_recon", "subdomain_enum", "map_workflow", "http_probe", "spa_harvest"):
        assert ts._is_dangerous_task(_mk(t)) is False, t


def test_exploit_validation_agent_type_always_gates():
    ts = TaskScheduler.__new__(TaskScheduler)
    assert ts._is_dangerous_task(_mk("history_import", agent_type=AgentType.EXPLOIT_VALIDATION)) is True


if __name__ == "__main__":
    test_task_claim_dedupe()
