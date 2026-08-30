"""Tests for the Tool Reality scheduling gate (TOOL-REALITY-001).

Charter section 4: never tell the user a capability exists solely because an
adapter class exists — and never DISPATCH a task whose required tool is down.
Observed live: a burp_scan against a dead burp-mcp burned 3 retries into an
open circuit breaker and failed opaquely. The scheduler must instead park the
task as `blocked`, revive it when the tool recovers, and fail it with an
actionable reason if the tool stays down.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import asyncio

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def _task(task_type: str, tid: str = "task-tr-1") -> Task:
    return Task(
        id=tid,
        type=task_type,
        agent_type=AgentType.VULN_ANALYSIS,
        engagement_id="eng-tool-reality",
        payload={"url": "https://target.example/"},
        scope_check=False,
        approval_required=False,
    )


def _scheduler_with_server(ready: bool, circuit_open: bool = False, registered: bool = True):
    sched = TaskScheduler.__new__(TaskScheduler)
    sched._orch = MagicMock()
    sched._orch.rate_limiter = None
    sched._orch._sessions = {}
    sched._blocked_tasks = {}
    sched._block_reaper_started = False
    sched.state_machine = None
    # assign-race-2026-08-30: _assign_task now serializes per task id via
    # _assign_locks (initialized in __init__, which __new__ skips).
    sched._assign_locks = {}

    conn = None
    if registered:
        conn = SimpleNamespace(
            _circuit_open=circuit_open,
            _initialized=True,
            get_state=AsyncMock(return_value=SimpleNamespace(status="ready" if ready else "init")),
        )
    sched._orch.mcp_registry.get_server.return_value = conn
    sched._orch.session_memory.store_task = AsyncMock()
    sched._orch.graph_memory.upsert_task = AsyncMock()
    sched._orch.coordination_bus.publish = AsyncMock()
    sched._on_task_failure = AsyncMock()
    return sched


class TestServerReadyProbe:
    @pytest.mark.asyncio
    async def test_unregistered_server_not_ready(self):
        sched = _scheduler_with_server(ready=False, registered=False)
        ok, detail = await sched._server_ready("burp-mcp")
        assert not ok
        assert "not registered" in detail

    @pytest.mark.asyncio
    async def test_open_circuit_not_ready(self):
        sched = _scheduler_with_server(ready=True, circuit_open=True)
        ok, detail = await sched._server_ready("burp-mcp")
        assert not ok
        assert "circuit breaker open" in detail

    @pytest.mark.asyncio
    async def test_ready_server_passes(self):
        sched = _scheduler_with_server(ready=True)
        ok, detail = await sched._server_ready("nuclei-mcp")
        assert ok and detail == "ready"


class TestAssignmentGate:
    @pytest.mark.asyncio
    async def test_down_tool_blocks_task(self):
        """A burp_scan with burp-mcp DOWN is parked as blocked, NOT dispatched."""
        sched = _scheduler_with_server(ready=False, circuit_open=True)
        task = _task("burp_scan")

        await TaskScheduler._assign_task(sched, task)

        assert task.status == "blocked"
        assert task.result["blocked_on_tool"] == "burp-mcp"
        assert "circuit breaker open" in task.result["reason"]
        assert task.id in sched._blocked_tasks
        # task.blocked event published exactly once for this transition
        topics = [c.args[0] for c in sched._orch.coordination_bus.publish.call_args_list]
        assert "task.blocked" in topics
        # failure path NOT taken (no retry burn, no opaque circuit error)
        sched._on_task_failure.assert_not_called()

    @pytest.mark.asyncio
    async def test_healthy_tool_dispatches_normally(self):
        """nuclei_scan with nuclei-mcp UP passes the gate (dispatch proceeds)."""
        sched = _scheduler_with_server(ready=True)
        task = _task("nuclei_scan")
        task.status = "pending"

        # Downstream dispatch has no live agents in this harness and returns
        # quietly ("no_agent_found") — what matters is that the GATE passed:
        await TaskScheduler._assign_task(sched, task)

        assert task.status != "blocked"
        assert task.id not in sched._blocked_tasks

    @pytest.mark.asyncio
    async def test_unmapped_task_type_ungated(self):
        """Task types without a verified server requirement are not gated."""
        sched = _scheduler_with_server(ready=False, registered=False)
        task = _task("jwt_scan")  # direct HTTP analysis; no MCP requirement

        await TaskScheduler._assign_task(sched, task)

        assert task.status != "blocked"
        assert task.id not in sched._blocked_tasks


class TestBlockReaper:
    @pytest.mark.asyncio
    async def test_reap_pass_revives_when_tool_recovers(self):
        """One reap pass resets a blocked task to pending and re-assigns it."""
        import time

        sched = _scheduler_with_server(ready=False)
        conn = sched._orch.mcp_registry.get_server.return_value
        conn.get_state = AsyncMock(return_value=SimpleNamespace(status="ready"))

        task = _task("burp_scan", tid="task-revive")
        task.status = "blocked"
        task.result = {"status": "blocked", "blocked_on_tool": "burp-mcp", "reason": "x"}
        sched._blocked_tasks[task.id] = (task, time.monotonic())
        reassign = AsyncMock()
        sched._assign_task = reassign  # type: ignore[method-assign]

        await TaskScheduler._reap_blocked_once(sched)
        await asyncio.sleep(0)  # let the create_task'd reassignment start

        assert task.status == "pending"
        assert task.result is None
        assert task.id not in sched._blocked_tasks
        reassign.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_reap_pass_fails_after_max_wait(self):
        """Blocked beyond BLOCK_MAX_WAIT_SEC -> failed with actionable reason."""
        import time

        sched = _scheduler_with_server(ready=False)  # stays down
        task = _task("burp_scan", tid="task-timeout")
        task.result = {"status": "blocked", "blocked_on_tool": "burp-mcp", "reason": "x"}
        parked_at = time.monotonic() - (sched.BLOCK_MAX_WAIT_SEC + 5)
        sched._blocked_tasks[task.id] = (task, parked_at)

        await TaskScheduler._reap_blocked_once(sched)

        assert task.id not in sched._blocked_tasks
        result = sched._on_task_failure.call_args.args[1]
        assert result["error_type"] == "ToolUnavailable"
        assert "remained unavailable" in result["error"]

    @pytest.mark.asyncio
    async def test_reap_pass_keeps_parked_while_down(self):
        """Tool still down within the window -> stays parked untouched."""
        import time

        sched = _scheduler_with_server(ready=False)
        task = _task("burp_scan", tid="task-parked")
        task.status = "blocked"
        task.result = {"status": "blocked", "blocked_on_tool": "burp-mcp", "reason": "x"}
        sched._blocked_tasks[task.id] = (task, time.monotonic())

        await TaskScheduler._reap_blocked_once(sched)

        assert task.id in sched._blocked_tasks
        assert task.status == "blocked"
        sched._on_task_failure.assert_not_called()


def test_requirements_map_only_verified_backends():
    """Guard against speculative mappings that would falsely block tasks."""
    allowed = {
        "burp-mcp",
        "turbo-intruder-mcp",
        "nuclei-mcp",
        "browser-mcp",
        "security-bridge",
        "recon-mcp",
    }
    for ttype, server in TaskScheduler.TASK_TYPE_SERVER_REQUIREMENTS.items():
        assert server in allowed, f"{type} mapped to unknown server {server}"
