"""Unit tests for RecoveryService.

Tests reaper audit, stuck-task recovery, and restart recovery.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from ai_osop.core.enums import AgentType
from ai_osop.core.models import AuditEvent, Task
from ai_osop.orchestrator.recovery_service import RecoveryService


class TestReaperAudit:
    """Tests for the _reaper_audit static method."""

    def test_returns_audit_event(self):
        task = Task(type="scan", agent_type=AgentType.RECON, priority=5, engagement_id="eng-1")
        event = RecoveryService._reaper_audit(task, 42.0, "recovering")
        assert isinstance(event, AuditEvent)
        assert event.event_type == "task_reaped"
        assert event.severity == "warning"
        assert event.actor_type == "system"
        assert event.actor_id == "orchestrator-reaper"
        assert event.engagement_id == "eng-1"

    def test_action_contains_task_metadata(self):
        task = Task(
            id="task-abc123",
            type="exploit_validation",
            agent_type=AgentType.EXPLOIT_VALIDATION,
            priority=9,
            engagement_id="eng-2",
            timeout_seconds=120,
            status="running",
        )
        event = RecoveryService._reaper_audit(task, 99.5, "failed")
        action = event.action
        assert action["task_id"] == "task-abc123"
        assert action["prior_status"] == "running"
        assert action["age_seconds"] == 99
        assert action["outcome"] == "failed"

    def test_age_rounded_to_int(self):
        task = Task(type="scan", agent_type=AgentType.RECON, priority=5, engagement_id="eng-1")
        event = RecoveryService._reaper_audit(task, 3.14159, "recovering")
        assert event.action["age_seconds"] == 3

    def test_result_reaped_true(self):
        task = Task(type="scan", agent_type=AgentType.RECON, priority=5, engagement_id="eng-1")
        event = RecoveryService._reaper_audit(task, 10.0, "failed")
        assert event.result == {"reaped": True}

    def test_context(self):
        task = Task(type="scan", agent_type=AgentType.RECON, priority=5, engagement_id="eng-99")
        event = RecoveryService._reaper_audit(task, 5.0, "recovering")
        assert event.context == {"engagement_id": "eng-99"}


class TestReapStuckTasks:

    async def test_empty(self):
        orch = MagicMock()
        orch._tasks = {}
        orch._running = False
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        assert await svc._reap_stuck_tasks() == 0

    async def test_pending_is_skipped(self):
        task = Task(
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="pending",
            started_at=datetime.utcnow(),
        )
        orch = MagicMock()
        orch._tasks = {"t1": task}
        orch._running = False
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        assert await svc._reap_stuck_tasks() == 0
        assert task.status == "pending"

    async def test_running_within_timeout(self):
        task = Task(
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="running",
            started_at=datetime.utcnow(),
            timeout_seconds=300,
        )
        orch = MagicMock()
        orch._tasks = {"t1": task}
        orch._running = False
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        assert await svc._reap_stuck_tasks() == 0

    async def test_reaps_stuck_no_retries(self):
        task = Task(
            id="t1",
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="running",
            started_at=datetime.utcnow() - timedelta(seconds=600),
            timeout_seconds=300,
            retry_count=3,
            max_retries=3,
        )
        orch = MagicMock()
        orch._tasks = {"t1": task}
        orch._running = False
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        assert await svc._reap_stuck_tasks() == 1
        assert task.status == "failed"
        assert "reaper timeout" in (task.result or {}).get("error", "")

    async def test_retries_when_available(self):
        task = Task(
            id="t2",
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="running",
            started_at=datetime.utcnow() - timedelta(seconds=600),
            timeout_seconds=300,
            retry_count=0,
            max_retries=3,
        )
        orch = MagicMock()
        orch._tasks = {"t2": task}
        orch._running = False
        import asyncio

        orch._task_handles = {"t2": asyncio.Future()}

        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        assert await svc._reap_stuck_tasks() == 1
        orch.task_scheduler._maybe_retry.assert_awaited_once()

    async def test_terminal_synced_is_skipped(self):
        task = Task(
            id="t1",
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="completed",
        )
        orch = MagicMock()
        orch._tasks = {"t1": task}
        orch._running = False
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        svc._graph_terminal_synced.add("t1")
        assert await svc._reap_stuck_tasks() == 0
        orch.graph_memory.upsert_task.assert_not_awaited()

    async def test_terminal_unsynced_triggers_upsert(self):
        task = Task(
            id="t1",
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="completed",
            result={"status": "completed"},
        )
        orch = MagicMock()
        orch._tasks = {"t1": task}
        orch._running = False
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.acquire_lock = AsyncMock(return_value=True)
        orch.session_memory.release_lock = AsyncMock(return_value=True)
        orch._audit_log = AsyncMock()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock()
        svc = RecoveryService(orch)
        assert await svc._reap_stuck_tasks() == 0
        orch.graph_memory.upsert_task.assert_awaited_once()
        assert "t1" in svc._graph_terminal_synced


class TestRecoverState:

    async def test_empty(self):
        orch = MagicMock()
        orch._agents = {}
        orch._sessions = {}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=[])
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        r = await svc.recover_state()
        assert r == {
            "engagements": 0,
            "tasks": 0,
            "approvals": 0,
            "exhausted": 0,
            "skipped_terminal_phase": 0,
            "skipped_orphaned": 0,
        }

    async def test_releases_stale_agent_locks(self):
        agent = MagicMock()
        agent.ctx.agent_id = "agent-1"
        orch = MagicMock()
        orch._agents = {"recon": agent}
        orch._sessions = {}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=[])
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        await svc.recover_state()
        orch.task_scheduler._release_agent.assert_awaited_once_with("agent-1")

    async def test_restores_sessions(self):
        session = MagicMock()
        session.session_id = "s1"
        orch = MagicMock()
        orch._agents = {}
        orch._sessions = {}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=["session:s1"])
        orch.session_memory.get_session_state = AsyncMock(return_value=session)
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        r = await svc.recover_state()
        assert r["engagements"] == 1
        assert "s1" in orch._sessions

    async def test_restores_pending_approvals(self):
        apr = MagicMock()
        apr.id = "apr-1"
        orch = MagicMock()
        orch._agents = {}
        orch._sessions = {}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.task_scheduler._sanitize_external_payload = MagicMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=[])
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[apr])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[])
        orch.session_memory.push_task_queue = AsyncMock()
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        r = await svc.recover_state()
        assert r["approvals"] == 1
        orch.approval_coordinator._register_approval.assert_awaited_once_with(apr)

    async def test_restores_pending_task(self):
        task = Task(
            id="t1",
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="pending",
        )
        # AIOSOP-RECOVERY-ORPHAN-001: a recovered task needs a live engagement
        # session, else the orphan gate cancels it as a ghost. Seed one for eng-1.
        session = MagicMock()
        session.session_id = "eng-1"
        session.canonical_engagement_id = "eng-1"
        session.phase = "reconnaissance"
        orch = MagicMock()
        orch._agents = {}
        orch._sessions = {"eng-1": session}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.task_scheduler._sanitize_external_payload = MagicMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=[])
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[task])
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.push_task_queue = AsyncMock()
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        r = await svc.recover_state()
        assert r["tasks"] == 1
        assert "t1" in orch._tasks
        assert orch._tasks["t1"].assigned_agent_id is None

    async def test_exhausted_after_max_recovery(self):
        task = Task(
            id="t1",
            type="scan",
            agent_type=AgentType.RECON,
            priority=5,
            engagement_id="eng-1",
            status="running",
            payload={"_recovery_attempts": 3},
        )
        # Orphan gate (AIOSOP-RECOVERY-ORPHAN-001): seed a live session so the
        # exhausted task reaches the recovery-attempt cap rather than being
        # cancelled as a ghost before the cap is evaluated.
        session = MagicMock()
        session.session_id = "eng-1"
        session.canonical_engagement_id = "eng-1"
        session.phase = "reconnaissance"
        orch = MagicMock()
        orch._agents = {}
        orch._sessions = {"eng-1": session}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.task_scheduler._sanitize_external_payload = MagicMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=[])
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[task])
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.push_task_queue = AsyncMock()
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        r = await svc.recover_state()
        assert r["exhausted"] == 1
        assert orch._tasks["t1"].status == "failed"
        orch.dlq.enqueue.assert_awaited_once()

    async def test_exploit_reattaches_approval(self):
        task = Task(
            id="t1",
            type="validate_exploit",
            agent_type=AgentType.EXPLOIT_VALIDATION,
            priority=9,
            engagement_id="eng-1",
            status="pending",
            approval_required=False,
        )
        # Orphan gate (AIOSOP-RECOVERY-ORPHAN-001): seed a live session so the
        # exploit task is recovered (and re-gated for approval) instead of being
        # cancelled as a ghost.
        session = MagicMock()
        session.session_id = "eng-1"
        session.canonical_engagement_id = "eng-1"
        session.phase = "exploitation"
        orch = MagicMock()
        orch._agents = {}
        orch._sessions = {"eng-1": session}
        orch._tasks = {}
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._release_agent = AsyncMock()
        orch.task_scheduler._sanitize_external_payload = MagicMock()
        orch.session_memory = MagicMock()
        orch.session_memory.list_all_sessions = AsyncMock(return_value=[])
        orch.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        orch.session_memory.load_all_active_tasks = AsyncMock(return_value=[task])
        orch.session_memory.store_task = AsyncMock()
        orch.session_memory.push_task_queue = AsyncMock()
        orch.graph_memory = MagicMock()
        orch.graph_memory.upsert_task = AsyncMock()
        orch.approval_coordinator = MagicMock()
        orch.approval_coordinator._register_approval = AsyncMock()
        orch.approval_coordinator._await_approval_outcome = AsyncMock()
        orch.dlq = MagicMock()
        orch.dlq.enqueue = AsyncMock()
        svc = RecoveryService(orch)
        await svc.recover_state()
        assert orch._tasks["t1"].approval_required is True
