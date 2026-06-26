"""Tests for Sprint 9 extracted components."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, PropertyMock

import pytest
import asyncio

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.models import ApprovalRequest, SessionState, Task
from ai_osop.orchestrator.approval_coordinator import ApprovalCoordinator
from ai_osop.orchestrator.engagement_manager import EngagementManager
from ai_osop.orchestrator.phase_monitor import PhaseMonitor
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.orchestrator.task_scheduler import TaskScheduler


class MockOrchestrator:
    """Minimal mock orchestrator for testing extracted components."""

    def __init__(self):
        self._agents = {}
        self._tasks = {}
        self._sessions = {}
        self._approval_requests = {}
        self.session_memory = AsyncMock()
        self.session_memory.acquire_lock = AsyncMock(return_value=True)
        self.session_memory.release_lock = AsyncMock(return_value=True)
        self.session_memory.add_busy_agent = AsyncMock()
        self.session_memory.remove_busy_agent = AsyncMock()
        self.session_memory.is_busy_agent = AsyncMock()
        self.session_memory.store_task = AsyncMock()
        self._running = True
        self.graph_memory = AsyncMock()
        self.graph_memory.upsert_task = AsyncMock()
        self.coordination_bus = AsyncMock()
        self.dlq = AsyncMock()
        self.rate_limiter = None
        self.temporal_enabled = False
        self.temporal_scheduler = None
        self._approval_callbacks = []

    async def _retry_sleep(self, seconds: float) -> None:
        pass

    async def _assign_task(self, task: Any) -> None:
        pass

    async def _audit_log(self, event):
        pass

    async def _schedule_authenticated_discovery(self, *args, **kwargs):
        pass


class TestTaskScheduler:
    @pytest.fixture
    def scheduler(self):
        orch = MockOrchestrator()
        return TaskScheduler(orch)

    async def test_schedule_task_adds_to_tasks(self, scheduler):
        """schedule_task should add task to orchestrator's task dict."""
        task = Task(type="test", agent_type=AgentType.RECON, engagement_id="eng-1")
        result = await scheduler.schedule_task(task)
        assert scheduler._orch._tasks[task.id] == task
        assert result == task

    async def test_find_available_agent_claims_idle_agent(self, scheduler):
        """_find_available_agent should claim an idle agent."""
        mock_agent = MagicMock()
        mock_agent.ctx.agent_id = "agent-1"
        mock_agent.ctx.agent_type = AgentType.RECON
        mock_agent.ctx.status = "idle"
        scheduler._orch._agents["agent-1"] = mock_agent
        result = await scheduler._find_available_agent(AgentType.RECON)
        assert result is mock_agent
        scheduler._orch.session_memory.add_busy_agent.assert_awaited_with("agent-1")
    async def test_release_agent_removes_claim(self, scheduler):
        """_release_agent should remove the agent from busy set."""
        await scheduler._release_agent("agent-1")
        scheduler._orch.session_memory.remove_busy_agent.assert_awaited_with("agent-1")

    async def test_maybe_retry_increments_retry_count(self, scheduler):
        """_maybe_retry should increment retry_count and requeue."""
        task = Task(type="test", agent_type=AgentType.RECON, engagement_id="eng-1", retry_count=0, max_retries=3)
        scheduler._orch._tasks[task.id] = task
        scheduler._orch.graph_memory.upsert_task = AsyncMock()
        scheduler._orch.session_memory.store_task = AsyncMock()
        scheduler._orch._assign_task = AsyncMock()
        scheduler._orch._retry_sleep = AsyncMock()

        result = await scheduler._maybe_retry(task, {"error": "test"})
        assert result is True
        assert task.retry_count == 1

    async def test_maybe_retry_exhausted_sends_to_dlq(self, scheduler):
        """_maybe_retry should send to DLQ when retries exhausted."""
        task = Task(type="test", agent_type=AgentType.RECON, engagement_id="eng-1", retry_count=3, max_retries=3)
        scheduler._orch.dlq.enqueue = AsyncMock()
        result = await scheduler._maybe_retry(task, {"error": "test"})
        assert result is False
        scheduler._orch.dlq.enqueue.assert_awaited_once()

    async def test_strip_stale_approval_removes_keys(self, scheduler):
        """_strip_stale_approval should remove approval keys from payload."""
        task = Task(type="test", agent_type=AgentType.RECON, engagement_id="eng-1")
        task.approval_required = True
        task.payload = {"operator_approved": True, "approval_id": "apr-1", "other": "data"}
        TaskScheduler._strip_stale_approval(task)
        assert "operator_approved" not in task.payload
        assert "approval_id" not in task.payload
        assert task.payload["other"] == "data"


class TestApprovalCoordinator:
    @pytest.fixture
    def coordinator(self):
        orch = MockOrchestrator()
        return ApprovalCoordinator(orch)

    async def test_register_approval_adds_to_dict(self, coordinator):
        """_register_approval should add request to orchestrator's approval dict."""
        request = ApprovalRequest(
            task_id="task-1", agent_id="agent-1", action_type="test", target="http://test.com", engagement_id="eng-1",
            payload_summary="summary", risk_assessment="low"
        )
        coordinator._orch.session_memory.store_approval_request = AsyncMock()
        await coordinator._register_approval(request)
        assert coordinator._orch._approval_requests[request.id] == request

    async def test_strip_stale_approval_removes_keys(self, coordinator):
        """_strip_stale_approval should remove approval keys from payload."""
        task = Task(type="test", agent_type=AgentType.RECON, engagement_id="eng-1")
        task.approval_required = True
        task.payload = {"operator_approved": True, "approval_id": "apr-1"}
        ApprovalCoordinator._strip_stale_approval(task)
        assert "operator_approved" not in task.payload
        assert "approval_id" not in task.payload


class TestEngagementManager:
    @pytest.fixture
    def manager(self):
        orch = MockOrchestrator()
        return EngagementManager(orch)

    async def test_create_engagement_adds_to_sessions(self, manager):
        """create_engagement should add session to orchestrator's sessions dict."""
        from ai_osop.core.models import ScopeDefinition
        scope = ScopeDefinition(engagement_id="test-eng", domains=["example.com"])
        manager._orch.session_memory.store_session_state = AsyncMock()
        manager._orch.session_memory.persist_session_state = AsyncMock()
        result = await manager.create_engagement(scope, {}, created_by="tester")
        assert manager._orch._sessions[result.session_id] == result
        assert result.scope == scope

    async def test_halt_engagement_cancels_tasks(self, manager):
        """halt_engagement should cancel pending tasks."""
        task = Task(type="test", agent_type=AgentType.RECON, engagement_id="eng-1", status="pending")
        manager._orch._tasks[task.id] = task
        manager._orch._sessions["eng-1"] = MagicMock()
        manager._orch._sessions["eng-1"].scope.engagement_id = "eng-1"
        manager._orch._sessions["eng-1"].phase = "initialized"
        manager._orch.session_memory.store_session_state = AsyncMock()
        await manager.halt_engagement("eng-1", "test reason")
        assert task.status == "cancelled"


class TestPhaseMonitor:
    @pytest.fixture
    def monitor(self):
        orch = MockOrchestrator()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler.schedule_task = AsyncMock()
        return PhaseMonitor(orch)

    async def test_on_phase_enter_recon_creates_tasks(self, monitor):
        """_on_phase_enter should create recon tasks for RECONNAISSANCE phase."""
        from ai_osop.core.models import ScopeDefinition
        scope = ScopeDefinition(engagement_id="test-eng", domains=["example.com"])
        session = SessionState(session_id="eng-1", scope=scope, roe={}, phase="initialized")
        monitor._orch.engagement_manager = MagicMock()
        monitor._orch.engagement_manager.ensure_authenticated_discovery = AsyncMock()
        await monitor._on_phase_enter(session, EngagementPhase.RECONNAISSANCE)
        monitor._orch.task_scheduler.schedule_task.assert_awaited()


class TestRecoveryService:
    @pytest.fixture
    def service(self):
        orch = MockOrchestrator()
        orch.task_scheduler = MagicMock()
        orch.task_scheduler._maybe_retry = AsyncMock(return_value=True)
        return RecoveryService(orch)

    async def test_reap_stuck_tasks_fails_expired_pending(self, service):
        """_reap_stuck_tasks should fail tasks that have exceeded their timeout."""
        from datetime import datetime, timedelta
        task = Task(
            type="test", agent_type=AgentType.RECON, engagement_id="eng-1",
            status="pending", created_at=datetime.utcnow() - timedelta(seconds=400),
            timeout_seconds=300
        )
        service._orch._tasks[task.id] = task
        service._orch.graph_memory.upsert_task = AsyncMock()
        service._orch._audit_log = AsyncMock()
        reaped = await service._reap_stuck_tasks()
        assert reaped == 1
        assert task.status == "failed"
