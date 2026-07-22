"""Safety regression tests for the approval authority (GAP-2-1, GAP-2-2, GAP-2-3).

These encode the invariant that an exploit-class task can NEVER reach an agent
unless an ApprovalRequest for it was resolved 'approved' by a named operator.
The mutable task.payload['operator_approved'] field must never be trusted.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import scope_signing_key
from ai_osop.core.enums import AgentType
from ai_osop.core.models import ApprovalRequest, ScopeDefinition, Task
from ai_osop.orchestrator.approval_coordinator import ApprovalCoordinator
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def _signed_session(phase: str = "exploitation", engagement_id: str = "eng-1"):
    """A session whose scope is signed exactly as engagement_manager does in
    production, so the task_scheduler's fail-closed scope-signature gate passes
    and the test can exercise the approval/phase logic it actually targets
    (previously these tasks were rejected at the scope gate before reaching it)."""
    scope = ScopeDefinition(engagement_id=engagement_id, domains=["victim.example"], ips=[])
    scope.sign(scope_signing_key())
    return SimpleNamespace(phase=phase, scope=scope)


class _Orch:
    """Minimal orchestrator wiring real TaskScheduler + ApprovalCoordinator."""

    def __init__(self):
        self._tasks = {}
        self._approval_requests = {}
        self._agents = {}
        # Default engagement has a signed scope + exploitation phase so the
        # scope-signature gate passes; phase tests override this explicitly.
        self._sessions = {"eng-1": _signed_session(phase="exploitation")}
        self._approval_callbacks = []
        self.rate_limiter = None
        self.temporal_enabled = False
        self.temporal_scheduler = None
        self.session_memory = AsyncMock()
        self.graph_memory = AsyncMock()
        self.coordination_bus = AsyncMock()
        self.task_scheduler = TaskScheduler(self)
        self.approval_coordinator = ApprovalCoordinator(self)
        # Inject a mock state_machine to avoid NoneType errors in task assignment
        from unittest.mock import MagicMock

        from ai_osop.core.enums import EngagementPhase
        from ai_osop.core.exceptions import WorkflowException

        self.task_scheduler.state_machine = MagicMock()

        def _mock_assert_task_allowed(task, phase):
            if phase != EngagementPhase.EXPLOITATION and task.type == "exploit_validation":
                raise WorkflowException(f"Task {task.type} not allowed in phase {phase.value}")

        self.task_scheduler.state_machine.assert_task_allowed = _mock_assert_task_allowed

    async def _audit_log(self, event):
        pass

    async def _retry_sleep(self, seconds):
        pass

    async def _assign_task(self, task):
        await self.task_scheduler._assign_task(task)


def _exploit_task(**payload_extra):
    payload = {"target": "https://victim.example", "vulnerability_id": "v1"}
    payload.update(payload_extra)
    return Task(
        type="exploit_validation",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        payload=payload,
        engagement_id="eng-1",
    )


async def test_agent_self_authorized_queue_task_is_parked(monkeypatch):
    """GAP-2-1: an agent-injected, self-'approved' exploit task pushed to the queue
    must be stripped + parked for approval, never dispatched."""
    orch = _Orch()
    task = _exploit_task(operator_approved=True, approval_id="sim-v1")
    # arrives via the untrusted queue boundary
    await orch.task_scheduler.ingest_queued_task(task)

    assert task.approval_required is True
    assert "operator_approved" not in task.payload  # self-grant stripped
    assert "approval_id" not in task.payload
    assert task.status == "awaiting_approval"


async def test_gate_ignores_tampered_payload():
    """GAP-2-2: even bypassing ingestion, a tampered payload.operator_approved must
    not satisfy the gate — authority is the ApprovalRequest record."""
    orch = _Orch()
    task = _exploit_task(operator_approved=True, approval_id="forged")
    task.approval_required = True
    orch._tasks[task.id] = task
    # No approved ApprovalRequest exists for this task.
    assert orch.approval_coordinator.is_task_approved(task.id) is False
    await orch.task_scheduler._assign_task(task)
    assert task.status == "awaiting_approval"


async def test_real_operator_approval_allows_dispatch():
    """Positive path: a genuinely operator-approved request satisfies the gate."""
    orch = _Orch()
    task = _exploit_task()
    task.approval_required = True
    orch._tasks[task.id] = task
    req = ApprovalRequest(
        task_id=task.id,
        agent_id="",
        action_type=task.type,
        target="t",
        payload_summary="s",
        risk_assessment="high",
        engagement_id="eng-1",
        status="approved",
        operator_id="alice",
    )
    orch._approval_requests[req.id] = req

    assert orch.approval_coordinator.is_task_approved(task.id) is True
    await orch.task_scheduler._assign_task(task)
    # No agent registered -> falls through to pending, but crucially NOT parked.
    assert task.status != "awaiting_approval"


async def test_exploit_task_refused_outside_exploitation_phase():
    """GAP-3-1: an exploit task must not dispatch while the engagement is in RECON,
    even if it has a valid operator approval."""
    orch = _Orch()
    orch._sessions["eng-1"] = _signed_session(phase="reconnaissance")
    task = _exploit_task()
    task.approval_required = True
    orch._tasks[task.id] = task
    req = ApprovalRequest(
        task_id=task.id,
        agent_id="",
        action_type=task.type,
        target="t",
        payload_summary="s",
        risk_assessment="high",
        engagement_id="eng-1",
        status="approved",
        operator_id="alice",
    )
    orch._approval_requests[req.id] = req  # genuinely approved...

    await orch.task_scheduler._assign_task(task)
    # ...but wrong phase -> refused, not dispatched.
    assert task.status == "failed"


async def test_exploit_task_allowed_in_exploitation_phase():
    """Positive: same task in EXPLOITATION is not phase-blocked."""
    orch = _Orch()
    orch._sessions["eng-1"] = _signed_session(phase="exploitation")
    task = _exploit_task()
    task.approval_required = True
    orch._tasks[task.id] = task
    req = ApprovalRequest(
        task_id=task.id,
        agent_id="",
        action_type=task.type,
        target="t",
        payload_summary="s",
        risk_assessment="high",
        engagement_id="eng-1",
        status="approved",
        operator_id="alice",
    )
    orch._approval_requests[req.id] = req
    await orch.task_scheduler._assign_task(task)
    assert task.status != "failed"  # no agent -> pending, but not phase-blocked


class _RecoveryOrch(_Orch):
    def __init__(self, active_tasks):
        super().__init__()
        self.dlq = AsyncMock()
        self.session_memory.list_all_sessions = AsyncMock(return_value=[])
        self.session_memory.list_pending_approvals = AsyncMock(return_value=[])
        self.session_memory.load_all_active_tasks = AsyncMock(return_value=active_tasks)
        self.session_memory.push_task_queue = AsyncMock()
        self.recovery_service = RecoveryService(self)


async def test_recovery_strips_persisted_approval():
    """GAP-2-3: a persisted operator_approved on an exploit task must be stripped and
    the task re-gated for approval after restart."""
    task = _exploit_task(operator_approved=True, approval_id="stale")
    task.approval_required = True
    task.status = "running"
    orch = _RecoveryOrch([task])

    await orch.recovery_service.recover_state()

    assert task.approval_required is True
    assert "operator_approved" not in task.payload
    assert "approval_id" not in task.payload
    assert task.status == "pending"  # re-queued for re-approval
    assert orch.approval_coordinator.is_task_approved(task.id) is False


async def test_recovery_attempt_cap_dead_letters_poison_task():
    """GAP-4-5: a task past the recovery cap is failed + dead-lettered, not resurrected."""
    task = _exploit_task()
    task.approval_required = True
    task.status = "running"
    task.payload["_recovery_attempts"] = RecoveryService.MAX_RECOVERY_ATTEMPTS
    orch = _RecoveryOrch([task])

    await orch.recovery_service.recover_state()

    assert task.status == "failed"
    orch.dlq.enqueue.assert_awaited_once()


async def test_approval_record_requires_operator_id():
    """An 'approved' record with no operator_id is not authority (defensive)."""
    orch = _Orch()
    task = _exploit_task()
    req = ApprovalRequest(
        task_id=task.id,
        agent_id="",
        action_type=task.type,
        target="t",
        payload_summary="s",
        risk_assessment="high",
        engagement_id="eng-1",
        status="approved",
        operator_id=None,
    )
    orch._approval_requests[req.id] = req
    assert orch.approval_coordinator.is_task_approved(task.id) is False
