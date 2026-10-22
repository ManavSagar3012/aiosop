"""Restart Redis hint follows one current signed PostgreSQL authority snapshot.

Deterministic row-lock/transaction surrogate for the *real* SessionMemory-backed
recovery path. No application DB, Redis service, network or target is accessed.
These tests deliberately mutate the durable rows AFTER the original startup
list/ROE/Flow reads to model a second process winning the revocation/CAS race.
The final agent/Temporal claim is separately covered by existing tests.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.models import FlowRecord
from ai_osop.memory import authorization_store
from ai_osop.memory.supervision_store import SupervisionStore
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_signed_recovery_gate import _harness


class _Result:
    def __init__(self, row):
        self.row = row

    def scalar_one_or_none(self):
        return self.row

    def all(self):
        return self.row


class _Sql:
    """Minimal transaction-aware ORM fixture with PostgreSQL locking checks."""

    def __init__(self, task):
        self.task = SimpleNamespace(**{
            name: getattr(task, name)
            for name in (
                "id", "engagement_id", "status", "type", "flow_id", "subtask_id",
                "parent_task_id", "dependencies", "approval_required", "priority",
                "retry_count", "scope_check", "max_retries", "timeout_seconds",
                "created_at", "payload",
            )
        })
        self.task.agent_type = task.agent_type.value
        self.flow = SimpleNamespace(
            id=task.flow_id, engagement_id=task.engagement_id,
            status="running", revision=3,
        )
        self.step = SimpleNamespace(
            id=task.subtask_id, execution_task_id=task.id,
            task_id=task.parent_task_id, status="dispatched",
            task_type=task.type, approval_required=task.approval_required,
        )
        self.dependencies = [(item, "completed") for item in task.dependencies]
        self.approval = SimpleNamespace(
            operator_id="human-test-senior", responded_at=datetime.utcnow(),
            evidence=pinned_evidence([], task.payload),
        )
        self.active = False
        self.reads = []

    async def __aenter__(self):
        self.active = True
        return self

    async def __aexit__(self, *exc):
        self.active = False

    def begin(self):
        return self

    async def execute(self, stmt):
        assert self.active, "Every authoritative PG read must share the queue transaction"
        assert getattr(stmt, "_for_update_arg", None) is not None
        assert stmt._for_update_arg.read is True
        sql = str(stmt)
        if "FROM execution_flows" in sql:
            kind, value = "flow", self.flow
        elif "FROM execution_subtasks" in sql:
            kind, value = "step", self.step
        elif "FROM approval_requests" in sql:
            kind, value = "approval", self.approval
        elif "FROM tasks" in sql and " IN (" in sql:
            kind, value = "dependencies", self.dependencies
        elif "FROM tasks" in sql:
            kind, value = "task", self.task
        else:
            raise AssertionError(f"Unrecognized authoritative query: {sql}")
        self.reads.append(kind)
        return _Result(value)


def _recovery(monkeypatch, *, flow=True, subtask=False, dependency=False, approved=False):
    recovery, memory = _harness()
    task = memory.list_all_tasks.return_value[0]
    if flow:
        task.flow_id = "flow-recovery-current"
        task.payload["_flow_revision"] = 3
    if subtask:
        task.subtask_id = "subtask-recovery-current"
        task.parent_task_id = "task-recovery-parent"
    if dependency:
        task.dependencies = ["task-completed-authoritative"]
    if approved:
        task.status = "awaiting_approval"
        task.approval_required = True
        task.payload.update({"approval_id": "apr-recovery-current", "operator_approved": True})
        memory.is_task_approved = AsyncMock(return_value=True)
    sql = _Sql(task)
    memory._async_session = lambda: sql
    memory.load_flow = AsyncMock(return_value=FlowRecord(
        id=task.flow_id, engagement_id=task.engagement_id,
        status="running", revision=3, objective="Recovery flow",
    )) if flow else AsyncMock()

    async def active_guard(db, engagement_id, *, require_window):
        assert db is sql and sql.active and require_window
        assert engagement_id == task.engagement_id
        return SimpleNamespace(phase="reconnaissance"), None

    async def current_roe(db, engagement_id, expected_version=None):
        assert db is sql and sql.active
        assert engagement_id == task.engagement_id
        assert expected_version == task.payload["_authorization_version"]
        return SimpleNamespace(version=expected_version)

    monkeypatch.setattr(SupervisionStore, "_guard", staticmethod(active_guard))
    monkeypatch.setattr(authorization_store, "guard_sql", current_roe)

    async def queue_hint(queue, payload):
        assert sql.active, "Redis hint must be published before PG authority unlocks"
        assert queue == "tasks:" + task.engagement_id
        assert payload["id"] == task.id

    memory.push_task_queue = AsyncMock(side_effect=queue_hint)
    return recovery, memory, task, sql


@pytest.mark.asyncio
async def test_fresh_signed_flow_subtask_dependencies_and_approved_human_publish_under_pg_locks(
    monkeypatch,
):
    recovery, memory, task, sql = _recovery(
        monkeypatch, flow=True, subtask=True, dependency=True, approved=True,
    )
    result = await recovery.recover_state()
    assert result["tasks"] == 1 and result["skipped"] == 0
    assert sql.reads == ["task", "flow", "step", "dependencies", "approval"]
    memory.push_task_queue.assert_awaited_once()
    assert task.status == "awaiting_approval"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "claimed_unknown", "payload_changed", "different_tenant", "flow_paused",
        "flow_revision_changed", "step_reassigned", "step_no_longer_dispatched",
        "dependency_incomplete", "dependency_foreign", "grant_revoked",
        "approval_unpinned", "human_no_actor",
    ],
)
async def test_restart_refuses_stale_queue_after_concurrent_signed_cas(
    monkeypatch, change,
):
    recovery, memory, task, sql = _recovery(
        monkeypatch, flow=True, subtask=True, dependency=True, approved=True,
    )
    # Original startup reads remain good; the second worker changes actual
    # committed rows before the transaction-bound prequeue recheck.
    if change == "claimed_unknown":
        sql.task.status = "dispatch_unknown"
    elif change == "payload_changed":
        sql.task.payload = {**sql.task.payload, "url": "https://changed.example.test"}
    elif change == "different_tenant":
        sql.task.engagement_id = "eng-foreign"
    elif change == "flow_paused":
        sql.flow.status = "paused"
    elif change == "flow_revision_changed":
        sql.flow.revision += 1
    elif change == "step_reassigned":
        sql.step.execution_task_id = "task-another-tenant"
    elif change == "step_no_longer_dispatched":
        sql.step.status = "dispatch_unknown"
    elif change == "dependency_incomplete":
        sql.dependencies = [(task.dependencies[0], "running")]
    elif change == "dependency_foreign":
        sql.dependencies = []
    elif change == "grant_revoked":
        sql.approval = None
    elif change == "approval_unpinned":
        sql.approval.evidence = []
    elif change == "human_no_actor":
        sql.approval.operator_id = None

    result = await recovery.recover_state()
    assert result["tasks"] == 0 and result["skipped"] == 1
    memory.push_task_queue.assert_not_awaited()
    # Recovery is an advisory publisher; no changed/unknown Task is ever
    # rewritten or transformed into a retry by the recovery path.
    assert task.status == "awaiting_approval"
    assert not sql.active


@pytest.mark.asyncio
async def test_parent_not_yet_done_keeps_pending_task_durable_without_queue(monkeypatch):
    recovery, memory, task, sql = _recovery(monkeypatch, dependency=True, flow=True)
    sql.dependencies = [(task.dependencies[0], "running")]
    result = await recovery.recover_state()
    assert result["tasks"] == 0 and result["skipped"] == 1
    assert task.status == "pending"
    memory.push_task_queue.assert_not_awaited()


@pytest.mark.asyncio
async def test_redis_publish_failure_rolls_back_locked_hint_without_resubmission(monkeypatch):
    recovery, memory, task, sql = _recovery(monkeypatch, flow=True)
    memory.push_task_queue.side_effect = OSError("Redis ACK unknown after publish")
    result = await recovery.recover_state()
    assert result["tasks"] == 0 and result["skipped"] == 1
    assert memory.push_task_queue.await_count == 1
    assert not sql.active and task.status == "pending"


@pytest.mark.asyncio
async def test_signer_revoked_between_warm_check_and_locked_recovery_read(monkeypatch):
    recovery, memory, task, sql = _recovery(monkeypatch, flow=True)

    async def revoked_during_transaction(db, engagement_id, expected_version=None):
        assert db is sql and sql.active
        raise PermissionError("Signer revoked after initial startup precheck")

    monkeypatch.setattr(authorization_store, "guard_sql", revoked_during_transaction)
    result = await recovery.recover_state()
    assert result["tasks"] == 0 and result["skipped"] == 1
    memory.assert_signed_authorization.assert_awaited_once()
    memory.push_task_queue.assert_not_awaited()
    assert task.status == "pending" and not sql.active


@pytest.mark.asyncio
async def test_unsigned_approval_grant_on_non_approval_task_cannot_be_queued(monkeypatch):
    recovery, memory, task, sql = _recovery(monkeypatch, flow=True)
    task.payload.update({"approval_id": "apr-untrusted", "operator_approved": True})
    sql.task.payload = dict(task.payload)
    result = await recovery.recover_state()
    assert result["tasks"] == 0 and result["skipped"] == 1
    memory.push_task_queue.assert_not_awaited()
