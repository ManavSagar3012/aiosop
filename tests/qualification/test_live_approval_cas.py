"""Actual multi-connection PostgreSQL approval CAS and signed revocation tests.

Opt-in against an isolated, disposable pgvector Postgres only; no app store,
network scan, Redis, remote provider, or paid model is needed.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.config import settings
from ai_osop.core.models import ApprovalRequest
from ai_osop.memory.authorization_store import AuthorizationStore, AuthorizationDenied
from ai_osop.memory.session_memory import (
    SessionMemory, SessionStateORM, TaskORM, ApprovalRequestORM,
    ExecutionFlowORM, ExecutionSubtaskORM,
)
from ai_osop.memory.supervision_store import (
    SupervisionConflict, SupervisionEventORM, SupervisionOutboxORM, SupervisionStore,
)
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelUsageLedger
from ai_osop.api.deps import state
from ai_osop.api.routers.approvals import router as approvals_router
from ai_osop.orchestrator.orchestrator import Orchestrator
from tests.test_authorization_store import make_signed_session


def _url():
    uri = os.environ.get("OSOP_APPROVAL_CAS_TEST_PG_URI")
    if not uri:
        pytest.skip("Disposable approval CAS PostgreSQL not configured")
    url = make_url(uri)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"127.0.0.1", "localhost"}
        or url.port in {None, 5432, 5433, 15645}
        or not str(url.database or "").startswith("approval_cas_qualification_")
    ):
        pytest.fail("Refusing non-disposable approval qualification database")
    return uri


def _migrate(conn):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = conn
    command.upgrade(config, "head")


@pytest.fixture
async def live(monkeypatch):
    engine = create_async_engine(_url(), pool_size=6, max_overflow=0)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_migrate)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:12]
        sid = "eng-approval-cas-" + nonce
        signed_session, verified, _, _ = make_signed_session(
            monkeypatch, session_id=sid, authorization_id="auth-approval-" + nonce
        )
        signed_session.phase = "reconnaissance"
        memory = SessionMemory()
        memory._async_session = factory
        memory.store_hot = AsyncMock()
        auth = AuthorizationStore(memory)
        await auth.create_authorized_session(
            signed_session, verified, signed_session.created_by,
        )
        task_id = "task-appr-" + nonce
        request = ApprovalRequest(
            id="apr-cas-" + nonce,
            task_id=task_id, agent_id="agent-recon",
            action_type="summarize_context", target="unknown",
            payload_summary="internal summary", risk_assessment="low",
            engagement_id=sid,
        )
        async with factory() as db, db.begin():
            db.add(TaskORM(
                id=task_id, type="summarize_context", priority=5,
                agent_type=AgentType.CONTEXT_MANAGER.value,
                engagement_id=sid,
                payload={"_authorization_version": verified.version},
                dependencies=[], max_retries=0, timeout_seconds=60,
                scope_check=True, approval_required=True,
                status="awaiting_approval", result=None, retry_count=0,
                created_at=datetime.utcnow(),
            ))
        await memory.store_approval_request(request)
        yield memory, factory, auth, request
    finally:
        await engine.dispose()


def second_worker(memory, factory):
    second = SessionMemory()
    second._async_session = factory
    second.store_hot = AsyncMock()
    return second


@pytest.mark.asyncio
async def test_live_chain_parent_recovery_uses_pg_without_graph_and_blocks_legacy_duplicate(live):
    """Completed SQL parent is discoverable with no Neo4j node/edge at all."""
    memory, factory, _, request = live
    eid = request.engagement_id
    parent_id = "task-chain-parent-" + uuid.uuid4().hex[:12]
    child_id = "task-chain-legacy-" + uuid.uuid4().hex[:12]
    async with factory() as db, db.begin():
        db.add(TaskORM(
            id=parent_id, type="map_workflow", priority=7,
            agent_type=AgentType.WORKFLOW.value, engagement_id=eid,
            payload={"url": "https://authorized.example/", "_authorization_version": 1},
            dependencies=[], max_retries=0, timeout_seconds=60,
            scope_check=True, approval_required=False, status="completed",
            result={"workflow_id": "workflow-qual"}, retry_count=0,
            created_at=datetime.utcnow(), completed_at=datetime.utcnow(),
        ))
    fresh_replica = second_worker(memory, factory)
    hints = await fresh_replica.list_recoverable_signed_chain_parents()
    assert any(item["id"] == parent_id and item["engagement_id"] == eid for item in hints)

    # Older children lacked parent_task_id; their immutable JSON dependency
    # still proves admission and must prevent a second automated child.
    async with factory() as db, db.begin():
        db.add(TaskORM(
            id=child_id, type="capture_authenticated_surface", priority=6,
            agent_type=AgentType.WORKFLOW.value, engagement_id=eid,
            payload={"url": "https://authorized.example/", "_authorization_version": 1},
            dependencies=[parent_id], max_retries=0, timeout_seconds=60,
            scope_check=True, approval_required=False, status="pending",
            retry_count=0, created_at=datetime.utcnow(),
        ))
    after = await fresh_replica.list_recoverable_signed_chain_parents()
    assert all(item["id"] != parent_id for item in after)


@pytest.mark.asyncio
async def test_live_temporal_parent_must_complete_in_same_tenant_before_claim(live):
    """A stale Redis-completed predecessor never authorizes Temporal start."""
    memory, factory, _, request = live
    parent_id = "task-qual-parent-" + uuid.uuid4().hex[:12]
    async with factory() as db, db.begin():
        db.add(TaskORM(
            id=parent_id, type="summarize_context", priority=5,
            agent_type=AgentType.CONTEXT_MANAGER.value,
            engagement_id=request.engagement_id,
            payload={"_authorization_version": 1},
            dependencies=[], max_retries=0, timeout_seconds=60,
            scope_check=True, approval_required=False,
            status="pending", retry_count=0, created_at=datetime.utcnow(),
        ))
        await db.execute(update(TaskORM).where(
            TaskORM.id == request.task_id,
        ).values(dependencies=[parent_id]))
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-verified",
    )
    candidate = await memory.load_task_authoritative(request.task_id)
    assert candidate.dependencies == [parent_id]
    with pytest.raises(PermissionError, match="dependencies"):
        await memory.claim_temporal_dispatch(candidate)
    # No irreversible one-shot reservation or event was created.
    assert (await memory.load_task_authoritative(request.task_id)).status == "awaiting_approval"
    async with factory() as db, db.begin():
        await db.execute(update(TaskORM).where(
            TaskORM.id == parent_id,
        ).values(status="completed", completed_at=datetime.utcnow()))
    assert (await memory.claim_temporal_dispatch(candidate)).startswith("temporal-claim-")
    with pytest.raises(PermissionError, match="already claimed"):
        await second_worker(memory, factory).claim_temporal_dispatch(candidate)


@pytest.mark.asyncio
async def test_live_pending_timeout_rechecks_parent_completion_with_locked_sql(live):
    """A recent parent success cannot make an old child immediately expire."""
    memory, factory, _, request = live
    parent_id = "task-reaper-parent-" + uuid.uuid4().hex[:12]
    cutoff = datetime.utcnow() - timedelta(seconds=60)
    async with factory() as db, db.begin():
        db.add(TaskORM(
            id=parent_id, type="summarize_context", priority=5,
            agent_type=AgentType.CONTEXT_MANAGER.value,
            engagement_id=request.engagement_id,
            payload={"_authorization_version": 1},
            dependencies=[], max_retries=0, timeout_seconds=60,
            scope_check=True, approval_required=False,
            status="completed", retry_count=0,
            created_at=datetime.utcnow()-timedelta(hours=2),
            completed_at=datetime.utcnow(),
        ))
        await db.execute(update(TaskORM).where(
            TaskORM.id == request.task_id,
        ).values(
            status="pending", dependencies=[parent_id],
            created_at=datetime.utcnow()-timedelta(hours=1),
        ))
    assert not await memory.expire_pending_task_atomic(
        request.task_id, request.engagement_id, created_before=cutoff,
    )
    assert (await memory.load_task_authoritative(request.task_id)).status == "pending"
    async with factory() as db, db.begin():
        await db.execute(update(TaskORM).where(
            TaskORM.id == parent_id,
        ).values(completed_at=datetime.utcnow()-timedelta(minutes=5)))
    assert await memory.expire_pending_task_atomic(
        request.task_id, request.engagement_id, created_before=cutoff,
    )
    assert (await memory.load_task_authoritative(request.task_id)).status == "failed"


@pytest.mark.asyncio
async def test_live_temporal_flow_subtask_lineage_is_fenced_in_claim(live):
    """Mismatched persisted subtask identity blocks a valid signed approval."""
    memory, factory, _, request = live
    fid = "flow-qual-lineage-" + uuid.uuid4().hex[:12]
    sid = "subtask-qual-lineage-" + uuid.uuid4().hex[:12]
    parent_id = "task-qual-main-" + uuid.uuid4().hex[:12]
    now = datetime.utcnow()
    async with factory() as db, db.begin():
        db.add(ExecutionFlowORM(
            id=fid, engagement_id=request.engagement_id,
            objective="Local synthetic signed Flow lineage qualification",
            status="running", revision=2, created_at=now, updated_at=now,
        ))
        db.add(ExecutionSubtaskORM(
            id=sid, engagement_id=request.engagement_id, flow_id=fid,
            task_id=parent_id, title="Internal summary",
            description="Synthetic safe local context only",
            task_type="summarize_context",
            agent_type=AgentType.CONTEXT_MANAGER.value,
            approval_required=True, order=0, dependencies=[],
            status="dispatched", refinement_count=0,
            execution_task_id="task-foreign-substitution",
            created_at=now, updated_at=now,
        ))
        await db.execute(update(TaskORM).where(
            TaskORM.id == request.task_id,
        ).values(flow_id=fid, subtask_id=sid, parent_task_id=parent_id))
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-verified",
    )
    task = await memory.load_task_authoritative(request.task_id)
    with pytest.raises(PermissionError, match="lineage"):
        await memory.claim_temporal_dispatch(task)
    async with factory() as db, db.begin():
        await db.execute(update(ExecutionSubtaskORM).where(
            ExecutionSubtaskORM.id == sid,
        ).values(execution_task_id=request.task_id))
    assert (await memory.claim_temporal_dispatch(task)).startswith("temporal-claim-")


@pytest.mark.asyncio
async def test_live_approved_parked_restart_recovery_is_single_use(live):
    """PG-approved Task survives crash before enqueue; only one replica claims."""
    from types import SimpleNamespace
    from ai_osop.orchestrator.recovery_service import RecoveryService

    memory, factory, _, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-verified",
    )
    saved = await memory.load_task_authoritative(request.task_id)
    assert saved.status == "awaiting_approval"
    assert saved.payload.get("approval_id") == request.id
    assert await memory.is_task_approved(
        saved.id, saved.engagement_id, request.id
    )
    memory.list_all_sessions = AsyncMock(return_value=[
        await memory.load_session_state(saved.engagement_id),
    ])
    memory.list_all_tasks = AsyncMock(return_value=[saved])
    memory.push_task_queue = AsyncMock()
    orch = SimpleNamespace(session_memory=memory, _sessions={}, _tasks={})
    summary = await RecoveryService(orch).recover_state()
    assert summary["tasks"] == 1 and summary["unresolved"] == 0
    memory.push_task_queue.assert_awaited_once()
    assert orch._tasks[saved.id].status == "awaiting_approval"

    second = second_worker(memory, factory)
    winners = await asyncio.gather(
        memory.claim_local_agent_start(saved.model_copy(deep=True), "agent-qual-a"),
        second.claim_local_agent_start(saved.model_copy(deep=True), "agent-qual-b"),
    )
    assert sorted(winners) == [False, True]
    persisted = await memory.load_task_authoritative(saved.id)
    assert persisted.status == "running"
    assert persisted.assigned_agent_id in {"agent-qual-a", "agent-qual-b"}


async def age_approval_for_timeout(factory, request):
    """Move only the test row's immutable registration clock before a race."""
    async with factory() as db, db.begin():
        await db.execute(update(ApprovalRequestORM).where(
            ApprovalRequestORM.id == request.id,
            ApprovalRequestORM.engagement_id == request.engagement_id,
        ).values(requested_at=datetime.utcnow() - timedelta(
            seconds=settings.approval_timeout_seconds + 60,
        )))


@pytest.mark.asyncio
async def test_live_timeout_and_human_approval_race_commit_one_winner(live):
    memory, factory, _, request = live
    competing = second_worker(memory, factory)
    # Both expiration callers are eligible; the first row-lock winner is
    # authoritative, and a second replica may not double-settle its outbox.
    await age_approval_for_timeout(factory, request)
    results = await asyncio.gather(
        memory.expire_approval_atomic(
            request.id, request.engagement_id, request.task_id,
        ),
        competing.expire_approval_atomic(
            request.id, request.engagement_id, request.task_id,
        ),
    )
    assert sorted(won for _, won in results) == [False, True]
    assert {result.status for result, _ in results} == {"timeout"}
    final = await memory.load_approval_request(request.id)
    assert final.status == "timeout"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert task.status == "failed"
        assert task.result["reason"] == "approval_timeout"
        assert task.payload.get("operator_approved") is not True
        event_count = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(
            SupervisionEventORM.engagement_id == request.engagement_id,
            SupervisionEventORM.kind.in_(["approval.resolved", "approval.timeout"]),
        ))).scalar_one()
        assert event_count == 1
        outbox_count = (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM,
        ).where(
            SupervisionOutboxORM.engagement_id == request.engagement_id,
            SupervisionOutboxORM.topic.in_(["approval.resolved", "approval.timeout"]),
        ))).scalar_one()
        assert outbox_count == 1


@pytest.mark.asyncio
async def test_live_timeout_after_signed_revocation_is_still_denial(live):
    memory, factory, auth, request = live
    await age_approval_for_timeout(factory, request)
    await auth.revoke(request.engagement_id, "operator-owner", 1, "approval timeout isolation")
    decided, first = await memory.expire_approval_atomic(
        request.id, request.engagement_id, request.task_id,
    )
    assert first and decided.status == "timeout"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert task.status == "failed"
        assert task.payload.get("operator_approved") is not True


@pytest.mark.asyncio
async def test_live_timeout_outbox_failure_rolls_back_approval_and_task(live, monkeypatch):
    memory, factory, _, request = live
    await age_approval_for_timeout(factory, request)

    async def fail_event(*args, **kwargs):
        raise OSError("injected event failure")

    monkeypatch.setattr(SupervisionStore, "_append_event", fail_event)
    with pytest.raises(OSError, match="injected event failure"):
        await memory.expire_approval_atomic(
            request.id, request.engagement_id, request.task_id,
        )
    assert (await memory.load_approval_request(request.id)).status == "pending"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert task.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_late_timeout_never_erases_existing_committed_approval(live):
    memory, factory, _, request = live
    committed, won = await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    assert won and committed.status == "approved"
    other = second_worker(memory, factory)
    still_approved, timer_won = await other.expire_approval_atomic(
        request.id, request.engagement_id, request.task_id,
    )
    assert not timer_won
    assert still_approved.status == "approved"
    assert still_approved.operator_id == "verified-senior"


@pytest.mark.asyncio
async def test_late_human_approval_never_restarts_a_timed_out_task(live):
    memory, factory, _, request = live
    await age_approval_for_timeout(factory, request)
    expired, won = await memory.expire_approval_atomic(
        request.id, request.engagement_id, request.task_id,
    )
    assert won and expired.status == "timeout"
    other = second_worker(memory, factory)
    still_expired, granted = await other.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    assert not granted
    assert still_expired.status == "timeout"
    assert still_expired.operator_id is None
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert task.status == "failed"
        assert task.payload.get("operator_approved") is not True


@pytest.mark.asyncio
async def test_expiration_before_durable_deadline_is_a_noop(live):
    memory, factory, _, request = live
    snapshot, committed = await memory.expire_approval_atomic(
        request.id, request.engagement_id, request.task_id,
    )
    assert not committed and snapshot.status == "pending"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert task.status == "awaiting_approval"
    assert (await memory.load_approval_request(request.id)).status == "pending"


@pytest.mark.asyncio
async def test_human_approval_after_deadline_rejected_even_without_watcher(live):
    memory, factory, _, request = live
    await age_approval_for_timeout(factory, request)
    with pytest.raises(PermissionError, match="deadline"):
        await memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "senior-too-late",
        )
    assert (await memory.load_approval_request(request.id)).status == "pending"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert task.status == "awaiting_approval"
        assert task.payload.get("operator_approved") is not True


@pytest.mark.asyncio
async def test_live_signed_task_snapshots_preserve_owner_approval_and_terminal(live):
    memory, factory, _, request = live
    approved, won = await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-verified",
    )
    assert won and approved.status == "approved"
    original = await memory.load_task_authoritative(request.task_id)
    assert original.payload["operator_approved"] is True
    unauthorized = original.model_copy(deep=True)
    unauthorized.status = "pending"
    unauthorized.payload.pop("operator_approved")
    unauthorized.payload.pop("approval_id")
    await memory.store_task(unauthorized)
    restored = await memory.load_task_authoritative(request.task_id)
    assert restored.status == "awaiting_approval"
    assert restored.payload == original.payload

    assert await memory.claim_local_agent_start(original, "agent-owner")
    foreign = original.model_copy(deep=True)
    foreign.status = "completed"
    foreign.assigned_agent_id = "foreign-agent"
    foreign.result = {"status": "success", "unexpected": True}
    await memory.store_task(foreign)
    running = await memory.load_task_authoritative(request.task_id)
    assert running.status == "running"
    assert running.assigned_agent_id == "agent-owner"
    assert running.result is None

    owner = original.model_copy(deep=True)
    owner.status = "completed"
    owner.assigned_agent_id = "agent-owner"
    owner.result = {"status": "success"}
    owner.completed_at = datetime.utcnow()
    await memory.store_task(owner)
    finished = await memory.load_task_authoritative(request.task_id)
    assert finished.status == "completed"
    assert finished.result == {"status": "success"}
    assert finished.payload == original.payload
    await memory.store_task(foreign)
    assert (await memory.load_task_authoritative(request.task_id)).result == {"status": "success"}


@pytest.mark.asyncio
async def test_live_temporal_start_unknown_reconciles_provider_existence_once(live):
    memory, factory, _, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-verified",
    )
    parked = await memory.load_task_authoritative(request.task_id)
    claim_id = await memory.claim_temporal_dispatch(parked)
    await memory.settle_temporal_dispatch(
        request.task_id, request.engagement_id, claim_id, "dispatch_unknown",
    )
    with pytest.raises(ValueError, match="observation identity"):
        await memory.reconcile_temporal_dispatch_observation(
            request.task_id, request.engagement_id,
            "ai-osop-" + request.task_id, provider_run_id="run-test-one",
            provider_status="INVALID",
        )
    workflow_id = "ai-osop-" + request.task_id
    committed = await memory.reconcile_temporal_dispatch_observation(
        request.task_id, request.engagement_id, workflow_id,
        provider_run_id="run-test-one", provider_status="RUNNING",
    )
    assert committed
    repeated = await memory.reconcile_temporal_dispatch_observation(
        request.task_id, request.engagement_id, workflow_id,
        provider_run_id="run-test-one", provider_status="RUNNING",
    )
    assert not repeated
    async with factory() as db:
        row = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert row.status == "scheduled"
        assert row.result["workflow_id"] == workflow_id
        assert row.result["provider_run_id"] == "run-test-one"
        assert "executed" not in row.result
        event_count = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(SupervisionEventORM.engagement_id == request.engagement_id,
                SupervisionEventORM.kind == "temporal.dispatch_reconciled"))).scalar_one()
        assert event_count == 1
        outbox_count = (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM,
        ).where(SupervisionOutboxORM.engagement_id == request.engagement_id,
                SupervisionOutboxORM.topic == "temporal.dispatch_reconciled"))).scalar_one()
        assert outbox_count == 1


@pytest.mark.asyncio
async def test_live_temporal_activity_unknown_never_reconciles_as_start(live):
    memory, factory, _, request = live
    async with factory() as db, db.begin():
        await db.execute(update(TaskORM).where(TaskORM.id == request.task_id).values(
            status="dispatch_unknown",
            result={"status": "execution_unknown", "reason": "remote_outcome_unverified"},
        ))
    with pytest.raises(PermissionError, match="reconcilable"):
        await memory.reconcile_temporal_dispatch_observation(
            request.task_id, request.engagement_id, "ai-osop-" + request.task_id,
            provider_run_id="run-test-two", provider_status="RUNNING",
        )
    assert (await memory.load_task_authoritative(request.task_id)).status == "dispatch_unknown"


@pytest.mark.asyncio
async def test_live_temporal_claim_is_single_use_across_signed_replicas(live):
    memory, factory, _, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    candidate = await memory.load_task_authoritative(request.task_id)
    assert candidate.status == "awaiting_approval"
    other = second_worker(memory, factory)
    outcomes = await asyncio.gather(
        memory.claim_temporal_dispatch(candidate.model_copy(deep=True)),
        other.claim_temporal_dispatch(candidate.model_copy(deep=True)),
        return_exceptions=True,
    )
    assert sum(isinstance(result, str) and result.startswith("temporal-claim-") for result in outcomes) == 1
    assert sum(isinstance(result, PermissionError) for result in outcomes) == 1
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert task.status == "dispatching"
        events = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(
            SupervisionEventORM.engagement_id == request.engagement_id,
            SupervisionEventORM.kind == "temporal.dispatch_claimed",
        ))).scalar_one()
        assert events == 1


@pytest.mark.asyncio
async def test_live_temporal_claim_rejects_tampered_snapshot_and_revoked_signer(live):
    memory, factory, auth, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    candidate = await memory.load_task_authoritative(request.task_id)
    changed = candidate.model_copy(deep=True)
    changed.payload["nested"] = {"rate": 9000}
    with pytest.raises(PermissionError):
        await memory.claim_temporal_dispatch(changed)
    assert await auth.revoke(
        request.engagement_id, "operator-owner", 1, "temporal admission revoked",
    )
    with pytest.raises(Exception):
        await memory.claim_temporal_dispatch(candidate)
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert task.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_live_temporal_claim_event_failure_rolls_back_reservation(live, monkeypatch):
    memory, factory, _, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    candidate = await memory.load_task_authoritative(request.task_id)

    async def fail_outbox(*args, **kwargs):
        raise OSError("claim outbox failed")

    monkeypatch.setattr(SupervisionStore, "_append_event", fail_outbox)
    with pytest.raises(OSError, match="claim outbox failed"):
        await memory.claim_temporal_dispatch(candidate)
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert task.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_live_temporal_claim_settlement_is_owner_fenced_and_non_replayable(live):
    memory, factory, _, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    candidate = await memory.load_task_authoritative(request.task_id)
    claim_id = await memory.claim_temporal_dispatch(candidate)
    competing = second_worker(memory, factory)
    with pytest.raises(PermissionError):
        await competing.settle_temporal_dispatch(
            request.task_id, request.engagement_id,
            "temporal-claim-foreign", "scheduled",
            workflow_id="ai-osop-" + request.task_id,
        )
    # An old queue snapshot cannot reverse the unknown pre-ack state.
    stale = candidate.model_copy(deep=True)
    stale.status = "pending"
    await competing.store_task(stale)
    async with factory() as db:
        row = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert row.status == "dispatching"
        assert row.result["claim_id"] == claim_id

    await competing.settle_temporal_dispatch(
        request.task_id, request.engagement_id, claim_id,
        "scheduled", workflow_id="ai-osop-" + request.task_id,
    )
    with pytest.raises(PermissionError):
        await memory.settle_temporal_dispatch(
            request.task_id, request.engagement_id, claim_id,
            "dispatch_unknown",
        )
    async with factory() as db:
        row = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert row.status == "scheduled"
        assert row.result["workflow_id"] == "ai-osop-" + request.task_id


@pytest.mark.asyncio
async def test_live_temporal_unknown_settlement_cannot_be_reset_to_pending(live):
    memory, factory, _, request = live
    await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "verified-senior",
    )
    candidate = await memory.load_task_authoritative(request.task_id)
    claim_id = await memory.claim_temporal_dispatch(candidate)
    await memory.settle_temporal_dispatch(
        request.task_id, request.engagement_id, claim_id, "dispatch_unknown",
    )
    stale = candidate.model_copy(deep=True)
    stale.status = "pending"
    await second_worker(memory, factory).store_task(stale)
    async with factory() as db:
        row = (await db.execute(select(TaskORM).where(TaskORM.id == request.task_id))).scalar_one()
        assert row.status == "dispatch_unknown"
        assert row.result["status"] == "unknown"


@pytest.mark.asyncio
async def test_competing_replicas_commit_exactly_one_grant_and_outbox(live):
    memory, factory, _, request = live
    another = second_worker(memory, factory)
    outcomes = await asyncio.gather(
        memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "senior-first",
        ),
        another.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "rejected", "senior-second",
        ),
    )
    assert sorted(won for _, won in outcomes) == [False, True]
    final = outcomes[0][0]
    assert all(row.status == final.status for row, _ in outcomes)
    assert final.operator_id in {"senior-first", "senior-second"}
    async with factory() as db:
        approval = (await db.execute(select(ApprovalRequestORM).where(
            ApprovalRequestORM.id == request.id,
        ))).scalar_one()
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert approval.status == final.status
        assert approval.operator_id == final.operator_id
        if final.status == "approved":
            assert task.payload["operator_approved"] is True
            assert task.payload["approval_id"] == request.id
        else:
            assert task.status == "failed"
            assert task.payload.get("operator_approved") is not True
        assert (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(
            SupervisionEventORM.engagement_id == request.engagement_id,
            SupervisionEventORM.kind == "approval.resolved",
        ))).scalar_one() == 1
        assert (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM,
        ).where(
            SupervisionOutboxORM.engagement_id == request.engagement_id,
            SupervisionOutboxORM.topic == "approval.resolved",
        ))).scalar_one() == 1


@pytest.mark.asyncio
async def test_revocation_prevents_pending_grant_without_remote_execution(live):
    memory, factory, auth, request = live
    assert await auth.revoke(
        request.engagement_id, "operator-owner", 1, "revoked before user consent",
    )
    with pytest.raises(AuthorizationDenied):
        await memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "senior-operator",
        )
    assert (await memory.load_approval_request(request.id)).status == "pending"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert task.status == "awaiting_approval"
        assert "operator_approved" not in task.payload


@pytest.mark.asyncio
async def test_outbox_failure_rolls_back_grant_approval_and_task(live, monkeypatch):
    memory, factory, _, request = live
    async def fail_outbox(*args, **kwargs):
        raise OSError("simulated outbox failure")
    monkeypatch.setattr(SupervisionStore, "_append_event", fail_outbox)
    with pytest.raises(OSError, match="simulated outbox failure"):
        await memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "senior-operator",
        )
    assert (await memory.load_approval_request(request.id)).status == "pending"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        assert "operator_approved" not in task.payload
        assert task.status == "awaiting_approval"


@pytest.mark.asyncio
async def test_authenticated_http_across_empty_replica_cache_uses_durable_approval(
    live, monkeypatch
):
    """PostgreSQL request/decision remains accessible on a different API replica."""
    memory, factory, _, request = live
    replica_memory = second_worker(memory, factory)
    replica = Orchestrator(
        replica_memory, AsyncMock(), AsyncMock(), AsyncMock(),
    )
    assert replica._approval_requests == {}
    assert replica._tasks == {}
    monkeypatch.setitem(state, "orchestrator", replica)
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "isolated-approval-api-secret")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    token = jwt.encode({
        "sub": "signed-senior", "role": "senior_operator",
        "exp": 4102444800,
    }, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    headers = {"Authorization": "Bearer " + token}
    app = FastAPI()
    app.include_router(approvals_router)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver",
    ) as client:
        pending = await client.get("/approvals/pending", headers=headers)
        assert pending.status_code == 200, pending.text
        assert request.id in {p["id"] for p in pending.json()}
        get = await client.get(f"/approvals/{request.id}", headers=headers)
        assert get.status_code == 200
        assert get.json()["status"] == "pending"
        spoof = await client.post(
            f"/approvals/{request.id}/resolve", headers=headers,
            json={"request_id": request.id, "decision": "approved",
                  "operator_id": "forged-operator"},
        )
        assert spoof.status_code == 403
        decision = await client.post(
            f"/approvals/{request.id}/resolve", headers=headers,
            json={"request_id": request.id, "decision": "approved"},
        )
        assert decision.status_code == 200, decision.text
        assert decision.json()["operator_id"] == "signed-senior"
        duplicate = await client.post(
            f"/approvals/{request.id}/resolve", headers=headers,
            json={"request_id": request.id, "decision": "rejected"},
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["status"] == "approved"
        assert duplicate.json()["operator_id"] == "signed-senior"
    assert (await memory.load_approval_request(request.id)).status == "approved"
    assert replica._tasks == {}  # No unowned in-memory agent dispatch.


@pytest.mark.parametrize("tamper", ["target", "authorization_version", "status", "signed_scope"])
@pytest.mark.asyncio
async def test_changed_task_or_policy_cannot_use_pending_approval(live, tamper):
    memory, factory, _, request = live
    async with factory() as db, db.begin():
        if tamper == "signed_scope":
            session = (await db.execute(select(SessionStateORM).where(
                SessionStateORM.session_id == request.engagement_id,
            ))).scalar_one()
            session.scope = {
                **session.scope, "domains": ["unauthorized.example"],
            }
        else:
            task = (await db.execute(select(TaskORM).where(
                TaskORM.id == request.task_id,
            ))).scalar_one()
            if tamper == "target":
                task.payload = {**task.payload, "target": "unauthorized.example"}
            elif tamper == "authorization_version":
                task.payload = {**task.payload, "_authorization_version": 2}
            else:
                task.status = "cancelled"
    with pytest.raises(AuthorizationDenied if tamper == "signed_scope" else PermissionError):
        await memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "signed-operator",
        )
    assert (await memory.load_approval_request(request.id)).status == "pending"
    async with factory() as db:
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
    assert task.payload.get("operator_approved") is not True


@pytest.mark.asyncio
async def test_real_pg_nested_payload_change_after_pending_request_is_denied(live):
    memory, factory, _, request = live
    async with factory() as db, db.begin():
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        # Target string is UNCHANGED; only a nested execution option expands.
        task.payload = {**task.payload, "options": {"high_impact": True}}
    with pytest.raises(PermissionError, match="payload changed"):
        await memory.resolve_approval_atomic(
            request.id, request.engagement_id, request.task_id,
            "approved", "senior-operator",
        )
    assert (await memory.load_approval_request(request.id)).status == "pending"
    assert not await memory.is_task_approved(request.task_id, request.engagement_id, request.id)


@pytest.mark.asyncio
async def test_real_pg_postgrant_nested_payload_tamper_invalidates_approval(live):
    memory, factory, _, request = live
    approved, won = await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-operator",
    )
    assert won and approved.status == "approved"
    assert await memory.is_task_approved(request.task_id, request.engagement_id, request.id)
    async with factory() as db, db.begin():
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        task.payload = {**task.payload, "options": {"high_impact": True}}
    assert not await memory.is_task_approved(request.task_id, request.engagement_id, request.id)


@pytest.mark.asyncio
async def test_live_modified_approved_task_cannot_start_attempt_or_paid_model(live):
    memory, factory, _, request = live
    granted, did_win = await memory.resolve_approval_atomic(
        request.id, request.engagement_id, request.task_id,
        "approved", "senior-operator",
    )
    assert did_win and granted.status == "approved"
    async with factory() as db, db.begin():
        task = (await db.execute(select(TaskORM).where(
            TaskORM.id == request.task_id,
        ))).scalar_one()
        task.status = "running"
        task.payload = {**task.payload, "options": {"unexpected_nested_option": True}}
    with pytest.raises(SupervisionConflict, match="payload-bound"):
        await SupervisionStore(memory).start_attempt(
            request.engagement_id, request.task_id, 1, status="running",
        )
    with pytest.raises(ModelBudgetExceeded, match="stale"):
        await ModelUsageLedger(memory).reserve(
            request.engagement_id, request.task_id,
            "openai/isolated-inert-model", "completion",
        )
