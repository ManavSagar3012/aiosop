"""Signed Flow admission against a fresh, disposable PostgreSQL only.

No application database, external security target, worker/agent, or model is
contacted. This suite tests atomic persistence and queue *intent*, not scans.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import redis.asyncio as redis
from alembic import command
from alembic.config import Config
from sqlalchemy import func, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import ApprovalRequest, FlowRecord, SubtaskRecord, Task
from ai_osop.memory.authorization_store import AuthorizationStore
from ai_osop.memory.model_usage import ModelUsageLedger, ModelUsageORM
from ai_osop.core.exceptions import MemoryException
from ai_osop.memory.session_memory import (
    ApprovalRequestORM, ExecutionFlowORM, ExecutionSubtaskORM, SessionMemory, TaskORM,
)
from ai_osop.memory.supervision_store import (
    SupervisionEventORM, SupervisionOutboxORM, SupervisionStore,
)
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.supervision_outbox import SupervisionOutboxDispatcher
from tests.test_authorization_store import make_signed_session


def _disposable_url():
    value = os.environ.get("OSOP_FLOW_ADMISSION_TEST_PG_URI", "")
    if not value:
        pytest.skip("Dedicated disposable Flow admission PostgreSQL unavailable")
    url = make_url(value)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"localhost", "127.0.0.1"}
        or url.port != 15678
        or url.database != "flow_dispatch_qualification_20261014"
    ):
        pytest.fail("Refusing to use a non-disposable Flow admission database")
    return value


def _migrate(connection):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    command.upgrade(config, "head")


@pytest.fixture
async def signed_flow(monkeypatch):
    engine = create_async_engine(_disposable_url(), pool_size=5, max_overflow=0)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(_migrate)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        nonce = uuid.uuid4().hex[:12]
        engagement, signed, _, _ = make_signed_session(
            monkeypatch, session_id="eng-flow-" + nonce,
            authorization_id="auth-flow-" + nonce,
        )
        engagement.phase = "reconnaissance"
        memory = SessionMemory()
        memory._async_session = factory
        memory.store_hot = AsyncMock()
        memory.push_task_queue = AsyncMock()
        authorization = AuthorizationStore(memory)
        await authorization.create_authorized_session(
            engagement, signed, engagement.created_by,
        )
        flow = FlowRecord(
            id="flow-" + nonce, engagement_id=engagement.session_id,
            objective="Consent-based test planning, no external calls",
        )
        assert await memory.create_flow_if_absent(flow)
        parent = Task(
            id="task-parent-" + nonce, type="flow_objective",
            agent_type=AgentType.RECON, engagement_id=engagement.session_id,
            flow_id=flow.id, status="planned", payload={"title": "Approved scope"},
        )
        await memory.store_task(parent)
        step = SubtaskRecord(
            id="subtask-" + nonce, engagement_id=engagement.session_id,
            flow_id=flow.id, task_id=parent.id, task_type="recon",
            agent_type=AgentType.RECON, approval_required=False,
            title="Inert authorized Flow admission fixture",
        )
        await memory.store_subtask(step)
        task = Task(
            id="task-exec-" + nonce, engagement_id=engagement.session_id,
            type=step.task_type, agent_type=AgentType.RECON,
            flow_id=flow.id, subtask_id=step.id, parent_task_id=parent.id,
            payload={"target": "authorized.example"},
            approval_required=False, status="pending",
        )
        yield memory, factory, authorization, engagement, flow, step, task
    finally:
        await engine.dispose()


async def _claim(context, memory=None):
    sm, _, _, session, flow, step, task = context
    return await (memory or sm).claim_subtask(
        step.id, session.session_id, flow=flow, engagement=session,
        subtask=step, payload={"target": "authorized.example"},
        execution_task=task.model_copy(deep=True),
    )


@pytest.mark.asyncio
async def test_live_competing_flow_claim_creates_one_task_one_intent(signed_flow):
    sm, factory, _, session, flow, step, task = signed_flow
    competitor = SessionMemory()
    competitor._async_session = factory
    result = await asyncio.gather(_claim(signed_flow), _claim(signed_flow, competitor))
    assert sorted(result) == [False, True]
    async with factory() as db:
        actual_task = (await db.execute(select(TaskORM).where(TaskORM.id == task.id))).scalar_one()
        actual_step = (await db.execute(select(ExecutionSubtaskORM).where(
            ExecutionSubtaskORM.id == step.id,
        ))).scalar_one()
        actual_flow = (await db.execute(select(ExecutionFlowORM).where(
            ExecutionFlowORM.id == flow.id,
        ))).scalar_one()
        assert actual_task.status == "pending"
        assert actual_task.payload == {"target": "authorized.example", "_authorization_version": 1}
        assert actual_step.status == "dispatched"
        assert actual_step.execution_task_id == task.id
        assert actual_flow.revision == 1
        count_events = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(SupervisionEventORM.engagement_id == session.session_id,
                SupervisionEventORM.kind == "flow.subtask_dispatch_intent"))).scalar_one()
        count_outbox = (await db.execute(select(func.count()).select_from(
            SupervisionOutboxORM,
        ).where(SupervisionOutboxORM.engagement_id == session.session_id,
                SupervisionOutboxORM.topic == "flow.subtask_dispatch_intent"))).scalar_one()
        assert count_events == count_outbox == 1


@pytest.mark.asyncio
async def test_live_event_write_failure_rolls_back_task_lineage_and_flow(signed_flow, monkeypatch):
    sm, factory, _, _, flow, step, task = signed_flow

    async def fail(*args, **kwargs):
        raise OSError("synthetic outbox failure")

    monkeypatch.setattr(SupervisionStore, "_append_event", fail)
    with pytest.raises(OSError, match="synthetic outbox failure"):
        await _claim(signed_flow)
    async with factory() as db:
        assert (await db.execute(select(TaskORM).where(TaskORM.id == task.id))).scalar_one_or_none() is None
        actual_step = (await db.execute(select(ExecutionSubtaskORM).where(
            ExecutionSubtaskORM.id == step.id,
        ))).scalar_one()
        actual_flow = (await db.execute(select(ExecutionFlowORM).where(
            ExecutionFlowORM.id == flow.id,
        ))).scalar_one()
        assert actual_step.status == "pending" and actual_step.execution_task_id is None
        assert actual_flow.revision == 0


@pytest.mark.asyncio
async def test_live_delivery_does_not_start_any_agent_or_remote_tool(signed_flow):
    sm, _, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    orch = Orchestrator.__new__(Orchestrator)
    orch.session_memory = sm
    hydrated = await orch.enqueue_registered_task(task.id)
    assert hydrated.id == task.id
    assert hydrated.status == "pending"
    sm.push_task_queue.assert_awaited_once()
    assert (await sm.load_task_authoritative(task.id)).status == "pending"


@pytest.mark.asyncio
async def test_live_local_start_claim_is_single_winner_and_not_replayed(signed_flow):
    sm, factory, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    hydrated = await sm.load_task_authoritative(task.id)
    competitor = SessionMemory()
    competitor._async_session = factory
    outcomes = await asyncio.gather(
        sm.claim_local_agent_start(hydrated, "offline-agent-a"),
        competitor.claim_local_agent_start(hydrated, "offline-agent-b"),
    )
    assert sorted(outcomes) == [False, True]
    persisted = await sm.load_task_authoritative(task.id)
    assert persisted.status == "running"
    assert persisted.assigned_agent_id in {"offline-agent-a", "offline-agent-b"}
    assert not await competitor.claim_local_agent_start(hydrated, "offline-agent-third")


@pytest.mark.asyncio
async def test_live_revoked_signer_rejects_queue_delivery_and_local_start(signed_flow):
    sm, _, authorization, session, _, _, task = signed_flow
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    await authorization.revoke(session.session_id, session.created_by, 1, "fixture-only revocation")
    orch = Orchestrator.__new__(Orchestrator)
    orch.session_memory = sm
    with pytest.raises(Exception, match="no longer authorized"):
        await orch.enqueue_registered_task(task.id)
    sm.push_task_queue.assert_not_awaited()
    with pytest.raises(Exception):
        await sm.claim_local_agent_start(pending, "offline-agent")
    assert (await sm.load_task_authoritative(task.id)).status == "pending"


@pytest.mark.asyncio
async def test_live_stale_step_snapshot_cannot_erase_committed_task_lineage(signed_flow):
    sm, factory, _, _, _, step, task = signed_flow
    stale = step.model_copy(deep=True)
    assert await _claim(signed_flow)
    with pytest.raises(MemoryException, match="stale write refused"):
        await sm.store_subtask(stale)
    with pytest.raises(MemoryException, match="stale write refused"):
        await sm.store_subtask(stale.model_copy(update={
            "status": "dispatched", "execution_task_id": "task-intruder",
        }))
    async with factory() as db:
        actual_step = (await db.execute(select(ExecutionSubtaskORM).where(
            ExecutionSubtaskORM.id == step.id,
        ))).scalar_one()
        assert actual_step.execution_task_id == task.id
        assert actual_step.status == "dispatched"


@pytest.mark.asyncio
async def test_live_pending_timeout_and_agent_start_have_one_durable_winner(signed_flow):
    sm, factory, _, session, _, _, task = signed_flow
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    other = SessionMemory()
    other._async_session = factory
    expired, started = await asyncio.gather(
        sm.expire_pending_task_atomic(
            task.id, session.session_id,
            created_before=task.created_at + timedelta(seconds=10),
        ),
        other.claim_local_agent_start(pending, "synthetic-offline-agent"),
    )
    assert sorted([expired, started]) == [False, True]
    final = await sm.load_task_authoritative(task.id)
    assert final.status == ("failed" if expired else "running")
    if expired:
        assert final.result["reason"] == "pending_task_timeout"
    else:
        assert final.assigned_agent_id == "synthetic-offline-agent"


@pytest.mark.asyncio
async def test_live_expiry_rolls_back_when_outbox_unavailable(signed_flow, monkeypatch):
    sm, _, _, session, _, _, task = signed_flow
    assert await _claim(signed_flow)

    async def fail(*args, **kwargs):
        raise OSError("synthetic reaper outbox outage")

    monkeypatch.setattr(SupervisionStore, "_append_event", fail)
    with pytest.raises(OSError, match="synthetic reaper outbox outage"):
        await sm.expire_pending_task_atomic(
            task.id, session.session_id,
            created_before=task.created_at + timedelta(seconds=10),
        )
    assert (await sm.load_task_authoritative(task.id)).status == "pending"


def _request(memory, task):
    return ApprovalRequest(
        id=memory.deterministic_task_approval_id(task.engagement_id, task.id),
        task_id=task.id, agent_id="", action_type=task.type,
        target=str(task.payload["target"]), payload_summary="Synthetic-only review",
        risk_assessment="high", engagement_id=task.engagement_id,
    )


@pytest.mark.asyncio
async def test_live_approval_parking_is_atomic_and_single_winner(signed_flow):
    sm, factory, _, session, _, _, task = signed_flow
    task.approval_required = True
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    assert pending.approval_required is True
    other = SessionMemory()
    other._async_session = factory
    request = _request(sm, pending)
    outcomes = await asyncio.gather(
        sm.park_task_for_approval_atomic(pending, request),
        other.park_task_for_approval_atomic(pending, request),
    )
    assert sorted(outcomes) == [False, True]
    final = await sm.load_task_authoritative(task.id)
    assert final.status == "awaiting_approval"
    async with factory() as db:
        rows = (await db.execute(select(ApprovalRequestORM).where(
            ApprovalRequestORM.task_id == task.id,
            ApprovalRequestORM.engagement_id == session.session_id,
        ))).scalars().all()
        assert len(rows) == 1 and rows[0].id == request.id
        assert rows[0].status == "pending"
        assert len(rows[0].evidence) == 1
        assert rows[0].evidence[0]["kind"] == "task_payload_sha256_v1"
        events = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(
            SupervisionEventORM.engagement_id == session.session_id,
            SupervisionEventORM.kind == "approval.requested",
        ))).scalar_one()
        assert events == 1
    decided, won = await sm.resolve_approval_atomic(
        request.id, session.session_id, task.id, "approved", "synthetic-senior",
    )
    assert won and decided.status == "approved"
    approved = await sm.load_task_authoritative(task.id)
    assert approved.payload["operator_approved"] is True
    assert approved.payload["approval_id"] == request.id
    assert await sm.claim_local_agent_start(approved, "offline-approved-agent")


@pytest.mark.asyncio
async def test_live_approval_parking_outbox_failure_never_strands_task(signed_flow, monkeypatch):
    sm, factory, _, _, _, _, task = signed_flow
    task.approval_required = True
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)

    async def fail(*args, **kwargs):
        raise OSError("synthetic approval outbox failure")

    monkeypatch.setattr(SupervisionStore, "_append_event", fail)
    with pytest.raises(OSError, match="synthetic approval outbox failure"):
        await sm.park_task_for_approval_atomic(pending, _request(sm, pending))
    assert (await sm.load_task_authoritative(task.id)).status == "pending"
    async with factory() as db:
        count = (await db.execute(select(func.count()).select_from(
            ApprovalRequestORM,
        ).where(ApprovalRequestORM.task_id == task.id))).scalar_one()
        assert count == 0


@pytest.mark.asyncio
async def test_live_revocation_prevents_new_human_approval_request(signed_flow):
    sm, factory, auth, session, _, _, task = signed_flow
    task.approval_required = True
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    await auth.revoke(session.session_id, session.created_by, 1, "fixture revoke")
    with pytest.raises(Exception):
        await sm.park_task_for_approval_atomic(pending, _request(sm, pending))
    assert (await sm.load_task_authoritative(task.id)).status == "pending"
    async with factory() as db:
        count = (await db.execute(select(func.count()).select_from(
            ApprovalRequestORM,
        ).where(ApprovalRequestORM.task_id == task.id))).scalar_one()
        assert count == 0


@pytest.mark.asyncio
async def test_live_committed_intent_recovered_by_leased_outbox_worker(signed_flow):
    sm, factory, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    # Each module fixture has a newly generated signer in this shared *test*
    # database; historical fixture events cannot be re-signed by this fixture.
    # Retire only previous test-fixture outbox rows, not the current signed run.
    async with factory() as db, db.begin():
        await db.execute(update(SupervisionOutboxORM).where(
            SupervisionOutboxORM.engagement_id != task.engagement_id,
        ).values(delivered_at=datetime.utcnow(), lease_id=None, leased_until=None))
    orch = Orchestrator.__new__(Orchestrator)
    orch.session_memory = sm
    bus = AsyncMock()
    dispatcher = SupervisionOutboxDispatcher(
        SupervisionStore(sm), bus,
        enqueue_registered_task=orch.reconcile_flow_dispatch_intent,
    )
    delivered = await dispatcher.flush_once()
    assert delivered >= 1  # May also include signed engagement creation.
    sm.push_task_queue.assert_awaited_once()
    assert (await sm.load_task_authoritative(task.id)).status == "pending"
    async with factory() as db:
        outbox = (await db.execute(select(SupervisionOutboxORM).where(
            SupervisionOutboxORM.engagement_id == task.engagement_id,
            SupervisionOutboxORM.topic == "flow.subtask_dispatch_intent",
        ))).scalar_one()
        assert outbox.delivered_at is not None
    assert await dispatcher.flush_once() == 0
    sm.push_task_queue.assert_awaited_once()


@pytest.mark.asyncio
async def test_live_outbox_acks_claimed_task_without_replaying_queue(signed_flow):
    sm, factory, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    async with factory() as db, db.begin():
        await db.execute(update(SupervisionOutboxORM).where(
            SupervisionOutboxORM.engagement_id != task.engagement_id,
        ).values(delivered_at=datetime.utcnow(), lease_id=None, leased_until=None))
    claimed = await sm.load_task_authoritative(task.id)
    assert await sm.claim_local_agent_start(claimed, "synthetic-agent")
    orch = Orchestrator.__new__(Orchestrator)
    orch.session_memory = sm
    dispatcher = SupervisionOutboxDispatcher(
        SupervisionStore(sm), AsyncMock(),
        enqueue_registered_task=orch.reconcile_flow_dispatch_intent,
    )
    assert await dispatcher.flush_once() >= 1
    sm.push_task_queue.assert_not_awaited()
    async with factory() as db:
        outbox = (await db.execute(select(SupervisionOutboxORM).where(
            SupervisionOutboxORM.engagement_id == task.engagement_id,
            SupervisionOutboxORM.topic == "flow.subtask_dispatch_intent",
        ))).scalar_one()
        assert outbox.delivered_at is not None


@pytest.mark.asyncio
async def test_live_terminal_callback_has_single_owner_fenced_winner(signed_flow):
    sm, factory, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    assert await sm.claim_local_agent_start(pending, "synthetic-terminal-owner")
    running = await sm.load_task_authoritative(task.id)
    other = SessionMemory()
    other._async_session = factory
    wins = await asyncio.gather(
        sm.settle_local_task_terminal_atomic(running, "completed", {"status": "success"}),
        other.settle_local_task_terminal_atomic(running, "failed", {"status": "failed"}),
    )
    assert sorted(wins) == [False, True]
    actual = await sm.load_task_authoritative(task.id)
    assert actual.status in {"completed", "failed"}
    assert not await other.settle_local_task_terminal_atomic(
        running, "completed", {"status": "late"},
    )
    async with factory() as db:
        rows = (await db.execute(select(SupervisionEventORM).where(
            SupervisionEventORM.engagement_id == task.engagement_id,
            SupervisionEventORM.kind == "task.local_terminal",
        ))).scalars().all()
        assert len(rows) == 1


@pytest.mark.asyncio
async def test_live_terminal_outbox_rollback_and_foreign_owner_denial(signed_flow, monkeypatch):
    sm, _, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    assert await sm.claim_local_agent_start(pending, "synthetic-terminal-owner")
    running = await sm.load_task_authoritative(task.id)
    foreign = running.model_copy(update={"assigned_agent_id": "wrong-owner"})
    assert not await sm.settle_local_task_terminal_atomic(
        foreign, "completed", {"status": "fabricated"},
    )

    async def fail(*args, **kwargs):
        raise OSError("synthetic terminal outbox failure")
    monkeypatch.setattr(SupervisionStore, "_append_event", fail)
    with pytest.raises(OSError, match="synthetic terminal outbox failure"):
        await sm.settle_local_task_terminal_atomic(
            running, "completed", {"status": "success"},
        )
    assert (await sm.load_task_authoritative(task.id)).status == "running"


@pytest.mark.asyncio
async def test_live_signed_invoice_attestation_settles_reserved_call_once(signed_flow):
    sm, factory, _, engagement, _, _, task = signed_flow
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    assert await sm.claim_local_agent_start(pending, "synthetic-model-owner")
    ledger = ModelUsageLedger(sm)
    call_id = await ledger.reserve(
        engagement.session_id, task.id, "openai/gpt-test", "completion",
    )
    kwargs = dict(
        expected_task_id=task.id, expected_model="openai/gpt-test",
        expected_operation="completion", expected_authorization_version=1,
        provider="openai", invoice_reference="invoice-isolated-1",
        invoice_line_id="line-isolated-1", invoice_sha256="a" * 64,
        billed_cost_usd="0.0150", actor_id=engagement.created_by,
        actor_role="senior_operator", input_tokens=11, output_tokens=7,
    )
    assert await ledger.reconcile_provider_invoice(
        engagement.session_id, call_id, **kwargs,
    )
    assert not await ledger.reconcile_provider_invoice(
        engagement.session_id, call_id, **kwargs,
    )
    async with factory() as db:
        row = (await db.execute(select(ModelUsageORM).where(
            ModelUsageORM.call_id == call_id,
        ))).scalar_one()
        assert row.status == "settled"
        assert str(row.billed_cost_usd).startswith("0.015")
        event_count = (await db.execute(select(func.count()).select_from(
            SupervisionEventORM,
        ).where(
            SupervisionEventORM.engagement_id == engagement.session_id,
            SupervisionEventORM.kind == "llm.invoice_reconciled",
        ))).scalar_one()
        assert event_count == 1


@pytest.mark.asyncio
async def test_live_invoice_event_failure_rolls_back_unverified_cost(signed_flow, monkeypatch):
    sm, factory, _, engagement, _, _, task = signed_flow
    assert await _claim(signed_flow)
    pending = await sm.load_task_authoritative(task.id)
    assert await sm.claim_local_agent_start(pending, "synthetic-model-owner")
    ledger = ModelUsageLedger(sm)
    call_id = await ledger.reserve(
        engagement.session_id, task.id, "openai/gpt-test", "completion",
    )

    async def fail(*args, **kwargs):
        raise OSError("synthetic invoice audit loss")

    monkeypatch.setattr(ModelUsageLedger, "_append_event", fail)
    with pytest.raises(OSError, match="synthetic invoice audit loss"):
        await ledger.reconcile_provider_invoice(
            engagement.session_id, call_id,
            expected_task_id=task.id, expected_model="openai/gpt-test",
            expected_operation="completion", expected_authorization_version=1,
            provider="openai", invoice_reference="invoice-isolated-2",
            invoice_line_id="line-isolated-2", invoice_sha256="b" * 64,
            billed_cost_usd="0.0150", actor_id=engagement.created_by,
            actor_role="senior_operator",
        )
    async with factory() as db:
        row = (await db.execute(select(ModelUsageORM).where(
            ModelUsageORM.call_id == call_id,
        ))).scalar_one()
        assert row.status == "reserved" and row.billed_cost_usd is None


def _disposable_redis_url():
    from urllib.parse import urlparse

    value = os.environ.get("OSOP_FLOW_ADMISSION_TEST_REDIS_URL", "")
    if not value:
        pytest.skip("Explicit disposable Flow qualification Redis not provisioned")
    parsed = urlparse(value)
    if (
        parsed.scheme != "redis"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.port != 16391 or parsed.path != "/15"
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        pytest.fail("Refusing shared/non-disposable Redis for Flow qualification")
    return value


@pytest.mark.asyncio
async def test_live_postgres_outbox_delivers_real_redis_queue_and_consumes_once(signed_flow):
    """Actual leased PG outbox -> real Redis sorted-set queue, inert task only."""
    cache = redis.from_url(_disposable_redis_url(), decode_responses=True)
    sm, factory, _, _, _, _, task = signed_flow
    try:
        assert await cache.ping()
        assert await _claim(signed_flow)
        sm._redis = cache
        sm.push_task_queue = SessionMemory.push_task_queue.__get__(sm, SessionMemory)
        async with factory() as db, db.begin():
            # Mark only older isolated fixture events delivered, never
            # manipulate outboxes or user data from another application.
            await db.execute(update(SupervisionOutboxORM).where(
                SupervisionOutboxORM.engagement_id != task.engagement_id,
            ).values(delivered_at=datetime.utcnow(), lease_id=None, leased_until=None))
        orch = Orchestrator.__new__(Orchestrator)
        orch.session_memory = sm
        worker = SupervisionOutboxDispatcher(
            SupervisionStore(sm), AsyncMock(),
            enqueue_registered_task=orch.reconcile_flow_dispatch_intent,
        )
        assert await worker.flush_once() >= 1
        queue_key = f"queue:tasks:{task.engagement_id}"
        assert await cache.zcard(queue_key) == 1
        payload = await sm.pop_task_queue(f"tasks:{task.engagement_id}")
        assert payload["id"] == task.id
        assert payload["status"] == "pending"
        assert await cache.zcard(queue_key) == 0
        assert await worker.flush_once() == 0
        assert await cache.zcard(queue_key) == 0
        assert (await sm.load_task_authoritative(task.id)).status == "pending"
    finally:
        await cache.aclose()


@pytest.mark.asyncio
async def test_live_outbox_keeps_unknown_delivery_when_redis_unreachable(signed_flow):
    """Real PG outbox remains unacknowledged if its Redis ACK is uncertain."""
    valid_redis_url = _disposable_redis_url()
    sm, factory, _, _, _, _, task = signed_flow
    assert await _claim(signed_flow)
    # Only connection to a deliberately unbound loopback port; no external
    # traffic or target-side effects, and no application Redis instance.
    bad_cache = redis.from_url(
        "redis://127.0.0.1:16392/15", decode_responses=True,
        socket_connect_timeout=0.2, socket_timeout=0.2,
    )
    try:
        sm._redis = bad_cache
        sm.push_task_queue = SessionMemory.push_task_queue.__get__(sm, SessionMemory)
        async with factory() as db, db.begin():
            await db.execute(update(SupervisionOutboxORM).where(
                SupervisionOutboxORM.engagement_id != task.engagement_id,
            ).values(delivered_at=datetime.utcnow(), lease_id=None, leased_until=None))
        orch = Orchestrator.__new__(Orchestrator)
        orch.session_memory = sm
        worker = SupervisionOutboxDispatcher(
            SupervisionStore(sm), AsyncMock(),
            enqueue_registered_task=orch.reconcile_flow_dispatch_intent,
        )
        await worker.flush_once()
        async with factory() as db:
            intent = (await db.execute(select(SupervisionOutboxORM).where(
                SupervisionOutboxORM.engagement_id == task.engagement_id,
                SupervisionOutboxORM.topic == "flow.subtask_dispatch_intent",
            ))).scalar_one()
            assert intent.delivered_at is None
            assert intent.attempts >= 1
        assert (await sm.load_task_authoritative(task.id)).status == "pending"
        # A process restart or expired outbox lease must be able to deliver
        # the SAME registered Task through the real Redis service. Never
        # create a second Task or bypass its eventual human approval gate.
        good_cache = redis.from_url(valid_redis_url, decode_responses=True)
        try:
            assert await good_cache.ping()
            sm._redis = good_cache
            async with factory() as db, db.begin():
                await db.execute(update(SupervisionOutboxORM).where(
                    SupervisionOutboxORM.engagement_id == task.engagement_id,
                    SupervisionOutboxORM.topic == "flow.subtask_dispatch_intent",
                    SupervisionOutboxORM.delivered_at.is_(None),
                ).values(leased_until=datetime.utcnow() - timedelta(seconds=1)))
            assert await worker.flush_once() >= 1
            payload = await sm.pop_task_queue(f"tasks:{task.engagement_id}")
            assert payload["id"] == task.id
            assert (await sm.load_task_authoritative(task.id)).status == "pending"
            assert await worker.flush_once() == 0
        finally:
            await good_cache.aclose()
    finally:
        await bad_cache.aclose()
