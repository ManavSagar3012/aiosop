"""Real PostgreSQL supervision/outbox qualification against an isolated database.

Opt-in: OSOP_LIVE_POSTGRES_URI must point to a disposable local test database.
The test creates records and runs schema migrations. It never executes tools
or contacts security-testing targets.
"""

import asyncio
import os
import uuid
from datetime import datetime

import pytest
from sqlalchemy import inspect, select, update
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.schema_migrations import ensure_schema
from ai_osop.core.exceptions import MemoryException
from ai_osop.memory.session_memory import Base, SessionMemory, SessionStateORM, TaskORM
from ai_osop.memory.supervision_store import (
    SupervisionConflict, SupervisionStore, SupervisionEventORM,
    SupervisionControlORM,
)
from ai_osop.memory.outbox_delivery_dedupe import OutboxConsumerUnavailable
from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.supervision_outbox import (
    SupervisionNotificationConsumer, _safe_notification,
)


@pytest.fixture
async def live_store():
    uri = os.environ.get("OSOP_LIVE_POSTGRES_URI")
    if not uri:
        pytest.skip("Set OSOP_LIVE_POSTGRES_URI to an isolated local database")
    engine = create_async_engine(uri, pool_size=5)
    try:
        await ensure_schema(engine, uri)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        memory = SessionMemory()
        memory._pg_engine = engine
        memory._async_session = async_sessionmaker(engine, expire_on_commit=False)
        yield SupervisionStore(memory)
    finally:
        await engine.dispose()


async def _engagement(store: SupervisionStore):
    suffix = uuid.uuid4().hex[:14]
    engagement_id = "eng-sup-" + suffix
    task_id = "task-sup-" + suffix
    session = SessionState(
        session_id=engagement_id,
        created_by="operator-qual",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id=engagement_id,
            domains=["example.test"],
            authorization_ref="local-qualification-signed-roe",
        ),
    )
    task = Task(
        id=task_id, engagement_id=engagement_id,
        type="full_recon", agent_type=AgentType.RECON, status="running",
    )
    async with store.session_memory._async_session() as db:
        db.add(SessionStateORM(
            session_id=engagement_id, created_by=session.created_by,
            phase=session.phase, scope=session.scope.model_dump(mode="json"),
            roe={}, agents={}, audit_log_position="", created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        ))
        db.add(TaskORM(
            **{**task.model_dump(exclude={"agent_type", "trace_context"}),
               "agent_type": task.agent_type.value}
        ))
        await db.commit()
    return engagement_id, task_id


@pytest.mark.asyncio
async def test_real_migration_includes_supervision_relations(live_store):
    async with live_store.session_memory._pg_engine.connect() as conn:
        tables = await conn.run_sync(lambda s: set(inspect(s).get_table_names()))
    assert {"supervision_events", "supervision_controls", "supervision_attempts",
            "supervision_messages", "supervision_outbox"} <= tables


@pytest.mark.asyncio
async def test_two_replicas_cannot_start_same_execution_attempt(live_store):
    eid, tid = await _engagement(live_store)
    competing = SupervisionStore(live_store.session_memory)
    first, second = await asyncio.gather(
        live_store.start_attempt(eid, tid, 1, status="running"),
        competing.start_attempt(eid, tid, 1, status="running"),
    )
    assert sorted([first["created"], second["created"]]) == [False, True]
    assert first["id"] == second["id"]
    result = await live_store.update_attempt(first["id"], 0, "succeeded", receipt={"result_code": "success"})
    assert result is not None and result["status"] == "succeeded"
    assert await competing.update_attempt(first["id"], 0, "unknown") is None


@pytest.mark.asyncio
async def test_control_command_event_outbox_commit_and_lease(live_store):
    eid, tid = await _engagement(live_store)
    req_id = "control-" + uuid.uuid4().hex[:20]
    command = dict(
        engagement_id=eid, task_id=tid, action="cancel",
        actor_id="operator-qual", actor_role="operator",
        reason="Operator requests safe interruption and receipt reconciliation",
        request_id=req_id,
    )
    created = await live_store.request_control(**command)
    assert created["status"] == "pending"
    again = await live_store.request_control(**command)
    assert again["request_id"] == req_id
    assert created["revision"] == again["revision"]
    events = await live_store.list_events(eid, tid)
    assert len([event for event in events if event["kind"] == "agent.control.requested"]) == 1
    leased = await live_store.claim_outbox(limit=50)
    own = [entry for entry in leased if entry["engagement_id"] == eid]
    assert len(own) >= 1
    assert await live_store.ack_outbox(own[0]["id"], own[0]["lease_id"])
    assert not await live_store.ack_outbox(own[0]["id"], own[0]["lease_id"])
    updated = await live_store.resolve_control(
        req_id, "unknown", {"status": "cancellation_requested", "execution_stopped": False},
    )
    assert updated["status"] == "unknown"
    assert updated["receipt"].get("execution_stopped") is False
    assert (await live_store.get_control(tid, eid))["status"] == "unknown"


@pytest.mark.asyncio
async def test_live_notification_consumer_replacement_and_tenant_source_fence(live_store):
    """Two PG-backed replicas commit only one completed named-consumer receipt.

    This is notification idempotency, NOT proof of exactly-once publication or
    any remote target-side effect. An ambiguous external callback without an
    ACK can still cause another delivery after its lease expires.
    """
    eid, tid = await _engagement(live_store)
    await live_store.request_control(
        engagement_id=eid,
        task_id=tid,
        action="cancel",
        actor_id="operator-qual",
        actor_role="operator",
        reason="Qualification of durable notification replay after worker replacement",
        request_id="control-notify-" + uuid.uuid4().hex[:20],
    )
    rows = await live_store.claim_outbox(limit=10)
    owned = [row for row in rows if row["engagement_id"] == eid]
    assert len(owned) == 1
    safe = _safe_notification(owned[0])
    event = CoordinationEvent(
        topic="supervision.event", source="supervision-outbox", payload=safe,
    )
    consumer_id = "qualification-notification-v1"
    replica_a = SupervisionNotificationConsumer(
        durable_store=SupervisionStore(live_store.session_memory),
        consumer_id=consumer_id,
    )
    replica_b = SupervisionNotificationConsumer(
        durable_store=SupervisionStore(live_store.session_memory),
        consumer_id=consumer_id,
    )
    callback = AsyncMock()
    results = await asyncio.gather(
        replica_a.consume(event, callback), replica_b.consume(event, callback),
        return_exceptions=True,
    )
    assert sum(result is True for result in results) == 1
    assert all(
        result is True or result is False or isinstance(result, OutboxConsumerUnavailable)
        for result in results
    )
    callback.assert_awaited_once()
    replacement = SupervisionNotificationConsumer(
        durable_store=SupervisionStore(live_store.session_memory),
        consumer_id=consumer_id,
    )
    assert await replacement.consume(event, callback) is False
    callback.assert_awaited_once()
    events = await live_store.list_events(eid, tid)
    receipts = [row for row in events if row["kind"] == "supervision.notification_consumed"]
    assert len(receipts) == 1
    assert receipts[0]["payload"]["source_event_id"] == safe["event_id"]
    assert receipts[0]["payload"]["delivery_guarantee"] == "at_least_once"

    forged = CoordinationEvent(
        topic=event.topic,
        source=event.source,
        payload={**safe, "engagement_id": "eng-foreign-tenant"},
    )
    with pytest.raises(OutboxConsumerUnavailable, match="committed source event"):
        await replacement.consume(forged, callback)
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_control_denies_foreign_operator_and_fake_confirmed_stop(live_store):
    eid, tid = await _engagement(live_store)
    with pytest.raises(SupervisionConflict, match="own"):
        await live_store.request_control(
            eid, tid, "cancel", "operator-foreign",
            "Attempt to control an unrelated operator's task",
            "control-" + uuid.uuid4().hex[:20], actor_role="operator",
        )
    request_id = "control-" + uuid.uuid4().hex[:20]
    await live_store.request_control(
        eid, tid, "cancel", "operator-qual",
        "Safety interruption while awaiting a remote receipt",
        request_id, actor_role="operator",
    )
    with pytest.raises(SupervisionConflict, match="receipt"):
        await live_store.resolve_control(request_id, "confirmed_stopped", {"remote_stopped": False})
    assert (await live_store.load_control(request_id))["status"] == "pending"


@pytest.mark.asyncio
async def test_checkpoint_restore_never_rewinds_halt_or_scope(live_store):
    eid, _ = await _engagement(live_store)
    memory = live_store.session_memory
    snapshot = await memory.load_session_state(eid)
    checkpoint_id = "chk-" + uuid.uuid4().hex[:20]
    memory.retrieve_hot = AsyncMock(return_value={
        "checkpoint_id": checkpoint_id,
        "session_id": eid,
        "state": snapshot.model_dump(mode="json"),
    })

    restored = await memory.restore_checkpoint(checkpoint_id)
    assert restored.checkpoint_id == checkpoint_id
    assert restored.phase == "reconnaissance"

    # Another operator has halted the engagement since the snapshot.
    async with memory._async_session() as db:
        await db.execute(
            update(SessionStateORM).where(SessionStateORM.session_id == eid)
            .values(phase="halted")
        )
        await db.commit()
    with pytest.raises(MemoryException, match="inactive"):
        await memory.restore_checkpoint(checkpoint_id)
    assert (await memory.load_session_state(eid)).phase == "halted"

    # Even without a halt, altered signed rules of engagement cannot be
    # rolled back by replaying an old Redis checkpoint.
    async with memory._async_session() as db:
        await db.execute(
            update(SessionStateORM).where(SessionStateORM.session_id == eid)
            .values(phase="reconnaissance", roe={"allow_active_scanning": False})
        )
        await db.commit()
    with pytest.raises(MemoryException, match="stale"):
        await memory.restore_checkpoint(checkpoint_id)
    assert (await memory.load_session_state(eid)).roe == {"allow_active_scanning": False}


@pytest.mark.asyncio
async def test_live_engagement_execution_attempt_quota_is_atomic(live_store):
    eid, tid = await _engagement(live_store)
    memory = live_store.session_memory
    async with memory._async_session() as db:
        await db.execute(
            update(SessionStateORM).where(SessionStateORM.session_id == eid)
            .values(roe={"execution_attempt_budget_total": 1})
        )
        await db.commit()
    other = SupervisionStore(memory)
    results = await asyncio.gather(
        live_store.start_attempt(eid, tid, 1, "running"),
        other.start_attempt(eid, tid, 2, "running"),
        return_exceptions=True,
    )
    assert sum(isinstance(result, dict) and result.get("created") is True for result in results) == 1
    denied = [result for result in results if isinstance(result, SupervisionConflict)]
    assert len(denied) == 1 and "quota exhausted" in str(denied[0])
    winner = next(result for result in results if isinstance(result, dict))
    replay = await other.start_attempt(eid, tid, winner["attempt"], "running")
    assert replay["created"] is False
    assert replay["id"] == winner["id"]
