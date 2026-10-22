"""Isolated PostgreSQL 16 terminal/callback atomicity qualification.

Never point this suite at the application database. It rejects the standard
5432/5433 ports, requires a terminal_qualification_ database and loopback.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import AsyncMock
from types import SimpleNamespace

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    ExecutionFlowORM,
    SessionMemory,
    SessionStateORM,
    TaskORM,
)
from ai_osop.memory.supervision_store import SupervisionConflict
from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore, TerminalCallbackORM
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher


def _db_url():
    raw = os.getenv("OSOP_TERMINAL_TEST_PG_URI", "")
    if not raw:
        pytest.skip("No disposable terminal qualification database configured")
    url = make_url(raw)
    if (
        url.drivername != "postgresql+asyncpg"
        or url.host not in {"localhost", "127.0.0.1"}
        or url.port in {None, 5432, 5433}
        or not str(url.database or "").startswith("terminal_qualification_")
    ):
        pytest.fail("Refusing to run terminal qualification on application database")
    return raw


def _migration(connection, revision, op):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "migrations"))
    config.attributes["connection"] = connection
    getattr(command, op)(config, revision)


@pytest.fixture
async def live():
    engine = create_async_engine(_db_url(), pool_size=5)
    async with engine.begin() as connection:
        await connection.run_sync(_migration, "head", "upgrade")
    maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    memory = SessionMemory()
    memory._async_session = maker

    try:
        yield engine, maker, TerminalLifecycleStore(memory)
    finally:
        await engine.dispose()


async def _seed(maker):
    suffix = uuid.uuid4().hex[:14]
    eid, tid = "eng-" + suffix, "task-" + suffix
    now = datetime.utcnow()
    async with maker() as session:
        async with session.begin():
            session.add(
                SessionStateORM(
                    session_id=eid,
                    scope={
                        "engagement_id": eid,
                        "domains": ["example.test"],
                        "ips": [],
                        "authorization_ref": "signed-qualification-roe",
                    },
                    roe={},
                    phase="reconnaissance",
                    agents={},
                    checkpoint_id=None,
                    audit_log_position="0",
                    created_by="qualification-operator",
                    created_at=now,
                    updated_at=now,
                )
            )
            session.add(
                TaskORM(
                    id=tid,
                    engagement_id=eid,
                    type="recon",
                    priority=5,
                    agent_type="recon",
                    payload={},
                    dependencies=[],
                    max_retries=0,
                    timeout_seconds=120,
                    scope_check=True,
                    approval_required=False,
                    status="running",
                    result=None,
                    retry_count=0,
                    created_at=now,
                    started_at=now,
                )
            )
    return eid, tid


@pytest.mark.asyncio
async def test_live_terminal_transaction_single_winner_and_durable_outbox(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    writes = await asyncio.gather(
        store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded"),
        store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded"),
    )
    assert sum(bool(result and result.get("created")) for result in writes) == 1
    async with maker() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == tid))).scalar_one()
        assert task.status == "completed"
        assert task.result == {"status": "completed"}
        rows = (
            (
                await db.execute(
                    select(TerminalCallbackORM).where(TerminalCallbackORM.task_id == tid)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1 and rows[0].status == "pending"
    events = await store.list_events_after(eid, 0, tid)
    assert len([event for event in events if event["kind"] == "task.completed"]) == 1
    assert any(
        item.get("topic") == "task.completed"
        or item.get("payload", {}).get("kind") == "task.completed"
        for item in await store.claim_outbox(limit=50)
    )


@pytest.mark.asyncio
async def test_live_callback_claim_ack_and_duplicate_replay_blocked(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    claims = await asyncio.gather(
        store.claim_callbacks("process-a"),
        store.claim_callbacks("process-b"),
    )
    matching = [item for group in claims for item in group if item["task_id"] == tid]
    assert len(matching) == 1
    claim = matching[0]
    assert await store.finish_callback(claim["id"], "wrong-owner") is False
    assert not await store.finish_callback(claim["id"], claim["lease_id"])
    assert await store.plan_callback_effects(
        claim["id"], claim["lease_id"], claim["worker_id"], ["sync_subtask"]
    )
    assert await store.start_callback_effect(
        claim["id"], claim["lease_id"], claim["worker_id"], "sync_subtask"
    )
    assert await store.confirm_callback_effect(
        claim["id"], claim["lease_id"], claim["worker_id"], "sync_subtask"
    )
    assert await store.finish_callback(claim["id"], claim["lease_id"])
    assert not await store.finish_callback(claim["id"], claim["lease_id"])
    assert not any(item["task_id"] == tid for item in await store.claim_callbacks("process-c"))


@pytest.mark.asyncio
async def test_live_crashed_callback_before_any_effect_can_reclaim_without_replay(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    original = next(row for row in await store.claim_callbacks("owner-before-start") if row["task_id"] == tid)
    steps = ["sync_subtask", "graph_upsert"]
    assert await store.plan_callback_effects(
        original["id"], original["lease_id"], "owner-before-start", steps
    )
    # The worker died after committing the whole manifest but BEFORE
    # persisting any started effect, the only safe callback replay case.
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TerminalCallbackORM)
                .where(TerminalCallbackORM.id == original["id"])
                .values(leased_until=datetime.utcnow() - timedelta(seconds=1))
            )
    replacement = next(
        row for row in await store.claim_callbacks("owner-recover") if row["task_id"] == tid
    )
    assert replacement["id"] == original["id"]
    assert replacement["lease_id"] != original["lease_id"]
    assert replacement["effect_steps"]["states"] == dict.fromkeys(steps, "pending")
    assert not await store.finish_callback(original["id"], original["lease_id"])
    for step in steps:
        assert await store.start_callback_effect(
            replacement["id"], replacement["lease_id"], "owner-recover", step
        )
        assert await store.confirm_callback_effect(
            replacement["id"], replacement["lease_id"], "owner-recover", step
        )
    assert await store.finish_callback(replacement["id"], replacement["lease_id"])
    assert (await store.list_callbacks(eid, tid))[0]["status"] == "done"


@pytest.mark.asyncio
async def test_live_callback_all_effects_done_recovers_only_lost_final_ack(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    item = next(
        row for row in await store.claim_callbacks("worker-effects") if row["task_id"] == tid
    )
    steps = ["sync_subtask", "graph_upsert", "downstream_schedule"]
    assert await store.plan_callback_effects(
        item["id"], item["lease_id"], "worker-effects", steps
    )
    for step in steps:
        assert await store.start_callback_effect(
            item["id"], item["lease_id"], "worker-effects", step
        )
        assert await store.confirm_callback_effect(
            item["id"], item["lease_id"], "worker-effects", step
        )
    # Simulate a process death after durable last effect return, but before
    # the overall callback ACK was committed.
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TerminalCallbackORM)
                .where(TerminalCallbackORM.id == item["id"])
                .values(leased_until=datetime.utcnow() - timedelta(seconds=1))
            )
    assert not any(
        row["task_id"] == tid for row in await store.claim_callbacks("worker-recovery")
    )
    recovered = (await store.list_callbacks(eid, tid))[0]
    assert recovered["status"] == "done"
    assert recovered["effect_steps"]["states"] == dict.fromkeys(steps, "done")
    events = await store.list_events_after(eid, 0, tid)
    assert len([event for event in events if event["kind"] == "agent.callback_done"]) == 1
    assert not await store.finish_callback(item["id"], item["lease_id"])


@pytest.mark.asyncio
async def test_live_callback_started_effect_crash_quarantines_only_uncertain_step(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    item = next(
        row for row in await store.claim_callbacks("worker-partial") if row["task_id"] == tid
    )
    steps = ["sync_subtask", "downstream_schedule", "surface_continuation"]
    assert await store.plan_callback_effects(item["id"], item["lease_id"], "worker-partial", steps)
    assert await store.start_callback_effect(
        item["id"], item["lease_id"], "worker-partial", "sync_subtask"
    )
    assert await store.confirm_callback_effect(
        item["id"], item["lease_id"], "worker-partial", "sync_subtask"
    )
    assert await store.start_callback_effect(
        item["id"], item["lease_id"], "worker-partial", "downstream_schedule"
    )
    # No return was observed: provider may have acted before the crash.
    assert not await store.finish_callback(item["id"], "wrong-owner")
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TerminalCallbackORM)
                .where(TerminalCallbackORM.id == item["id"])
                .values(leased_until=datetime.utcnow() - timedelta(seconds=1))
            )
    assert not any(
        row["task_id"] == tid for row in await store.claim_callbacks("worker-replacement")
    )
    state = (await store.list_callbacks(eid, tid))[0]
    assert state["status"] == "unknown"
    assert state["effect_steps"]["states"] == {
        "sync_subtask": "done",
        "downstream_schedule": "unknown",
        "surface_continuation": "pending",
    }
    assert not await store.confirm_callback_effect(
        item["id"], item["lease_id"], "worker-partial", "downstream_schedule"
    )


@pytest.mark.asyncio
async def test_live_effect_steps_are_ordered_lease_fenced_and_not_replanned(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    item = next(
        row for row in await store.claim_callbacks("worker-ordered") if row["task_id"] == tid
    )
    callback_id, lease_id = item["id"], item["lease_id"]
    assert await store.plan_callback_effects(
        callback_id, lease_id, "worker-ordered", ["sync_subtask", "graph_upsert"]
    )
    with pytest.raises(SupervisionConflict, match="plan changed"):
        await store.plan_callback_effects(
            callback_id, lease_id, "worker-ordered", ["graph_upsert", "sync_subtask"]
        )
    with pytest.raises(SupervisionConflict, match="Previous callback effect"):
        await store.start_callback_effect(
            callback_id, lease_id, "worker-ordered", "graph_upsert"
        )
    with pytest.raises(SupervisionConflict, match="ownership"):
        await store.start_callback_effect(
            callback_id, lease_id, "different-worker", "sync_subtask"
        )
    assert await store.start_callback_effect(
        callback_id, lease_id, "worker-ordered", "sync_subtask"
    )
    with pytest.raises(SupervisionConflict, match="uncertain prior dispatch"):
        await store.start_callback_effect(
            callback_id, lease_id, "worker-ordered", "sync_subtask"
        )
    assert await store.confirm_callback_effect(
        callback_id, lease_id, "worker-ordered", "sync_subtask"
    )
    assert not await store.start_callback_effect(
        callback_id, lease_id, "worker-ordered", "sync_subtask"
    )
    assert await store.start_callback_effect(
        callback_id, lease_id, "worker-ordered", "graph_upsert"
    )
    assert not await store.finish_callback(callback_id, lease_id)
    assert await store.finish_callback(callback_id, lease_id, status="unknown")
    result = (await store.list_callbacks(eid, tid))[0]
    assert result["effect_steps"]["states"] == {
        "sync_subtask": "done", "graph_upsert": "unknown"
    }


@pytest.mark.asyncio
async def test_live_failed_effect_audit_transaction_never_dispatches(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    item = next(
        row for row in await store.claim_callbacks("worker-audit") if row["task_id"] == tid
    )
    assert await store.plan_callback_effects(
        item["id"], item["lease_id"], "worker-audit", ["sync_subtask"]
    )
    append_original = store._append_event

    async def broken_audit(*args, **kwargs):
        raise RuntimeError("simulated audit outbox failure")

    store._append_event = broken_audit
    try:
        with pytest.raises(RuntimeError, match="audit outbox failure"):
            await store.start_callback_effect(
                item["id"], item["lease_id"], "worker-audit", "sync_subtask"
            )
    finally:
        store._append_event = append_original
    assert (await store.list_callbacks(eid, tid))[0]["effect_steps"]["states"] == {
        "sync_subtask": "pending"
    }
    assert await store.start_callback_effect(
        item["id"], item["lease_id"], "worker-audit", "sync_subtask"
    )


@pytest.mark.asyncio
async def test_live_callback_renewal_is_owner_fenced_and_never_revives_expired_lease(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    item = next(
        row for row in await store.claim_callbacks("worker-owner", lease_seconds=30)
        if row["task_id"] == tid
    )
    assert not await store.renew_callback_lease(
        item["id"], item["lease_id"], "foreign-worker"
    )
    assert not await store.renew_callback_lease(
        item["id"], "foreign-token", "worker-owner"
    )
    assert await store.renew_callback_lease(
        item["id"], item["lease_id"], "worker-owner"
    )
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TerminalCallbackORM)
                .where(TerminalCallbackORM.id == item["id"])
                .values(leased_until=datetime.utcnow() - timedelta(seconds=1))
            )
    assert not await store.renew_callback_lease(
        item["id"], item["lease_id"], "worker-owner"
    )
    assert not await store.finish_callback(item["id"], item["lease_id"])
    assert not any(
        row["task_id"] == tid
        for row in await store.claim_callbacks("replacement-worker")
    )
    assert (await store.list_callbacks(eid, tid))[0]["status"] == "unknown"


@pytest.mark.asyncio
async def test_live_unknown_callback_never_blind_replayed_after_crash(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    claim = next(
        item
        for item in await store.claim_callbacks("worker-crashed", lease_seconds=1)
        if item["task_id"] == tid
    )
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TerminalCallbackORM)
                .where(TerminalCallbackORM.id == claim["id"])
                .values(leased_until=datetime.utcnow() - timedelta(seconds=1))
            )
    assert not any(
        item["task_id"] == tid for item in await store.claim_callbacks("worker-restarted")
    )
    assert (await store.list_callbacks(eid, tid))[0]["status"] == "unknown"
    assert not await store.finish_callback(claim["id"], claim["lease_id"])


@pytest.mark.asyncio
async def test_live_halt_prevents_terminal_success_and_any_callback(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(SessionStateORM)
                .where(SessionStateORM.session_id == eid)
                .values(phase="halted")
            )
    with pytest.raises(SupervisionConflict, match="closed"):
        await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    async with maker() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == tid))).scalar_one()
        assert task.status == "running"
    assert await store.list_callbacks(eid, tid) == []


@pytest.mark.asyncio
async def test_live_late_unknown_quarantine_cannot_erase_committed_completion(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    orchestrator = Orchestrator(store.session_memory, AsyncMock(), AsyncMock(), AsyncMock())
    orchestrator._supervision_active = True
    stale = Task(id=tid, engagement_id=eid, type="recon", agent_type=AgentType.RECON)
    stale.status = "running"
    await orchestrator._quarantine_unknown_execution(stale)
    assert stale.status == "completed"
    async with maker() as db:
        row = (await db.execute(select(TaskORM).where(TaskORM.id == tid))).scalar_one()
        assert row.status == "completed"
    assert (await store.list_callbacks(eid, tid))[0]["status"] == "pending"


@pytest.mark.asyncio
async def test_live_stale_task_upsert_cannot_resurrect_terminal_row(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    stale = Task(
        id=tid,
        engagement_id=eid,
        type="recon",
        agent_type=AgentType.RECON,
        status="running",
        payload={"secret": "stale-snapshot"},
    )
    store.session_memory.store_hot = AsyncMock()
    await store.session_memory.store_task(stale)
    store.session_memory.store_hot.assert_not_awaited()
    fresh = await store.session_memory.load_task_authoritative(tid)
    assert fresh.status == "completed"
    assert fresh.result == {"status": "completed"}
    assert fresh.payload == {}


@pytest.mark.asyncio
async def test_live_terminal_event_write_failure_rolls_back_task_attempt_and_callback(
    live, monkeypatch
):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    original = store._append_event
    monkeypatch.setattr(
        store, "_append_event", AsyncMock(side_effect=RuntimeError("injected transaction failure"))
    )
    with pytest.raises(RuntimeError, match="injected transaction failure"):
        await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    async with maker() as db:
        task = (await db.execute(select(TaskORM).where(TaskORM.id == tid))).scalar_one()
        assert task.status == "running"
    rows = await store.list_attempts(eid, tid)
    assert rows[0]["status"] == "running" and rows[0]["revision"] == 0
    assert await store.list_callbacks(eid, tid) == []
    monkeypatch.setattr(store, "_append_event", original)
    assert (await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded"))["created"]


@pytest.mark.asyncio
async def test_live_wrong_owner_lease_cannot_finalize_or_replay_task(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    lease = await store.claim_execution_lease(eid, tid, "original-owner", ttl_seconds=30)
    assert lease["acquired"]
    assert await store.mark_execution_dispatched(eid, tid, "original-owner", lease["lease_id"])
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    with pytest.raises(SupervisionConflict, match="lease proof"):
        await store.commit_terminal(
            eid,
            tid,
            attempt["id"],
            0,
            "succeeded",
            owner_id="other-owner",
            lease_id=lease["lease_id"],
        )
    assert await store.list_callbacks(eid, tid) == []
    saved = await store.commit_terminal(
        eid,
        tid,
        attempt["id"],
        0,
        "succeeded",
        owner_id="original-owner",
        lease_id=lease["lease_id"],
    )
    assert saved and saved["created"]
    assert not (await store.claim_execution_lease(eid, tid, "other-owner"))["acquired"]


@pytest.mark.asyncio
async def test_live_revoked_approval_blocks_terminal_success(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    approval_id = "apr-" + uuid.uuid4().hex[:16]
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TaskORM)
                .where(TaskORM.id == tid)
                .values(
                    type="exploit_validation",
                    approval_required=True,
                    payload={"approval_id": approval_id, "operator_approved": True},
                )
            )
            db.add(
                ApprovalRequestORM(
                    id=approval_id,
                    task_id=tid,
                    engagement_id=eid,
                    status="approved",
                    action_type="exploit_validation",
                    agent_id="test",
                    target="example.test",
                    payload_summary="Approved in isolated qualification",
                    risk_assessment="test",
                    evidence={},
                    requested_at=datetime.utcnow(),
                )
            )
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    # Approval was valid at dispatch, then the operator revoked it while a
    # possibly consequential execution was running. Finalization must reject
    # any report claiming success under this now-revoked authorization.
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(ApprovalRequestORM)
                .where(ApprovalRequestORM.id == approval_id)
                .values(status="rejected")
            )
    with pytest.raises(SupervisionConflict, match="approval"):
        await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(ApprovalRequestORM)
                .where(ApprovalRequestORM.id == approval_id)
                .values(status="approved")
            )
    saved = await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    assert saved and saved["created"]


@pytest.mark.asyncio
async def test_live_paused_flow_blocks_terminal_success_until_resumed(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    flow_id = "flow-" + uuid.uuid4().hex[:16]
    now = datetime.utcnow()
    async with maker() as db:
        async with db.begin():
            db.add(
                ExecutionFlowORM(
                    id=flow_id,
                    engagement_id=eid,
                    objective="isolated lifecycle",
                    status="paused",
                    revision=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            await db.execute(update(TaskORM).where(TaskORM.id == tid).values(flow_id=flow_id))
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    with pytest.raises(SupervisionConflict, match="paused"):
        await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(ExecutionFlowORM)
                .where(ExecutionFlowORM.id == flow_id)
                .values(status="running", revision=2)
            )
    assert (await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded"))["created"]


@pytest.mark.asyncio
async def test_live_scope_shrink_after_dispatch_blocks_terminal_and_callback(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TaskORM)
                .where(TaskORM.id == tid)
                .values(payload={"target": "https://example.test/report"})
            )
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    async with maker() as db:
        async with db.begin():
            engagement = (
                await db.execute(select(SessionStateORM).where(SessionStateORM.session_id == eid))
            ).scalar_one()
            engagement.scope = {
                **engagement.scope,
                "domains": ["unrelated.test"],
            }
    with pytest.raises(SupervisionConflict, match="targets"):
        await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    assert await store.list_callbacks(eid, tid) == []
    assert (await store.list_attempts(eid, tid))[0]["status"] == "running"


@pytest.mark.asyncio
async def test_live_workflow_continuation_survives_without_streaming_private_path(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    async with maker() as db:
        async with db.begin():
            await db.execute(
                update(TaskORM)
                .where(TaskORM.id == tid)
                .values(
                    type="capture_authenticated_surface",
                    agent_type=AgentType.WORKFLOW.value,
                    payload={"target": "https://example.test"},
                )
            )
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    private_path = "C:\\isolated\\evidence\\capture.har"
    record = await store.commit_terminal(
        eid,
        tid,
        attempt["id"],
        0,
        "succeeded",
        continuation={
            "status": "success",
            "har_path": private_path,
            "model_reasoning": "PRIVATE_CONTENT_MUST_NOT_LEAK",
        },
    )
    assert record["created"]
    callbacks = await store.list_callbacks(eid, tid)
    assert private_path not in str(callbacks)
    events = await store.list_events_after(eid, 0, tid)
    assert private_path not in str(events)
    assert "PRIVATE_CONTENT_MUST_NOT_LEAK" not in str(events)

    orch = _callback_orchestrator(store)
    dispatcher = TerminalCallbackDispatcher(orch)
    await dispatcher.flush_once()
    own = [
        call for call in orch._chain_authenticated_surface.await_args_list if call.args[0].id == tid
    ]
    assert len(own) == 1
    assert own[0].args[1]["har_path"] == private_path
    assert "model_reasoning" not in own[0].args[1]


@pytest.mark.asyncio
async def test_live_postgres_terminal_callback_projects_once_into_isolated_neo4j(live):
    neo_uri = os.getenv("OSOP_TERMINAL_TEST_NEO4J_URI")
    if not neo_uri:
        pytest.skip("Isolated Neo4j instance not configured")
    if neo_uri not in {"bolt://127.0.0.1:17688", "bolt://localhost:17688"}:
        pytest.fail("Refusing live graph qualification against non-isolated Neo4j")

    from neo4j import AsyncGraphDatabase
    from ai_osop.memory.graph_memory import GraphMemory

    graph = GraphMemory()
    graph._driver = AsyncGraphDatabase.driver(neo_uri, auth=None)
    try:
        await graph._driver.verify_connectivity()
        await graph._setup_schema()
        _, maker, store = live
        eid, tid = await _seed(maker)
        attempt = await store.start_attempt(eid, tid, 1, status="running")
        await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
        orch = _callback_orchestrator(store)
        orch.graph_memory = graph
        dispatcher = TerminalCallbackDispatcher(orch)
        assert await dispatcher.flush_once() >= 1
        assert (await store.list_callbacks(eid, tid))[0]["status"] == "done"
        async with graph._driver.session() as session:
            result = await session.run(
                "MATCH (t:Task {id:$id}) RETURN count(t) AS copies, "
                "collect(t.status) AS statuses",
                {"id": tid},
            )
            row = await result.single()
        assert row["copies"] == 1
        assert row["statuses"] == ["completed"]
        # Reprocessing a terminal notification must not perform a duplicate
        # projection or spawn a second graph task.
        assert await dispatcher.flush_once() == 0
        async with graph._driver.session() as session:
            result = await session.run(
                "MATCH (t:Task {id:$id}) RETURN count(t) AS copies",
                {"id": tid},
            )
            row = await result.single()
        assert row["copies"] == 1
    finally:
        await graph.close()


def _callback_orchestrator(store):
    orch = Orchestrator(store.session_memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch._terminal_store = store
    orch._supervision_active = True
    orch._sync_subtask_result = AsyncMock()
    orch._refine_completed_flow_subtask = AsyncMock()
    orch._trigger_downstream_tasks = AsyncMock()
    orch._chain_authenticated_surface = AsyncMock()
    orch.adaptive_planner = SimpleNamespace(on_task_completed=AsyncMock())
    return orch


@pytest.mark.asyncio
async def test_live_agent_result_to_atomic_terminal_to_callback_ack(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    orch = _callback_orchestrator(store)
    task = Task(
        id=tid,
        engagement_id=eid,
        type="recon",
        agent_type=AgentType.RECON,
        status="running",
    )
    agent = SimpleNamespace(
        ctx=SimpleNamespace(agent_id="qualification-agent"),
        execute_task=AsyncMock(
            return_value={"status": "success", "secret": "private-should-not-reach-event"}
        ),
    )
    outcome = await orch._execute_supervised_agent(agent, task)
    assert outcome == {"status": "terminal_committed", "task_id": tid}
    callbacks = await store.list_callbacks(eid, tid)
    assert callbacks[0]["status"] == "pending"
    dispatcher = TerminalCallbackDispatcher(orch)
    # The dispatcher can legitimately process earlier pending callbacks from
    # this disposable database; assert our task's durable disposition instead
    # of assuming the entire queue was empty when the test began.
    assert await dispatcher.flush_once() >= 1
    assert (await store.list_callbacks(eid, tid))[0]["status"] == "done"
    assert await dispatcher.flush_once() == 0
    assert any(call.args[0].id == tid for call in orch._sync_subtask_result.await_args_list)
    assert any(call.args[0].id == tid for call in orch._trigger_downstream_tasks.await_args_list)
    assert any(call.args[0].id == tid for call in orch._chain_authenticated_surface.await_args_list)
    assert "private-should-not-reach-event" not in str(await store.list_events_after(eid, 0, tid))


@pytest.mark.asyncio
async def test_live_callback_failure_after_projection_stays_unknown_without_reexecution(live):
    _, maker, store = live
    eid, tid = await _seed(maker)
    attempt = await store.start_attempt(eid, tid, 1, status="running")
    await store.commit_terminal(eid, tid, attempt["id"], 0, "succeeded")
    orch = _callback_orchestrator(store)
    orch._trigger_downstream_tasks.side_effect = RuntimeError("injected worker crash")
    dispatcher = TerminalCallbackDispatcher(orch)
    assert await dispatcher.flush_once() == 0
    assert (await store.list_callbacks(eid, tid))[0]["status"] == "unknown"
    assert await dispatcher.flush_once() == 0
    orch._trigger_downstream_tasks.assert_awaited_once()


@pytest.mark.asyncio
async def test_live_migration_0008_effect_receipts_upgrade_downgrade(live):
    engine, _, _ = live

    def column_exists(connection):
        return "effect_steps" in {
            column["name"]
            for column in inspect(connection).get_columns("supervision_terminal_callbacks")
        }

    async with engine.begin() as connection:
        assert await connection.run_sync(column_exists)
        await connection.run_sync(_migration, "0007", "downgrade")
        assert not await connection.run_sync(column_exists)
        await connection.run_sync(_migration, "head", "upgrade")
        assert await connection.run_sync(column_exists)


@pytest.mark.asyncio
async def test_live_migration_0006_round_trip_without_user_data(live):
    engine, _, _ = live
    async with engine.begin() as connection:
        await connection.run_sync(_migration, "0005", "downgrade")
        await connection.run_sync(_migration, "head", "upgrade")
