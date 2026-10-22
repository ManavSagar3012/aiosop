"""Joined signed Temporal/PG/outbox/0022 recovery faults, with honest scope.

Default run tests production code with deterministic injected SQL/network faults.
Set OSOP_DISPOSABLE_JOINED_RECOVERY=1 to ALSO run REAL Temporal + migrated
PostgreSQL against two fresh, uniquely owned loopback Docker containers.
No application database, assessment target, real observer or agent is used.
0022 readback is deliberately UNKNOWN: a synthetic witness cannot mint VERIFIED.
"""

import asyncio
import time
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, text, update

from ai_osop.memory.independent_target_effect_verifications import (
    read_independent_target_effect_verification,
)
from ai_osop.memory.outbox_delivery_dedupe import OutboxConsumerUnavailable
from ai_osop.memory.supervision_store import SupervisionOutboxORM, SupervisionStore
from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.supervision_outbox import (
    SupervisionNotificationConsumer,
    _safe_notification,
)
from tests.qualification.joined_recovery_fixture_20261018 import (
    disposable_recovery_services,
    joined_signed_pg,
)
from tests.test_outbox_cross_replica_idempotency import (
    _claims,
    _completed,
    _event,
    _expire_claim,
)
from tests.test_outbox_readback_identity_20261018 import _IdentityStore, _consumer


class _NoPromotion:
    """Return no immutable witness rows, not a made-up VERIFIED certificate."""

    def in_transaction(self):
        return True

    async def execute(self, statement, params):
        assert "independent_target_effect_verifications" in str(statement)
        assert "FOR SHARE" in str(statement)
        return SimpleNamespace(mappings=lambda: SimpleNamespace(one_or_none=lambda: None))


async def _independent_unknown(db, engagement_id, flow_id, finding_id):
    # All caller-side approvals intentionally evaluate True: with no distinct
    # target-owned signed witness, none is sufficient to mint a verification.
    allow = AsyncMock(return_value=True)
    result = await read_independent_target_effect_verification(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        evidence_sha256="a" * 64,
        authorization_version=1,
        reviewer_sub="senior-joined",
        reviewer_role="senior_operator",
        reviewer_token_sha256="b" * 64,
        reviewer_expires_at=int(time.time()) + 120,
        trusted_current_verifier=allow,
        trusted_report_source_check=AsyncMock(return_value=True),
        trusted_anonymous_signed_dispatch_check=AsyncMock(return_value=True),
    )
    assert result == {
        "status": "UNKNOWN",
        "finding_verified": False,
        "independent_effect_verified": False,
        "authorization_violation_verified": False,
        "report_release_approved": False,
        "finding_release_eligible": False,
        "verification_id": None,
        "verification_sha256": None,
    }
    return result


@pytest.mark.asyncio
async def test_injected_missing_0022_witness_never_promotes_signed_claims():
    """INJECTED read-only transaction; not a live PostgreSQL qualification."""
    await _independent_unknown(
        _NoPromotion(),
        "eng-joined-synthetic",
        "flow-joined-synthetic",
        "finding-joined-synthetic",
    )


@pytest.mark.asyncio
async def test_injected_expired_notification_lease_never_becomes_effect_proof():
    """INJECTED transactional store + fault after the real callback function."""
    store = _IdentityStore()
    side_effect = AsyncMock()

    async def sent_then_lease_lost(safe):
        await side_effect(safe)
        _expire_claim(store)

    with pytest.raises(OutboxConsumerUnavailable, match="expired"):
        await _consumer(store).consume(_event(), sent_then_lease_lost)
    assert len(_claims(store)) == 1 and not _completed(store)
    assert await _consumer(store).consume(_event(), side_effect)
    assert not await _consumer(store).consume(_event(), side_effect)
    assert side_effect.await_count == 2  # Legitimate at-least-once retry.
    assert len(_completed(store)) == 1
    await _independent_unknown(
        _NoPromotion(),
        "eng-joined-synthetic",
        "flow-joined-synthetic",
        "finding-joined-synthetic",
    )


@pytest.mark.asyncio
async def test_injected_source_revocation_during_callback_blocks_receipt():
    """INJECTED transactional source tamper, not a real PG revocation event."""
    store = _IdentityStore()
    called = AsyncMock()

    async def revoke_after_side_effect(safe):
        await called(safe)
        store.origin.engagement_id = "eng-revoked-foreign"

    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await _consumer(store).consume(_event(), revoke_after_side_effect)
    called.assert_awaited_once()
    assert not _completed(store)
    _expire_claim(store)
    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await _consumer(store).consume(_event(), called)
    called.assert_awaited_once()
    await _independent_unknown(
        _NoPromotion(),
        "eng-joined-synthetic",
        "flow-joined-synthetic",
        "finding-joined-synthetic",
    )


async def _committed_notification(pg):
    async with pg.memory._async_session() as db:
        row = (
            await db.execute(
                select(SupervisionOutboxORM).where(
                    SupervisionOutboxORM.event_id == pg.source_event_id,
                    SupervisionOutboxORM.engagement_id == pg.session.session_id,
                )
            )
        ).scalar_one()
        safe = _safe_notification(
            {
                "event_id": row.event_id,
                "engagement_id": row.engagement_id,
                "topic": row.topic,
                "payload": row.payload,
            }
        )
    return CoordinationEvent(topic="supervision.event", source="supervision-outbox", payload=safe)


async def _assert_real_0022_unknown(pg):
    async with pg.memory._async_session() as db:
        async with db.begin():
            count = (
                await db.execute(
                    text("SELECT count(*) FROM independent_target_effect_verifications")
                )
            ).scalar_one()
            assert count == 0, "No synthetic promotion may enter isolated PG"
            await _independent_unknown(
                db,
                pg.session.session_id,
                pg.flow.id,
                "finding-joined-" + pg.task.id.removeprefix("task-joined-"),
            )


@pytest.mark.asyncio
@pytest.mark.timeout(150)
async def test_live_joined_signed_temporal_unknown_replay_outbox_and_0022(joined_signed_pg):
    """LIVE fresh PostgreSQL + Temporal; network timeout is injected after commit."""
    from temporalio.client import Client

    from ai_osop.orchestrator.temporal_worker import TemporalTaskScheduler
    from tests.qualification.test_live_temporal_admission_recovery import _local_worker

    pg = joined_signed_pg
    client = await asyncio.wait_for(Client.connect(pg.temporal_address), timeout=12)
    claim = await pg.memory.claim_temporal_dispatch(pg.task)
    assert claim.startswith("temporal-claim-")
    assert (await pg.memory.load_task_authoritative(pg.task.id)).status == "dispatching"

    queue = "joined-qual-" + uuid.uuid4().hex[:12]
    payload = {"id": pg.task.id, "timeout_seconds": 10}
    count = []

    async def accepted_but_ack_lost(*args, **kwargs):
        await client.start_workflow(*args, **kwargs)  # ACTUAL disposable Temporal RPC.
        raise TimeoutError("injected response lost AFTER real Temporal acceptance")

    interrupted = TemporalTaskScheduler(
        client=SimpleNamespace(start_workflow=accepted_but_ack_lost),
        task_queue=queue,
    )
    primary = TemporalTaskScheduler(client=client, task_queue=queue)
    async with _local_worker(client, queue, counter=count):
        with pytest.raises(TimeoutError, match="response lost"):
            await interrupted.start_task_workflow(payload)
        # The server deduplicates the same workflow ID after response loss.
        workflow_id = await primary.start_task_workflow(payload)
        assert workflow_id == "ai-osop-" + pg.task.id
        result = await asyncio.wait_for(client.get_workflow_handle(workflow_id).result(), 20)
        assert result == {"status": "synthetic_complete", "remote_targets": 0}
    assert count == ["invoked"]
    await pg.memory.settle_temporal_dispatch(
        pg.task.id, pg.session.session_id, claim, "dispatch_unknown"
    )
    with pytest.raises(PermissionError):
        await pg.memory.claim_temporal_dispatch(pg.task)
    assert (await pg.memory.load_task_authoritative(pg.task.id)).status == "dispatch_unknown"

    event = await _committed_notification(pg)
    notify = AsyncMock()
    first = SupervisionNotificationConsumer(
        durable_store=SupervisionStore(pg.memory), consumer_id="joined-notify-v1"
    )
    second = SupervisionNotificationConsumer(
        durable_store=SupervisionStore(pg.memory), consumer_id="joined-notify-v1"
    )
    outcomes = await asyncio.gather(
        first.consume(event, notify),
        second.consume(event, notify),
        return_exceptions=True,
    )
    assert sum(value is True for value in outcomes) == 1
    assert all(
        value is True or value is False or isinstance(value, OutboxConsumerUnavailable)
        for value in outcomes
    )
    assert await second.consume(event, notify) is False
    notify.assert_awaited_once()
    async with pg.memory._async_session() as db:
        receipts = (
            await db.execute(
                text(
                    "SELECT id FROM supervision_events WHERE engagement_id=:eng "
                    "AND kind='supervision.notification_consumed' AND "
                    "payload->>'source_event_id'=:source"
                ),
                {"eng": pg.session.session_id, "source": pg.source_event_id},
            )
        ).all()
    assert len(receipts) == 1
    await _assert_real_0022_unknown(pg)


@pytest.mark.asyncio
@pytest.mark.timeout(130)
async def test_live_joined_revoked_roe_and_cross_tenant_receipt_fails_closed(joined_signed_pg):
    """LIVE PostgreSQL signed revocation, outbox identity, 0022 UNKNOWN."""
    pg = joined_signed_pg
    event = await _committed_notification(pg)
    notify = AsyncMock()
    consumer = SupervisionNotificationConsumer(
        durable_store=SupervisionStore(pg.memory), consumer_id="joined-revocation-v1"
    )
    foreign = CoordinationEvent(
        topic=event.topic,
        source=event.source,
        payload={**event.payload, "engagement_id": "eng-foreign-joined"},
    )
    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await consumer.consume(foreign, notify)
    notify.assert_not_awaited()
    assert await consumer.consume(event, notify) is True
    assert await consumer.consume(event, notify) is False
    notify.assert_awaited_once()
    assert await pg.authority.revoke(
        pg.session.session_id,
        pg.session.created_by,
        1,
        "Disposable qualification revokes signed authorization",
    )
    with pytest.raises(Exception):
        await pg.memory.claim_temporal_dispatch(pg.task)
    assert (await pg.memory.load_task_authoritative(pg.task.id)).status == "pending"
    # Revocation does not rewrite an already committed notification receipt
    # into independently verified private target effects.
    await _assert_real_0022_unknown(pg)


@pytest.mark.asyncio
@pytest.mark.timeout(130)
async def test_live_pg_stale_outbox_lease_cannot_ack_after_reclaim(joined_signed_pg):
    """LIVE PG lease CAS; only the expiry clock jump is injected in disposable PG."""
    pg = joined_signed_pg
    old = next(
        row
        for row in await pg.supervision.claim_outbox(limit=50, lease_seconds=30)
        if row["event_id"] == pg.source_event_id
    )
    assert not await pg.supervision.ack_outbox(old["id"], "lease-foreign-token")
    # Advance exactly our new outbox lease in the isolated database, rather
    # than waiting 30 seconds or changing a shared application database.
    async with pg.memory._async_session() as db:
        async with db.begin():
            await db.execute(
                update(SupervisionOutboxORM)
                .where(
                    SupervisionOutboxORM.id == old["id"],
                    SupervisionOutboxORM.engagement_id == pg.session.session_id,
                )
                .values(leased_until=datetime.utcnow() - timedelta(seconds=1))
            )
    assert not await pg.supervision.ack_outbox(old["id"], old["lease_id"])
    new = next(
        row
        for row in await pg.supervision.claim_outbox(limit=50, lease_seconds=30)
        if row["id"] == old["id"]
    )
    assert new["lease_id"] != old["lease_id"]
    assert not await pg.supervision.ack_outbox(old["id"], old["lease_id"])
    assert await pg.supervision.ack_outbox(new["id"], new["lease_id"])
    assert not await pg.supervision.ack_outbox(new["id"], new["lease_id"])
    # Outbox ACK alone never establishes independently verified target effect.
    await _assert_real_0022_unknown(pg)
