"""Adversarial identity and receipt readback for the durable PG notification path.

The session double evaluates the same correlated source constraints as the
PostgreSQL query, asserting the generated SQL has them. No app DB or provider.
"""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.memory.outbox_delivery_dedupe import (
    OutboxConsumerUnavailable,
    OutboxDeliveryDedupe,
)
from ai_osop.memory.supervision_store import SupervisionEventORM
from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.supervision_outbox import SupervisionNotificationConsumer
from tests.test_outbox_cross_replica_idempotency import (
    _DurableSession,
    _DurableStore,
    _Read,
    _claims,
    _completed,
    _event,
    _expire_claim,
)
from tests.test_outbox_notification_recovery import notification


class _IdentitySession(_DurableSession):
    async def execute(self, statement):
        if "FROM supervision_outbox" not in str(statement):
            return await super().execute(statement)
        compiled = str(statement.compile(dialect=postgresql.dialect()))
        # The mock below emulates *these* enforced SQL predicates, not a
        # separate Python-only rule absent from the actual production query.
        for required in (
            "FOR UPDATE",
            "EXISTS (SELECT supervision_events.id",
            "supervision_events.id = supervision_outbox.event_id",
            "supervision_events.engagement_id = supervision_outbox.engagement_id",
            "supervision_events.kind = supervision_outbox.topic",
            "IS NOT DISTINCT FROM",
            "supervision_events.payload =",
            "supervision_outbox.payload",
            "FOR SHARE",
        ):
            assert required in compiled, f"Missing durable source constraint: {required}"
        selected = (await super().execute(statement)).scalar_one_or_none()
        if selected is None:
            return _Read(None)
        event = self.store.origin
        if event is None or not (
            event.id == selected.event_id
            and event.engagement_id == selected.engagement_id
            and event.kind == selected.topic
            and event.task_id == selected.payload.get("task_id")
            and event.payload == selected.payload.get("metadata")
        ):
            return _Read(None)
        return _Read(selected)


class _IdentityStore(_DurableStore):
    def __init__(self):
        item = notification()
        super().__init__(item)
        self.origin = SimpleNamespace(
            id=item["event_id"],
            engagement_id=item["engagement_id"],
            kind=item["topic"],
            task_id=item["payload"].get("task_id"),
            payload=deepcopy(item["payload"].get("metadata")),
        )

    def _sessions(self):
        return _IdentitySession(self)


def _consumer(store, name="ops-watch-v1"):
    return SupervisionNotificationConsumer(durable_store=store, consumer_id=name)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["missing_event", "foreign_tenant", "wrong_kind", "wrong_task", "altered_metadata"],
)
async def test_outbox_fk_is_insufficient_for_original_event_identity(change):
    store = _IdentityStore()
    if change == "missing_event":
        store.origin = None
    elif change == "foreign_tenant":
        store.origin.engagement_id = "eng-other-tenant"
    elif change == "wrong_kind":
        store.origin.kind = "report.human_release_approved"
    elif change == "wrong_task":
        store.origin.task_id = "task-another-engagement"
    else:
        store.origin.payload = {"revoked": True}
    notify = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await _consumer(store).consume(_event(), notify)
    notify.assert_not_awaited()
    assert not _claims(store) and not _completed(store)


@pytest.mark.asyncio
async def test_null_task_source_still_delivers_under_postgres_is_not_distinct_from():
    store = _IdentityStore()
    store.rows["out-1"]["payload"]["task_id"] = None
    store.origin.task_id = None
    payload = _event().payload
    event = CoordinationEvent(
        topic="supervision.event",
        source="supervision-outbox",
        payload={**payload, "task_id": None},
    )
    notify = AsyncMock()
    assert await _consumer(store).consume(event, notify) is True
    assert await _consumer(store).consume(event, notify) is False
    notify.assert_awaited_once()


@pytest.mark.asyncio
async def test_original_source_revoked_while_callback_active_never_commits_receipt():
    store = _IdentityStore()
    callback = AsyncMock()

    async def revoke(safe):
        await callback(safe)
        store.origin.engagement_id = "eng-revoked-tenant"

    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await _consumer(store).consume(_event(), revoke)
    callback.assert_awaited_once()
    assert len(_claims(store)) == 1
    assert not _completed(store)
    _expire_claim(store)
    restored = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await _consumer(store).consume(_event(), restored)
    restored.assert_not_awaited()


@pytest.mark.asyncio
async def test_forged_completed_receipt_without_original_claim_cannot_silence_callback():
    store = _IdentityStore()
    consumer = _consumer(store)
    dedupe = OutboxDeliveryDedupe(store, "ops-watch-v1")
    safe = _event().payload
    key, _ = dedupe._identity(safe)
    store.receipts.append(
        SupervisionEventORM(
            id="evt-forged-receipt",
            engagement_id=safe["engagement_id"],
            task_id=safe["task_id"],
            kind="supervision.notification_consumed",
            actor_id=dedupe.consumer_id,
            idempotency_key=key,
            payload=dedupe._receipt_payload(safe),
        )
    )
    notify = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable, match="lacks a claim"):
        await consumer.consume(_event(), notify)
    notify.assert_not_awaited()
    assert not _claims(store)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["wrong_actor", "wrong_task", "wrong_digest"])
async def test_spoofed_completed_receipt_is_rejected_despite_real_claim(change):
    store = _IdentityStore()
    dedupe = OutboxDeliveryDedupe(store, "ops-watch-v1")
    safe = _event().payload
    key, prefix = dedupe._identity(safe)
    assert await dedupe._claim(safe, key, prefix)
    receipt = SupervisionEventORM(
        id="evt-forged-completed",
        engagement_id=safe["engagement_id"],
        task_id=safe["task_id"],
        kind="supervision.notification_consumed",
        actor_id=dedupe.consumer_id,
        idempotency_key=key,
        payload=dedupe._receipt_payload(safe),
    )
    if change == "wrong_actor":
        receipt.actor_id = "foreign-callback"
    elif change == "wrong_task":
        receipt.task_id = "task-wrong-tenant"
    else:
        receipt.payload = {**receipt.payload, "notification_sha256": "f" * 64}
    store.receipts.append(receipt)
    callback = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable, match="conflicts"):
        await _consumer(store).consume(_event(), callback)
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_noncontiguous_claim_ledger_denies_retry_and_minted_receipt():
    store = _IdentityStore()
    dedupe = OutboxDeliveryDedupe(store, "ops-watch-v1")
    safe = _event().payload
    key, prefix = dedupe._identity(safe)
    assert await dedupe._claim(safe, key, prefix)
    claim = _claims(store)[0]
    claim.payload["attempt"] = 7
    claim.idempotency_key = prefix + "07"
    notify = AsyncMock()
    _expire_claim(store)
    with pytest.raises(OutboxConsumerUnavailable, match="malformed"):
        await _consumer(store).consume(_event(), notify)
    notify.assert_not_awaited()
    assert not _completed(store)


@pytest.mark.asyncio
async def test_expired_claim_still_blocks_completion_after_callback_side_effect():
    store = _IdentityStore()
    side_effects = AsyncMock()

    async def deliver(safe):
        await side_effects(safe)
        _expire_claim(store)

    with pytest.raises(OutboxConsumerUnavailable, match="expired"):
        await _consumer(store).consume(_event(), deliver)
    side_effects.assert_awaited_once()
    assert not _completed(store)
    assert await _consumer(store).consume(_event(), side_effects)
    assert side_effects.await_count == 2  # At-least-once after unknown callback result.


@pytest.mark.asyncio
async def test_duplicate_and_distinct_consumer_identities_have_independent_receipts():
    store = _IdentityStore()
    a, b = AsyncMock(), AsyncMock()
    assert await _consumer(store, "consumer-a").consume(_event(), a)
    assert not await _consumer(store, "consumer-a").consume(_event(), a)
    assert await _consumer(store, "consumer-b").consume(_event(), b)
    assert not await _consumer(store, "consumer-b").consume(_event(), b)
    a.assert_awaited_once()
    b.assert_awaited_once()
    assert len(_completed(store)) == 2


@pytest.mark.asyncio
async def test_unknown_receipt_commit_rolls_back_and_keeps_retry_possible():
    store = _IdentityStore()
    store.fail_receipt_commit = True
    callback = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable):
        await _consumer(store).consume(_event(), callback)
    assert not _completed(store)
    _expire_claim(store)
    store.fail_receipt_commit = False
    assert await _consumer(store).consume(_event(), callback)
    assert callback.await_count == 2
    assert len(_completed(store)) == 1
