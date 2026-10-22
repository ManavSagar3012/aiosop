"""Independent replicas and crash windows for durable notification consumers.

All SQL is simulated under one transactional row lock. No application database,
network provider, external target or new migration is used.
"""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.outbox_delivery_dedupe import (
    OutboxConsumerUnavailable,
    OutboxDeliveryDedupe,
)
from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.supervision_outbox import (
    SupervisionNotificationConsumer,
    SupervisionOutboxDispatcher,
)
from tests.test_outbox_notification_recovery import PgSession, PgStore, RecorderBus, notification


class _Read:
    def __init__(self, row):
        self.row = row

    def scalar_one_or_none(self):
        return self.row

    def scalars(self):
        return self

    def all(self):
        return self.row


class _DurableSession(PgSession):
    def __init__(self, store):
        super().__init__(store)
        self.staged = []

    @asynccontextmanager
    async def begin(self):
        async with self.store.lock:
            checkpoint = deepcopy((self.store.rows, self.store.receipts))
            try:
                yield
                if self.store.fail_commit or (
                    self.store.fail_receipt_commit
                    and any(e.kind == "supervision.notification_consumed" for e in self.staged)
                ):
                    raise ConnectionError("simulated receipt commit unknown")
                self.store.receipts.extend(self.staged)
            except BaseException:
                self.store.rows, self.store.receipts = checkpoint
                raise
            finally:
                self.staged.clear()

    async def execute(self, statement):
        sql = str(statement)
        if sql.startswith("UPDATE supervision_outbox SET "):
            return await super().execute(statement)
        params = statement.compile().params
        if "FROM supervision_outbox" in sql:
            assert "FOR UPDATE" in sql
            event_id = next(value for key, value in params.items() if key.startswith("event_id_"))
            engagement = next(
                value for key, value in params.items() if key.startswith("engagement_id_")
            )
            original = next(
                (
                    row
                    for row in self.store.rows.values()
                    if row["event_id"] == event_id and row["engagement_id"] == engagement
                ),
                None,
            )
            if original is None:
                return _Read(None)
            return _Read(SimpleNamespace(**deepcopy(original)))
        if "FROM supervision_events" in sql:
            engagement = next(
                value for key, value in params.items() if key.startswith("engagement_id_")
            )
            idem_key = next(
                value for key, value in params.items() if key.startswith("idempotency_key_")
            )
            if idem_key.endswith("%"):
                return _Read(
                    list(
                        reversed(
                            [
                                row
                                for row in self.store.receipts
                                if row.engagement_id == engagement
                                and row.idempotency_key.startswith(idem_key[:-1])
                            ]
                        )
                    )[:17]
                )
            receipt = next(
                (
                    row
                    for row in self.store.receipts
                    if row.engagement_id == engagement and row.idempotency_key == idem_key
                ),
                None,
            )
            return _Read(receipt)
        raise AssertionError("Unexpected SQL query")

    def add(self, value):
        self.staged.append(value)

    async def flush(self):
        if self.store.fail_flush:
            raise ConnectionError("simulated receipt flush failure")
        if self.store.fail_receipt_flush and any(
            row.kind == "supervision.notification_consumed" for row in self.staged
        ):
            raise ConnectionError("simulated receipt flush failure")
        for row in self.staged:
            if any(
                existing.engagement_id == row.engagement_id
                and existing.idempotency_key == row.idempotency_key
                for existing in self.store.receipts
            ):
                raise ConnectionError("unique event receipt constraint")


class _DurableStore(PgStore):
    def __init__(self, *events):
        super().__init__(*events)
        self.receipts = []
        self.fail_flush = False
        self.fail_commit = False
        self.fail_receipt_flush = False
        self.fail_receipt_commit = False

    def _sessions(self):
        return _DurableSession(self)


def _event(index=1):
    item = notification(index)
    return CoordinationEvent(
        topic="supervision.event",
        source="supervision-outbox",
        payload={
            "event_id": item["event_id"],
            "engagement_id": item["engagement_id"],
            "task_id": item["payload"]["task_id"],
            "kind": item["payload"]["kind"],
        },
    )


def _completed(store):
    return [row for row in store.receipts if row.kind == "supervision.notification_consumed"]


def _claims(store):
    return [row for row in store.receipts if row.kind == "supervision.notification_claimed"]


def _expire_claim(store):
    for entry in _claims(store):
        entry.payload["expires_at"] = (datetime.utcnow() - timedelta(seconds=1)).isoformat()


@pytest.mark.asyncio
async def test_cross_replica_same_consumer_serializes_one_callback_and_one_receipt():
    store = _DurableStore(notification())
    replica_a = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-watch-v1",
    )
    replica_b = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-watch-v1",
    )
    callback = AsyncMock()
    decisions = await asyncio.gather(
        replica_a.consume(_event(), callback),
        replica_b.consume(_event(), callback),
    )
    assert sorted(decisions) == [False, True]
    callback.assert_awaited_once()
    assert len(_completed(store)) == 1
    assert len(_claims(store)) == 1
    receipt = _completed(store)[0]
    assert receipt.kind == "supervision.notification_consumed"
    assert receipt.actor_id == "ops-watch-v1"
    assert receipt.payload == {
        "source_event_id": "evt-1",
        "notification_sha256": receipt.payload["notification_sha256"],
        "consumer_id": "ops-watch-v1",
        "status": "notified",
        "delivery_guarantee": "at_least_once",
    }
    assert len(receipt.payload["notification_sha256"]) == 64
    assert len(receipt.idempotency_key) <= 128
    assert "MUST_NOT_LEAK" not in str(store.receipts)


@pytest.mark.asyncio
async def test_process_recreation_does_not_republish_completed_named_consumer():
    store = _DurableStore(notification())
    callback = AsyncMock()
    first = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-watch-v1",
    )
    assert await first.consume(_event(), callback) is True
    replica_after_restart = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-watch-v1",
    )
    assert await replica_after_restart.consume(_event(), callback) is False
    callback.assert_awaited_once()
    assert len(_completed(store)) == 1


@pytest.mark.asyncio
async def test_independent_consumer_identities_have_independent_receipts():
    store = _DurableStore(notification())
    first = SupervisionNotificationConsumer(durable_store=store, consumer_id="email-v1")
    second = SupervisionNotificationConsumer(durable_store=store, consumer_id="audit-v1")
    email, audit = AsyncMock(), AsyncMock()
    assert await first.consume(_event(), email)
    assert await second.consume(_event(), audit)
    assert len(_completed(store)) == 2
    assert _completed(store)[0].idempotency_key != _completed(store)[1].idempotency_key
    assert not await second.consume(_event(), audit)
    assert not await first.consume(_event(), email)
    email.assert_awaited_once()
    audit.assert_awaited_once()


@pytest.mark.asyncio
async def test_failure_before_callback_completion_rolls_back_receipt_and_retries():
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(durable_store=store, consumer_id="ops-v1")
    callback = AsyncMock(side_effect=[OSError("upstream unknown"), None])
    with pytest.raises(OutboxConsumerUnavailable):
        await consumer.consume(_event(), callback)
    assert len(_completed(store)) == 0
    _expire_claim(store)
    assert await consumer.consume(_event(), callback)
    assert callback.await_count == 2
    assert len(_completed(store)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["fail_receipt_flush", "fail_receipt_commit"])
async def test_callback_then_receipt_failure_is_at_least_once_not_exactly_once(fault):
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(durable_store=store, consumer_id="ops-v1")
    callback = AsyncMock()
    setattr(store, fault, True)
    with pytest.raises(OutboxConsumerUnavailable):
        await consumer.consume(_event(), callback)
    # The external callback may have already sent a notification. Without a
    # committed PG receipt, a new process MUST retry, not falsely ACK it.
    assert len(_completed(store)) == 0
    setattr(store, fault, False)
    _expire_claim(store)
    assert await SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    ).consume(_event(), callback)
    assert callback.await_count == 2
    assert len(_completed(store)) == 1


@pytest.mark.asyncio
async def test_original_outbox_payload_must_match_untrusted_bus_payload():
    store = _DurableStore(notification())
    callback = AsyncMock()
    consumer = SupervisionNotificationConsumer(durable_store=store, consumer_id="ops-v1")
    event = _event()
    altered = CoordinationEvent(
        topic=event.topic,
        source=event.source,
        payload={**event.payload, "kind": "other.event"},
    )
    with pytest.raises(OutboxConsumerUnavailable, match="disagrees"):
        await consumer.consume(altered, callback)
    callback.assert_not_awaited()
    assert len(_completed(store)) == 0
    assert await consumer.consume(event, callback)


@pytest.mark.asyncio
async def test_unknown_uncommitted_event_must_not_notify():
    store = _DurableStore()
    consumer = SupervisionNotificationConsumer(durable_store=store, consumer_id="ops-v1")
    callback = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable, match="committed source"):
        await consumer.consume(_event(), callback)
    callback.assert_not_awaited()


@pytest.mark.asyncio
async def test_receipt_conflict_detected_instead_of_silent_success():
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(durable_store=store, consumer_id="ops-v1")
    callback = AsyncMock()
    assert await consumer.consume(_event(), callback)
    _completed(store)[0].payload = {"status": "forged"}
    with pytest.raises(OutboxConsumerUnavailable, match="conflicts"):
        await consumer.consume(_event(), callback)
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_durable_consumer_timeout_and_cancellation_are_retryable():
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
        delivery_timeout=0.1,
    )
    waiting = asyncio.Event()

    async def slow(_safe):
        await waiting.wait()

    with pytest.raises(OutboxConsumerUnavailable):
        await consumer.consume(_event(), slow)
    assert len(_completed(store)) == 0
    _expire_claim(store)
    callback = AsyncMock()
    assert await consumer.consume(_event(), callback)
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_dispatcher_publish_then_ack_crash_recovers_without_duplicate_callback():
    store, bus = _DurableStore(notification()), RecorderBus()
    notify = AsyncMock()
    dispatcher = SupervisionOutboxDispatcher(
        store,
        bus,
        max_batch=1,
        notification_callback=notify,
        notification_consumer_id="email-v1",
    )
    original_ack = dispatcher._ack

    async def crashed(_entry):
        raise OSError("synthetic failure after bus publication")

    dispatcher._ack = crashed
    assert await dispatcher.flush_once() == 0
    assert len(bus.events) == 1
    assert len(_completed(store)) == 1
    notify.assert_awaited_once()
    assert store.rows["out-1"]["delivered_at"] is None
    store.rows["out-1"]["leased_until"] = datetime.utcnow() - timedelta(seconds=1)

    replica_b = SupervisionOutboxDispatcher(
        store,
        bus,
        max_batch=1,
        notification_callback=notify,
        notification_consumer_id="email-v1",
    )
    assert await replica_b.flush_once() == 1
    assert len(bus.events) == 2  # At-least-once bus publish remains unchanged.
    assert bus.events[0].event_id != bus.events[1].event_id
    assert bus.events[0].payload["event_id"] == bus.events[1].payload["event_id"]
    notify.assert_awaited_once()  # Cross-process receipt suppressed callback.
    assert store.rows["out-1"]["delivered_at"] is not None
    assert len(_completed(store)) == 1
    assert not await original_ack(
        {
            "id": "out-1",
            "lease_id": "stolen-old-lease",
        }
    )


@pytest.mark.asyncio
async def test_dispatcher_receipt_db_outage_preserves_unacked_outbox():
    store, bus, notify = _DurableStore(notification()), RecorderBus(), AsyncMock()
    store.fail_flush = True
    dispatcher = SupervisionOutboxDispatcher(
        store,
        bus,
        max_batch=1,
        notification_callback=notify,
        notification_consumer_id="email-v1",
    )
    assert await dispatcher.flush_once() == 0
    assert len(bus.events) == 1
    assert store.rows["out-1"]["delivered_at"] is None
    assert len(_completed(store)) == 0
    store.fail_flush = False
    store.rows["out-1"]["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    assert await dispatcher.flush_once() == 1
    # Failure was in the claim transaction BEFORE the callback, so only the
    # successful retry executed the external notification.
    notify.assert_awaited_once()
    assert len(_completed(store)) == 1


@pytest.mark.asyncio
async def test_separate_replica_sees_active_claim_without_db_lock_across_notify():
    store = _DurableStore(notification())
    entered = asyncio.Event()
    release = asyncio.Event()
    first = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    )
    second = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    )

    async def notify(_safe):
        # Database lease already committed. No row lock or transaction is
        # held across an external side effect, even when it is slow.
        assert not store.lock.locked()
        entered.set()
        await release.wait()

    task = asyncio.create_task(first.consume(_event(), notify))
    await asyncio.wait_for(entered.wait(), timeout=1)
    with pytest.raises(OutboxConsumerUnavailable, match="another replica"):
        await second.consume(_event(), AsyncMock())
    assert len(_claims(store)) == 1
    assert not _completed(store)
    release.set()
    assert await task
    assert len(_completed(store)) == 1
    assert not await second.consume(_event(), AsyncMock())


@pytest.mark.asyncio
async def test_expired_claim_refuses_late_completion_and_recovery_replays():
    store = _DurableStore(notification())
    external = AsyncMock()
    consumer = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    )

    async def response(safe):
        assert not store.lock.locked()
        await external(safe)
        _expire_claim(store)

    with pytest.raises(OutboxConsumerUnavailable, match="expired"):
        await consumer.consume(_event(), response)
    assert not _completed(store)
    assert await SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    ).consume(_event(), external)
    assert external.await_count == 2
    assert len(_completed(store)) == 1


@pytest.mark.asyncio
async def test_corrupted_previous_claim_blocks_later_consumer():
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    )
    first = AsyncMock(side_effect=OSError("retriable"))
    with pytest.raises(OutboxConsumerUnavailable):
        await consumer.consume(_event(), first)
    _expire_claim(store)
    _claims(store)[0].payload["notification_sha256"] = "f" * 64
    later = AsyncMock()
    with pytest.raises(OutboxConsumerUnavailable, match="malformed"):
        await consumer.consume(_event(), later)
    later.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_negative_callback_ack_is_unconfirmed_until_retry():
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    )
    declined = AsyncMock(return_value=False)
    with pytest.raises(OutboxConsumerUnavailable, match="declined"):
        await consumer.consume(_event(), declined)
    assert not _completed(store)
    _expire_claim(store)
    accepted = AsyncMock(return_value=True)
    assert await consumer.consume(_event(), accepted)
    assert len(_completed(store)) == 1


@pytest.mark.asyncio
async def test_bounded_append_only_retry_attempts_then_manual_reconciliation():
    store = _DurableStore(notification())
    consumer = SupervisionNotificationConsumer(
        durable_store=store,
        consumer_id="ops-v1",
    )
    denied = AsyncMock(side_effect=RuntimeError("synthetic transient downstream"))
    for index in range(16):
        with pytest.raises(OutboxConsumerUnavailable):
            await consumer.consume(_event(), denied)
        _expire_claim(store)
        assert len(_claims(store)) == index + 1
    with pytest.raises(OutboxConsumerUnavailable, match="retry budget"):
        await consumer.consume(_event(), denied)
    assert denied.await_count == 16
    assert len(_claims(store)) == 16
    assert not _completed(store)


@pytest.mark.asyncio
async def test_dispatcher_callback_configuration_rejects_local_only_fakes():
    with pytest.raises(ValueError, match="PostgreSQL"):
        SupervisionOutboxDispatcher(
            AsyncMock(),
            RecorderBus(),
            notification_callback=AsyncMock(),
            notification_consumer_id="ops",
        )
    with pytest.raises(ValueError, match="identity"):
        SupervisionOutboxDispatcher(
            _DurableStore(notification()),
            RecorderBus(),
            notification_callback=AsyncMock(),
        )
    with pytest.raises(ValueError):
        SupervisionNotificationConsumer(
            durable_store=_DurableStore(notification()),
            consumer_id="../../forged",
        )
