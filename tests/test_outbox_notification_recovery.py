"""Deterministic PostgreSQL lease, crash and notification replay coverage."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.supervision_store import SupervisionStore
from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.supervision_outbox import (
    SupervisionNotificationConsumer,
    SupervisionOutboxDispatcher,
)


def notification(index=1, *, kind="agent.message", metadata=None):
    event_id = f"evt-{index}"
    return {
        "id": f"out-{index}",
        "event_id": event_id,
        "engagement_id": "eng-1",
        "topic": kind,
        "payload": {
            "event_id": event_id,
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "kind": kind,
            "metadata": metadata or {"secret": "MUST_NOT_LEAK"},
        },
        "attempts": 0,
        "lease_id": None,
        "leased_until": None,
        "delivered_at": None,
    }


class SqlResult:
    def __init__(self, rowcount):
        self.rowcount = rowcount


class PgSession:
    def __init__(self, store):
        self.store = store

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    @asynccontextmanager
    async def begin(self):
        async with self.store.lock:
            yield

    async def execute(self, statement):
        sql = str(statement)
        assert sql.startswith("UPDATE supervision_outbox SET ")
        # Real SQL predicates must require both the current lease ID and a
        # future expiry; this model then applies the update atomically.
        assert "supervision_outbox.lease_id =" in sql
        assert "supervision_outbox.leased_until > " in sql
        assert "supervision_outbox.delivered_at IS NULL" in sql
        compiled = statement.compile()
        params = compiled.params
        identifier = next(value for key, value in params.items() if key.startswith("id_"))
        lease_id = next(value for key, value in params.items() if key.startswith("lease_id_"))
        row = self.store.rows[identifier]
        now = datetime.utcnow()
        if (
            row["lease_id"] != lease_id
            or row["delivered_at"] is not None
            or row["leased_until"] is None
            or row["leased_until"] <= now
        ):
            return SqlResult(0)
        # Only UPDATE values, not WHERE bind parameters.
        for key, value in statement._values.items():
            column = key.key if hasattr(key, "key") else str(key)
            row[column] = value.value
        self.store.sql_statements.append(sql)
        return SqlResult(1)


class PgStore(SupervisionStore):
    """Small transactional row-lock model; never uses the application DB."""

    def __init__(self, *events):
        self.lock = asyncio.Lock()
        self.rows = {e["id"]: deepcopy(e) for e in events}
        self.counter = 0
        self.claim_limits = []
        self.sql_statements = []
        self.acks = []

    def _sessions(self):
        return PgSession(self)

    async def claim_outbox(self, limit=50, lease_seconds=60):
        self.claim_limits.append(limit)
        async with self.lock:
            now = datetime.utcnow()
            available = sorted(
                (
                    row
                    for row in self.rows.values()
                    if row["delivered_at"] is None
                    and (row["leased_until"] is None or row["leased_until"] < now)
                ),
                key=lambda row: row["id"],
            )
            claimed = []
            for row in available[:limit]:
                self.counter += 1
                row["lease_id"] = f"lease-{self.counter}"
                row["leased_until"] = now + timedelta(seconds=lease_seconds)
                row["attempts"] += 1
                claimed.append(deepcopy(row))
            return claimed

    async def ack_outbox(self, *_):
        raise AssertionError("Production dispatcher must use SQL lease fencing")


class RecorderBus:
    def __init__(self):
        self.events = []
        self.before_publish = None
        self.failure = None

    async def publish(self, topic, payload, source):
        if self.before_publish:
            await self.before_publish()
        if self.failure:
            raise self.failure
        # Transport envelope IDs vary on every attempt; payload event ID must not.
        event = CoordinationEvent(topic=topic, payload=dict(payload), source=source)
        self.events.append(event)
        return event


@pytest.mark.asyncio
async def test_one_fresh_claim_per_notification_and_safe_schema():
    store = PgStore(notification(1), notification(2), notification(3))
    bus = RecorderBus()
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=3)
    assert await worker.flush_once() == 3
    assert store.claim_limits == [1, 1, 1]
    assert len(bus.events) == 3
    assert {e.payload["event_id"] for e in bus.events} == {
        "evt-1",
        "evt-2",
        "evt-3",
    }
    for event in bus.events:
        assert set(event.payload) == {"event_id", "engagement_id", "task_id", "kind"}
        assert "MUST_NOT_LEAK" not in str(event.payload)
    assert all(row["delivered_at"] for row in store.rows.values())
    assert all(row["lease_id"] is None for row in store.rows.values())


@pytest.mark.asyncio
async def test_competing_pollers_cannot_publish_same_active_lease():
    store, bus = PgStore(notification()), RecorderBus()
    started = asyncio.Event()
    release = asyncio.Event()

    async def block_once():
        started.set()
        await release.wait()

    bus.before_publish = block_once
    worker_a = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    worker_b = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    a = asyncio.create_task(worker_a.flush_once())
    await asyncio.wait_for(started.wait(), timeout=1)
    assert await worker_b.flush_once() == 0
    release.set()
    assert await a == 1
    assert len(bus.events) == 1


@pytest.mark.asyncio
async def test_expired_lease_and_stolen_token_block_publish_and_ack():
    store, bus = PgStore(notification()), RecorderBus()
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    first = (await store.claim_outbox(limit=1, lease_seconds=30))[0]
    store.rows["out-1"]["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    assert not await worker._fence(first)
    assert not await worker._ack(first)
    newer = (await store.claim_outbox(limit=1, lease_seconds=30))[0]
    assert first["lease_id"] != newer["lease_id"]
    assert not await worker._fence(first)
    assert not await worker._ack(first)
    assert await worker._fence(newer)
    assert await worker._ack(newer)
    assert store.rows["out-1"]["delivered_at"] is not None
    assert bus.events == []


@pytest.mark.asyncio
async def test_publish_then_ack_crash_replays_same_id_but_not_notification():
    store, bus = PgStore(notification()), RecorderBus()
    dispatcher = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    original_ack = dispatcher._ack

    async def crashed(_entry):
        raise OSError("simulated crash between publish and ACK")

    dispatcher._ack = crashed
    assert await dispatcher.flush_once() == 0
    assert store.rows["out-1"]["delivered_at"] is None
    assert len(bus.events) == 1
    assert store.rows["out-1"]["leased_until"] > datetime.utcnow()
    # The deterministic clock jump models a retry after the durable backoff.
    store.rows["out-1"]["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    dispatcher._ack = original_ack
    assert await dispatcher.flush_once() == 1
    assert len(bus.events) == 2
    assert bus.events[0].event_id != bus.events[1].event_id
    assert bus.events[0].payload["event_id"] == bus.events[1].payload["event_id"]

    notifications = AsyncMock()
    dedupe = SupervisionNotificationConsumer()
    observed = await asyncio.gather(
        dedupe.consume(bus.events[0], notifications),
        dedupe.consume(bus.events[1], notifications),
    )
    assert sorted(observed) == [False, True]
    notifications.assert_awaited_once()


@pytest.mark.asyncio
async def test_poison_failures_defer_durably_with_bounded_exponential_backoff():
    store, bus = PgStore(notification()), RecorderBus()
    bus.failure = ConnectionError("UPSTREAM_CREDENTIAL_SHOULD_NOT_LEAK")
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    delays = []
    for _ in range(4):
        assert await worker.flush_once() == 0
        row = store.rows["out-1"]
        delays.append((row["leased_until"] - datetime.utcnow()).total_seconds())
        assert row["lease_id"] is None
        assert row["delivered_at"] is None
        # Durable delay excludes the same row from fresh claims.
        assert (await store.claim_outbox(limit=1, lease_seconds=30)) == []
        row["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    assert all(lo <= delay <= hi for delay, lo, hi in zip(delays, (4, 9, 19, 39), (6, 11, 21, 41)))
    assert worker._retry_seconds(500) == 3600
    assert len(bus.events) == 0


@pytest.mark.asyncio
async def test_poison_entry_deferral_does_not_starve_other_committed_events():
    bad = notification(1)
    bad["payload"]["event_id"] = "evt-tampered"
    store, bus = PgStore(bad, notification(2)), RecorderBus()
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=2)
    assert await worker.flush_once() == 1
    assert [event.payload["event_id"] for event in bus.events] == ["evt-2"]
    assert store.rows["out-1"]["delivered_at"] is None
    assert store.rows["out-1"]["leased_until"] > datetime.utcnow()
    assert store.rows["out-2"]["delivered_at"] is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tampering",
    [
        {"event_id": "evt-FOREIGN"},
        {"engagement_id": "eng-FOREIGN"},
        {"kind": "x\nsecret"},
        {"task_id": ["evil"]},
    ],
)
async def test_malformed_notification_is_quarantined_without_publication(tampering):
    item = notification()
    item["payload"].update(tampering)
    store, bus = PgStore(item), RecorderBus()
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    assert await worker.flush_once() == 0
    assert bus.events == []
    assert store.rows["out-1"]["leased_until"] > datetime.utcnow()
    assert store.rows["out-1"]["delivered_at"] is None


@pytest.mark.asyncio
async def test_slow_broker_timeout_preserves_undelivered_and_defers():
    store, bus = PgStore(notification()), RecorderBus()

    async def slow():
        await asyncio.Event().wait()

    bus.before_publish = slow
    worker = SupervisionOutboxDispatcher(
        store,
        bus,
        max_batch=1,
        delivery_timeout=0.1,
    )
    assert await asyncio.wait_for(worker.flush_once(), timeout=1) == 0
    assert not bus.events
    assert store.rows["out-1"]["delivered_at"] is None
    assert store.rows["out-1"]["leased_until"] > datetime.utcnow()


@pytest.mark.asyncio
async def test_cancellation_after_claim_does_not_ack_or_emit_a_second_request():
    store, bus = PgStore(notification()), RecorderBus()
    entered = asyncio.Event()

    async def suspend():
        entered.set()
        await asyncio.Event().wait()

    bus.before_publish = suspend
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    running = asyncio.create_task(worker.flush_once())
    await asyncio.wait_for(entered.wait(), timeout=1)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert store.rows["out-1"]["delivered_at"] is None
    assert store.rows["out-1"]["lease_id"] is not None
    assert not bus.events


@pytest.mark.asyncio
async def test_mismatched_general_durable_topic_kind_denied_without_publish():
    item = notification(kind="agent.message")
    item["payload"]["kind"] = "flow.created"
    store, bus = PgStore(item), RecorderBus()
    worker = SupervisionOutboxDispatcher(store, bus, max_batch=1)
    assert await worker.flush_once() == 0
    assert not bus.events
    assert store.rows["out-1"]["delivered_at"] is None


@pytest.mark.asyncio
async def test_corrupt_flow_intent_cannot_be_acked_as_nonexecution_notice():
    item = notification(kind="flow.subtask_dispatch_intent")
    item["payload"]["kind"] = "agent.message"
    store, bus, queue = PgStore(item), RecorderBus(), AsyncMock()
    worker = SupervisionOutboxDispatcher(
        store,
        bus,
        max_batch=1,
        enqueue_registered_task=queue,
    )
    assert await worker.flush_once() == 0
    assert not bus.events
    queue.assert_not_awaited()
    assert store.rows["out-1"]["delivered_at"] is None


@pytest.mark.asyncio
async def test_notification_consumer_retries_callback_failure_and_bounds_cache():
    consumer = SupervisionNotificationConsumer(capacity=1)
    event1 = CoordinationEvent(
        topic="supervision.event",
        source="supervision-outbox",
        payload={
            "event_id": "evt-1",
            "engagement_id": "eng-1",
            "task_id": None,
            "kind": "flow.created",
            "secret": "OMIT",
        },
    )
    event2 = CoordinationEvent(
        topic=event1.topic,
        source=event1.source,
        payload={**event1.payload, "event_id": "evt-2"},
    )
    callback = AsyncMock(side_effect=[RuntimeError("transient"), None, None, None])
    with pytest.raises(RuntimeError, match="transient"):
        await consumer.consume(event1, callback)
    assert await consumer.consume(event1, callback)
    assert not await consumer.consume(event1, callback)
    assert await consumer.consume(event2, callback)
    # Capacity=1 evicted evt-1, allowing a local replay; no task callbacks.
    assert await consumer.consume(event1, callback)
    assert callback.await_count == 4
    assert all("secret" not in str(call.args[0]) for call in callback.await_args_list)


@pytest.mark.asyncio
async def test_notification_consumer_never_dispatches_flow_execution():
    queue = AsyncMock()
    notify = AsyncMock()
    consumer = SupervisionNotificationConsumer()
    event = CoordinationEvent(
        topic="supervision.event",
        source="supervision-outbox",
        payload={
            "event_id": "evt-flow-9",
            "engagement_id": "eng-1",
            "kind": "flow.subtask_dispatch_intent",
            "task_id": "task-existing",
        },
    )
    assert await consumer.consume(event, notify)
    assert not await consumer.consume(event, notify)
    queue.assert_not_awaited()
    notify.assert_awaited_once()


@pytest.mark.asyncio
async def test_notification_consumer_drops_forged_source_and_incomplete_identity():
    consumer, notify = SupervisionNotificationConsumer(), AsyncMock()
    payload = {
        "event_id": "evt-safe",
        "engagement_id": "eng-1",
        "task_id": None,
        "kind": "agent.message",
    }
    forged = CoordinationEvent(topic="supervision.event", source="untrusted-agent", payload=payload)
    incomplete = CoordinationEvent(
        topic="supervision.event",
        source="supervision-outbox",
        payload={**payload, "event_id": None},
    )
    assert not await consumer.consume(forged, notify)
    assert not await consumer.consume(incomplete, notify)
    notify.assert_not_awaited()
