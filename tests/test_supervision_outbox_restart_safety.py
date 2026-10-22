"""Crash/restart notification outbox fences without any application database.

The existing deterministic transactional PostgreSQL model inspects real
SQLAlchemy UPDATE predicates and emulates lease replacement.  These tests do
not publish to a network or interact with Redis, Temporal or providers.
"""

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
from tests.test_outbox_notification_recovery import (
    PgStore,
    RecorderBus,
    notification,
)


@pytest.mark.asyncio
async def test_public_sql_ack_requires_live_lease_even_without_competing_claim():
    store = PgStore(notification())
    original = (await store.claim_outbox(limit=1, lease_seconds=30))[0]
    row = store.rows[original["id"]]
    assert row["lease_id"] == original["lease_id"]

    # A worker crashed; no one has stolen its token, but the deadline passed.
    row["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    assert not await SupervisionStore.ack_outbox(
        store, original["id"], original["lease_id"]
    )
    assert row["delivered_at"] is None
    assert row["lease_id"] == original["lease_id"]

    replacement = (await store.claim_outbox(limit=1, lease_seconds=30))[0]
    assert replacement["lease_id"] != original["lease_id"]
    assert not await SupervisionStore.ack_outbox(
        store, original["id"], original["lease_id"]
    )
    assert await SupervisionStore.ack_outbox(
        store, replacement["id"], replacement["lease_id"]
    )
    assert row["delivered_at"] is not None
    assert row["lease_id"] is None
    assert not await SupervisionStore.ack_outbox(
        store, replacement["id"], replacement["lease_id"]
    )


@pytest.mark.asyncio
async def test_explicit_bus_negative_ack_recovers_after_worker_restart():
    store = PgStore(notification())
    first_bus = RecorderBus()
    first_bus.publish = AsyncMock(return_value=False)
    first = SupervisionOutboxDispatcher(store, first_bus, max_batch=1)
    assert await first.flush_once() == 0
    assert first_bus.publish.await_count == 1
    row = store.rows["out-1"]
    assert row["delivered_at"] is None
    assert row["lease_id"] is None
    assert row["leased_until"] > datetime.utcnow()
    # Defer survives process exit. A fresh instance must not immediately retry.
    second_bus = RecorderBus()
    second = SupervisionOutboxDispatcher(store, second_bus, max_batch=1)
    assert await second.flush_once() == 0
    assert second_bus.events == []
    row["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    assert await second.flush_once() == 1
    assert len(second_bus.events) == 1
    assert second_bus.events[0].payload["event_id"] == "evt-1"
    assert row["delivered_at"] is not None


@pytest.mark.asyncio
async def test_explicit_flow_queue_negative_ack_preserves_pending_intent_until_restart():
    original = notification(kind="flow.subtask_dispatch_intent")
    original["payload"]["task_id"] = "task-original"
    store, bus = PgStore(original), RecorderBus()
    declined_queue = AsyncMock(return_value=False)
    first = SupervisionOutboxDispatcher(
        store, bus, enqueue_registered_task=declined_queue, max_batch=1
    )
    assert await first.flush_once() == 0
    declined_queue.assert_awaited_once_with("task-original")
    assert len(bus.events) == 1  # Publication is at least once.
    row = store.rows["out-1"]
    assert row["delivered_at"] is None
    assert row["leased_until"] > datetime.utcnow()
    assert row["lease_id"] is None
    row["leased_until"] = datetime.utcnow() - timedelta(seconds=1)
    successful_queue = AsyncMock(return_value=None)
    second = SupervisionOutboxDispatcher(
        store, bus, enqueue_registered_task=successful_queue, max_batch=1
    )
    assert await second.flush_once() == 1
    successful_queue.assert_awaited_once_with("task-original")
    assert len(bus.events) == 2
    assert [event.payload["event_id"] for event in bus.events] == [
        "evt-1", "evt-1",
    ]
    assert row["delivered_at"] is not None


@pytest.mark.asyncio
async def test_local_callback_decline_does_not_claim_completed_receipt():
    consumer = SupervisionNotificationConsumer()
    payload = {
        "event_id": "evt-1", "engagement_id": "eng-1",
        "task_id": "task-1", "kind": "agent.message",
    }
    event = CoordinationEvent(
        topic="supervision.event", payload=payload, source="supervision-outbox"
    )
    refused = AsyncMock(return_value=False)
    with pytest.raises(RuntimeError, match="declined"):
        await consumer.consume(event, refused)
    refused.assert_awaited_once()
    accepted = AsyncMock(return_value=None)
    assert await consumer.consume(event, accepted) is True
    assert await consumer.consume(event, accepted) is False
    accepted.assert_awaited_once()


@pytest.mark.asyncio
async def test_local_consumer_does_not_merge_same_event_id_between_engagements():
    consumer = SupervisionNotificationConsumer()
    notify = AsyncMock(return_value=True)
    base = {
        "event_id": "evt-import-1", "engagement_id": "eng-alpha",
        "task_id": None, "kind": "flow.created",
    }
    first = CoordinationEvent(
        topic="supervision.event", source="supervision-outbox", payload=base
    )
    other = CoordinationEvent(
        topic="supervision.event", source="supervision-outbox",
        payload={**deepcopy(base), "engagement_id": "eng-beta"},
    )
    assert await consumer.consume(first, notify)
    assert await consumer.consume(other, notify)
    assert not await consumer.consume(first, notify)
    assert not await consumer.consume(other, notify)
    assert notify.await_count == 2
