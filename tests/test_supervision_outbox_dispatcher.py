"""Committed event outbox publishes at-least-once, never raw operator data."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.supervision_outbox import SupervisionOutboxDispatcher


def _item():
    return {
        "id": "out-1",
        "event_id": "evt-1",
        "engagement_id": "eng-1",
        "lease_id": "lease-1",
        "payload": {
            "event_id": "evt-1",
            "task_id": "task-1",
            "kind": "agent.message",
            "metadata": {"content": "sensitive secret must not enter bus"},
        },
    }


@pytest.mark.asyncio
async def test_outbox_acknowledged_only_after_bus_publishes():
    store = AsyncMock()
    bus = AsyncMock()
    store.claim_outbox.return_value = [_item()]
    store.ack_outbox.return_value = True
    dispatcher = SupervisionOutboxDispatcher(store, bus)

    assert await dispatcher.flush_once() == 1
    published = bus.publish.await_args.args
    assert published[0] == "supervision.event"
    assert published[1]["event_id"] == "evt-1"
    assert "sensitive" not in str(published[1])
    store.ack_outbox.assert_awaited_once_with("out-1", "lease-1")


@pytest.mark.asyncio
async def test_outbox_publish_error_preserves_unacknowledged_lease():
    store = AsyncMock()
    bus = AsyncMock()
    store.claim_outbox.return_value = [_item()]
    bus.publish.side_effect = RuntimeError("transient")
    dispatcher = SupervisionOutboxDispatcher(store, bus)

    assert await dispatcher.flush_once() == 0
    store.ack_outbox.assert_not_awaited()


@pytest.mark.asyncio
async def test_outbox_replayed_after_missing_ack_with_stable_event_id():
    store = AsyncMock()
    bus = AsyncMock()
    store.claim_outbox.return_value = [_item()]
    store.ack_outbox.side_effect = [False, True]
    dispatcher = SupervisionOutboxDispatcher(store, bus)

    assert await dispatcher.flush_once() == 0
    assert await dispatcher.flush_once() == 1
    assert bus.publish.await_count == 2
    assert all(
        call.args[1]["event_id"] == "evt-1"
        for call in bus.publish.await_args_list
    )
