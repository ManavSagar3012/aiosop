"""The signed Flow outbox delivers only already-registered queue hints."""

from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.supervision_outbox import SupervisionOutboxDispatcher


def _intent():
    return {
        "id": "out-flow-1",
        "event_id": "evt-flow-1",
        "lease_id": "lease-flow-1",
        "engagement_id": "eng-1",
        "topic": "flow.subtask_dispatch_intent",
        "payload": {
            "task_id": "task-signed-1",
            "kind": "flow.subtask_dispatch_intent",
            "metadata": {"target": "never-publish-secret", "authorization_version": 1},
        },
    }


@pytest.mark.asyncio
async def test_flow_outbox_ack_requires_successful_registered_queue_delivery():
    store, bus, queue = AsyncMock(), AsyncMock(), AsyncMock()
    store.claim_outbox.return_value = [_intent()]
    store.ack_outbox.return_value = True
    worker = SupervisionOutboxDispatcher(
        store,
        bus,
        enqueue_registered_task=queue,
    )

    assert await worker.flush_once() == 1
    queue.assert_awaited_once_with("task-signed-1")
    store.ack_outbox.assert_awaited_once_with("out-flow-1", "lease-flow-1")
    sent = bus.publish.await_args.args[1]
    assert "target" not in sent and "never-publish-secret" not in str(sent)


@pytest.mark.asyncio
async def test_transient_redis_queue_failure_keeps_outbox_unacknowledged():
    store, bus, queue = AsyncMock(), AsyncMock(), AsyncMock()
    store.claim_outbox.return_value = [_intent()]
    queue.side_effect = OSError("synthetic Redis disconnection")
    worker = SupervisionOutboxDispatcher(
        store,
        bus,
        enqueue_registered_task=queue,
    )
    assert await worker.flush_once() == 0
    store.ack_outbox.assert_not_awaited()
    bus.publish.assert_awaited_once()
    assert queue.await_count == 1


@pytest.mark.asyncio
async def test_missing_queue_reconciler_fails_closed_and_never_acks():
    store, bus = AsyncMock(), AsyncMock()
    store.claim_outbox.return_value = [_intent()]
    worker = SupervisionOutboxDispatcher(store, bus)
    assert await worker.flush_once() == 0
    store.ack_outbox.assert_not_awaited()


@pytest.mark.asyncio
async def test_nonflow_outbox_event_never_enqueues_execution_task():
    store, bus, queue = AsyncMock(), AsyncMock(), AsyncMock()
    event = _intent()
    event["topic"] = "approval.resolved"
    store.claim_outbox.return_value = [event]
    store.ack_outbox.return_value = True
    worker = SupervisionOutboxDispatcher(
        store,
        bus,
        enqueue_registered_task=queue,
    )
    # A changed row topic with the original execution-bearing payload is
    # corrupt provenance, not a harmless notification to acknowledge.
    assert await worker.flush_once() == 0
    store.ack_outbox.assert_not_awaited()
    queue.assert_not_awaited()
