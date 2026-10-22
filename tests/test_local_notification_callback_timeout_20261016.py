"""A stalled local notification callback cannot indefinitely own dedupe lock."""

import asyncio

import pytest

from ai_osop.orchestrator.coordination_bus import CoordinationEvent
from ai_osop.orchestrator.supervision_outbox import SupervisionNotificationConsumer


def _event(event_id: str) -> CoordinationEvent:
    return CoordinationEvent(
        topic="supervision.event",
        source="supervision-outbox",
        payload={
            "event_id": event_id,
            "engagement_id": "eng-1",
            "task_id": "task-1",
            "kind": "task.updated",
        },
    )


@pytest.mark.asyncio
async def test_timed_out_local_callback_does_not_mark_delivered_or_block_successor() -> None:
    consumer = SupervisionNotificationConsumer(delivery_timeout=0.1)

    async def stuck(_payload: dict) -> None:
        await asyncio.Event().wait()

    with pytest.raises(TimeoutError):
        await consumer.consume(_event("evt-1"), stuck)

    observed = []

    async def notify(payload: dict) -> bool:
        observed.append(payload["event_id"])
        return True

    assert await asyncio.wait_for(consumer.consume(_event("evt-2"), notify), 0.5)
    assert await consumer.consume(_event("evt-1"), notify)
    assert observed == ["evt-2", "evt-1"]


@pytest.mark.parametrize("deadline", [0, -1, 9, float("nan"), "5", True])
def test_invalid_local_callback_deadline_rejected(deadline: object) -> None:
    with pytest.raises(ValueError):
        SupervisionNotificationConsumer(delivery_timeout=deadline)
