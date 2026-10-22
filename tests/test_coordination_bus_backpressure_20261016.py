"""Concurrency regression tests for in-process coordination fanout."""

import asyncio
import time
from typing import Any, AsyncIterator

import pytest

from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus, CoordinationEvent


async def _subscribe_waiting(
    bus: AgentCoordinationBus, topic: str
) -> tuple[AsyncIterator[CoordinationEvent], asyncio.Task[CoordinationEvent]]:
    subscriber = bus.subscribe(topic)
    pending = asyncio.create_task(anext(subscriber))
    await asyncio.sleep(0)
    return subscriber, pending


@pytest.mark.asyncio
async def test_slow_subscriber_drops_after_bound_without_blocking_healthy_peer() -> None:
    bus = AgentCoordinationBus(max_queue_size=1, subscriber_send_timeout=0.2)
    slow, first = await _subscribe_waiting(bus, "task.completed")
    try:
        await bus.publish("task.completed", {"n": 1}, "scheduler")
        assert (await first).payload["n"] == 1
        await bus.publish("task.completed", {"n": 2}, "scheduler")

        fast, waiting = await _subscribe_waiting(bus, "task.completed")
        try:
            publish_task = asyncio.create_task(bus.publish("task.completed", {"n": 3}, "scheduler"))
            received = await asyncio.wait_for(waiting, timeout=0.1)
            assert received.payload["n"] == 3
            assert not publish_task.done()  # slow queue is still saturated
            event = await asyncio.wait_for(publish_task, timeout=0.5)
            assert event.payload["n"] == 3
            assert (await asyncio.wait_for(anext(slow), timeout=0.1)).payload["n"] == 2
            assert bus._subscribers["task.completed"][0].empty()
        finally:
            await fast.aclose()
    finally:
        await slow.aclose()


@pytest.mark.asyncio
async def test_slow_subscriber_accepts_when_buffer_frees_before_timeout() -> None:
    bus = AgentCoordinationBus(max_queue_size=1, subscriber_send_timeout=0.4)
    slow, first = await _subscribe_waiting(bus, "observation")
    try:
        await bus.publish("observation", {"n": 1}, "agent")
        assert (await first).payload["n"] == 1
        await bus.publish("observation", {"n": 2}, "agent")
        pending = asyncio.create_task(bus.publish("observation", {"n": 3}, "agent"))
        await asyncio.sleep(0)
        assert not pending.done()
        assert (await anext(slow)).payload["n"] == 2
        await asyncio.wait_for(pending, timeout=0.3)
        assert (await anext(slow)).payload["n"] == 3
    finally:
        await slow.aclose()


@pytest.mark.asyncio
async def test_many_saturated_subscribers_wait_concurrently_not_sequentially() -> None:
    bus = AgentCoordinationBus(max_queue_size=1, subscriber_send_timeout=0.06)
    subscribers = []
    try:
        waiting = []
        for _ in range(12):
            sub, pending = await _subscribe_waiting(bus, "task.failed")
            subscribers.append(sub)
            waiting.append(pending)
        await bus.publish("task.failed", {"status": "primed"}, "orchestrator")
        await asyncio.gather(*waiting)
        # All queues must be full simultaneously before the timed fanout.
        await bus.publish("task.failed", {"status": "buffered"}, "orchestrator")
        start = time.monotonic()
        await bus.publish("task.failed", {"status": "dropped"}, "orchestrator")
        elapsed = time.monotonic() - start
        assert elapsed < 0.35  # sequential 12 x 0.06 s would exceed this
        assert bus.subscriber_count("task.failed") == 12
    finally:
        for subscriber in subscribers:
            await subscriber.aclose()


@pytest.mark.asyncio
async def test_subscriber_error_isolated_and_topic_names_do_not_leak(monkeypatch) -> None:
    bus = AgentCoordinationBus(max_queue_size=2, subscriber_send_timeout=0.02)
    broken, waiting_broken = await _subscribe_waiting(bus, "supervision.event")
    healthy, waiting_healthy = await _subscribe_waiting(bus, "supervision.event")
    other, waiting_other = await _subscribe_waiting(bus, "task.completed")

    def raise_on_offer(_event: CoordinationEvent) -> None:
        raise RuntimeError("do not emit sensitive exception text")

    try:
        monkeypatch.setattr(bus._subscribers["supervision.event"][0], "put_nowait", raise_on_offer)
        event = await bus.publish("supervision.event", {"engagement_id": "eng-tenant-1"}, "outbox")
        assert event.payload["engagement_id"] == "eng-tenant-1"
        assert (await asyncio.wait_for(waiting_healthy, timeout=0.1)).event_id == event.event_id
        assert not waiting_other.done()
        assert not waiting_broken.done()
        assert bus.subscriber_count("task.completed") == 1
    finally:
        waiting_broken.cancel()
        waiting_other.cancel()
        await asyncio.gather(waiting_broken, waiting_other, return_exceptions=True)
        await healthy.aclose()
        await broken.aclose()
        await other.aclose()
    assert bus.subscriber_count("supervision.event") == 0
    assert bus.subscriber_count("task.completed") == 0


@pytest.mark.asyncio
async def test_saturated_subscriber_put_failure_does_not_fail_publication(monkeypatch) -> None:
    bus = AgentCoordinationBus(max_queue_size=1, subscriber_send_timeout=0.1)
    broken, waiting_broken = await _subscribe_waiting(bus, "supervision.event")
    healthy, waiting_healthy = await _subscribe_waiting(bus, "supervision.event")

    async def fail_while_waiting(_event: CoordinationEvent) -> None:
        raise RuntimeError("test failure")

    try:
        await bus.publish("supervision.event", {"n": 1}, "outbox")
        await asyncio.gather(waiting_broken, waiting_healthy)
        await bus.publish("supervision.event", {"n": 2}, "outbox")
        assert (await anext(healthy)).payload["n"] == 2
        healthy_next = asyncio.create_task(anext(healthy))
        await asyncio.sleep(0)
        monkeypatch.setattr(bus._subscribers["supervision.event"][0], "put", fail_while_waiting)
        event = await bus.publish("supervision.event", {"n": 3}, "outbox")
        assert event.payload["n"] == 3
        assert (await asyncio.wait_for(healthy_next, timeout=0.1)).payload["n"] == 3
        assert (await anext(broken)).payload["n"] == 2
    finally:
        await broken.aclose()
        await healthy.aclose()


@pytest.mark.asyncio
async def test_cancelled_publisher_does_not_enqueue_late_event() -> None:
    bus = AgentCoordinationBus(max_queue_size=1, subscriber_send_timeout=2)
    subscriber, first = await _subscribe_waiting(bus, "task.scheduled")
    try:
        await bus.publish("task.scheduled", {"n": 1}, "scheduler")
        await first
        await bus.publish("task.scheduled", {"n": 2}, "scheduler")
        pending = asyncio.create_task(bus.publish("task.scheduled", {"n": 3}, "scheduler"))
        await asyncio.sleep(0)
        assert not pending.done()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert (await anext(subscriber)).payload["n"] == 2
        # If the timed put was left running after cancellation it could enqueue
        # event 3 when the previous item was drained.
        await asyncio.sleep(0)
        assert bus._subscribers["task.scheduled"][0].empty()
    finally:
        await subscriber.aclose()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_queue_size": 0},
        {"max_queue_size": False},
        {"max_queue_size": 10001},
        {"subscriber_send_timeout": 0},
        {"subscriber_send_timeout": float("inf")},
        {"subscriber_send_timeout": float("nan")},
        {"subscriber_send_timeout": True},
    ],
)
def test_invalid_queue_and_timeout_bounds_rejected(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        AgentCoordinationBus(**kwargs)
