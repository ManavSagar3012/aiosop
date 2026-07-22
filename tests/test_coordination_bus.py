"""Unit tests for AgentCoordinationBus.

Tests the in-process pub/sub bus used for task, approval, and audit events.
"""

from __future__ import annotations

import asyncio

from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus


class TestCoordinationBus:
    """Tests for AgentCoordinationBus."""

    async def test_publish_no_subscribers(self):
        """Publishing to a topic without subscribers succeeds silently."""
        bus = AgentCoordinationBus()
        event = await bus.publish("test.topic", {"msg": "hello"}, "tester")
        assert event.topic == "test.topic"
        assert event.payload == {"msg": "hello"}
        assert event.source == "tester"
        assert bus.subscriber_count("test.topic") == 0

    async def test_subscriber_receives_event(self):
        """A subscriber receives events published to its topic."""
        bus = AgentCoordinationBus()

        async def collect():
            results = []
            async for event in bus.subscribe("task.scheduled"):
                results.append(event)
                break
            return results

        collector = asyncio.create_task(collect())
        await asyncio.sleep(0.05)  # let subscriber register

        await bus.publish("task.scheduled", {"task_id": "t-1"}, "orchestrator")
        events = await asyncio.wait_for(collector, timeout=2.0)
        assert len(events) == 1
        assert events[0].topic == "task.scheduled"
        assert events[0].payload["task_id"] == "t-1"
        assert events[0].source == "orchestrator"

    async def test_multiple_subscribers_receive_event(self):
        """Multiple subscribers on the same topic all receive the event."""
        bus = AgentCoordinationBus()

        async def collect(name: str, results: list):
            async for event in bus.subscribe("broadcast"):
                results.append((name, event))
                break

        results_a = []
        results_b = []
        task_a = asyncio.create_task(collect("A", results_a))
        task_b = asyncio.create_task(collect("B", results_b))
        await asyncio.sleep(0.05)

        assert bus.subscriber_count("broadcast") == 2

        await bus.publish("broadcast", {"seq": 1}, "test")
        await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=2.0)

        assert len(results_a) == 1
        assert len(results_b) == 1
        assert results_a[0][1].topic == "broadcast"
        assert results_b[0][1].topic == "broadcast"

    async def test_subscriber_filtered_by_topic(self):
        """A subscriber on topic A does NOT receive events from topic B."""
        bus = AgentCoordinationBus()

        async def collect():
            async for event in bus.subscribe("topic.a"):
                return event  # return first event
            return None

        collector = asyncio.create_task(collect())
        await asyncio.sleep(0.05)

        # Publish to a different topic first
        await bus.publish("topic.b", {"msg": "wrong"}, "test")
        await asyncio.sleep(0.05)
        # The subscriber should NOT have received it
        assert collector.done() is False

        # Now publish to the subscribed topic
        await bus.publish("topic.a", {"msg": "right"}, "test")
        result = await asyncio.wait_for(collector, timeout=2.0)
        assert result is not None
        assert result.payload["msg"] == "right"

    async def test_subscriber_count(self):
        """subscriber_count returns the correct number of active subscribers."""
        bus = AgentCoordinationBus()
        assert bus.subscriber_count("any.topic") == 0

        async def sub():
            async for _ in bus.subscribe("any.topic"):
                break

        t1 = asyncio.create_task(sub())
        t2 = asyncio.create_task(sub())
        await asyncio.sleep(0.05)

        assert bus.subscriber_count("any.topic") == 2

        # Cancel one subscriber
        t1.cancel()
        await asyncio.sleep(0.05)
        assert bus.subscriber_count("any.topic") == 1

        t2.cancel()

    async def test_event_has_auto_fields(self):
        """Events get auto-generated event_id and created_at fields."""
        bus = AgentCoordinationBus()
        event = await bus.publish("test", {}, "source")
        assert event.event_id is not None
        assert event.event_id != ""
        assert event.created_at is not None

    async def test_payload_is_copied(self):
        """The event stores a copy of the payload, not the original reference."""
        bus = AgentCoordinationBus()
        original = {"key": "value"}
        event = await bus.publish("test", original, "src")
        original["key"] = "mutated"
        assert event.payload["key"] == "value"  # original dict not affected
