"""
Unit and Integration Tests for Distributed Coordination Bus.

Tests cover:
- Redis connection and fallback behavior
- Event publishing and persistence
- Consumer groups and message acknowledgment
- History retrieval and replay
- Dead Letter Queue (DLQ) integration
- Multi-agent swarm communication
"""

import asyncio
import uuid
from datetime import datetime

import pytest

from src.ai_osop.orchestrator.distributed_bus import (
    CoordinationEvent,
    DistributedCoordinationBus,
    get_coordination_bus,
    initialize_bus,
)


@pytest.fixture
def redis_url():
    # FIX (tests-follow-env-2026-08-23): was hardcoded localhost:6379, which on
    # this host is an unrelated foreign container. Follow OSOP_REDIS_URI.
    from ai_osop.core.config import settings

    return settings.redis_uri


@pytest.fixture
def engagement_id():
    return f"test-{uuid.uuid4().hex[:8]}"


@pytest.fixture
async def bus(redis_url, engagement_id):
    """Create and initialize a bus instance."""
    bus = DistributedCoordinationBus(redis_url=redis_url, engagement_id=engagement_id)
    await bus.connect()
    yield bus
    await bus.disconnect()


@pytest.fixture
async def clean_redis(redis_url, engagement_id):
    """Clean up Redis streams before and after test."""
    # Clean before
    r = __import__("redis.asyncio", fromlist=["redis"]).from_url(redis_url)
    await r.delete(f"aiosop:{engagement_id}:events")
    await r.delete(f"aiosop:{engagement_id}:dlq")
    await r.aclose()  # FIX (redis-aclose-2026-08-24)

    yield

    # Clean after
    r = __import__("redis.asyncio", fromlist=["redis"]).from_url(redis_url)
    await r.delete(f"aiosop:{engagement_id}:events")
    await r.delete(f"aiosop:{engagement_id}:dlq")
    await r.aclose()  # FIX (redis-aclose-2026-08-24)


class TestDistributedCoordinationBusConnection:
    """Test bus connection and initialization."""

    @pytest.mark.asyncio
    async def test_connect_success(self, redis_url):
        """Test successful Redis connection."""
        bus = DistributedCoordinationBus(redis_url=redis_url, engagement_id="test-connect")
        result = await bus.connect()

        assert result is True
        assert bus._running is True
        assert bus.redis is not None

        await bus.disconnect()

    @pytest.mark.asyncio
    async def test_connect_invalid_redis(self):
        """Test connection failure triggers local fallback."""
        bus = DistributedCoordinationBus(
            redis_url="redis://invalid-host:9999", engagement_id="test-fail"
        )
        result = await bus.connect()

        assert result is False
        assert bus._local_fallback is True
        assert bus._running is True  # Still running in fallback mode

        await bus.disconnect()


class TestEventPublishing:
    """Test event publishing functionality."""

    @pytest.mark.asyncio
    async def test_publish_event(self, bus, clean_redis):
        """Test publishing a single event."""
        event = CoordinationEvent(
            topic="recon.endpoint_found",
            payload={"endpoint": "/api/test", "method": "GET"},
            source_agent="test_agent",
            event_type="discovery",
            confidence=0.9,
        )

        event_id = await bus.publish(event)

        assert event_id is not None
        assert len(event_id) > 0

    @pytest.mark.asyncio
    async def test_publish_multiple_events(self, bus, clean_redis):
        """Test publishing multiple events."""
        events = []
        for i in range(5):
            event = CoordinationEvent(
                topic=f"test.event_{i}",
                payload={"index": i},
                source_agent="test_agent",
                event_type="discovery",
                confidence=0.5 + (i * 0.1),
            )
            events.append(event)
            await bus.publish(event)

        # Verify all published
        history = await bus.get_history("*", count=10)
        assert len(history) >= 5

    @pytest.mark.asyncio
    async def test_publish_preserves_all_fields(self, bus, clean_redis):
        """Test that all event fields are preserved in Redis."""
        # FIX (bus-fields-test-2026-08-23): use an AUTHORIZED source. Unauthorized
        # sources get _unauthorized_source/_original_source tags injected by design
        # (Phase 6 defense-in-depth), so a strict payload-equality roundtrip check
        # must exercise the trusted path. "scanner_01" was unauthorized, which also
        # used to trip the pre-fix signature-verification ordering bug.
        original_event = CoordinationEvent(
            topic="vuln.found",
            payload={"type": "sqli", "severity": "high"},
            source_agent="recon_agent",
            event_type="discovery",
            confidence=0.95,
            engagement_id="test-eng",
            timestamp="2026-08-23T12:00:00Z",
        )

        await bus.publish(original_event)

        # Retrieve and verify
        history = await bus.get_history("vuln.found", count=1)
        assert len(history) == 1

        retrieved = history[0]
        assert retrieved.topic == original_event.topic
        assert retrieved.source_agent == original_event.source_agent
        assert retrieved.event_type == original_event.event_type
        assert retrieved.confidence == original_event.confidence
        assert retrieved.payload == original_event.payload
        assert retrieved.verify_signature(), "signature must survive the Redis roundtrip"


class TestEventConsumption:
    """Test event consumption and consumer groups."""

    @pytest.mark.asyncio
    async def test_subscribe_and_receive(self, bus, clean_redis):
        """Test subscribing to events and receiving them."""
        received_events = []

        async def handler(event):
            received_events.append(event)

        # Start subscriber
        subscribe_task = asyncio.create_task(
            bus.subscribe(
                topics=["recon.*"],
                consumer_id="test_consumer_01",
                group_name="test_group",
                callback=handler,
            )
        )

        # Give subscriber time to start
        await asyncio.sleep(0.5)

        # Publish matching event
        event = CoordinationEvent(
            topic="recon.endpoint_found",
            payload={"endpoint": "/api/users"},
            source_agent="recon_agent",
            event_type="discovery",
        )
        await bus.publish(event)

        # Wait for processing
        await asyncio.sleep(1)

        # Stop subscriber
        subscribe_task.cancel()
        try:
            await subscribe_task
        except asyncio.CancelledError:
            pass

        assert len(received_events) == 1
        assert received_events[0].topic == "recon.endpoint_found"

    @pytest.mark.asyncio
    async def test_topic_filtering(self, bus, clean_redis):
        """Test that subscribers only receive matching topics."""
        received_topics = []

        async def handler(event):
            received_topics.append(event.topic)

        # Subscribe only to vuln.* topics
        subscribe_task = asyncio.create_task(
            bus.subscribe(
                topics=["vuln.*"],
                consumer_id="filter_test_consumer",
                group_name="filter_test_group",
                callback=handler,
            )
        )

        await asyncio.sleep(0.5)

        # Publish mixed topics
        await bus.publish(
            CoordinationEvent(
                topic="recon.discovery", payload={}, source_agent="test", event_type="discovery"
            )
        )
        await bus.publish(
            CoordinationEvent(
                topic="vuln.found", payload={}, source_agent="test", event_type="discovery"
            )
        )
        await bus.publish(
            CoordinationEvent(
                topic="exploit.success", payload={}, source_agent="test", event_type="discovery"
            )
        )

        await asyncio.sleep(1)

        subscribe_task.cancel()
        try:
            await subscribe_task
        except asyncio.CancelledError:
            pass

        # Should only receive vuln.found
        assert len(received_topics) == 1
        assert received_topics[0] == "vuln.found"


class TestHistoryAndReplay:
    """Test event history retrieval and replay."""

    @pytest.mark.asyncio
    async def test_get_history(self, bus, clean_redis):
        """Test retrieving historical events."""
        # Publish several events
        for i in range(10):
            await bus.publish(
                CoordinationEvent(
                    topic="test.event",
                    payload={"index": i},
                    source_agent="test",
                    event_type="discovery",
                )
            )

        history = await bus.get_history("*", count=5)

        assert len(history) <= 5  # May include init event
        assert len(history) >= 4  # At least most recent 4

    @pytest.mark.asyncio
    async def test_get_stats(self, bus, clean_redis):
        """Test getting stream statistics."""
        # Publish some events
        for i in range(3):
            await bus.publish(
                CoordinationEvent(
                    topic="stats.test", payload={}, source_agent="test", event_type="discovery"
                )
            )

        stats = await bus.get_stats()

        assert "stream_name" in stats
        assert "total_messages" in stats
        assert stats["total_messages"] >= 3
        assert stats["engagement_id"] == bus.engagement_id


class TestLocalFallback:
    """Test local memory fallback when Redis unavailable."""

    @pytest.mark.asyncio
    async def test_local_fallback_publish(self):
        """Test publishing works in local fallback mode."""
        bus = DistributedCoordinationBus(
            redis_url="redis://invalid:9999", engagement_id="fallback-test"
        )
        await bus.connect()

        assert bus._local_fallback is True

        # Should not raise
        event = CoordinationEvent(
            topic="fallback.test", payload={}, source_agent="test", event_type="discovery"
        )
        event_id = await bus.publish(event)

        assert event_id is not None

        await bus.disconnect()


class TestSwarmIntegration:
    """Integration tests for multi-agent swarm behavior."""

    @pytest.mark.asyncio
    async def test_multiple_consumers_same_group(self, redis_url, engagement_id, clean_redis):
        """Test load balancing across consumer group members."""
        bus1 = DistributedCoordinationBus(redis_url=redis_url, engagement_id=engagement_id)
        bus2 = DistributedCoordinationBus(redis_url=redis_url, engagement_id=engagement_id)

        await bus1.connect()
        await bus2.connect()

        received_by_1 = []
        received_by_2 = []

        async def handler1(event):
            received_by_1.append(event)

        async def handler2(event):
            received_by_2.append(event)

        # Start both consumers in same group
        task1 = asyncio.create_task(
            bus1.subscribe(
                topics=["swarm.test"],
                consumer_id="consumer_1",
                group_name="swarm_group",
                callback=handler1,
            )
        )

        task2 = asyncio.create_task(
            bus2.subscribe(
                topics=["swarm.test"],
                consumer_id="consumer_2",
                group_name="swarm_group",
                callback=handler2,
            )
        )

        await asyncio.sleep(0.5)

        # Publish events
        for i in range(4):
            await bus1.publish(
                CoordinationEvent(
                    topic="swarm.test",
                    payload={"msg": i},
                    source_agent="publisher",
                    event_type="discovery",
                )
            )

        await asyncio.sleep(1)

        # Cleanup
        task1.cancel()
        task2.cancel()
        try:
            await asyncio.gather(task1, task2, return_exceptions=True)
        except:
            pass

        await bus1.disconnect()
        await bus2.disconnect()

        # Messages should be distributed (not duplicated)
        total_received = len(received_by_1) + len(received_by_2)
        assert total_received >= 3  # At least most messages received
        # Note: Exact distribution depends on Redis consumer group behavior


# Run with: pytest tests/test_distributed_coordination_bus.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
