"""
Buzz-Inspired Feature Tests

Tests for architectural improvements ported from Block's Buzz:
- Signed events (HMAC-SHA256)
- Unified event pipeline
- Source validation
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import settings
from ai_osop.core.config import scope_signing_key


# ============================================================
# Signed Events
# ============================================================


class TestSignedEvents:
    """Test HMAC-SHA256 event signing (inspired by Buzz Nostr events)."""

    def test_event_signing(self):
        """Event should produce a valid signature."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        event = CoordinationEvent(
            topic="recon.discovery",
            payload={"endpoint": "/api/users"},
            source_agent="recon_agent",
            event_type="discovery",
            engagement_id="eng-001",
        )
        sig = event.sign()
        assert len(sig) == 64  # SHA-256 hex digest
        assert event.signature == sig

    def test_event_signature_verification(self):
        """Signed event should verify successfully."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        event = CoordinationEvent(
            topic="vuln.detected",
            payload={"severity": "high"},
            source_agent="vuln_agent",
            event_type="discovery",
            engagement_id="eng-001",
        )
        event.sign()
        assert event.verify_signature() is True

    def test_tampered_event_fails_verification(self):
        """Tampered event should fail signature verification."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        event = CoordinationEvent(
            topic="recon.discovery",
            payload={"endpoint": "/api/users"},
            source_agent="recon_agent",
            event_type="discovery",
            engagement_id="eng-001",
        )
        event.sign()

        # Tamper with the payload
        event.payload["endpoint"] = "/admin/backdoor"
        assert event.verify_signature() is False

    def test_unsigned_event_fails_verification(self):
        """Event without signature should fail verification."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        event = CoordinationEvent(
            topic="test",
            payload={},
            source_agent="test",
            event_type="test",
        )
        assert event.verify_signature() is False

    def test_canonical_form_deterministic(self):
        """Same event fields should produce same canonical form."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        shared_id = "test-event-001"
        e1 = CoordinationEvent(
            event_id=shared_id,
            topic="test", payload={"a": 1}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        e2 = CoordinationEvent(
            event_id=shared_id,
            topic="test", payload={"a": 1}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        assert e1._canonical_form() == e2._canonical_form()

    def test_different_events_different_signatures(self):
        """Different events should produce different signatures."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        e1 = CoordinationEvent(
            topic="topic_a", payload={}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        e2 = CoordinationEvent(
            topic="topic_b", payload={}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        e1.sign()
        e2.sign()
        assert e1.signature != e2.signature

    def test_event_to_dict_includes_signature(self):
        """Serialized event should include signature."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent

        event = CoordinationEvent(
            topic="test", payload={}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        event.sign()
        d = event.to_dict()
        assert "signature" in d
        assert d["signature"] == event.signature


# ============================================================
# Event Pipeline
# ============================================================


class TestEventPipeline:
    """Test the unified event pipeline (inspired by Buzz 12-step pipeline)."""

    @pytest.mark.asyncio
    async def test_pipeline_processes_event(self):
        """Pipeline should process an event through all steps."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent
        from ai_osop.orchestrator.event_pipeline import EventPipeline

        pipeline = EventPipeline()
        event = CoordinationEvent(
            topic="recon.discovery",
            payload={"endpoint": "/api"},
            source_agent="recon_agent",
            event_type="discovery",
            engagement_id="eng-001",
        )
        event.sign()

        result = await pipeline.process_event(event)
        assert result.success is True
        assert result.event_id == event.event_id
        assert len(result.steps_completed) >= 5

    @pytest.mark.asyncio
    async def test_pipeline_validates_source(self):
        """Pipeline should validate event source."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent
        from ai_osop.orchestrator.event_pipeline import EventPipeline

        pipeline = EventPipeline(authorized_sources={"recon_agent"})

        # Authorized source
        event1 = CoordinationEvent(
            topic="test", payload={}, source_agent="recon_agent",
            event_type="discovery", engagement_id="eng-001",
        )
        result1 = await pipeline.process_event(event1)
        assert result1.step_details["source_validation"]["authorized"] is True

        # Unauthorized source
        event2 = CoordinationEvent(
            topic="test", payload={}, source_agent="EVIL_HACKER",
            event_type="discovery", engagement_id="eng-001",
        )
        result2 = await pipeline.process_event(event2)
        assert result2.step_details["source_validation"]["authorized"] is False

    @pytest.mark.asyncio
    async def test_pipeline_verifies_signature(self):
        """Pipeline should verify event signatures."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent
        from ai_osop.orchestrator.event_pipeline import EventPipeline

        pipeline = EventPipeline()

        # Signed event
        event = CoordinationEvent(
            topic="test", payload={}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        event.sign()
        result = await pipeline.process_event(event)
        assert result.step_details["signature_verification"]["valid"] is True

    @pytest.mark.asyncio
    async def test_pipeline_rejects_invalid_schema(self):
        """Pipeline should reject events with missing required fields."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent
        from ai_osop.orchestrator.event_pipeline import EventPipeline

        pipeline = EventPipeline()

        # Missing topic
        event = CoordinationEvent(
            topic="", payload={}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        result = await pipeline.process_event(event)
        assert result.success is False
        assert "schema_validation" in result.steps_failed

    @pytest.mark.asyncio
    async def test_pipeline_metrics(self):
        """Pipeline should track metrics."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent
        from ai_osop.orchestrator.event_pipeline import EventPipeline

        pipeline = EventPipeline()

        for i in range(5):
            event = CoordinationEvent(
                topic=f"test.{i}", payload={}, source_agent="agent",
                event_type="discovery", engagement_id="eng-001",
            )
            await pipeline.process_event(event)

        metrics = pipeline.get_metrics()
        assert metrics["total_events"] == 5
        assert metrics["successful_events"] == 5
        assert metrics["success_rate"] == 100.0

    @pytest.mark.asyncio
    async def test_pipeline_audit_events(self):
        """Pipeline should record audit events."""
        from ai_osop.orchestrator.distributed_bus import CoordinationEvent
        from ai_osop.orchestrator.event_pipeline import EventPipeline

        pipeline = EventPipeline()

        event = CoordinationEvent(
            topic="test", payload={}, source_agent="agent",
            event_type="discovery", engagement_id="eng-001",
        )
        await pipeline.process_event(event)

        # Wait for fire-and-forget audit step to complete
        await asyncio.sleep(0.1)

        audit = pipeline.get_recent_audit_events()
        assert len(audit) >= 1
        assert audit[0]["topic"] == "test"


# ============================================================
# Coordination Bus Integration
# ============================================================


class TestBusIntegration:
    """Test that signed events work with the coordination bus."""

    @pytest.mark.asyncio
    async def test_bus_publishes_signed_event(self):
        """Bus should sign events on publish."""
        from ai_osop.orchestrator.distributed_bus import (
            CoordinationEvent,
            DistributedCoordinationBus,
        )

        bus = DistributedCoordinationBus(
            redis_url=settings.redis_uri,
            engagement_id="test-eng",
        )

        # Simulate local fallback mode
        bus._local_fallback = True
        bus._running = True

        event = CoordinationEvent(
            topic="test.signed",
            payload={"data": "test"},
            source_agent="test_agent",
            event_type="discovery",
        )

        event_id = await bus.publish(event)
        assert event_id is not None

        # Verify the event was signed
        queued = await bus._local_queue.get()
        assert queued["signature"] != ""
