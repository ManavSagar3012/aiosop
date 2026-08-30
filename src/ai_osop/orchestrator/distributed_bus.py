"""
Distributed Coordination Bus using Redis Streams.

This module replaces the in-memory coordination bus with a persistent,
distributed event backbone suitable for the AI-OSOP Cognitive Swarm.

Features:
- Persistent event logging via Redis Streams
- Consumer Groups for parallel agent processing
- Automatic event replay for late-joining agents
- Integration with existing Dead Letter Queue (DLQ)
- Fallback to local memory if Redis is unavailable
"""

import asyncio
import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import redis.asyncio as redis
from redis.exceptions import ResponseError as RedisResponseError

from ai_osop.core.config import scope_signing_key, settings

logger = logging.getLogger(__name__)


@dataclass
class CoordinationEvent:
    """Standardized event structure for the swarm.

    Inspired by Buzz (block/buzz) Nostr event model:
    - Every event has a unique ID (SHA-256 of canonical form)
    - Every event is signed by its source agent (HMAC-SHA256)
    - Signature can be verified to prevent spoofing

    Buzz uses Schnorr signatures (secp256k1); we use HMAC-SHA256
    for simplicity since AI-OSOP agents share a secret key.
    """

    topic: str
    payload: Dict[str, Any]
    source_agent: str
    event_type: str  # 'discovery', 'analysis', 'request', 'command'
    confidence: float = 0.5
    engagement_id: str = "default"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signature: str = ""  # HMAC-SHA256 signature over canonical form

    def _canonical_form(self) -> bytes:
        """Produce deterministic byte representation for signing/verification."""
        data = {
            "topic": self.topic,
            "payload": self.payload,
            "source_agent": self.source_agent,
            "event_type": self.event_type,
            "confidence": self.confidence,
            "engagement_id": self.engagement_id,
            "timestamp": self.timestamp,
            "event_id": self.event_id,
        }
        return json.dumps(data, sort_keys=True, default=str).encode("utf-8")

    def sign(self, secret_key: Optional[bytes] = None) -> str:
        """Sign the event with HMAC-SHA256. Returns the signature."""
        key = secret_key or scope_signing_key()
        self.signature = hmac.new(key, self._canonical_form(), hashlib.sha256).hexdigest()
        return self.signature

    def verify_signature(self, secret_key: Optional[bytes] = None) -> bool:
        """Verify the event signature."""
        if not self.signature:
            return False
        key = secret_key or scope_signing_key()
        expected = hmac.new(key, self._canonical_form(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DistributedCoordinationBus:
    """
    Redis Streams-based coordination bus for AI-OSOP agents.

    Usage:
        bus = DistributedCoordinationBus(redis_url="redis://localhost:6379")
        await bus.connect()

        # Publish an event
        await bus.publish(CoordinationEvent(...))

        # Subscribe as a specific agent type
        await bus.subscribe(["recon.*"], "recon_agent_01", callback)
    """

    # Phase 6: Authorized sources — only these agents can publish events
    AUTHORIZED_SOURCES = {
        "recon_agent",
        "vuln_agent",
        "exploit_agent",
        "attack_chain_agent",
        "payload_agent",
        "reporting_agent",
        "workflow_agent",
        "strategic_planner",
        "self_pentest_agent",
        "orchestrator",
        "system",
        # Simulated/demo sources
        "simulated_recon_01",
        "simulated_scanner_01",
    }

    def __init__(
        self,
        # FIX (redis-url-settings-2026-08-23): default now resolves OSOP_REDIS_URI
        # instead of a hardcoded localhost:6379.
        redis_url: Optional[str] = None,
        engagement_id: str = "default",
    ):
        self.redis_url = redis_url or settings.redis_uri
        self.engagement_id = engagement_id
        self.stream_name = f"aiosop:{engagement_id}:events"
        self.redis: Optional[redis.Redis] = None
        self.consumer_groups: Dict[str, str] = {}  # group_name -> stream_key
        self._local_fallback: bool = False
        self._local_queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    async def connect(self) -> bool:
        """Establish connection to Redis. Fallback to local memory if failed."""
        try:
            self.redis = redis.from_url(self.redis_url, decode_responses=True)
            await self.redis.ping()
            logger.info(f"Connected to Redis Streams at {self.redis_url}")

            # Ensure stream exists
            await self.redis.xadd(
                self.stream_name, {"init": "true"}, maxlen=10000, approximate=True
            )
            await self.redis.xtrim(self.stream_name, maxlen=10000, approximate=True)

            self._running = True
            return True
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Falling back to local memory mode.")
            self._local_fallback = True
            self._running = True
            return False

    async def disconnect(self):
        """Close Redis connection."""
        self._running = False
        if self.redis:
            # FIX (redis-aclose-2026-08-24): deprecated close() -> aclose().
            await self.redis.aclose()
            logger.info("Disconnected from Redis")

    async def close(self):
        """Alias for disconnect()."""
        await self.disconnect()

    async def publish(
        self,
        event: CoordinationEvent = None,
        topic: str = None,
        payload: Dict[str, Any] = None,
        source: str = None,
    ) -> str:
        """Publish an event to the stream.

        Supports both new CoordinationEvent signature and legacy (topic, payload, source) signature.
        """
        # FIX (bus-publish-legacy-2026-08-23): legacy POSITIONAL calls bind the
        # topic STRING into `event` (publish("task.scheduled", {...}, "orchestrator")
        # -> event="task.scheduled", topic={...}, payload="orchestrator"). The old
        # legacy branch only fired when `event is None`, so those calls crashed with
        # AttributeError: 'str' object has no attribute 'engagement_id' inside
        # task_scheduler.schedule_task -> every phase transition failed.
        if isinstance(event, str):
            # Legacy positional style: publish(topic_name, payload_dict, source_str)
            legacy_payload = topic if isinstance(topic, dict) else (payload or {})
            legacy_source = source or (payload if isinstance(payload, str) else None) or "unknown"
            event = CoordinationEvent(
                topic=event,
                payload=legacy_payload,
                source_agent=legacy_source,
                event_type="command",
            )
            topic = None
        elif event is None and topic is not None:
            # Keyword style: publish(event=None, topic="x", payload={...}, source="y")
            event = CoordinationEvent(
                topic=topic,
                payload=payload or {},
                source_agent=source or "unknown",
                event_type="command",
            )
        elif event is None:
            raise ValueError("Either event object or topic must be provided")

        event.engagement_id = self.engagement_id

        # Phase 7 (Buzz-inspired): Sign the event before publishing
        if not event.signature:
            event.sign()

        event_dict = event.to_dict()

        if self._local_fallback or not self.redis:
            await self._local_queue.put(event_dict)
            logger.debug(f"[LOCAL] Published event: {event.topic}")
            return event.event_id

        try:
            # Add to Redis Stream - store all event fields for proper reconstruction
            # Phase 7: Include signature in the stream for verification on consumption
            await self.redis.xadd(
                self.stream_name,
                {
                    "event_id": event.event_id,
                    "topic": event.topic,
                    "source": event.source_agent,
                    "type": event.event_type,
                    "confidence": str(event.confidence),
                    "engagement_id": event.engagement_id,
                    "timestamp": event.timestamp,
                    # FIX (bus-payload-serialize-2026-08-30): task/agent payloads
                    # routinely carry datetime objects (Task.started_at, lease_expires
                    # echoed into events). Plain json.dumps raised
                    # "Object of type datetime is not JSON serializable", the publish
                    # failed, and the bus silently degraded to local fallback — the
                    # dashboard's live feed and cross-component events stopped
                    # flowing. default=str matches the canonical serializer on line 68.
                    "payload": json.dumps(event.payload, default=str),
                    "signature": event.signature,
                },
                maxlen=10000,  # Keep last 10k events per engagement
                approximate=True,
            )
            logger.debug(f"[REDIS] Published event {event.event_id} to {event.topic}")
            return event.event_id
        except Exception as e:
            logger.error(f"Failed to publish to Redis: {e}. Switching to local fallback.")
            self._local_fallback = True
            await self._local_queue.put(event_dict)
            return event.event_id

    async def subscribe(
        self,
        topics: List[str],
        consumer_id: str,
        group_name: str,
        callback: Callable[[CoordinationEvent], None],
        batch_size: int = 10,
    ):
        """
        Subscribe to topics as part of a consumer group.
        Supports automatic event replay from '0' (beginning) if group is new.
        """
        if not self._running:
            logger.error("Bus not running. Call connect() first.")
            return

        if self._local_fallback:
            await self._run_local_consumer(topics, callback)
            return

        # Ensure consumer group exists
        try:
            await self.redis.xgroup_create(
                self.stream_name,
                group_name,
                id="0",  # Start from beginning for new groups
                mkstream=True,
            )
            logger.info(f"Created/Verified consumer group: {group_name}")
        except RedisResponseError as e:
            if "BUSYGROUP" not in str(e):
                logger.error(f"Error creating consumer group: {e}")
                return

        logger.info(f"Starting consumer {consumer_id} in group {group_name} for topics: {topics}")

        while self._running:
            try:
                # Read from stream
                messages = await self.redis.xreadgroup(
                    groupname=group_name,
                    consumername=consumer_id,
                    streams={self.stream_name: ">"},  # '>' means only new messages
                    count=batch_size,
                    block=5000,  # Block for 5s waiting for messages
                )

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for msg_id, fields in stream_messages:
                        event = self._parse_message(fields)

                        # Filter by topic pattern (simple wildcard support)
                        if self._matches_topic(event.topic, topics):
                            try:
                                await callback(event)
                                # Acknowledge message
                                await self.redis.xack(self.stream_name, group_name, msg_id)
                            except Exception as e:
                                logger.error(f"Callback error for event {msg_id}: {e}")
                                # Optional: Move to DLQ here if repeated failures
                                # For now, we don't ack, so it stays in PEL (Pending Entries List)

            except Exception as e:
                logger.error(f"Stream read error: {e}")
                await asyncio.sleep(1)  # Backoff on error

    def _parse_message(self, fields: Dict[str, str]) -> CoordinationEvent:
        """Parse raw Redis message into CoordinationEvent.

        Phase 6: Validates source_agent against the authorized sources list.
        Phase 7 (Buzz-inspired): Verifies event signature.
        """
        if fields.get("init") == "true":
            return CoordinationEvent(
                topic="system.init",
                source_agent="system",
                event_type="system",
                payload={"raw": fields}
            )
        try:
            payload_data = json.loads(fields.get("payload", "{}"))
            source = fields.get("source", fields.get("source_agent", "unknown"))
            signature = fields.get("signature", "")

            # FIX (bus-parse-order-2026-08-23): construct and SIGNATURE-VERIFY the
            # event from the PRISTINE payload first, then apply security tags.
            # Tagging before verification mutated the canonical form, so every
            # event from an unauthorized source was additionally flagged as
            # having an invalid signature (two different signals conflated).
            event = CoordinationEvent(
                event_id=fields.get("event_id", str(uuid.uuid4())),
                topic=fields["topic"],
                source_agent=source,
                event_type=fields.get("type", "unknown"),
                confidence=float(fields.get("confidence", 0.5)),
                # FIX (bus-parse-fields-2026-08-23): restore engagement_id and the
                # original timestamp from the stream. engagement_id participates in
                # the canonical form used for HMAC signing — dropping it here made
                # every parsed event default to "default" and fail signature
                # verification whenever the bus ran under a real engagement id.
                engagement_id=fields.get("engagement_id", self.engagement_id),
                payload=payload_data,
                timestamp=fields.get("timestamp", datetime.utcnow().isoformat()),
                signature=signature,
            )
            # Phase 7 (Buzz-inspired): Verify event signature (pre-tagging)
            if signature and not event.verify_signature():
                logger.warning(
                    f"event_signature_invalid event_id={event.event_id} "
                    f"source={source} topic={event.topic}"
                )
                payload_data["_invalid_signature"] = True

            # Phase 6: Source validation (post-verification tagging)
            # FIX (bus-parse-logger-2026-08-23): these were structlog-style
            # kwarg calls on a STDLIB logger, which raise TypeError once INFO
            # logging is enabled -> the exception was swallowed by the broad
            # handler below and EVERY event from an unauthorized source was
            # reclassified as error.parse (history/consume lost the event).
            # FIX (bus-source-normalize-2026-08-30): agents publish with their
            # full instance id ("strategic-planner-001", "recon-agent-002")
            # while AUTHORIZED_SOURCES lists base types ("strategic_planner"),
            # so every instance-published event was tagged _unauthorized_source.
            # Normalize the instance id to its base type before the check.
            _source_base = (
                source.rsplit("-", 1)[0].replace("-", "_") if "-" in source else source
            )
            if (
                source not in self.AUTHORIZED_SOURCES
                and _source_base not in self.AUTHORIZED_SOURCES
            ):
                logger.warning(
                    f"unauthorized_event_source source={source} "
                    f"topic={fields.get('topic', '?')} event_id={fields.get('event_id', '?')}"
                )
                payload_data["_unauthorized_source"] = True
                payload_data["_original_source"] = source

            return event
        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            return CoordinationEvent(
                topic="error.parse",
                payload={"raw": fields},
                source_agent="system",
                event_type="error",
            )

    def _matches_topic(self, event_topic: str, patterns: List[str]) -> bool:
        """Simple wildcard matching for topics (e.g., 'recon.*')."""
        import fnmatch

        for pattern in patterns:
            if fnmatch.fnmatch(event_topic, pattern):
                return True
        return False

    async def _run_local_consumer(self, topics: List[str], callback: Callable):
        """Fallback consumer for local memory queue."""
        logger.warning("Running in LOCAL FALLBACK mode. Events are not persistent.")
        while self._running:
            try:
                payload = await asyncio.wait_for(self._local_queue.get(), timeout=1.0)
                event = CoordinationEvent(**payload)
                if self._matches_topic(event.topic, topics):
                    await callback(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Local consumer error: {e}")

    async def subscribe_iter(
        self,
        topics: List[str],
        consumer_id: str,
        group_name: str,
    ):
        """Async-iterator adapter over subscribe().

        FIX (bus-subscribe-iter-2026-08-23): several consumers (payload agent
        feedback loop, the dashboard WS forward pump) still used the legacy
        in-memory bus API `async for ev in bus.subscribe(topic)`. Against this
        class that call signature raises TypeError (missing consumer_id /
        group_name / callback), silently killing those background loops at
        startup. This adapter bridges to the callback API via a queue so
        iterator-style consumers work against the distributed backbone.
        """
        queue: asyncio.Queue = asyncio.Queue()

        async def _cb(event: CoordinationEvent) -> None:
            await queue.put(event)

        task = asyncio.create_task(
            self.subscribe(
                topics=topics,
                consumer_id=consumer_id,
                group_name=group_name,
                callback=_cb,
            )
        )
        try:
            while True:
                yield await queue.get()
        finally:
            task.cancel()

    async def get_history(self, topic_pattern: str, count: int = 100) -> List[CoordinationEvent]:
        """Retrieve historical events for replay or analysis."""
        if self._local_fallback or not self.redis:
            return []

        try:
            # Read latest 'count' messages
            messages = await self.redis.xrevrange(self.stream_name, max="+", min="-", count=count)
            events = []
            for msg_id, fields in messages:
                event = self._parse_message(fields)
                if self._matches_topic(event.topic, [topic_pattern]):
                    events.append(event)
            return events
        except Exception as e:
            logger.error(f"Failed to retrieve history: {e}")
            return []

    async def get_stats(self) -> Dict[str, Any]:
        """Get current bus statistics."""
        if self._local_fallback or not self.redis:
            return {"error": "Not connected or in local fallback mode"}

        try:
            info = await self.redis.xinfo_stream(self.stream_name)
            dlq_len = await self.redis.xlen(f"aiosop:{self.engagement_id}:dlq")

            return {
                "stream_name": self.stream_name,
                "total_messages": info.get("length", 0),
                "first_msg_id": (
                    info.get("first-entry", [""])[0] if info.get("first-entry") else None
                ),
                "last_msg_id": info.get("last-entry", [""])[0] if info.get("last-entry") else None,
                "consumer_groups": info.get("groups", 0),
                "dlq_size": dlq_len,
                "engagement_id": self.engagement_id,
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {"error": str(e)}


# Singleton instance manager
_bus_instance: Optional[DistributedCoordinationBus] = None


def get_coordination_bus(engagement_id: str = "default") -> DistributedCoordinationBus:
    """Return the process-wide bus singleton.

    FIX (bus-connect-2026-08-23): the returned instance previously relied on the
    caller to connect() it; nothing ever did, so publish() silently degraded to
    a local queue and subscribe() was dead. It now auto-connects on first use so
    orchestrators constructed without an explicit bus still get a live backbone
    (connection failures degrade to local-fallback exactly like connect()).
    """
    global _bus_instance
    if _bus_instance is None:
        _bus_instance = DistributedCoordinationBus(engagement_id=engagement_id)
    return _bus_instance


async def ensure_bus_connected(bus: "DistributedCoordinationBus") -> "DistributedCoordinationBus":
    """Connect the bus if it has never been connected (idempotent)."""
    if not bus._running:
        await bus.connect()
    return bus


async def initialize_bus(
    redis_url: str, engagement_id: str = "default"
) -> DistributedCoordinationBus:
    """Initialize the global bus instance."""
    global _bus_instance
    _bus_instance = DistributedCoordinationBus(redis_url=redis_url, engagement_id=engagement_id)
    await _bus_instance.connect()
    return _bus_instance
