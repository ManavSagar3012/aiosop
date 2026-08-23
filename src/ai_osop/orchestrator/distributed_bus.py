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
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict

import redis.asyncio as redis

logger = logging.getLogger(__name__)

@dataclass
class CoordinationEvent:
    """Standardized event structure for the swarm."""
    topic: str
    payload: Dict[str, Any]
    source_agent: str
    event_type: str  # 'discovery', 'analysis', 'request', 'command'
    confidence: float = 0.5
    engagement_id: str = "default"
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
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
    
    def __init__(self, redis_url: str = "redis://localhost:6379", engagement_id: str = "default"):
        self.redis_url = redis_url
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
            await self.redis.xadd(self.stream_name, {"init": "true"}, maxlen=10000, approximate=True)
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
            await self.redis.close()
            logger.info("Disconnected from Redis")
    
    async def close(self):
        """Alias for disconnect()."""
        await self.disconnect()

    async def publish(self, event: CoordinationEvent) -> str:
        """Publish an event to the stream."""
        event.engagement_id = self.engagement_id
        payload = event.to_dict()
        
        if self._local_fallback or not self.redis:
            await self._local_queue.put(payload)
            logger.debug(f"[LOCAL] Published event: {event.topic}")
            return event.event_id
            
        try:
            # Add to Redis Stream - store all event fields for proper reconstruction
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
                    "payload": json.dumps(event.payload)
                },
                maxlen=10000, # Keep last 10k events per engagement
                approximate=True
            )
            logger.debug(f"[REDIS] Published event {event.event_id} to {event.topic}")
            return event.event_id
        except Exception as e:
            logger.error(f"Failed to publish to Redis: {e}. Switching to local fallback.")
            self._local_fallback = True
            await self._local_queue.put(payload)
            return event.event_id

    async def subscribe(
        self, 
        topics: List[str], 
        consumer_id: str, 
        group_name: str,
        callback: Callable[[CoordinationEvent], None],
        batch_size: int = 10
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
                mkstream=True
            )
            logger.info(f"Created/Verified consumer group: {group_name}")
        except redis.exceptions.ResponseError as e:
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
                    block=5000  # Block for 5s waiting for messages
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
        """Parse raw Redis message into CoordinationEvent."""
        try:
            payload_data = json.loads(fields.get("payload", "{}"))
            return CoordinationEvent(
                event_id=fields.get("event_id", str(uuid.uuid4())), # Ideally stored in stream too
                topic=fields["topic"],
                source_agent=fields["source"],
                event_type=fields["type"],
                confidence=float(fields.get("confidence", 0.5)),
                payload=payload_data,
                timestamp=datetime.utcnow().isoformat()
            )
        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            # Return a dummy event to prevent crash
            return CoordinationEvent(
                topic="error.parse",
                payload={"raw": fields},
                source_agent="system",
                event_type="error"
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
                "total_messages": info.get('length', 0),
                "first_msg_id": info.get('first-entry', [''])[0] if info.get('first-entry') else None,
                "last_msg_id": info.get('last-entry', [''])[0] if info.get('last-entry') else None,
                "consumer_groups": info.get('groups', 0),
                "dlq_size": dlq_len,
                "engagement_id": self.engagement_id
            }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {"error": str(e)}

# Singleton instance manager
_bus_instance: Optional[DistributedCoordinationBus] = None

def get_coordination_bus(engagement_id: str = "default") -> DistributedCoordinationBus:
    global _bus_instance
    if _bus_instance is None:
        _bus_instance = DistributedCoordinationBus(engagement_id=engagement_id)
    return _bus_instance

async def initialize_bus(redis_url: str, engagement_id: str = "default") -> DistributedCoordinationBus:
    """Initialize the global bus instance."""
    global _bus_instance
    _bus_instance = DistributedCoordinationBus(redis_url=redis_url, engagement_id=engagement_id)
    await _bus_instance.connect()
    return _bus_instance
