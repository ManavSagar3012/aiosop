"""In-process agent coordination bus."""

from __future__ import annotations

import asyncio
import logging
import math
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, DefaultDict, Dict, List, Optional


logger = logging.getLogger(__name__)
_ENGAGEMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _engagement_id(value: Any) -> str:
    if type(value) is not str or not _ENGAGEMENT.fullmatch(value):
        raise ValueError("A valid, explicit engagement_id is required for scoped bus usage")
    return value


@dataclass(frozen=True)
class CoordinationEvent:
    """Event exchanged between orchestrator and agents."""

    topic: str
    payload: Dict[str, Any]
    source: str
    # Windows clocks can return the same timestamp for multiple immediate
    # publications, including after crash/replay. The bus envelope identity
    # is distinct from the stable PostgreSQL outbox payload.event_id and
    # must never collide because of clock resolution or clock rollback.
    event_id: str = field(default_factory=lambda: f"bus-{uuid.uuid4().hex}")
    created_at: datetime = field(default_factory=datetime.utcnow)


class AgentCoordinationBus:
    """Best-effort, process-local pub/sub for lifecycle notifications.

    Subscribers have bounded buffers. A stalled subscriber may miss events;
    durable state and replay guarantees belong to the PostgreSQL stores, not
    to this in-process notification bus.
    """

    def __init__(self, *, max_queue_size: int = 50, subscriber_send_timeout: float = 0.25) -> None:
        if (
            isinstance(max_queue_size, bool)
            or not isinstance(max_queue_size, int)
            or not 1 <= max_queue_size <= 10000
        ):
            raise ValueError("max_queue_size must be between 1 and 10000")
        if (
            isinstance(subscriber_send_timeout, bool)
            or not isinstance(subscriber_send_timeout, (int, float))
            or not math.isfinite(subscriber_send_timeout)
            or not 0 < subscriber_send_timeout <= 5
        ):
            raise ValueError("subscriber_send_timeout must be between 0 and 5 seconds")
        self._max_queue_size = max_queue_size
        # PentAGI v2.2 uses 50 buffered entries and a 5-second send bound.
        # Keep the default wait shorter because task completion and ASGI
        # request paths also await this bus.
        self._subscriber_send_timeout = subscriber_send_timeout
        self._subscribers: DefaultDict[str, List[asyncio.Queue[CoordinationEvent]]] = defaultdict(
            list
        )
        # A scoped subscription is ONLY an opt-in event filter. Unscoped
        # legacy subscribers remain global; topic labels are not RBAC and
        # this process-local bus does not authenticate event publishers.
        self._subscriber_engagements: Dict[asyncio.Queue[CoordinationEvent], str] = {}

    async def publish(
        self, topic: str, payload: Dict[str, Any], source: str,
        *, engagement_id: Optional[str] = None,
    ) -> CoordinationEvent:
        """Offer an event to each topic subscriber without unbounded waits.

        A returned event identifies publication, not consumption or durable
        delivery. A full or failing subscriber cannot hold up other listeners.
        """
        event_payload = dict(payload)
        if engagement_id is not None:
            expected = _engagement_id(engagement_id)
            if event_payload.get("engagement_id") != expected:
                raise ValueError("Scoped publisher engagement_id does not match payload")
        event = CoordinationEvent(topic=topic, payload=event_payload, source=source)
        saturated: List[asyncio.Queue[CoordinationEvent]] = []
        for queue in list(self._subscribers.get(topic, [])):
            scope = self._subscriber_engagements.get(queue)
            if scope is not None and event.payload.get("engagement_id") != scope:
                # Missing, wrong or malformed engagement metadata MUST NOT
                # enter a tenant-scoped queue, even if topic/source look right.
                continue
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                saturated.append(queue)
            except Exception as exc:
                logger.warning(
                    "coordination_bus_subscriber_send_failed topic=%s error_class=%s",
                    topic,
                    type(exc).__name__,
                )
        if saturated:
            # Start all slow sends together so total latency is bounded by
            # one subscriber timeout, never N * timeout. Cancellation of the
            # publisher propagates to pending sends during ASGI shutdown.
            await asyncio.gather(*(self._send_bounded(queue, event) for queue in saturated))
        return event

    async def _send_bounded(
        self, queue: asyncio.Queue[CoordinationEvent], event: CoordinationEvent
    ) -> None:
        try:
            async with asyncio.timeout(self._subscriber_send_timeout):
                await queue.put(event)
        except TimeoutError:
            logger.warning("coordination_bus_subscriber_backpressure topic=%s", event.topic)
        except Exception as exc:
            logger.warning(
                "coordination_bus_subscriber_send_failed topic=%s error_class=%s",
                event.topic,
                type(exc).__name__,
            )

    async def subscribe(
        self, topic: str, *, engagement_id: Optional[str] = None,
    ) -> AsyncIterator[CoordinationEvent]:
        """Subscribe to topic; optional explicit engagement-filtered delivery.

        This is defense-in-depth against accidental best-effort cross-tenant
        fanout, NOT authorization for producer or consumer principals.
        """
        scope = _engagement_id(engagement_id) if engagement_id is not None else None
        queue: asyncio.Queue[CoordinationEvent] = asyncio.Queue(maxsize=self._max_queue_size)
        self._subscribers[topic].append(queue)
        if scope is not None:
            self._subscriber_engagements[queue] = scope
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscriber_engagements.pop(queue, None)
            subscribers = self._subscribers.get(topic)
            if subscribers is not None:
                if queue in subscribers:
                    subscribers.remove(queue)
                if not subscribers:
                    self._subscribers.pop(topic, None)

    def subscriber_count(self, topic: str) -> int:
        """Return active subscriber count for a topic."""
        return len(self._subscribers.get(topic, []))
