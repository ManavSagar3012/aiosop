"""In-process agent coordination bus."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, DefaultDict, Dict, List


@dataclass(frozen=True)
class CoordinationEvent:
    """Event exchanged between orchestrator and agents."""

    topic: str
    payload: Dict[str, Any]
    source: str
    event_id: str = field(default_factory=lambda: f"bus-{datetime.utcnow().timestamp()}")
    created_at: datetime = field(default_factory=datetime.utcnow)


class AgentCoordinationBus:
    """Small pub/sub bus for task, approval, and audit lifecycle events."""

    def __init__(self) -> None:
        self._subscribers: DefaultDict[str, List[asyncio.Queue[CoordinationEvent]]] = defaultdict(
            list
        )

    async def publish(self, topic: str, payload: Dict[str, Any], source: str) -> CoordinationEvent:
        """Publish an event to all subscribers of a topic."""
        event = CoordinationEvent(topic=topic, payload=dict(payload), source=source)
        for queue in list(self._subscribers.get(topic, [])):
            await queue.put(event)
        return event

    async def subscribe(self, topic: str) -> AsyncIterator[CoordinationEvent]:
        """Subscribe to a topic as an async iterator."""
        queue: asyncio.Queue[CoordinationEvent] = asyncio.Queue()
        self._subscribers[topic].append(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers[topic].remove(queue)

    def subscriber_count(self, topic: str) -> int:
        """Return active subscriber count for a topic."""
        return len(self._subscribers.get(topic, []))
