"""Publish committed PostgreSQL outbox notifications with lease fencing.

Events are delivered *at least once*. A crash after bus publication but before
the PostgreSQL ACK may republish the same payload.event_id. An opt-in durable
notification callback uses the original event_id and a named consumer receipt
inside PostgreSQL; independent replicas skip committed receipts. A crash after
external notification but before receipt commit can still duplicate delivery.
No notification is proof of agent receipt or remote execution.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, Optional

import structlog
from sqlalchemy import select, update

from ai_osop.memory.supervision_store import (
    SupervisionEventORM,
    SupervisionOutboxORM,
    SupervisionStore,
)
from ai_osop.orchestrator.coordination_bus import CoordinationEvent

logger = structlog.get_logger("ai_osop.orchestrator.supervision_outbox")

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]*\Z")
_TOPIC = "supervision.event"
_SOURCE = "supervision-outbox"


def _identifier(value: Any, limit: int = 64) -> str:
    """Reject rather than truncate untrusted identifiers into collisions."""
    if not isinstance(value, str) or len(value) > limit or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("Invalid outbox notification identity")
    return value


def _safe_notification(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Send only immutable database identities and tightly bounded metadata."""
    if not isinstance(entry, dict):
        raise ValueError("Invalid outbox row")
    payload = entry.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Outbox payload must be an object")
    event_id = _identifier(entry.get("event_id"))
    engagement_id = _identifier(entry.get("engagement_id"))
    kind = _identifier(payload.get("kind"))
    topic = entry.get("topic")
    if topic is not None:
        _identifier(topic)
        # The PostgreSQL topic, not mutable payload metadata, determines the
        # durable event contract. Disagreeing event kinds must never be
        # republished under a different, apparently authorized identity.
        if topic != kind:
            raise ValueError("Durable event topic and kind differ")
    if payload.get("event_id", event_id) != event_id:
        raise ValueError("Outbox payload event identity differs from row")
    if payload.get("engagement_id", engagement_id) != engagement_id:
        raise ValueError("Outbox payload engagement differs from row")
    task_id = payload.get("task_id")
    if task_id is not None:
        task_id = _identifier(task_id)
    safe = {
        "event_id": event_id,
        "engagement_id": engagement_id,
        "task_id": task_id,
        "kind": kind,
    }
    if kind == "replay.pair_admitted":
        if (topic is not None and topic != kind) or task_id is None:
            raise ValueError("Replay pair lacks authenticated outbox identity")
        # SQL outbox uses nested metadata; the redacted bus notification
        # already contains only these bounded IDs, with no raw URL/session.
        metadata = payload.get("metadata", payload)
        if not isinstance(metadata, dict):
            raise ValueError("Replay pair lacks durable TaskORM identities")
        source = _identifier(metadata.get("source_task_id"))
        target = _identifier(metadata.get("target_task_id"))
        if source == target or not source.startswith("task-") or not target.startswith("task-"):
            raise ValueError("Replay pair observations must be distinct tasks")
        safe["source_task_id"] = source
        safe["target_task_id"] = target
    return safe


class SupervisionNotificationConsumer:
    """Notification handler dedupe, never a remote-task execution fence.

    Passing a durable SupervisionStore and stable consumer_id upgrades this
    to transactional completed receipts across replicas. The local default
    retains backward compatibility for isolated process-only observers.
    """

    def __init__(
        self,
        *,
        capacity: int = 2048,
        ttl_seconds: float = 3600,
        durable_store: Optional[SupervisionStore] = None,
        consumer_id: Optional[str] = None,
        delivery_timeout: float = 5.0,
    ) -> None:
        if not 1 <= capacity <= 100000 or not 1 <= ttl_seconds <= 86400:
            raise ValueError("Invalid notification dedupe bounds")
        if type(delivery_timeout) not in (int, float) or not 0.1 <= delivery_timeout <= 8.0:
            raise ValueError("Invalid notification callback deadline")
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self.delivery_timeout = float(delivery_timeout)
        self._seen: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = asyncio.Lock()
        self._durable = None
        if durable_store is not None or consumer_id is not None:
            if durable_store is None or consumer_id is None:
                raise ValueError("Durable notifications require store and consumer identity")
            from ai_osop.memory.outbox_delivery_dedupe import OutboxDeliveryDedupe

            self._durable = OutboxDeliveryDedupe(
                durable_store,
                consumer_id,
                timeout_seconds=delivery_timeout,
            )

    async def consume(
        self,
        event: Any,
        notify: Callable[[Dict[str, Any]], Awaitable[Any]],
    ) -> bool:
        """Notify once locally after success; failures remain retryable."""
        if getattr(event, "topic", None) != _TOPIC:
            return False
        if getattr(event, "source", None) != _SOURCE:
            return False
        payload = getattr(event, "payload", None)
        if not isinstance(payload, dict):
            return False
        try:
            safe = _safe_notification(
                {
                    "event_id": payload.get("event_id"),
                    "engagement_id": payload.get("engagement_id"),
                    "payload": payload,
                }
            )
        except ValueError:
            return False
        if self._durable is not None:
            return await self._durable.consume(safe, notify)
        # An event ID is unique in the normal outbox but is not sufficient
        # provenance for a process-local observer if another engagement sends
        # the same identity after restart/import. Never merge tenants.
        identifier = (safe["engagement_id"], safe["event_id"])
        async with self._lock:
            now = time.monotonic()
            while self._seen and next(iter(self._seen.values())) <= now:
                self._seen.popitem(last=False)
            if identifier in self._seen:
                return False
            # Do not mark complete until the notification callback succeeds.
            # A stuck process-local callback must not hold the subscriber
            # dedupe lock forever or block all subsequent notifications.
            # A timeout does not establish whether an external side effect
            # occurred; callers must retain at-least-once semantics.
            async with asyncio.timeout(self.delivery_timeout):
                result = await notify(safe)
            if result is False:
                raise RuntimeError("Notification callback declined acknowledgement")
            self._seen[identifier] = time.monotonic() + self.ttl_seconds
            self._seen.move_to_end(identifier)
            while len(self._seen) > self.capacity:
                self._seen.popitem(last=False)
            return True


class SupervisionOutboxDispatcher:
    def __init__(
        self,
        store: Any,
        bus: Any,
        interval: float = 2.0,
        *,
        enqueue_registered_task: Optional[Callable[[str], Awaitable[Any]]] = None,
        enqueue_signed_replay_pair: Optional[Callable[[str, str], Awaitable[Any]]] = None,
        max_batch: int = 50,
        lease_seconds: int = 30,
        delivery_timeout: float = 8.0,
        notification_callback: Optional[Callable[[Dict[str, Any]], Awaitable[Any]]] = None,
        notification_consumer_id: Optional[str] = None,
    ) -> None:
        if not 1 <= max_batch <= 50 or not 5 <= lease_seconds <= 3600:
            raise ValueError("Invalid outbox polling bounds")
        if not 0.1 <= delivery_timeout <= min(10, (lease_seconds - 1) / 2):
            raise ValueError("Delivery deadline exceeds safe lease budget")
        self.store = store
        self.bus = bus
        self.interval = max(0.1, interval)
        self.max_batch = max_batch
        self.lease_seconds = lease_seconds
        self.delivery_timeout = delivery_timeout
        self._task: Optional[asyncio.Task] = None
        self._enqueue_registered_task = enqueue_registered_task
        self._enqueue_signed_replay_pair = enqueue_signed_replay_pair
        self._sql_store = isinstance(store, SupervisionStore)
        if (notification_callback is None) != (notification_consumer_id is None):
            raise ValueError("Durable notification callback requires stable consumer identity")
        if notification_callback is not None and not self._sql_store:
            raise ValueError("Durable notification callback requires PostgreSQL store")
        self._notification_callback = notification_callback
        self._notification_consumer = (
            SupervisionNotificationConsumer(
                durable_store=store,
                consumer_id=notification_consumer_id,
                delivery_timeout=delivery_timeout,
            )
            if notification_callback is not None
            else None
        )

    @staticmethod
    def _committed_source_matches() -> Any:
        """Bind the leased hint to its committed source event in PostgreSQL.

        The outbox FK proves only that the event ID exists. It cannot prove
        that denormalized engagement, kind, task or payload belongs to that
        event. Check all four under the same transaction as the lease CAS.
        Historical bus notifications may be replayed, but a rewritten hint
        must never become a notification from a different signed engagement.
        """
        return (
            select(SupervisionEventORM.id)
            .where(
                SupervisionEventORM.id == SupervisionOutboxORM.event_id,
                SupervisionEventORM.engagement_id == SupervisionOutboxORM.engagement_id,
                SupervisionEventORM.kind == SupervisionOutboxORM.topic,
                SupervisionEventORM.task_id.is_not_distinct_from(
                    SupervisionOutboxORM.payload["task_id"].as_string()
                ),
                SupervisionEventORM.payload == SupervisionOutboxORM.payload["metadata"].as_json(),
                # The payload's redundant source identifiers cannot replace
                # either the event FK or the row's authoritative identity.
                SupervisionOutboxORM.payload["event_id"].as_string()
                == SupervisionOutboxORM.event_id,
                SupervisionOutboxORM.payload["engagement_id"].as_string()
                == SupervisionOutboxORM.engagement_id,
                SupervisionOutboxORM.payload["kind"].as_string() == SupervisionOutboxORM.topic,
            )
            .with_for_update(read=True)
            .exists()
        )

    async def _fence(self, entry: Dict[str, Any]) -> bool:
        """Reaffirm source identity and live lease before external publication."""
        if not self._sql_store:
            return True  # Existing isolated in-memory test stores.
        now = datetime.utcnow()
        async with self.store._sessions() as db:
            async with db.begin():
                result = await db.execute(
                    update(SupervisionOutboxORM)
                    .where(
                        SupervisionOutboxORM.id == entry["id"],
                        SupervisionOutboxORM.lease_id == entry["lease_id"],
                        SupervisionOutboxORM.delivered_at.is_(None),
                        SupervisionOutboxORM.leased_until > now,
                        self._committed_source_matches(),
                    )
                    .values(
                        leased_until=now + timedelta(seconds=self.lease_seconds),
                    )
                )
                return result.rowcount == 1

    async def _ack(self, entry: Dict[str, Any]) -> bool:
        """Fenced SQL ACK excludes expired leases, even before another claim."""
        if not self._sql_store:
            return await self.store.ack_outbox(entry["id"], entry["lease_id"])
        now = datetime.utcnow()
        async with self.store._sessions() as db:
            async with db.begin():
                result = await db.execute(
                    update(SupervisionOutboxORM)
                    .where(
                        SupervisionOutboxORM.id == entry["id"],
                        SupervisionOutboxORM.lease_id == entry["lease_id"],
                        SupervisionOutboxORM.delivered_at.is_(None),
                        SupervisionOutboxORM.leased_until > now,
                        self._committed_source_matches(),
                    )
                    .values(
                        delivered_at=now,
                        lease_id=None,
                        leased_until=None,
                    )
                )
                return result.rowcount == 1

    @staticmethod
    def _retry_seconds(attempts: Any) -> int:
        """Durable exponential backoff; poison stays undelivered for inspection."""
        count = min(max(attempts if type(attempts) is int else 1, 1), 20)
        return min(3600, 5 * (2 ** min(count - 1, 10)))

    async def _defer(self, entry: Dict[str, Any]) -> None:
        if not self._sql_store:
            return  # The fake store's original lease expires normally.
        now = datetime.utcnow()
        async with self.store._sessions() as db:
            async with db.begin():
                await db.execute(
                    update(SupervisionOutboxORM)
                    .where(
                        SupervisionOutboxORM.id == entry["id"],
                        SupervisionOutboxORM.lease_id == entry["lease_id"],
                        SupervisionOutboxORM.delivered_at.is_(None),
                        SupervisionOutboxORM.leased_until > now,
                    )
                    .values(
                        lease_id=None,
                        leased_until=now
                        + timedelta(
                            seconds=self._retry_seconds(entry.get("attempts")),
                        ),
                    )
                )

    async def flush_once(self) -> int:
        """Publish each fresh lease once; ACK only verified bus acceptance."""
        acknowledged = 0
        seen: set[str] = set()
        # Claim only when ready to deliver: a 50-row up-front claim could
        # expire while the previous rows are still being published.
        for _ in range(self.max_batch):
            items = await self.store.claim_outbox(limit=1, lease_seconds=self.lease_seconds)
            if not items:
                break
            entry = items[0]
            item_id = entry.get("id") if isinstance(entry, dict) else None
            if not isinstance(item_id, str) or item_id in seen:
                break
            seen.add(item_id)
            try:
                _identifier(entry.get("id"))
                _identifier(entry.get("lease_id"))
                safe = _safe_notification(entry)
                if entry.get("topic") == "flow.subtask_dispatch_intent" and (
                    self._enqueue_registered_task is None or safe["task_id"] is None
                ):
                    raise RuntimeError("Durable Flow intent reconciliation unavailable")
                if entry.get("topic") == "replay.pair_admitted" and (
                    self._enqueue_signed_replay_pair is None
                    or not safe.get("source_task_id")
                    or not safe.get("target_task_id")
                ):
                    raise RuntimeError("Durable replay pair reconciliation unavailable")
                if not await self._fence(entry):
                    continue
                async with asyncio.timeout(self.delivery_timeout):
                    published = await self.bus.publish(_TOPIC, safe, _SOURCE)
                    if published is False:
                        raise RuntimeError("Coordination bus declined publication")
                if self._notification_consumer is not None:
                    # This opt-in consumer runs in the actual delivery path
                    # before the publisher ACK. If its durable receipt fails,
                    # the outbox stays retryable rather than claiming success.
                    await self._notification_consumer.consume(
                        CoordinationEvent(
                            topic=_TOPIC,
                            source=_SOURCE,
                            payload=safe,
                        ),
                        self._notification_callback,
                    )
                if (
                    entry.get("topic") == "flow.subtask_dispatch_intent"
                    and safe["kind"] == "flow.subtask_dispatch_intent"
                ):
                    # This is only a queue hint for an immutable, pre-existing
                    # TaskORM. The orchestrator callback rechecks signed ROE
                    # and declines already running/uncertain/finished tasks.
                    async with asyncio.timeout(self.delivery_timeout):
                        queued = await self._enqueue_registered_task(safe["task_id"])
                        if queued is False:
                            raise RuntimeError("Durable Flow queue reconciliation declined")
                if (
                    entry.get("topic") == "replay.pair_admitted"
                    and safe["kind"] == "replay.pair_admitted"
                ):
                    async with asyncio.timeout(self.delivery_timeout):
                        queued = await self._enqueue_signed_replay_pair(
                            safe["source_task_id"],
                            safe["target_task_id"],
                        )
                        if queued is False:
                            raise RuntimeError("Durable replay pair reconciliation declined")
                if await self._ack(entry):
                    acknowledged += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # No raw payload, model text or exception detail in logs.
                event_id = entry.get("event_id") if isinstance(entry, dict) else None
                if (
                    not isinstance(event_id, str)
                    or len(event_id) > 64
                    or _IDENTIFIER.fullmatch(event_id) is None
                ):
                    event_id = None
                logger.warning(
                    "supervision_outbox_delivery_unconfirmed",
                    event_id=event_id,
                    error_class=type(exc).__name__,
                )
                try:
                    await self._defer(entry)
                except Exception as defer_exc:
                    logger.warning(
                        "supervision_outbox_retry_defer_unavailable",
                        error_class=type(defer_exc).__name__,
                    )
        return acknowledged

    async def run(self) -> None:
        while True:
            try:
                await self.flush_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "supervision_outbox_poll_failed",
                    error_class=type(exc).__name__,
                )
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
