"""Bounded durable notification-consumer claims and completed receipts.

Three phases: (1) claim under a short PostgreSQL outbox-row lock and commit,
(2) execute a deadline-limited notification callback WITHOUT holding a SQL
transaction/lock, (3) lock the original event again and commit a fenced receipt.

Existing supervision_events already has UNIQUE(engagement_id, idempotency_key).
Every attempt is append-only; no migrations or mutable consumer ledger needed.

There is no atomic commit across PostgreSQL and an external notification.
Crash after callback but before the completed receipt may repeat notification
after claim expiry. This is explicitly at-least-once, NOT exactly-once.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from sqlalchemy import select

from ai_osop.memory.supervision_store import (
    SupervisionEventORM,
    SupervisionOutboxORM,
    SupervisionStore,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}\Z")
_CLAIM_KIND = "supervision.notification_claimed"
_RECEIPT_KIND = "supervision.notification_consumed"
_MAX_NOTIFY_SECONDS = 8.0
_MAX_ATTEMPTS = 16


class OutboxConsumerUnavailable(RuntimeError):
    """Notification receipt is unavailable, busy, or not durable."""


def _consumer_id(value: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError("Invalid durable outbox consumer identity")
    return value


def _receipt_key(engagement_id: str, event_id: str, consumer_id: str) -> str:
    data = (
        engagement_id.encode("utf-8")
        + b"\x00"
        + event_id.encode("utf-8")
        + b"\x00"
        + consumer_id.encode("utf-8")
    )
    return hashlib.sha256(data).hexdigest()


def _fingerprint(notification: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            notification,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


class OutboxDeliveryDedupe:
    """Named consumer receipts secured by the original committed outbox row."""

    def __init__(
        self,
        store: SupervisionStore,
        consumer_id: str,
        *,
        timeout_seconds: float = 5.0,
        lease_seconds: int = 30,
    ) -> None:
        if not isinstance(store, SupervisionStore):
            raise ValueError("Durable notification consumer requires PostgreSQL store")
        if (
            type(timeout_seconds) not in {int, float}
            or not 0.1 <= timeout_seconds <= _MAX_NOTIFY_SECONDS
            or type(lease_seconds) is not int
            or not 10 <= lease_seconds <= 120
            or lease_seconds <= timeout_seconds + 2
        ):
            raise ValueError("Invalid durable consumer deadline or lease")
        self.store = store
        self.consumer_id = _consumer_id(consumer_id)
        self.timeout_seconds = float(timeout_seconds)
        self.lease_seconds = lease_seconds

    def _identity(self, safe: Dict[str, Any]) -> Tuple[str, str]:
        token = _receipt_key(
            safe["engagement_id"],
            safe["event_id"],
            self.consumer_id,
        )
        return "outbox-notified:" + token, "outbox-claim:" + token + ":"

    def _receipt_payload(self, safe: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source_event_id": safe["event_id"],
            "notification_sha256": _fingerprint(safe),
            "consumer_id": self.consumer_id,
            "status": "notified",
            "delivery_guarantee": "at_least_once",
        }

    @staticmethod
    def _matches(original: Any, safe: Dict[str, Any]) -> bool:
        from ai_osop.orchestrator.supervision_outbox import _safe_notification

        return (
            original is not None
            and _safe_notification(
                {
                    "event_id": original.event_id,
                    "engagement_id": original.engagement_id,
                    "topic": original.topic,
                    "payload": original.payload,
                }
            )
            == safe
        )

    async def _locked_source(self, db: Any, safe: Dict[str, Any]) -> None:
        # The outbox event_id FK establishes only that an event exists. It does
        # NOT bind its tenant, task, kind or payload to the denormalized outbox
        # row. Check that authoritative event in the same SQL statement as the
        # locked row before either claiming a callback or trusting a receipt.
        # IS NOT DISTINCT FROM admits legitimate NULL task IDs, while JSONB
        # equality binds even metadata that the safe bus payload omits.
        origin_matches = (
            select(SupervisionEventORM.id)
            .where(
                SupervisionEventORM.id == SupervisionOutboxORM.event_id,
                SupervisionEventORM.engagement_id == SupervisionOutboxORM.engagement_id,
                SupervisionEventORM.kind == SupervisionOutboxORM.topic,
                SupervisionEventORM.task_id.is_not_distinct_from(
                    SupervisionOutboxORM.payload["task_id"].as_string()
                ),
                SupervisionEventORM.payload == SupervisionOutboxORM.payload["metadata"].as_json(),
            )
            # Preserve the source row through receipt commit as well as the
            # outbox row. A concurrent source edit/revocation must wait until
            # this short transaction resolves, not race our final ACK.
            .with_for_update(read=True)
            .exists()
        )
        result = await db.execute(
            select(SupervisionOutboxORM)
            .where(
                SupervisionOutboxORM.event_id == safe["event_id"],
                SupervisionOutboxORM.engagement_id == safe["engagement_id"],
                origin_matches,
            )
            .with_for_update()
        )
        if not self._matches(result.scalar_one_or_none(), safe):
            raise OutboxConsumerUnavailable("Notification disagrees with committed source event")

    async def _receipt(self, db: Any, safe: Dict[str, Any], key: str) -> bool:
        result = await db.execute(
            select(SupervisionEventORM)
            .where(
                SupervisionEventORM.engagement_id == safe["engagement_id"],
                SupervisionEventORM.idempotency_key == key,
            )
            .with_for_update(read=True)
        )
        receipt = result.scalar_one_or_none()
        if receipt is None:
            return False
        if (
            receipt.kind != _RECEIPT_KIND
            or receipt.task_id != safe["task_id"]
            or receipt.actor_id != self.consumer_id
            or receipt.payload != self._receipt_payload(safe)
        ):
            raise OutboxConsumerUnavailable("Durable notification receipt conflicts")
        # A completed event with a predictable idempotency key can otherwise
        # silence an unsent callback. Every real completion first commits its
        # same-tenant, same-consumer, nonce-bearing claim under the source lock.
        _, prefix = self._identity(safe)
        if not await self._claims(db, safe, prefix):
            raise OutboxConsumerUnavailable("Durable notification receipt lacks a claim")
        return True

    async def _claims(
        self,
        db: Any,
        safe: Dict[str, Any],
        prefix: str,
    ) -> list[Any]:
        result = await db.execute(
            select(SupervisionEventORM)
            .where(
                SupervisionEventORM.engagement_id == safe["engagement_id"],
                SupervisionEventORM.idempotency_key.like(prefix + "%"),
            )
            .order_by(SupervisionEventORM.sequence.desc())
            .limit(_MAX_ATTEMPTS + 1)
            .with_for_update(read=True)
        )
        entries = result.scalars().all()
        if len(entries) > _MAX_ATTEMPTS:
            raise OutboxConsumerUnavailable("Notification retry ledger exhausted")
        for offset, attempt in enumerate(entries):
            payload = attempt.payload
            if (
                attempt.kind != _CLAIM_KIND
                or attempt.actor_id != self.consumer_id
                or attempt.task_id != safe["task_id"]
                or not isinstance(payload, dict)
                or payload.get("source_event_id") != safe["event_id"]
                or payload.get("notification_sha256") != _fingerprint(safe)
                or payload.get("consumer_id") != self.consumer_id
                or payload.get("status") != "claimed"
                or type(payload.get("attempt")) is not int
                or not 1 <= payload["attempt"] <= _MAX_ATTEMPTS
                or payload["attempt"] != len(entries) - offset
                or attempt.idempotency_key != prefix + f"{payload['attempt']:02d}"
                or not isinstance(payload.get("lease_id"), str)
                or not re.fullmatch(r"notif-[0-9a-f]{32}", payload["lease_id"])
                or not isinstance(payload.get("expires_at"), str)
            ):
                raise OutboxConsumerUnavailable("Notification retry ledger is malformed")
            self._expires(attempt)
        return entries

    @staticmethod
    def _expires(claim: Any) -> datetime:
        try:
            expires = datetime.fromisoformat(claim.payload["expires_at"])
        except (ValueError, TypeError, OverflowError) as exc:
            raise OutboxConsumerUnavailable("Notification claim expiry is malformed") from exc
        if expires.tzinfo is not None:
            raise OutboxConsumerUnavailable("Notification claim expiry is malformed")
        return expires

    async def _claim(self, safe: Dict[str, Any], key: str, prefix: str) -> Optional[str]:
        async with self.store._sessions() as db:
            async with db.begin():
                await self._locked_source(db, safe)
                if await self._receipt(db, safe, key):
                    return None
                claims = await self._claims(db, safe, prefix)
                now = datetime.utcnow()
                if claims:
                    current = claims[0]
                    if self._expires(current) > now:
                        raise OutboxConsumerUnavailable(
                            "Notification callback is claimed by another replica"
                        )
                if len(claims) >= _MAX_ATTEMPTS:
                    raise OutboxConsumerUnavailable(
                        "Notification retry budget exhausted; reconcile manually"
                    )
                serial = len(claims) + 1
                lease_id = "notif-" + uuid.uuid4().hex
                db.add(
                    SupervisionEventORM(
                        id="evt-" + uuid.uuid4().hex,
                        engagement_id=safe["engagement_id"],
                        task_id=safe["task_id"],
                        kind=_CLAIM_KIND,
                        actor_id=self.consumer_id,
                        idempotency_key=prefix + f"{serial:02d}",
                        payload={
                            "source_event_id": safe["event_id"],
                            "notification_sha256": _fingerprint(safe),
                            "consumer_id": self.consumer_id,
                            "status": "claimed",
                            "attempt": serial,
                            "lease_id": lease_id,
                            "expires_at": (
                                now
                                + timedelta(
                                    seconds=self.lease_seconds,
                                )
                            ).isoformat(),
                        },
                    )
                )
                await db.flush()
        return lease_id

    async def _complete(
        self,
        safe: Dict[str, Any],
        key: str,
        prefix: str,
        lease_id: str,
    ) -> bool:
        async with self.store._sessions() as db:
            async with db.begin():
                await self._locked_source(db, safe)
                if await self._receipt(db, safe, key):
                    return False
                claims = await self._claims(db, safe, prefix)
                if (
                    not claims
                    or claims[0].payload["lease_id"] != lease_id
                    or self._expires(claims[0]) <= datetime.utcnow()
                ):
                    raise OutboxConsumerUnavailable(
                        "Durable notification claim was lost or expired"
                    )
                db.add(
                    SupervisionEventORM(
                        id="evt-" + uuid.uuid4().hex,
                        engagement_id=safe["engagement_id"],
                        task_id=safe["task_id"],
                        kind=_RECEIPT_KIND,
                        actor_id=self.consumer_id,
                        payload=self._receipt_payload(safe),
                        idempotency_key=key,
                    )
                )
                await db.flush()
        return True

    async def consume(
        self,
        notification: Dict[str, Any],
        notify: Callable[[Dict[str, Any]], Awaitable[Any]],
    ) -> bool:
        """Consume without any PG transaction spanning the external callback."""
        from ai_osop.orchestrator.supervision_outbox import _safe_notification

        try:
            if (
                not isinstance(notification, dict)
                or set(notification)
                != {
                    "event_id",
                    "engagement_id",
                    "task_id",
                    "kind",
                }
                or not callable(notify)
            ):
                raise ValueError("Invalid durable notification schema")
            safe = _safe_notification(
                {
                    "event_id": notification["event_id"],
                    "engagement_id": notification["engagement_id"],
                    "payload": notification,
                }
            )
            if safe != notification:
                raise ValueError("Notification content changed")
            key, prefix = self._identity(safe)
        except (ValueError, TypeError, UnicodeError) as exc:
            raise OutboxConsumerUnavailable("Invalid durable notification") from exc
        try:
            lease_id = await self._claim(safe, key, prefix)
            if lease_id is None:
                return False
            async with asyncio.timeout(self.timeout_seconds):
                result = await notify(dict(safe))
                if result is False:
                    raise OutboxConsumerUnavailable(
                        "Notification callback explicitly declined acknowledgement"
                    )
            return await self._complete(safe, key, prefix, lease_id)
        except asyncio.CancelledError:
            raise
        except OutboxConsumerUnavailable:
            raise
        except Exception as exc:
            raise OutboxConsumerUnavailable(
                "Durable notification callback or receipt unavailable"
            ) from exc
