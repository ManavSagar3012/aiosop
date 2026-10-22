"""Reusable, unmounted 0040 publication fence; never HTTP delivery proof.

Prime must explicitly mount through current signed 0040 _context and host
Request.is_disconnected. The durable ACK transaction fence is separate.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Literal, Optional, Sequence, Tuple

from ai_osop.memory.durable_supervision_subscriptions import (
    DurableSupervisionSubscriptions,
    SubscriberLease,
    SubscriberPrincipal,
    SubscriptionDenied,
)

MAX_SEQUENCE = 9223372036854775807
MAX_ROW_BYTES = 8192
MAX_BATCH_BYTES = 262144
MAX_ROWS = 100


class PublicationRejected(SubscriptionDenied):
    """Current signed owner, ROE, lease or disconnect check denied publication."""


class PublicationUnknown(SubscriptionDenied):
    """Publication status unknown: do not infer a client receipt or retry ACK."""


CurrentContext = Callable[
    [], Awaitable[Tuple[SubscriberPrincipal, DurableSupervisionSubscriptions]]
]
HostDisconnect = Callable[[], Awaitable[bool]]


@dataclass(frozen=True)
class PublicationCallbacks:
    """Host-only callbacks. No client-provided trusted flags or lease authority.

    current_context must close over the mounted durable router's original
    _context(engagement_id, subscriber_id, task_id, request, operator),
    re-verifying signed bearer, tenant/Task/owner/ROE and constructing the
    transaction-scoped live credential/0014 revocation guard.

    is_disconnected must be request.is_disconnected of that SAME host Request.
    """

    current_context: CurrentContext
    is_disconnected: HostDisconnect


@dataclass(frozen=True)
class PublicationFence:
    """Expected original signed identity, lease and current committed cursor."""

    principal: SubscriberPrincipal
    lease: SubscriberLease
    expected_cursor: int


@dataclass(frozen=True)
class PublicationResult:
    """Only permission to attempt ASGI output, never delivery/ACK evidence."""

    mode: Literal["read", "cursor-readback", "leased-sse"]
    body: Optional[Dict[str, Any]] = None
    frame: Optional[str] = None
    client_receipt_verified: bool = False
    safe_to_retry_unknown_ack: bool = False


def _cursor(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SEQUENCE:
        raise PublicationRejected("Bounded committed publication cursor required")
    return value


def _json_default(value: Any) -> str:
    if not isinstance(value, datetime):
        raise TypeError("Unsupported committed event data")
    return value.isoformat()


def _event_bytes(
    event: Any, *, principal: SubscriberPrincipal, after: int
) -> tuple[int, Dict[str, Any], int]:
    if type(event) is not dict:
        raise PublicationRejected("Committed event object unavailable")
    seq = _cursor(event.get("sequence"))
    if (
        seq <= after
        or event.get("engagement_id") != principal.engagement_id
        or (principal.task_id is not None and event.get("task_id") != principal.task_id)
        or type(event.get("payload")) is not dict
        or any(
            type(event.get(k)) is not str or not 1 <= len(event[k]) <= 64
            for k in ("id", "kind", "actor_id")
        )
    ):
        raise PublicationRejected("Committed event tenant or sequence changed")
    try:
        raw = json.dumps(
            event, separators=(",", ":"), ensure_ascii=True, allow_nan=False, default=_json_default
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise PublicationRejected("Invalid committed event encoding") from exc
    if len(raw) > MAX_ROW_BYTES:
        raise PublicationRejected("Oversized committed event")
    return seq, json.loads(raw), len(raw)


def _read_projection(
    events: Sequence[Dict[str, Any]], principal: SubscriberPrincipal, cursor: int
) -> Dict[str, Any]:
    if type(events) not in (list, tuple) or len(events) > MAX_ROWS:
        raise PublicationRejected("Bounded committed event batch required")
    last, total, copied = cursor, 0, []
    for event in events:
        last, clean, size = _event_bytes(event, principal=principal, after=last)
        total += size
        if total > MAX_BATCH_BYTES:
            raise PublicationRejected("Oversized committed event batch")
        copied.append(clean)
    return {
        "events": copied,
        "cursor": cursor,
        "acknowledged": False,
        "delivery_semantics": "at_least_once",
    }


class DurableSubscriptionPublicationGuard:
    """Final signed 0040 owner/lease fence just before attempted HTTP publication.

    No ACK/lease mutation. Always requires a freshly reverified signed
    principal + store, a real PostgreSQL transaction's _active lease/cursor,
    and a bounded host disconnect check. Neither this check nor a subsequent
    ASGI yield can atomically establish that a client received bytes.
    """

    def __init__(
        self,
        callbacks: PublicationCallbacks,
        *,
        context_deadline_seconds: float = 3.0,
        disconnect_deadline_seconds: float = 0.25,
    ) -> None:
        if (
            not isinstance(callbacks, PublicationCallbacks)
            or not callable(callbacks.current_context)
            or not callable(callbacks.is_disconnected)
            or type(context_deadline_seconds) not in (int, float)
            or not 0.1 <= context_deadline_seconds <= 5
            or type(disconnect_deadline_seconds) not in (int, float)
            or not 0.01 <= disconnect_deadline_seconds <= 0.5
        ):
            raise PublicationRejected("Trusted bounded publication callbacks required")
        self.callbacks = callbacks
        self.context_deadline = float(context_deadline_seconds)
        self.disconnect_deadline = float(disconnect_deadline_seconds)

    async def _check(self, fence: PublicationFence) -> None:
        if (
            not isinstance(fence, PublicationFence)
            or not isinstance(fence.principal, SubscriberPrincipal)
            or not isinstance(fence.lease, SubscriberLease)
        ):
            raise PublicationRejected("Original signed publication identity required")
        expected = _cursor(fence.expected_cursor)
        if (fence.lease.engagement_id, fence.lease.subscriber_id) != (
            fence.principal.engagement_id,
            fence.principal.subscriber_id,
        ):
            raise PublicationRejected("Foreign subscriber lease")

        async def current() -> None:
            principal, store = await self.callbacks.current_context()
            if (
                type(principal) is not SubscriberPrincipal
                or principal != fence.principal
                or not isinstance(store, DurableSupervisionSubscriptions)
            ):
                raise PublicationRejected("Current signed owner or ROE changed")
            # _transaction performs current signed ROE/credential + 0014
            # revocation NOWAIT lock checks before/after _active; _active
            # verifies exact replica, generation, lease ID and PG lease clock.
            async with store._transaction(principal) as db:
                row = await store._active(db, principal, fence.lease)
                if (
                    type(row.get("cursor_sequence")) is not int
                    or row["cursor_sequence"] != expected
                ):
                    raise PublicationRejected("Committed cursor changed before publication")

        try:
            await asyncio.wait_for(current(), timeout=self.context_deadline)
        except asyncio.CancelledError:
            raise
        except PublicationRejected:
            raise
        except SubscriptionDenied as exc:
            raise PublicationRejected("Current signed subscriber lease denied") from exc
        except Exception as exc:
            raise PublicationUnknown("Current publication state UNKNOWN") from exc

        try:
            disconnected = await asyncio.wait_for(
                self.callbacks.is_disconnected(), timeout=self.disconnect_deadline
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise PublicationUnknown("Publication transport state UNKNOWN") from exc
        if type(disconnected) is not bool:
            raise PublicationUnknown("Publication transport state UNKNOWN")
        if disconnected:
            raise PublicationRejected("Host observed disconnect before publication")

    async def read(
        self, fence: PublicationFence, events: Sequence[Dict[str, Any]]
    ) -> PublicationResult:
        body = _read_projection(events, fence.principal, _cursor(fence.expected_cursor))
        await self._check(fence)
        return PublicationResult(mode="read", body=body)

    async def cursor_readback(
        self, fence: PublicationFence, committed: SubscriberLease
    ) -> PublicationResult:
        if (
            not isinstance(committed, SubscriberLease)
            or (
                committed.engagement_id,
                committed.subscriber_id,
                committed.replica_id,
                committed.lease_id,
                committed.generation,
            )
            != (
                fence.lease.engagement_id,
                fence.lease.subscriber_id,
                fence.lease.replica_id,
                fence.lease.lease_id,
                fence.lease.generation,
            )
            or committed.cursor != _cursor(fence.expected_cursor)
        ):
            raise PublicationRejected("Committed readback lease or cursor changed")
        if not isinstance(committed.lease_until, datetime):
            raise PublicationRejected("Committed lease clock unavailable")
        body = {
            "lease": {
                "engagement_id": committed.engagement_id,
                "subscriber_id": committed.subscriber_id,
                "replica_id": committed.replica_id,
                "lease_id": committed.lease_id,
                "generation": committed.generation,
                "cursor": committed.cursor,
                "lease_until": committed.lease_until,
                "delivery_semantics": "at_least_once",
                "provider_effect": "unobserved",
            },
            "cursor_readback": "committed_database_state_only",
            "acknowledgement_delivered_to_client_verified": False,
            "safe_to_retry_unknown_ack": False,
            "target_effect_verified": False,
        }
        await self._check(fence)
        return PublicationResult(mode="cursor-readback", body=body)

    async def leased_sse(self, fence: PublicationFence, event: Dict[str, Any]) -> PublicationResult:
        sequence, clean, _ = _event_bytes(
            event, principal=fence.principal, after=_cursor(fence.expected_cursor)
        )
        frame = (
            f"id: {sequence}\nevent: supervision\ndata: "
            + json.dumps(clean, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
            + "\n\n"
        )
        if len(frame.encode("ascii")) > MAX_ROW_BYTES + 128:
            raise PublicationRejected("Oversized leased SSE frame")
        await self._check(fence)
        return PublicationResult(mode="leased-sse", frame=frame)
