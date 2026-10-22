"""Strict operator API for inert, PostgreSQL-fenced supervision subscribers.

The gateway mounts this inert API separately from its existing SSE handler.
Mounting is not proof of multi-replica deployment or current provider effects.
No scanner, SSE producer, external target, or historical UNKNOWN action is
activated by these endpoints.

Every operation verifies the signed operator bearer, existing supervision
tenant/Task access, current signed ROE, and an independent durable subscriber
lease. Client-supplied lease fields are CAS *expectations*, never authority.
The durable store owns all journal mutations and PostgreSQL transactions.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr
from sqlalchemy import select, text

from ai_osop.api.deps import require_role, state, verify_token
from ai_osop.api.routers.supervision import _access as _supervisor_access
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.durable_supervision_subscriptions import (
    DurableSupervisionSubscriptions,
    SubscriberLease,
    SubscriberPrincipal,
    SubscriptionDenied,
)
from ai_osop.memory.operator_revocation import (
    OperatorSubjectControlORM,
    OperatorTokenRevocationORM,
)


class _BoundedSubscriptionRoute(APIRoute):
    """Reject an oversized/ambiguous POST *before* FastAPI body/Pydantic parsing.

    A dependency runs after FastAPI has loaded and parsed the complete body;
    by then, a malicious client has already consumed the parser's memory. This
    route handler uses the same 4096-byte limit while streaming, preserving
    accepted original bytes for FastAPI's later schema validation.
    """

    def get_route_handler(self):
        original = super().get_route_handler()

        async def bounded(request: Request):
            content_types = request.headers.getlist("content-type")
            if (
                len(content_types) != 1
                or content_types[0].lower().split(";", 1)[0].strip() != "application/json"
            ):
                raise HTTPException(415, "JSON subscription request required")
            size_header = request.headers.getlist("content-length")
            if len(size_header) > 1 or (
                size_header
                and (
                    len(size_header[0]) > 4
                    or not size_header[0]
                    or not size_header[0].isascii()
                    or not size_header[0].isdecimal()
                    or int(size_header[0]) > 4096
                )
            ):
                raise HTTPException(413, "Bounded subscription request required")
            payload = bytearray()
            async for chunk in request.stream():
                if len(payload) + len(chunk) > 4096:
                    raise HTTPException(413, "Bounded subscription request required")
                payload.extend(chunk)
            if not payload:
                raise HTTPException(413, "Bounded subscription request required")
            # Starlette's Request.body() and FastAPI/Pydantic reuse this exact
            # accepted byte sequence; no substitute JSON re-encoding occurs.
            request._body = bytes(payload)
            _strict_json_bytes(request._body)
            return await original(request)

        return bounded


router = APIRouter(
    prefix="/supervision",
    tags=["durable-supervision-subscriptions"],
    route_class=_BoundedSubscriptionRoute,
)

_MAX_SEQUENCE = 9223372036854775807
_ENG = r"^eng-[A-Za-z0-9._-]{1,60}$"
_SUB = r"^subscr-[0-9a-f]{32}$"
_TASK = r"^task-[A-Za-z0-9._:-]{1,59}$"
_REPLICA = r"^replica-[A-Za-z0-9._-]{1,90}$"
_LEASE = r"^lease-[0-9a-f]{32}$"
_ISSUER = re.compile(r"^[\x21-\x7e]{1,128}$")
_SUBJECT = re.compile(r"^[\x21-\x7e]{1,128}$")


class _StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AcquireRequest(_StrictBody):
    replica_id: StrictStr = Field(pattern=_REPLICA)
    task_id: Optional[StrictStr] = Field(default=None, pattern=_TASK)
    lease_seconds: StrictInt = Field(default=30, ge=5, le=120)


class LeaseBinding(_StrictBody):
    replica_id: StrictStr = Field(pattern=_REPLICA)
    lease_id: StrictStr = Field(pattern=_LEASE)
    generation: StrictInt = Field(ge=1, le=_MAX_SEQUENCE - 1)
    cursor: StrictInt = Field(ge=0, le=_MAX_SEQUENCE)
    task_id: Optional[StrictStr] = Field(default=None, pattern=_TASK)


class RenewRequest(LeaseBinding):
    lease_seconds: StrictInt = Field(default=30, ge=5, le=120)


class ReadRequest(LeaseBinding):
    limit: StrictInt = Field(default=50, ge=1, le=100)


class AcknowledgeRequest(LeaseBinding):
    expected_cursor: StrictInt = Field(ge=0, le=_MAX_SEQUENCE)
    next_sequence: StrictInt = Field(ge=1, le=_MAX_SEQUENCE)


class RevokeRequest(_StrictBody):
    task_id: Optional[StrictStr] = Field(default=None, pattern=_TASK)


def _privacy(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


async def _host_ack_disconnected(request: Request) -> bool:
    """Best-effort ASGI disconnect after the bounded POST body was consumed.

    Starlette's `is_disconnected` uses an already-cancelled nonblocking scope;
    some receive channels yield a queued `http.disconnect` only after their
    first await, so that probe can return False for an already-lost client.
    Poll the *host's own* ASGI receive channel for a bounded 50 ms after the
    strict pre-parser consumed the complete original body. Never trust body
    fields or client-provided connection claims. Absence of a signal cannot
    guarantee future socket delivery and ACK outcomes remain UNKNOWN on loss.
    """
    if await request.is_disconnected():
        return True
    try:
        message = await asyncio.wait_for(request.receive(), timeout=0.05)
    except asyncio.TimeoutError:
        return False
    if message.get("type") == "http.disconnect":
        return True
    # No additional `http.request` is legitimate after the pre-parser has
    # consumed more_body=False; reject unexpected ASGI messages before COMMIT.
    raise SubscriptionDenied("Subscriber transport state ambiguous before ACK commit")


def _signed_identity(operator: Dict[str, Any]) -> tuple[str, str, str, int]:
    claims, actor, role = operator.get("claims"), operator.get("sub"), operator.get("role")
    if (
        type(claims) is not dict
        or type(actor) is not str
        or _SUBJECT.fullmatch(actor) is None
        or role not in {"operator", "senior_operator"}
        or type(claims.get("exp")) is not int
        or claims["exp"] <= int(datetime.now(timezone.utc).timestamp())
    ):
        raise HTTPException(403, "Current signed operator bearer required")
    issuer = claims.get("iss", "local-jwt")
    if type(issuer) is not str or _ISSUER.fullmatch(issuer) is None:
        raise HTTPException(403, "Signed issuer identity unavailable")
    return issuer, actor, role, claims["exp"]


def _bearer(request: Request) -> str:
    raw = request.headers.get("authorization", "")
    if (
        len(request.headers.getlist("authorization")) != 1
        or type(raw) is not str
        or len(raw) > 16400
        or not raw.startswith("Bearer ")
        or not 1 <= len(raw[7:]) <= 16384
        or any(ord(char) <= 32 or ord(char) >= 127 for char in raw[7:])
        or "," in raw
    ):
        raise HTTPException(401, "Signed Authorization: Bearer header required")
    return raw[7:]


async def _verified_bearer(token_value: str) -> Dict[str, Any]:
    return await verify_token(
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_value),
        token=None,
    )


def _memory() -> Any:
    orchestrator = state.get("orchestrator")
    memory = getattr(orchestrator, "session_memory", None)
    if not callable(getattr(memory, "_async_session", None)):
        raise HTTPException(503, "Durable supervision PostgreSQL unavailable")
    return memory


async def _current_signed_roe(memory: Any, engagement_id: str, task_id: Optional[str]) -> Any:
    """Read real signed current authorization and Task revision, never body data."""
    try:
        async with memory._async_session() as db:
            async with db.begin():
                current = await guard_sql(db, engagement_id)
                if task_id is not None:
                    result = await db.execute(
                        text(
                            "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:engagement FOR SHARE"
                        ),
                        {"task": task_id, "engagement": engagement_id},
                    )
                    row = result.mappings().one_or_none()
                    payload = row.get("payload") if row is not None else None
                    if (
                        type(payload) is not dict
                        or type(payload.get("_authorization_version")) is not int
                        or payload["_authorization_version"] != current.version
                        or type(payload.get("_authorization_sha256")) is not str
                        or payload["_authorization_sha256"] != current.policy_sha256
                    ):
                        raise SubscriptionDenied("Current signed Task authorization unavailable")
                return current
    except SubscriptionDenied:
        raise
    except Exception as exc:
        raise SubscriptionDenied("Current signed supervision authorization unavailable") from exc


def _lease(engagement_id: str, subscriber_id: str, body: LeaseBinding) -> SubscriberLease:
    # lease_until is intentionally not accepted from clients. The store tests
    # the authoritative PostgreSQL lease clock and live generation every time.
    return SubscriberLease(
        engagement_id=engagement_id,
        subscriber_id=subscriber_id,
        replica_id=body.replica_id,
        lease_id=body.lease_id,
        generation=body.generation,
        cursor=body.cursor,
        lease_until=datetime.fromtimestamp(0, tz=timezone.utc),
    )


def _lease_response(lease: SubscriberLease) -> Dict[str, Any]:
    if not isinstance(lease, SubscriberLease):
        raise SubscriptionDenied("Committed subscriber lease unavailable")
    return {
        "engagement_id": lease.engagement_id,
        "subscriber_id": lease.subscriber_id,
        "replica_id": lease.replica_id,
        "lease_id": lease.lease_id,
        "generation": lease.generation,
        "cursor": lease.cursor,
        "lease_until": lease.lease_until,
        "delivery_semantics": "at_least_once",
        "provider_effect": "unobserved",
    }


async def _context(
    engagement_id: str,
    subscriber_id: str,
    task_id: Optional[str],
    request: Request,
    operator: Dict[str, Any],
) -> tuple[SubscriberPrincipal, DurableSupervisionSubscriptions]:
    # Existing supervision policy is mandatory even for senior operators.
    token_value = _bearer(request)
    current_operator = await _verified_bearer(token_value)
    issuer, subject, role, expiry = _signed_identity(current_operator)
    if (issuer, subject, role, expiry) != _signed_identity(operator):
        raise HTTPException(403, "Operator credential changed during admission")
    await _supervisor_access(engagement_id, current_operator, task_id)
    memory = _memory()
    current = await _current_signed_roe(memory, engagement_id, task_id)
    principal = SubscriberPrincipal(
        engagement_id=engagement_id,
        subscriber_id=subscriber_id,
        issuer=issuer,
        subject=subject,
        role=role,
        expires_at=expiry,
        authorization_version=current.version,
        authorization_sha256=current.policy_sha256,
        task_id=task_id,
    )
    digest = hashlib.sha256(token_value.encode("utf-8")).hexdigest()

    async def live_credential_guard(db: Any, checked: SubscriberPrincipal) -> bool:
        # This callback runs INSIDE worker42's transaction twice, including
        # immediately before commit. Token/subject revocation queries use the
        # SAME PostgreSQL session; a failed lookup denies all lease/cursor writes.
        now = int(datetime.now(timezone.utc).timestamp())
        if checked != principal or now >= checked.expires_at:
            return False
        observed = await _verified_bearer(token_value)
        if _signed_identity(observed) != (issuer, subject, role, expiry):
            return False
        revoked = (
            await db.execute(
                select(OperatorTokenRevocationORM.digest)
                .where(OperatorTokenRevocationORM.digest == digest)
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        disabled = (
            await db.execute(
                select(OperatorSubjectControlORM.disabled)
                .where(OperatorSubjectControlORM.actor_id == subject)
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        if revoked is not None or disabled is True:
            return False
        if task_id is not None:
            row = (
                (
                    await db.execute(
                        text(
                            "SELECT payload FROM tasks WHERE id=:task AND engagement_id=:engagement FOR SHARE"
                        ),
                        {"task": task_id, "engagement": engagement_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            payload = row.get("payload") if row is not None else None
            if (
                type(payload) is not dict
                or type(payload.get("_authorization_version")) is not int
                or payload["_authorization_version"] != checked.authorization_version
                or type(payload.get("_authorization_sha256")) is not str
                or payload["_authorization_sha256"] != checked.authorization_sha256
            ):
                return False
        return True

    return principal, DurableSupervisionSubscriptions(
        memory, credential_guard=live_credential_guard
    )


def _denied(exc: SubscriptionDenied) -> HTTPException:
    # Do not disclose whether tenant IDs, tokens, subscriber leases or events
    # exist. Without a confirmed DB read, a conflict is not a completed ACK.
    return HTTPException(409, "Durable supervision subscription denied or unavailable")


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


async def _strict_json_envelope(request: Request) -> None:
    """Reject ambiguous client-controlled authority before subscription writes.

    FastAPI has already parsed Pydantic input by dependency execution time;
    this is a semantic ambiguity fence, not a raw transport memory limit.
    """
    content_types = request.headers.getlist("content-type")
    if (
        len(content_types) != 1
        or content_types[0].lower().split(";", 1)[0].strip() != "application/json"
    ):
        raise HTTPException(415, "JSON subscription request required")
    raw = await request.body()
    if not 1 <= len(raw) <= 4096:
        raise HTTPException(413, "Bounded subscription request required")
    _strict_json_bytes(raw)


def _strict_json_bytes(raw: bytes) -> None:
    """Reject duplicate or nonfinite authority fields using accepted raw JSON."""

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Nonfinite JSON numeric field")
        return number

    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
            parse_float=finite_float,
        )
        if type(parsed) is not dict:
            raise ValueError("JSON object expected")
    except (UnicodeDecodeError, ValueError, RecursionError, OverflowError):
        raise HTTPException(422, "Unambiguous subscription JSON required") from None


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/acquire",
    dependencies=[Depends(_strict_json_envelope)],
)
async def acquire(
    request: Request,
    response: Response,
    body: AcquireRequest,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        lease = await store.acquire(principal, body.replica_id, lease_seconds=body.lease_seconds)
        _privacy(response)
        return {"lease": _lease_response(lease)}
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/renew",
    dependencies=[Depends(_strict_json_envelope)],
)
async def renew(
    request: Request,
    response: Response,
    body: RenewRequest,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        new = await store.renew(
            principal, _lease(engagement_id, subscriber_id, body), lease_seconds=body.lease_seconds
        )
        _privacy(response)
        return {"lease": _lease_response(new)}
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/read",
    dependencies=[Depends(_strict_json_envelope)],
)
async def read(
    request: Request,
    response: Response,
    body: ReadRequest,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        events = await store.read_batch(
            principal, _lease(engagement_id, subscriber_id, body), limit=body.limit
        )
        from ai_osop.api.durable_subscription_publication_guard_20261022 import (
            DurableSubscriptionPublicationGuard,
            PublicationCallbacks,
            PublicationFence,
        )

        # The current lease, signed human, ROE and revocation are reloaded in
        # a separate last-check PostgreSQL transaction BEFORE the bounded
        # original event projection. This remains an attempted ASGI send,
        # never proof of delivery or a durable client-side acknowledgment.
        guarded = await DurableSubscriptionPublicationGuard(
            PublicationCallbacks(
                current_context=lambda: _context(
                    engagement_id, subscriber_id, body.task_id, request, operator
                ),
                is_disconnected=request.is_disconnected,
            )
        ).read(
            PublicationFence(
                principal,
                _lease(engagement_id, subscriber_id, body),
                expected_cursor=body.cursor,
            ),
            events,
        )
        _privacy(response)
        return guarded.body
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/ack",
    dependencies=[Depends(_strict_json_envelope)],
)
async def acknowledge(
    request: Request,
    response: Response,
    body: AcknowledgeRequest,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    if body.expected_cursor != body.cursor or body.next_sequence <= body.cursor:
        raise HTTPException(409, "Stale or non-monotonic cursor acknowledgement")
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        updated = await store.acknowledge(
            principal,
            _lease(engagement_id, subscriber_id, body),
            expected_cursor=body.expected_cursor,
            next_sequence=body.next_sequence,
            # Host-only trusted disconnect status, evaluated INSIDE the
            # PostgreSQL ACK transaction after the final current signed
            # credential/ROE and 0014 revocation checks but before COMMIT.
            # A lost HTTP ACK can still be UNKNOWN after the last check.
            precommit_disconnect=lambda: _host_ack_disconnected(request),
        )
        _privacy(response)
        return {"lease": _lease_response(updated), "acknowledged": True}
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/cursor-readback",
    dependencies=[Depends(_strict_json_envelope)],
)
async def readback_subscriber_cursor(
    request: Request,
    response: Response,
    body: LeaseBinding,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Non-mutating PostgreSQL cursor readback after an UNKNOWN HTTP ACK.

    A genuine committed database cursor is observable; the client receipt of
    the prior HTTP 200 is NOT. Require the exact current signed principal,
    owner/Task/ROE/revocation and same unexpired replica lease; do not renew,
    acquire, resubmit ACK, execute a tool or replay an unknown Action.
    """
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        current = await store.read_committed_cursor(
            principal, _lease(engagement_id, subscriber_id, body)
        )
        from ai_osop.api.durable_subscription_publication_guard_20261022 import (
            DurableSubscriptionPublicationGuard,
            PublicationCallbacks,
            PublicationFence,
        )

        # A lost HTTP ACK can leave the *body* cursor stale. Fence publication
        # against the newly read committed cursor without modifying it or
        # retrying any unknown ACK. Project the established response schema.
        await DurableSubscriptionPublicationGuard(
            PublicationCallbacks(
                current_context=lambda: _context(
                    engagement_id, subscriber_id, body.task_id, request, operator
                ),
                is_disconnected=request.is_disconnected,
            )
        ).cursor_readback(
            PublicationFence(
                principal,
                _lease(engagement_id, subscriber_id, body),
                expected_cursor=current.cursor,
            ),
            current,
        )
        _privacy(response)
        return {
            "lease": _lease_response(current),
            "cursor_readback": "committed_database_state_only",
            "acknowledgement_delivered_to_client_verified": False,
            "safe_to_retry_unknown_ack": False,
            "target_effect_verified": False,
        }
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/release",
    dependencies=[Depends(_strict_json_envelope)],
)
async def release(
    request: Request,
    response: Response,
    body: LeaseBinding,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        await store.release(principal, _lease(engagement_id, subscriber_id, body))
        _privacy(response)
        return {"released": True, "safe_to_retry": False}
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/revoke",
    dependencies=[Depends(_strict_json_envelope)],
)
async def revoke(
    request: Request,
    response: Response,
    body: RevokeRequest,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    try:
        principal, store = await _context(
            engagement_id, subscriber_id, body.task_id, request, operator
        )
        await store.revoke(principal)
        _privacy(response)
        return {"revoked": True, "safe_to_retry": False}
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc
