"""Bounded 0040 lease-fenced SSE of original committed supervision events.

This is an explicitly leased POST stream, separate from the legacy unleased
supervision SSE. It never acquires/renews/ACKs leases or dispatches MCP tools.
Only independently authorized existing owner/Task/ROE + durable PG lease can
publish rows; a streaming HTTP success is not evidence of client receipt.
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Dict

from fastapi import APIRouter, Depends, Path, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import Field, StrictInt

from ai_osop.api.deps import require_role
from ai_osop.api.durable_subscription_publication_guard_20261022 import (
    DurableSubscriptionPublicationGuard,
    PublicationCallbacks,
    PublicationFence,
)
from ai_osop.api.routers.durable_supervision_subscriptions import (
    ReadRequest,
    _BoundedSubscriptionRoute,
    _ENG,
    _SUB,
    _context,
    _denied,
    _lease,
    _privacy,
    _strict_json_envelope,
)
from ai_osop.memory.durable_supervision_subscriptions import SubscriptionDenied


router = APIRouter(
    prefix="/supervision",
    tags=["durable-supervision-leased-sse"],
    route_class=_BoundedSubscriptionRoute,
)

# A completed transport iterator still does NOT certify HTTP client receipt.
# This non-ACK terminator makes truncated/partially revoked batches detectable
# to the browser's streaming parser without claiming exactly-once delivery.
_COMPLETE = (
    "event: stream_complete\ndata: " '{"acknowledged":false,"client_receipt_verified":false}\n\n'
)


class LeasedStreamRequest(ReadRequest):
    """Same exact 0040 lease expectation, with a bounded live wait."""

    wait_seconds: StrictInt = Field(default=10, ge=1, le=15)


@router.post(
    "/engagements/{engagement_id}/subscriptions/{subscriber_id}/leased-stream",
    dependencies=[Depends(_strict_json_envelope)],
)
async def leased_stream(
    request: Request,
    response: Response,
    body: LeasedStreamRequest,
    engagement_id: str = Path(pattern=_ENG),
    subscriber_id: str = Path(pattern=_SUB),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> StreamingResponse:
    """Emit at most one committed batch; reconnect/ACK is always explicit.

    Do admission *before* returning 200 and redo full context, revocation,
    cursor and lease check immediately before EACH frame. A 200 response,
    a yielded frame or an acknowledged PG cursor is not client-side receipt.
    """
    lease = _lease(engagement_id, subscriber_id, body)

    async def current():
        return await _context(engagement_id, subscriber_id, body.task_id, request, operator)

    guard = DurableSubscriptionPublicationGuard(
        PublicationCallbacks(current_context=current, is_disconnected=request.is_disconnected)
    )
    fence = None
    try:
        principal, store = await current()
        fence = PublicationFence(principal, lease, expected_cursor=body.cursor)
        events = await store.read_batch(principal, lease, limit=body.limit)
        # Initial check prevents an HTTP 200 for a known stale/expired lease.
        await guard.read(fence, events)
    except SubscriptionDenied as exc:
        raise _denied(exc) from exc

    async def generate() -> AsyncIterator[str]:
        # No unbounded worker or global stream state; the entire response
        # runs within the already-authenticated request's short wait budget.
        deadline = asyncio.get_running_loop().time() + body.wait_seconds
        pending = events
        while True:
            try:
                if await request.is_disconnected():
                    return
                if not pending:
                    if asyncio.get_running_loop().time() >= deadline:
                        await guard.read(fence, [])
                        yield _COMPLETE
                        return
                    # Polls read only the original immutable committed rows;
                    # never infer or mutate an ACK from Last-Event-ID.
                    await asyncio.sleep(
                        min(0.25, max(0, deadline - asyncio.get_running_loop().time()))
                    )
                    now_principal, now_store = await current()
                    if now_principal != fence.principal:
                        return
                    pending = await now_store.read_batch(now_principal, lease, limit=body.limit)
                    await guard.read(fence, pending)
                    continue
                # Do not replay one batch repeatedly on a still-open socket.
                # Across reconnects, unACKed rows can be delivered again.
                for event in pending:
                    permitted = await guard.leased_sse(fence, event)
                    if permitted.frame is None:
                        return
                    yield permitted.frame
                # Do NOT tell the UI a batch completed without another
                # independent signed/current lease and host-transport fence.
                await guard.read(fence, [])
                yield _COMPLETE
                return
            except asyncio.CancelledError:
                raise
            except SubscriptionDenied:
                # Revoked/expired/UNKNOWN after headers were sent: close
                # without publishing any further original event or success.
                return
            except Exception:
                # An unexpected host error is fail-closed, not an SSE event
                # that might be mistaken for committed supervision evidence.
                return

    _privacy(response)
    return StreamingResponse(
        generate(),
        status_code=200,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Accel-Buffering": "no",
        },
    )
