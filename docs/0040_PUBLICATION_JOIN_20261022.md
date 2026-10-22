# 0040 durable subscription publication — current signed owner/ROE/lease join

**Date:** 2026-10-22 · Original dirty shared AI-OSOP · owner: worker-38.

## Delivery and status

New, **unmounted** reusable module:

- `src/ai_osop/api/durable_subscription_publication_guard_20261022.py`
- `tests/qualification/test_0040_mounted_publication_guard_20261022.py`
- This report.

**No existing router, store, main, supervision SSE, UI, migration, application
database, Docker, Git, external provider or target was modified.** Not
production deployed merely because the test imported the module.

## Traced original mounted 0040 paths

Actual `src/ai_osop/api/main.py` mounts
`durable_supervision_subscriptions.router` at prefix `/supervision`.
The existing seven endpoints are:

| Action | Original path suffix | Current transaction contract |
| --- | --- | --- |
| Acquire | `/engagements/{engagement_id}/subscriptions/{subscriber_id}/acquire` | Signed bearer/engagement/Task/ROE, current owner, 0040 lease |
| Renew | `.../renew` | Exact replica/generation/lease and unexpired PG clock |
| Read | `.../read` | Committed, monotonic bounded events; twice checked signed/current owner and active lease before HTTP response |
| ACK | `.../ack` | Consecutive committed cursor CAS; final credential/ROE/0014 revocation NOWAIT transaction fence and host-only bounded precommit disconnect |
| Cursor-readback | `.../cursor-readback` | Read-only committed PG cursor under same owner, authorization and lease, **not** HTTP ACK receipt |
| Release | `.../release` | Drops current lease, leaves durable cursor |
| Revoke | `.../revoke` | Persistent subscriber tombstone |

Original `supervision.stream_events` at
`/supervision/engagements/{engagement_id}/events/stream` is **a distinct
non-0040 SSE path**: it checks its current signed operator and commitment
per event, but does not receive a subscription ID/generation/0040 lease.
Do **not** blindly claim this path is protected by the new leased 0040 guard.
Only an explicitly created, already-authorized **leased** SSE stream can call
the new `leased_sse` method on each row.

The actual original credential and ROE logic is in
`durable_supervision_subscriptions._context`: original bearer reintrospection,
issuer/subject/role/expiry matching, existing supervision ownership/Task
checks, `guard_sql` signed ROE and the transaction-local callback that
checks token/subject revocation including 0014 tables. The existing
`DurableSupervisionSubscriptions._transaction` rechecks authority twice,
locks revocation tables SHARE NOWAIT before commit; `_active` checks exact
replica, lease id, generation, current PG lease clock and revoked flag.

## API and precise prime wiring (NO router edits made here)

```python
from ai_osop.api.durable_subscription_publication_guard_20261022 import (
    DurableSubscriptionPublicationGuard, PublicationCallbacks, PublicationFence,
)

# Inside existing 0040 read/cursor-readback route AFTER its committed store
# result is fetched; original request, operator, principal and original lease
# are already available from _context(...).
guard = DurableSubscriptionPublicationGuard(PublicationCallbacks(
    current_context=lambda: _context(
        engagement_id, subscriber_id, body.task_id, request, operator
    ),
    is_disconnected=request.is_disconnected,
))

# Read: body.cursor MUST match the read_batch's original committed cursor;
# events are already fetched, never inferred from user JSON.
allowed = await guard.read(
    PublicationFence(principal, _lease(engagement_id, subscriber_id, body),
                     expected_cursor=body.cursor),
    events,
)
_privacy(response)
return allowed.body  # No ACK; no transport/client-receipt assertion

# Cursor-readback: current is returned by store.read_committed_cursor.
# Old body.cursor MAY be stale after a lost ACK; use current.cursor for
# this last-row-cursor expectation, but retain the original lease identity.
allowed = await guard.cursor_readback(
    PublicationFence(principal, _lease(engagement_id, subscriber_id, body),
                     expected_cursor=current.cursor),
    current,
)
_privacy(response)
return allowed.body  # safe_to_retry_unknown_ack=False always
```

The `current_context` callback is **not an arbitrary user-supplied function,
HTTP body parameter or cached login flag**. It must close over the *original*
host Request, path IDs, signed operator and Task, and call the mounted 0040
`_context` **afresh** for each publication. It must return exactly
`(SubscriberPrincipal, DurableSupervisionSubscriptions)` after independent
signed owner/ROE/tenant/Task checks. `is_disconnected` must be the *same*
Starlette Request's `is_disconnected` method, not a client-provided boolean
or proxy header. Constructor deadlines are bounded: 0.1–5 seconds for signed
context + lease transaction (default 3), 0.01–0.5 seconds for disconnect
(default 0.25). Missing callbacks, incorrect principal/lease/cursor,
revocations, timeout, wrong-type disconnect or unknown return **deny**.

For leased SSE only, use
`allowed = await guard.leased_sse(fence, committed_event)` followed by
`yield allowed.frame` **for each individual row**, with the proper
subscription identity, current lease, and cursor. It does not acquire,
renew, auto-ACK or implicitly wire the existing general supervision SSE.
Renew/ACK remain the already-mounted store's responsibility.

Exceptions inherit from the mounted router's `SubscriptionDenied`:
`PublicationRejected` is a denial, and `PublicationUnknown` means the
fresh signed state or host disconnect could not be resolved. The existing
route `except SubscriptionDenied: raise _denied(exc)` can map these to a
generic HTTP 409. `asyncio.CancelledError` is propagated, not suppressed
or converted to success. No automatic resend/ACK retry is permitted.

The guard snapshots and bounds committed rows **before** the final authority
await: max 100 rows, <=8192 bytes/row, <=262144 bytes/batch; strict ascending
PG bigint sequence, exactly matching tenant and optionally Task, JSON-finite
payload with restricted datetime serialization. The completed read result
retains `acknowledged=False`, at-least-once semantics; cursor readback
retains `acknowledgement_delivered_to_client_verified=False` and
`safe_to_retry_unknown_ack=False`. SSE result is a bounded frame, never a
durable sent-to-client receipt.

**Important unavoidable gap:** PG commit and subsequent ASGI HTTP/SSE
publication are not one atomic operation. A revocation, lease transfer,
disconnect, socket buffering or client crash may occur *after* the last
bounded host check. An allowed PublicationResult certifies neither delivery
nor exactly-once consumption. ACK and cursor-readback must remain separate.

## Actual test evidence

Default focused tests:

```powershell
& .venv/Scripts/python.exe -m pytest -q -o addopts= -rs --tb=line `
  tests/qualification/test_0040_mounted_publication_guard_20261022.py
```

**Observed: 9 passed, 1 skipped.** The sole skip is the opt-in private
nonroot PG fixture, not an app DB failure. Synthetic fixture tests cover
owner/issuer/role/Task/current ROE mismatch, revoked/stale lease and cursor,
disconnect, timeout UNKNOWN, cancellation, invalid/oversized/foreign event,
cursor-readback ACK truth and per-row leased SSE. These synthetic fixtures
are **not signed production credentials or genuine SQL**.

The separate opt-in positive test was actually executed with the **existing
test-owned private nonroot PG16 (WSL Unix socket, no TCP listener)**:

```powershell
$env:OSOP_DURABLE_MOUNTED_ACTUAL_PG16='1'
& .venv/Scripts/python.exe -m pytest -q -o addopts= --tb=line `
  tests/qualification/test_0040_mounted_publication_guard_20261022.py `
  -k optional_genuine_mounted_private_pg16_read_and_revoke
Remove-Item Env:OSOP_DURABLE_MOUNTED_ACTUAL_PG16
```

**Observed: 1 passed, 9 deselected in 34.62 seconds.** It invoked the
original mounted route for acquire, then the original signed
`_context` with fixture-issued JWT and Ed25519 ROE, actual private
PostgreSQL 0014+0040 store transaction, committed 11/19 events, and the
new final publication guard. A real PG signed authorization revocation then
caused the guard to reject publication. The private fixture signs ephemeral
test authority only — **not enrolled production signer/readiness**.

## Release assessment

**A useful tested unmounted final-publication join exists; prime must
explicitly wire it in owned router paths. No production 0040 SSE integration,
atomic HTTP receipt, multi-replica delivery certification, live cloud/target,
or production signing-issuer verification is claimed.** The safe default on
missing/expired authorization, stale lease, ambiguous transport, cancelled
request or missing PG is no publication; an UNKNOWN lost HTTP ACK should
be resolved through the already-mounted, independent cursor-readback path.

**NOT PRODUCTION CERTIFIED / NOT READY until mounted and independently
qualified in the full original deployment.**
