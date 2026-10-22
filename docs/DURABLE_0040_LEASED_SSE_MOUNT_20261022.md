# 0040 actually mounted lease-fenced supervision SSE

**2026-10-22. Original shared `/burp_mcp/ai-osop` repository. NOT PRODUCTION CERTIFIED / NOT READY.**

## What changed

The durable `_context`/last-publication guard were **already mounted** in `durable_supervision_subscriptions.read` and `cursor-readback` when this continuation inspected the live source. This work did not remount or duplicate those paths. Instead it adds a distinct 0040 **POST leased-stream** endpoint, and a human-triggered Flow subscriptions UI client/action:

`POST /supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}/leased-stream`

- New `src/ai_osop/api/routers/durable_leased_sse_20261022.py` implements bounded Pydantic body (`ReadRequest` plus `wait_seconds` 1–15), inherited 4096-byte streaming pre-parser with duplicate-key rejection, signed bearer/supervision ownership/Task/current independently signed ROE `_context`, lease and exact database cursor, initial pre-HTTP-200 transaction publication guard, bounded 0.25-second read polling, and renewed signed owner/ROE/PG lease/disconnect check **before each SSE event** via `DurableSubscriptionPublicationGuard.leased_sse`.
- Mounted through current `src/ai_osop/api/main.py` separately from existing unleased `/supervision/engagements/{engagement_id}/events/stream`. Only committed original PostgreSQL rows become `id: N\nevent: supervision\ndata: ...\n\n`; a batch is sent at most once per connection. If none arrive the wait expires without emitting a speculative message. Lease expiry, revocation, tenant mismatch, stale cursor or unknown transport closes publication. Cancellation is propagated. No lease auto-acquire, auto-renew, auto-ACK, scanner/target calls, action replay or paid provider usage.
- New `ui/src/services/leasedSupervisionStream.ts` uses current verified human operator memory-only bearer, secure-origin checks and `fetch` POST with `credentials: omit`, `cache: no-store`, `redirect: error`, bounded strict UTF-8 `text/event-stream` framing. It rejects altered Task/tenant/sequence, malformed framing, oversized responses, sign-out and invalid current leases. It neither sends nor retries ACK and never construes a displayed SSE frame as independently verified HTTP receipt.
- Every complete batch now finishes with a fixed non-ACK `stream_complete` frame containing only `acknowledged:false` and `client_receipt_verified:false`, generated after one final signed-current owner/Task/ROE/PG cursor/lease/host-disconnect check. A socket close after partial rows, revocation, cancellation or unknown host error omits this marker; the UI discards the incomplete result instead of treating a truncated stream as complete. The marker certifies only the server-side final pre-send check, **never actual HTTP client receipt**.
- Existing `ui/src/components/flows/DurableSupervisionSubscribersPanel.tsx` narrowly adds an explicit `STREAM FENCED EVENTS (NO ACK)` human action to the already mounted durable named subscriptions Flow UI. Active stream is abortable on identity/scope change/unmount; manual ACK and independent UNKNOWN ACK readback remain unchanged.

## Executed verification (overlapping groups are not additive)

| Test | Observed outcome | Limits |
| --- | --- | --- |
| New actual route and synthetic fail-closed SSE | **6 passed**, 1 optional test deselected | Mounted path, local simulated owner/lease, two event frames plus explicit non-ACK completion marker, revoke between frames, stale PG cursor fixture, disconnect, bounded pre-parser, empty polling. No app DB. |
| Private PG16 opt-in mounted ASGI SSE | **1 passed**, 6 deselected, 76.84 s | Actual disposable nonroot WSL PG16 private Unix socket 0700, real migrations 0009/0014/0040, Ed25519 test-ROE, actual FastAPI route + SQL real lease, tenant-owned frames 11/19; wrong committed cursor denied. No independent deployed roots. |
| New Node/Vite authenticated stream client tests | **4 passed** | Explicit final marker required, truncated/partially revoked streams rejected; framing and once-only signed POST, foreign tenant/Task, duplicate sequence, malformed content, oversized response, sign-out, no ACK. |
| Previously mounted durable client Node tests | **8 passed** | Original cursor, manual ACK and UNKNOWN readback preserved. |
| Adjacent publication and new SSE Python selection | **15 passed**, 2 optional genuine PG cases deselected | Included 0040 publication guard tests without independent host enrollment. |
| UI TypeScript and production Vite build | **PASS**, 2,672 transformed modules | Compiled local source only, **not** deployed browser/API UI. |

## What is *not* proved

- A 200 SSE response, committed PostgreSQL cursor, emitted ASGI frame or returned UI array **cannot prove bytes were physically received** by the HTTP client. Delivery semantics remain **at least once**, not exactly once. ACK is a separate manual monotonic PostgreSQL CAS; unknown ACK must be resolved by explicit readback, never blind retry.
- Source-origin physical signer enrollment, actual independent production host ROE and reviewer roots, genuine all-eleven MCP Tool/Action transport and authorized target-owner effects were **not** enrolled/tested. The disposable PostgreSQL and Ed25519 fixtures are independent *test controls*, not a live deployment certificate.
- This is a **bounded one-batch stream**, not a horizontally scaled long-lived GraphQL subscription or automatic lease renewal. Physical multi-API-replica continuity, cancellation under a real reverse proxy, network disconnect at socket level, multi-tenant real deployment and crash-during-ASGI-send remain acceptance blockers.
- Existing unleased supervision SSE is not silently upgraded; both endpoints are separate and should be explicitly selected by clients.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
