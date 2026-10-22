# Durable supervision HTTP/SSE revocation-to-send boundary — 2026-10-21

**Scope:** Read-only trace and deterministic local ASGI qualification of the *existing* routes. No application database, target, provider, Docker, Git action, real OIDC identity provider, or migration is exercised by these tests. This report is not a multi-replica or external-network certification. Test evidence: `tests/qualification/test_durable_sse_postcommit_revocation_20261021.py`.

## Relevant production paths and what each guarantees

| Boundary | Actual production path | Evidence / limitation |
|---|---|---|
| Signed bearer, operator identity and tenant | `api/deps.py::verify_token`, `api/routers/durable_supervision_subscriptions.py::_context`, `api/routers/supervision.py::_stream_revalidate` | Header-bound role and tenant checks. For configured OIDC tokens the actor is namespaced as `oidc-` + SHA-256 of issuer+NUL+subject, not an unqualified IdP `sub`. OIDC live token status is consulted on each verification **only if introspection is configured**; JWT signature and expiration alone cannot establish prompt IdP revocation. |
| Transactional 0040 subscriber admission and ACK | `memory/durable_supervision_subscriptions.py::_transaction` and `_fence_revocation_insert` | Signed current ROE and live credential guard inside the transaction; PostgreSQL `READ COMMITTED`; two 0014 revocation tables `LOCK TABLE ... IN SHARE MODE NOWAIT` before final guard to close absent digest/subject phantom insertion **until transaction commit**. Lease owner/nonce/generation/DB expiry/tenant and cursor CAS remain enforced. Failed/busy lock denies the transaction rather than presuming an active bearer. |
| Durable HTTP event read | `POST /supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}/read` | Calls `store.read_batch`, validates tenant/event shape, then repeats `_context` after the store transaction before returning JSON. This extra check narrows the commit-to-send window, but cannot hold 0014 locks through FastAPI serialization, HTTP send, client receive, or later consumption. `read` returns `acknowledged: false` and the previous cursor; it never calls `acknowledge`. |
| Durable explicit ACK | `POST /supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}/ack` | Only this separate request requests `store.acknowledge` and advances to the next committed matching event under CAS. No delivery acknowledgment follows automatically from `read`, HTTP 200, or SSE yield. A lost ACK HTTP response can leave a **committed cursor**; retrying the same ACK is rejected as stale, not an instruction to re-execute an unknown task. |
| Legacy/event-monitor SSE | `GET /supervision/engagements/{engagement_id}/events/stream` | **Separate from 0040 durable subscriber read/ACK.** Keeps a request-local `cursor` and `Last-Event-ID`. Rechecks bearer/owner before streaming, per poll, per event after batch SELECT, **and again after serialization immediately before yielding the frame**. Also checks `request.is_disconnected()` before that final revalidation. Sends `event: auth_required` (inside HTTP 200 stream) when revalidation denies; stops without an event on observed disconnect. This still cannot make the final check and ASGI frame publication atomic. |
| Action/effect authority | Both event readers | Events are passive committed supervision records, not target-owned effect receipts, permission to dispatch MCP, cancellation/rollback proof, or a trigger for retry of original UNKNOWN execution. No provider or target operations are invoked by these read routes. |

## Precisely observed races

1. **0014 revocation committed just after a durable read transaction:** the store's 0014 table `SHARE NOWAIT` lock has already been released at commit. The current HTTP router performs a *second* `_context` check before returning events. The local ASGI test revokes the signed token in this interval with the live revocation ledger enabled; the response is denied and does not expose event JSON. This is a verified improvement, not atomic send authorization.
2. **0014 revocation after that final `_context` check:** a controlled revocation at the already-authorized read handler's final response preparation still produces `200` with event JSON despite the now-revoked synthetic token. There is no way to make PostgreSQL commit and an arbitrary remote HTTP delivery one atomic transaction. A later separate request is denied. This is the **remaining readback confidentiality gap**, not a lease/ACK authority bypass; durable cursor stays unchanged.
3. **SSE revocation after batch SELECT but before its per-event guard:** the next event is blocked and the stream emits `auth_required` without an event `id`. Verified via local ASGI with active bearer revocation and with a locally signed OIDC JWT plus simulated IdP status invalidation.
4. **SSE revocation after row serialization but before its new final guard:** the strengthened generator detects it through a fresh `_stream_revalidate`, emits `auth_required`, and **does not yield the serialized row**. **Residual final-guard-to-ASGI-yield boundary:** revocation that commits *after that final check returns*, but before the ASGI frame is handed over, can still allow a frame to be constructed; the deterministic test injects the revocation on the fourth successful check and observes the bounded frame. This is **not** proof of remote client delivery, nor does it advance the 0040 cursor. A future request is denied.
5. **Disconnect and lost response:** an ASGI GET cancelled while blocked in a batch read exits without changing the 0040 cursor or lease. The strengthened generator also rechecks `request.is_disconnected()` after serialization; a simulated disconnect occurring after the earlier poll check now ends the generator **without yielding that row**. A disconnect after the final disconnect check can still race with ASGI transport publication, which cannot retract bytes already sent. Conversely, a POST `/ack` cancelled *after* its database commit leaves the cursor advanced; its lost response does not authorize a second ACK or any automatic action.

### Causality timeline

```text
Durable POST /read:
  JWT/tenant/ROE admission
  [PG transaction: active credential + signed ROE -> event snapshot
                   -> revocation-table SHARE NOWAIT -> final DB guard -> COMMIT]
                         ^ transaction lock protection ends
  router tenant/event validation -> second JWT/tenant/ROE _context
                         ^ separately checked; no held DB revocation lock
  response dict -> serialization -> ASGI send -> transport -> client consumption
                     ^ a new revocation may commit at any later point
  cursor unchanged; only explicit POST /ack CAS can advance it

Legacy GET /events/stream (not 0040):
  auth -> poll auth -> SELECT committed events -> auth for this event
                  -> frame validation/serialization -> disconnect check
                  -> FINAL signed auth/owner check -> YIELD -> local cursor change
                                      ^ residual revocation/ASGI send gap
```

## Qualification evidence

Running `.venv\Scripts\python.exe -m pytest -q -o addopts='' tests/qualification/test_durable_sse_postcommit_revocation_20261021.py` validated **10 passing deterministic test cases** following the prime's per-event SSE fix. Scenarios covered:

- post-commit read revocation caught by the mounted router's new second `_context` check (explicitly enabled synthetic revocation ledger);
- revocation immediately after the final read check, exposing the residual bounded JSON response gap, with `acknowledged=false` and persisted cursor unchanged;
- HTTP `/ack` response cancellation *after commit*: one committed cursor, stale second ACK denied, next read resumes from next event;
- actual mounted SSE ASGI revalidation denying event publication after batch-read revocation and after serialized-row revocation; a separate deterministic ASGI frame produced only when revocation occurs **after** the new final live check;
- an SSE transport GET cancelled inside the suspended event SELECT, with no durable cursor or lease change;
- a direct controlled SSE generator confirming that the new post-serialization `is_disconnected` check prevents a frame when disconnection occurred after the poll check;
- synthetic signed OIDC RSA/JWT issuer+subject namespace, live simulated IdP token status denial, and per-event SSE IdP revalidation.

The test harness invokes production FastAPI routes and signed local JWT verification, but patches tenant/ROE SQL and the IdP's introspection/key source with deterministic fixtures. It uses 0040-like transaction and lease models from the existing test suite, not a real 0040 database. A separate owner has PostgreSQL-16 migration tests; their results do not automatically qualify this HTTP/SSE behavior.

The earlier **40/40** compatibility count belonged to the **pre-fix** SSE revision. Initially, the stronger per-event check invalidated two other-owner expectations in `tests/test_supervision_sse_current_revalidation_20261021.py`; another owner updated that file while worker42 kept to this scoped qualification. The final focused run of **10 new qualification cases plus 31 adjacent durable API/SSE tests passed 41/41**. Python compilation of this qualification file passed. These isolated validations do not replace real PostgreSQL, remote HTTP transport, or IdP qualification.

## Safe integration recommendation to prime

1. **Keep durable `/read` and `/ack` separate.** Explicitly require the authenticated consumer's ACK only after application-level receipt/processing confirmation; never ACK on enqueue, JSON serialization, HTTP 200, SSE generator yield, or a provider receipt. Maintain single-step committed-event cursor CAS, lease fencing, current Task/ROE, tenant identity and revocation checks. Preserve at-least-once replay and UNKNOWN non-retry semantics.
2. **Keep the new post-read `_context` recheck** because it closes a practical interval between DB commit and handler return. For any stricter confidentiality requirement, deploy a revocation-aware delivery gateway/client protocol that cancels or tears down streams, reauthorizes per chunk at the delivery boundary, minimizes buffering, and treats in-flight bytes as potentially already disclosed. Do not promise absolute revocation-versus-send atomicity without a transport-specific acknowledgment/linearization mechanism; even then bytes already sent cannot be recalled.
3. **Do not retrofit the legacy SSE `Last-Event-ID` as 0040 authority.** An EventSource reconnect cursor is client-supplied progress, not a lease or ACK. Preserve the new post-serialization disconnect + per-event authorization checks. If a durable SSE surface is added, build an independently authenticated subscriber binding, check the same lease and owner immediately before every emitted event, cap and validate each event, and preserve an explicit consumer ACK endpoint. Treat disconnect/cancel as incomplete delivery, not receipt. Return `auth_required`/close without replaying an execution effect when revalidation fails.
4. **Preserve OIDC semantics.** Namespace actors using the verified issuer+subject, pin issuer/audience/signature and trusted role mapping, and use live introspection where early IdP revocation is required. Missing/unavailable introspection must not quietly turn into a positive active claim when the deployment requires it. Locally mocked IdP tests cannot certify a real OIDC service. Use response `Cache-Control: private, no-store` and avoid logging raw access tokens.
5. **Separate operational readiness from read-only subscription data.** Verify real PG transaction/session dialect, `READ COMMITTED` lock behavior, migration 0040 trigger, replica failover, and actual ASGI disconnect/cancel under isolated infrastructure before claiming production durability. Neither a successful subscriber read nor an event describing UNKNOWN proves a provider stopped, a target changed, or an MCP tool may run again.

**Bottom line:** Worker42's revocation insert fence makes a *committing database action* safe against earlier concurrent 0014 inserts under the specified lock/isolation assumptions; it cannot freeze future revocations or protect bytes after that commit. The mounted read route's second `_context` narrows the response gap; the prime's SSE fix now closes the *serialization-to-last-check* interval, but cannot atomically protect the final authorization result through ASGI `yield` and transport delivery. No auto-ACK, no automatic execution, and no claims of exactly-once delivery arise from this qualification.
