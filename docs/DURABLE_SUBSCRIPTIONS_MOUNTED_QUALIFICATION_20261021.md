# Mounted durable supervision subscribers — ASGI qualification

**Date:** 2026-10-21  
**Scope:** Original, heavily dirty shared repository `/burp_mcp/ai-osop`  
**Disposition:** **NOT production certified.** This is a mounted FastAPI/ASGI contract
qualification against deterministic, synthetic PostgreSQL and authorization
producers, **not** an end-to-end real PostgreSQL16/0040/authentication-revocation
or multi-host qualification.

## Evidence and exact implementation under test

* The test imports `ai_osop.api.main.app` directly, not a newly assembled app.
  The actual main import registers **six** `POST` operations at
  `/supervision/engagements/{engagement_id}/subscriptions/{subscriber_id}/{action}`,
  for `acquire`, `renew`, `read`, `ack`, `release`, and `revoke`.
  The test verifies that each `APIRoute.endpoint` is the real
  `ai_osop.api.routers.durable_supervision_subscriptions` function and that
  no duplicate route is registered.
* Calls enter the real main ASGI middleware and dependency path using
  `httpx.ASGITransport(app=main.app, raise_app_exceptions=False)`. The
  application lifespan is **not** started; no production database, Redis,
  scanner, MCP server, or target is contacted.
* The local JWT verifier is the real `ai_osop.api.deps.verify_token` with
  synthetic fixture **HS256** token/key and `require_role` dependencies.
  Malformed signatures, missing/expired tokens, and a signed viewer are
  denied at the mounted route. This does **not** attest production JWT keys,
  OIDC introspection, identity-provider JWKS, or production revocation.
* The actual `supervision._access` procedure is invoked; its dependent
  persisted engagement read and `_supervision().assert_access` are intentionally
  substituted with controlled tenant/Task metadata. Independent owner,
  foreign Task, and signed senior (only within the matching Task) boundaries
  are checked.
* The mounted router calls the real worker42
  `DurableSupervisionSubscriptions` implementation. Its SQL statements,
  cross-transaction cursor CAS, replica lease generation, lease deadline,
  permanent revocation, and commit-time revalidation run on the bounded
  deterministic **FakePG/FakeSession** transactional model borrowed from
  `tests/test_durable_supervision_subscriptions_api_20261021.py`; they do
  **not** execute on a PostgreSQL server.
* The cryptographic `authorization_store.guard_sql` result is explicitly
  **synthetic**, including version 4 and a fixed policy digest. Tests exercise
  denial when that synthetic ROE is revoked or when the Task revision changes;
  they do not claim real detached signer/trust root validation.
* Revocation `SELECT`s, query-to-principal digest binding and pre-/post-CAS
  rechecks execute as real router/store code against modeled token digest
  and disabled-subject tables. Revocation inserted mid-CAS is explicitly
  modeled; the modeled SQL transaction rolls back a modified cursor.

## Positive and negative cases

| Category | Qualification observations |
| --- | --- |
| Main registration | Exactly six mounted POST endpoints; no fake app/route duplication |
| Signed principal | Local signed JWT owner succeeds; another owner, foreign Task, signed viewer, invalid signature and expired JWT denied |
| Signed senior | Different signed senior can access an engagement under the existing policy but cannot change the engagement/Task binding |
| ROE/Task | Current signed authorization revision required; revoked ROE or stale Task version denies progress and preserves cursor |
| Lease race | Two simulated replicas competing for same subscriber yield one success and one conflict; foreign replica/generation/expired lease fenced |
| Cursor/ACK | Next committed event only; forged/skipped event, stale cursor and replay denied; read does not automatically ACK |
| Lease recovery | Success path: acquire, renew, two contiguous ACKs, release, different replica reacquire, cursor preserved at 18 |
| Permanent revoke | A revoked subscriber cannot renew or reacquire; no external provider effect or replay authority claimed |
| Post-write revocation | Synthetic revocation after cursor SQL UPDATE, before transaction commit, rolls back the updated cursor |
| HTTP contract | Unknown actions/methods rejected, invalid/mixed fields denied, privacy/no-store headers on successful operations |
| Missing store | Actual `_memory` resolver returns service unavailable when orchestrator storage is absent; no subscriber mutation |
| Middleware audit | A real POST missing bearer now returns 401/403 without 500 after prime's scoped `main.py` stdlib logger fix |

## Commands and observed results

After final test changes, run in the original shared workspace:

```powershell
poetry run black tests/qualification/test_durable_subscriptions_mounted_asgi_20261021.py
# Exit 0; one file reformatted.

poetry run flake8 --select=F401,F821,F841 tests/qualification/test_durable_subscriptions_mounted_asgi_20261021.py
# Exit 0.

poetry run python -m py_compile tests/qualification/test_durable_subscriptions_mounted_asgi_20261021.py
# Exit 0.

poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_asgi_20261021.py --tb=short
# 19 passed in 17.84s; exit 0.

poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_asgi_20261021.py tests/test_durable_supervision_subscriptions_api_20261021.py tests/test_durable_supervision_subscriptions_20261021.py --tb=short
# 45 passed in 20.21s; exit 0.
```

One intermediate run exposed a mistaken test expectation (`_memory` was
replaced with a fake returning `None`, yielding a closed 409 instead of the
expected 503); the test was corrected to invoke the **actual** `_memory`
resolver against absent orchestrator state and now passes. This was a test
fixture issue, **not** a production failure. Initial independent inspection
found `main.py` stdlib logging keyword-argument incompatibility for audit
POSTs, reported to prime; prime made a scoped fix. The subsequently exercised
real unpatched middleware path passes the mounted missing-bearer regression.

## Unverified, residual risks and required qualification

1. **No live PostgreSQL16** used in this mounted ASGI qualification. Existing
   `tests/qualification/test_supervision_durable_subscriptions_0040_real_pg_20261021.py`
   has an independent `OSOP_DISPOSABLE_SUPERVISION_0040_PG=1` opt-in
   minimal-schema PG test. That DDL test is **not** this full mounted path,
   and it was not executed here. Real 0039→0040 application migration,
   real `session_states/tasks` and supervision event rows, serializable
   cross-replica lease/ACK claims and connection-pool failures require a
   separate controlled nonroot disposable qualification with proper cleanup.
2. **Principal origin and revocation**: Production local JWT, OIDC JWKS
   rotation/introspection, a durable token-revocation producer and current
   signed ROE signer/tenant state were not enrolled. The callback rechecks
   auth and reads revocation rows in the transaction; a concurrently
   **inserted** revocation digest absent before the read may not share an
   existing row lock. Do not claim all token-revocation races are serialized
   without a coordinated writer/fencing design and actual PG adversarial test.
3. **SSE delivery/consumer acknowledgment**: The API returns committed
   events and advances the cursor on explicit CAS ACK. It has **at-least-once**
   semantics. Neither external client receipt, exactly-once delivery, nor
   independent multi-process SSE reconciliation is certified.
4. **Security effects**: This router is inert; no provider, MCP, scanner or
   target activation occurred. No task replay, supervisor authorization
   minting, physical stop, or effect certification is implied by a successful
   HTTP response.
5. **Application lifecycle and independent infrastructure**: The full
   FastAPI startup/shutdown lifespan, real pooled DB, failover,
   external IdP revocation and real two-replica processes were not started.
   This test proves routing and modeled contract behavior, not production
   rollout safety.

**Required next gate:** Separate disposable PG16/0040 mounted ASGI test
against real session/Task/ROE fixtures and independent signer, with
cross-process race and revocation ACK-loss cases. Until then the mounted
durable subscriptions are **not production certified**.
