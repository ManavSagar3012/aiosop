# Durable subscriber: mounted main ASGI ↔ actual private PostgreSQL 16

**Date:** 21 October 2026. **Repository:** the original shared dirty
`/burp_mcp/ai-osop`. **Disposition:** substantive isolated real-PG
qualification, **NOT** full production end-to-end certification.

## Provenance and isolation

The only additions for this worker are:

* `tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py`
* `docs/DURABLE_MOUNTED_ACTUAL_PG16_20261021.md` (this report)

The Python test imports the **actual** `ai_osop.api.main.app` and runs HTTP
against its six already-mounted durable-supervision subscription `POST`
handlers through `httpx.ASGITransport`. It **does not** mount a copy of
the router or modify main, worker42's durable store, Alembic migrations, or
legacy tests.

The Windows process runs actual `verify_token` HS256 JWT verification,
`authorization_store.guard_sql`, Ed25519 canonical signed-ROE verification,
router input checks, and worker42's unmodified PostgreSQL-backed lease/cursor
store. The identity/authentication key and Ed25519 private key are generated
solely for the disposable fixture and never use provider or production keys.

In WSL Ubuntu a **separate nonroot PostgreSQL 16** is initialized inside a
fresh `tempfile.TemporaryDirectory` owned by the helper process. PostgreSQL
uses a directory mode `0700`, Unix socket `0700`, `listen_addresses=''`,
`fsync=on` and `synchronous_commit=on`; no TCP database listener. Windows
talks **only** to its own `wsl.exe -d Ubuntu -- python3 -u -c` child over
newline-delimited **stdio**. Every SQL statement executes on real PG16
using `psycopg` parameter binding, with SQLAlchemy's PG compilation on the
Windows side. Independent logical clients create separate actual PostgreSQL
connections and transactions; the helper explicitly closes its connections,
stops PostgreSQL and destroys the private directory at shutdown. It never
opens an existing application DB, Docker, provider, target, scanner, Git, or
external network endpoint.

The real `upgrade()` bodies of **0009, 0014, 0040** are invoked via Alembic
`Operations` against the fresh PG16 session. Minimal `session_states`,
`tasks`, `supervision_events` parent tables are built first, then a
fictional engagement with two Task/tenant rows and committed numbered events
is seeded. These minimal parents are deliberate: this test does **not**
demonstrate execution of the full Alembic 0001→0040 chain or compatibility of
the entire `SessionStateORM`/Task ORM schema.

## Cryptographic and authority boundary

* A fresh private Ed25519 key signs a complete ROE policy including scope,
  engagement owner, authorization ID, version, key ID and bounded UTC window.
  The public key alone is enrolled in the test `OSOP_ROE_TRUSTED_KEYS_JSON`.
  The signed authorization's **actual 0009 PostgreSQL ledger row** is inserted
  with the canonical policy, real SHA256 digest and signature. The first real
  `guard_sql` call verifies the policy and expected digest.
* Local operator JWTs are signed with a strictly isolated HS256 key and
  passed in `Authorization: Bearer`; real API token verification, role and
  expiry checks run. `operator_revocation_required=True` enables durable
  revocation checks against the **real 0014 PG16 tables**. **OIDC/JWKS/
  external IdP introspection was not exercised.**
* The existing `supervision._access` method and
  `deps.assert_engagement_access` execute. **Only the
  `SupervisionStore.assert_access` ORM-dependent lookup is replaced** with
  a minimal SQL adapter that queries the actual disposable parent rows;
  the real entire application `SessionStateORM` schema does not exist.
  Identity, Task, scope and signed version are also enforced inside the
  unchanged durable subscription store transaction.
* The store's PostgreSQL `_fence_revocation_insert` path runs with a
  `bind.dialect.name='postgresql'` supplied **only** by the bridge's
  genuine PostgreSQL-backed session. SQL recording verifies execution of
  `SELECT current_setting('transaction_isolation')` and
  `LOCK TABLE operator_token_revocations, operator_subject_controls
  IN SHARE MODE NOWAIT`. These are real PG16 commands, **not**
  fake-pool short-circuits.

## Real database outcomes

The isolated mounted checks include:

1. Cross-tenant operator/Task denies; valid JWT/Ed25519 owner and current
   signed ROE admit a single subscriber lease, with committed cursor 0.
2. Another replica cannot claim the leased subscriber; read returns only
   numbered committed events from its own engagement and Task. A forged or
   skipped next event cannot be ACKed. The first real ACK commits cursor 11,
   and an ACK retry with the old cursor is rejected (client receipt may have
   been lost; the **server-side commit is durable**, not exactly-once delivery).
3. Release followed by acquire on another logical replica preserves cursor
   11, replaces lease ID, and monotonically increases generation. A real
   `signed_authorizations.status='revoked'` update blocks further read
   without advancing the cursor.
4. Actual store `revoke()` writes a permanent 0040 tombstone. Both stale ACK
   and new replica acquisition are denied. Cursor remains 0.
5. Another **real PostgreSQL connection** holds a token revocation INSERT
   open and uncommitted. A mounted ACK on a different connection cannot
   pass worker42's real `SHARE MODE NOWAIT` admission fence: it is denied,
   preserves cursor 0, and does not block waiting for the other writer.
   Simulating cancellation/abort of the writer by rolling back the
   transaction makes a subsequent ACK possible.
6. A fault injected **after** a genuinely executed PG cursor UPDATE but
   **before** its transaction commit forces rollback. A new request through
   an independent connection sees cursor 0 and can subsequently commit the
   valid ACK. Finally, an actually committed 0014 token revocation digest
   makes the original signed bearer fail its mounted read; cursor persists.

The SQL bridge serializes individual stdio messages, but each logical
connection has an independent real PostgreSQL transaction. The uncommitted
revocation versus `NOWAIT` test uses real overlapping PG locks; it is not
a full timed two-process throughput/soak benchmark. Only explicitly safe,
fictional data was used; no scanning or external effects.

## Exact execution evidence

The opt-in environment variable is intentionally **off** by default. On
Windows PowerShell in the original shared repo:

```powershell
poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py --tb=short
# Non-opt-in: 1 passed, 3 skipped in 15.02s AFTER final additions;
# no WSL/PG helper was started, exit 0.

$env:OSOP_DURABLE_MOUNTED_ACTUAL_PG16='1'
poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py::test_mounted_real_pg16_signed_roe_lease_ack_and_revocation --tb=short
# 1 passed in 55.64s (real 0009/0014/0040 PG, signed ROE, JWT, leases).

poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py::test_mounted_actual_pg16_revoked_bearer_and_subscription tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py::test_real_pg16_token_revocation_blocks_mounted_read --tb=short
# 2 passed in 74.00s (earlier fixture version).

poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py::test_real_pg16_token_revocation_blocks_mounted_read --tb=short
# 1 passed in 42.74s AFTER enabling real PG revocation table lock,
# real uncommitted writer contention, and PG rollback-after-cursor-UPDATE.
```

Final **whole-file genuine private PostgreSQL16** run (latest test/store
revisions, including `bind.dialect` fence and NOWAIT contention):

```powershell
$env:OSOP_DURABLE_MOUNTED_ACTUAL_PG16='1'
poetry run pytest --no-cov -q tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py --tb=short
# .... [100%]
# 4 passed in 91.35s (0:01:31), exit 0.
```

Final static checks on the **single owned qualification test**:

```powershell
poetry run black --check tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py
# 1 file would be left unchanged; exit 0.
poetry run flake8 --select=F401,F821,F841 tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py
# Exit 0.
poetry run python -m py_compile tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py
# Exit 0.
```

## Explicit gaps and release decision

* The application lifespan and full migration chain were not started. A
  minimal real PG schema does not qualify full application database structure
  or production deployment/pooling/connection credentials.
* The parent-supervision ownership lookup is a minimal real PG SQL adapter,
  not the full ORM. The main app's other routes, client UI, SSE stream and
  external replicas are outside this scoped test.
* WSL stdio transport faithfully executes SQL on PostgreSQL but is
  intentionally not a production asyncpg/SQLAlchemy connection pool or
  independently connected application process. It cannot establish throughput,
  HA failover, crash recovery of real API worker hosts, or the absence of
  all possible cross-process races.
* Cancellation is tested by rollback of the held real transaction and
  failure injection after real SQL UPDATE. These are **not** tests of an
  HTTP client task forcibly cancelled by an OS signal or an independent
  multiprocess kill during commit.
* The returned read batch is a committed snapshot, not independently
  delivered to an external subscriber or attested by the client. ACK is an
  at-least-once cursor protocol. No exactly-once delivery, provider/target
  effects, or safe replay of UNKNOWN action is certified.
* Genuine Ed25519 authorization and local HS256 JWT were exercised with
  ephemeral test roots; production signing key custody, external IdP/OIDC
  revocation and signed ROE deployment remain unqualified.

**Disposition:** Actual isolated PostgreSQL16 plus mounted API **qualified
for the enumerated contract paths only**. Broader application production
readiness remains **NOT CERTIFIED**.
