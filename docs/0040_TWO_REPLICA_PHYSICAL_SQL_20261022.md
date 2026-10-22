# 0040 durable subscribers: physical two-connection PostgreSQL qualification

**Scope: original dirty shared checkout, new tests/docs only.**

The test `tests/qualification/test_0040_private_pg_two_replica_races_20261022.py`
imports the already installed `mounted_real` signed-ROE fixture and
`PgBridge` from
`tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py`
**unchanged**. The reused helper creates a fresh, disposable, nonroot
PostgreSQL 16 instance in a 0700 temporary directory under WSL Ubuntu,
with `listen_addresses=''` and a private Unix-domain socket (0700).
It loads the **actual** 0009 signed-ROE, 0014 durable operator revocation,
and 0040 durable subscription migrations against minimal disposable parent
tables. The Windows application accesses this private database **only**
via an owned JSON/parameterized-SQL stdio subprocess bridge. The app DB,
Docker, existing PostgreSQL/TCP listener, any target, scanners, external
provider and production credentials are untouched.

## How to run

Default no-PG route check and explicit opt-in skip:

```powershell
poetry run pytest tests/qualification/test_0040_private_pg_two_replica_races_20261022.py -q --no-cov
```

Private nonroot PG16 opt-in only:

```powershell
$env:OSOP_0040_PRIVATE_PG_TWO_REPLICA_RACES='1'
poetry run pytest tests/qualification/test_0040_private_pg_two_replica_races_20261022.py -q --no-cov
Remove-Item Env:OSOP_0040_PRIVATE_PG_TWO_REPLICA_RACES
```

This new opt-in is separate from the parent fixture's flag and sets the
parent flag only inside the test's scoped fixture. Every PG session has
a distinct physical backend connection. The test uses `SET LOCAL
lock_timeout='350ms'` and `statement_timeout='1600ms'` to prevent an
interleaved SQL operation from hanging indefinitely; asyncio also bounds
mounted operations. No server shutdown, app lifespan or deployment is invoked.

## Exact cases

1. Two simultaneous physical `pg_backend_pid()` values differ, both using
   PostgreSQL READ COMMITTED. A held `SELECT ... FOR UPDATE` on connection A
   causes connection B's `FOR UPDATE NOWAIT` to raise SQLSTATE `55P03`.
   With the row still locked by A, an actual mounted ASGI ACK using a separate
   connection must fail-closed, leaving the cursor unchanged.
2. Two independent ASGI clients concurrently claim the exact same signed
   subscriber/Task but with separate replica IDs. Only one may receive a
   current generation=1 lease, under real PostgreSQL PK/CAS constraints.
3. The store's existing host-only `precommit_disconnect` callback is
   triggered **after a real PostgreSQL cursor UPDATE**, using the actual
   mounted JWT/Task context and signed ROE admission obtained through the
   production router. This deliberately injected disconnect state causes
   `SubscriptionDenied` and a transaction ROLLBACK. An independent physical
   SQL read confirms that the cursor stayed at zero. This is a **host callback
   simulation**, not proof of a real ASGI socket disconnect or client delivery.
4. Two independent mounted ASGI ACK clients race on the **same exact signed
   lease**, `expected_cursor=0`, `next_sequence=11`. At most one SQL
   transaction may commit the cursor advance; the other is a conflict. No
   sequence 19 skip or duplicate cursor increment is allowed.
5. The test intentionally discards the successful ACK's HTTP response
   object to simulate a client losing an ACK receipt. A fresh independently
   authenticated `cursor-readback` uses the OLD lease expectation and must
   report the committed cursor **without performing another cursor UPDATE**.
   The stale prior ACK remains denied, never auto-replayed.
6. Release clears a lease without deleting the cursor; a new replica
   acquires a different lease ID and higher generation, retains the existing
   cursor, and fences old-generation ACK/readback.
7. While physical connection A holds an uncommitted 0014 token revocation
   INSERT, mounted connection B attempts to ACK. The production
   `SHARE MODE NOWAIT` revocation-insert fence must deny B, leaving the
   cursor unchanged. An explicit rollback of A permits a later separately
   signed ACK; a subsequently committed 0014 revocation denies another ACK
   while preserving the last committed cursor.

The test exercises the mounted **actual main.app router** without entering
its lifespan, unmodified JWT verification, original `guard_sql` signed
authorization, the 0040 store, and real SQL transactions. Synthetic
Ed25519 policy keys and JWT identities are only local test fixtures.

## What this test cannot certify

- **Two different PostgreSQL connections are NOT two deployed servers,
  physical machines, containers, replicas, or operating-system worker
  processes.** Two ASGI request clients share one Python process, and the
  single WSL stdio helper multiplexes two independent PostgreSQL backend
  transactions. The bridge serializes individual wire commands but does
  **not** serialize the held PostgreSQL row locks between commands.
- PostgreSQL uses a **private Unix socket**, never TCP, so this is not
  distributed network failover, multi-host packet-loss or WAN concurrency.
- Artificially discarding a successful HTTP response **simulates** a lost
  client ACK; it is not an independently recorded disconnect or exactly-once
  publication receipt. At-least-once subscription behavior remains unchanged.
- Injecting a host-only `precommit_disconnect=True` after a real SQL UPDATE
  proves transaction rollback on this callback path, **not** cancellation of
  a physical HTTP socket, external subscriber delivery or atomic response/COMMIT.
- The test does **not** run real SSE clients to completion, nor any actual
  independent signed subscriber delivery, consumer effects or target actions.
  It does not prove that an HTTP response and PostgreSQL COMMIT are atomic.
- No production host signing trust, separate IdP, multi-datacenter HA, failover
  or live database cluster is enrolled. Release should remain **NOT READY**
  until those deployment-level witnesses exist.

## Observed focused results — 22 October 2026

- Default without the opt-in environment variable: **1 passed, 1 skipped**.
- With `OSOP_0040_PRIVATE_PG_TWO_REPLICA_RACES=1`: **2 passed** (44.75 seconds).
- Both tests use actual mounted route paths; the opt-in case executes real
  nonroot PG16 transactions using distinct backend PIDs, and the signed
  0009/0014/0040 bootstrap. SQLSTATE `55P03` was observed for the held
  PostgreSQL row lock; lock waits were bounded.

These are **physical SQL connection** results, not proof of independent
machines, multiple worker processes or a production rollout.
