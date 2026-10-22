# 0040 durable supervision subscriptions — real transaction qualification

**Date:** 2026-10-21  
**Test:** `tests/qualification/test_0040_subscription_live_transactions_20261021.py`  
**Scope:** Actual worker42 `DurableSupervisionSubscriptions` SQL executed against one owned, fresh PostgreSQL 16 instance. This is a database/store qualification, **not** a mounted ASGI or deployed-signer qualification (worker33 owns the former).

**Measured latest opt-in execution:** `2 passed in 26.24s` using the real isolated PostgreSQL 16 instance, including the newer 0014 NOWAIT guard and an absent subject row. See commands below; default no-opt-in runs only the schema/source contract and skips the database test.

## Isolation and reproducibility

The opt-in test starts nonroot PostgreSQL16 from the existing WSL Ubuntu installation using `initdb` and `pg_ctl`. Its data and log directories live under a temporary 0700 directory; TCP listening is disabled (`listen_addresses=''`), and the only server socket is the owned `.s.PGSQL.<port>`. The test verifies two distinct live backend process IDs and uses independently connected PostgreSQL sessions. It cleans up by stopping the exact owned cluster and removing its temporary files.

The only schema predecessors are test-controlled `session_states`, `tasks`, and `supervision_events`. **Actual Alembic `0014.upgrade()`** creates operator token-revocation and subject-control tables; **actual Alembic `0040.upgrade()`** creates the durable subscriber table. These are checked-in functions invoked under real PostgreSQL transactions, but **the intervening application migration history is not executed**. Event producer rows are written by the qualification using the same per-tenant `pg_advisory_xact_lock(hashtextextended(engagement, 8044))` as the real producer; this does not execute the full supervision command/outbox path.

This Linux installation can import SQLAlchemy, Alembic and psycopg's existing pure-Python distribution through the Windows project `.venv`, but lacks a usable Linux `greenlet` compiled extension. For that reason, the test **does not claim to use SQLAlchemy AsyncSession**. Instead a small test-owned adapter gives worker42's unmodified store methods actual asynchronous psycopg3 connections and transactions; every original SQLAlchemy `text()` statement is compiled using SQLAlchemy's real PostgreSQL pyformat dialect, and its result shape is adapted. This is **real SQL executed by the real store** against real PostgreSQL, not a simulated SQL interpreter. Its `db.bind` is the genuine PostgreSQL SQLAlchemy Engine, so the production PostgreSQL-dialect guard does not short-circuit.

## Actual database behaviors covered

| Scenario | What is exercised |
| --- | --- |
| Concurrent subscribe and lease acquire | Independent store objects and backends race the same tenant/subscriber primary key; exactly one obtains an active lease; the loser is denied |
| Tenant/Task isolation | Same subscriber identifier can exist under a different engagement without sharing cursor; cross-tenant Task and wrong owner are denied |
| Producer event sequencing | Real committed JSONB event rows, interleaved foreign-tenant and foreign-Task events; the scoped read returns only the proper Task's ascending sequences |
| Actual acknowledge/cursor CAS | Skipped/forged event ACK and stale duplicate ACK denied; cursor advances one next eligible committed event at a time |
| Advisory serialization | One producer holds the per-tenant advisory lock on an uncommitted event; ACK cannot complete before producer commit, then succeeds |
| Producer rollback | Inserted but rolled-back event remains unacknowledgeable; cursor unchanged |
| Auth changed before transaction commit | Controlled identity guard rejects the second check after an ACK UPDATE; PostgreSQL rolls back the cursor UPDATE |
| Replica recovery | Real release increments generation; new store instance acquires preserving cursor, while old owner cannot read/renew/release |
| Crash/expiry emulation | A test-only SQL operation backdates an abandoned lease's expiration; replacement owner advances generation and fences the old handle |
| Revocation/lease interleavings | Revoke races renew; separately, revoke races another store's `INSERT ON CONFLICT DO NOTHING`/acquire; a permanent tombstone wins and prevents future ownership |
| Independent ROE/credential state | Fixture ROE and identity callbacks deny post-revocation mutation |
| Absent-row 0014 revocation window | Genuine uncommitted token/subject revocation writer acquires PostgreSQL ROW EXCLUSIVE lock; worker42's final `SHARE NOWAIT` check refuses to commit; after revocation commits, the transaction's credential fixture sees it |
| Lock acquired before writer | During worker42's final check, a true PostgreSQL `SHARE NOWAIT` table lock blocks otherwise valid inserts into both 0014 tables (including absent digest/subject), returning SQLSTATE `55P03` on a separate writer with a 400ms lock timeout |

Both the initial current principal check and the post-update check read PostgreSQL through the **same active transaction**. The `READ COMMITTED`/table-`SHARE NOWAIT` fence is materially different from just checking for an absent revocation row with `SELECT FOR SHARE`: an absent row cannot be row-locked, so the table lock serializes a concurrent revocation insert. Writer contention is denied; no app-level retries or fabricated successful acknowledgements occur.

## Exact security and test boundaries

The credential callback here is **not** an enrolled signed JWT or other independently verified bearer. It is a controlled fixture checking test-only identities, plus the actual PostgreSQL 0014 token/subject revocation rows inside the active transaction. The ROE callback is also a **test fixture** returning authority for fixed engagement/version/digest values; it does **not** verify a cryptographically signed live ROE. Accordingly these results do not qualify certificate/root enrollment, JWT verification, end-to-end revocation signature provenance, deployed ASGI identity, production multi-instance SSE delivery, remote replicas, a real container crash, or external target/provider effects.

The crash-recovery case tests database lease-expiry fencing **by backdating a fixture row** rather than killing a deployed process. A producer ACK means the store durably changed its cursor, not that an independent client received a stream event. Delivery remains at-least-once, and no exactly-once claims are made. Concurrency coverage is targeted; it is not a formal proof against every race or transaction isolation configuration.

No production source, router, migration, other tests, application DB, Docker environment, provider, external target, or Git state was modified by this qualification.

## Running

Safe default:

~~~powershell
.venv\Scripts\python.exe -m pytest tests/qualification/test_0040_subscription_live_transactions_20261021.py -q -o addopts='' -rs
~~~

Explicit opt-in:

~~~powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_0040_SUBSCRIPTION_LIVE_PG']='1'; raise SystemExit(pytest.main(['tests/qualification/test_0040_subscription_live_transactions_20261021.py','-q','-o','addopts=','-rs']))"
~~~

Without WSL Ubuntu's nonroot PostgreSQL16 binaries or existing compatible Python dependencies, the opt-in test fails closed instead of using an application database or inventing a positive result.
