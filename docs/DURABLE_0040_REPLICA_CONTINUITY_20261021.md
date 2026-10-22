# 0040 durable subscriptions — real PostgreSQL replica continuity

**Date:** 2026-10-21  
**Only new qualification:** tests/qualification/test_0040_replica_continuity_20261021.py

## Measured results

**Opt-in private PostgreSQL16: 2 passed in 35.90 seconds.**  
**Safe default: 1 passed, 1 skipped in 0.90 seconds.** Python compilation passed.

This new test exercises the **actual worker42 DurableSupervisionSubscriptions SQL operations** with multiple independently connected psycopg3 async sessions and real PostgreSQL transactions. It focuses on lost-ACK recovery, genuine lease expiry, replica replacement, fresh-store reconnect and cancellation while holding a real row lock. It does not re-execute the earlier comprehensive basic 0040 race and schema tests.

## Isolation

The test boots a fresh **nonroot PostgreSQL16** cluster under a uniquely named temporary owner-only directory. The server has no TCP listener (listen_addresses empty) and a Unix socket with 0700 permissions. The test checks that it is PostgreSQL16 and that the socket exists. The exact owned server is stopped in a finally block and its temporary files removed. No application DB, Docker, external service, scanner, provider, target or Git operation is involved.

Only helper *definitions* are reused from tests/qualification/test_0040_subscription_live_transactions_20261021.py. **No old test cases or existing cluster are executed or reused.** The checked-in 0014 and 0040 Alembic upgrade functions run on minimal synthetic session, Task and event parents. This does not qualify the complete application migration history.

WSL Linux can access the existing pure-Python SQLAlchemy/Alembic/psycopg libraries but lacks a compatible Linux greenlet binary. The test therefore adapts the actual store's unchanged SQLAlchemy text statements through the real PostgreSQL pyformat compiler to independently connected **genuine psycopg AsyncConnection transactions**. The adapter binds a real PostgreSQL SQLAlchemy Engine, so the worker42 READ COMMITTED and revocation-table SHARE NOWAIT guard genuinely executes. This is not a fake SQL interpreter or full SQLAlchemy AsyncSession qualification.

Identity and ROE guard callbacks are controlled synthetic **fixtures**, not independently enrolled/verified signing roots. The credential fixture does query actual 0014 PostgreSQL subject-control rows. Thus database/store continuity is qualified, not deployed authentication.

## New continuity observations

| Scenario | Actual result |
| --- | --- |
| Separate active PG clients | Two simultaneous async PostgreSQL sessions report distinct backend PIDs |
| Initial lease | Replica A obtains a named subscriber at generation 1 with real five-second lease |
| Competing same-subscriber replica | Replica B cannot acquire while A's lease is current |
| Event producer | A separate committed PostgreSQL transaction inserts a scoped event under the original producer's per-tenant advisory lock |
| Lost ACK result | Replica A's store ACK commits, but its return value is discarded to simulate a lost response; independent PostgreSQL readback shows advanced cursor |
| Duplicate ACK after lost result | Old cursor/lease ACK replay is rejected; next read excludes the acknowledged event |
| Real expiration | Test waits for the actual PostgreSQL lease_until timestamp (no artificial expiry UPDATE); replica B then acquires at **generation 2** with preserved cursor |
| Old lease fencing | Replica A cannot read or renew with previous generation/lease ID |
| New-store reconnect | Fresh store object and new database sessions see the correct durable cursor without restoring old in-memory subscriber state |
| Real ACK row lock | Worker42's genuine UPDATE runs without committing; different PG backend gets SQLSTATE **55P03** when attempting FOR UPDATE NOWAIT on the same row |
| Server task cancellation | Cancelling holder before commit releases its row lock and rolls back cursor; separate readback confirms original cursor |
| Resumed ACK | New store explicitly reads the next event after verified rollback and commits that next cursor; duplicate ACK is rejected |

Per-connection PostgreSQL limits include idle_in_transaction_session_timeout=7 seconds, statement_timeout=4 seconds and lock_timeout=2 seconds, plus bounded task cancellation and outer scenario timeout. An outer finally block stops the test-owned PostgreSQL instance.

## Limits and release interpretation

**This is NOT a production end-to-end certificate.** A replica is a distinct logical worker/store instance and a different real PostgreSQL backend, not a physically separate machine. No process crash was induced; lease expiration used the real PostgreSQL clock. The lost ACK was simulated by discarding the committed store return value, not by breaking a real HTTP connection. Server-side cancellation while holding a database row lock is not the same as client HTTP disconnect; the earlier SUBSCRIPTION_HTTP_CANCEL_LOCK_20261021.md documents that an ASGI disconnect signal can precede a valid committed ACK.

The test does not demonstrate actual signed JWT/ROE issuer enrollment, mounted ASGI delivery, successful browser receipt, execution or provider/target effect, or exactly-once event semantics. Lost response remains UNKNOWN until independent durable readback; automatic blind replay is unsafe.

## Run

Default safe mode:

~~~powershell
.venv\Scripts\python.exe -m pytest tests/qualification/test_0040_replica_continuity_20261021.py -q -o addopts='' -rs
~~~

Explicit opt-in fresh nonroot PostgreSQL16:

~~~powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_0040_REPLICA_CONTINUITY_PG']='1'; raise SystemExit(pytest.main(['tests/qualification/test_0040_replica_continuity_20261021.py','-q','-o','addopts=','--tb=short','-rs']))"
~~~

The opt-in path fails closed when the required nonroot PostgreSQL16 runtime is absent. The only changed paths are the two **new** replica-continuity test and document files.
