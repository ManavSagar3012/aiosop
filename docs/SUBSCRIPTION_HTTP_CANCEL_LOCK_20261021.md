# 0040 subscription ACK — bounded HTTP cancellation versus real PostgreSQL lock

**Date:** 2026-10-21  
**Owned test:** tests/qualification/test_subscription_http_disconnect_lock_20261021.py  
**Release decision:** No claim that a cancelled client, delivered ASGI disconnect, or a lost HTTP ACK implies PostgreSQL rollback. No exactly-once or production-root certification.

## Environment and isolation

The new test reuses worker33's mounted_real and private_pg fixtures. The actual mounted main.app ACK route and worker42's original store SQL run against an independent **nonroot PostgreSQL16** server with an owner-private 0700 Unix socket and TCP disabled. It uses minimal fixture-created session/Task/event parent tables plus actual 0009/0014/0040 migrations. JWT and Ed25519 ROE are signed by **test-only roots**, not independently enrolled production issuers. The inherited fixture substitutes a real-SQL minimal parent lookup for the full supervision ORM. No app DB, Docker, Git, real target or provider is touched.

The in-process HTTP experiment cancels an httpx ASGITransport request task; this is **not** an actual browser TCP disconnect. The separate raw ASGI experiment injects an actual **http.disconnect** message through the receive callable while the ACK SQL transaction is paused. That delivers an ASGI notification, **not** a real network FIN/RST or reverse-proxy event.

Both tests pause immediately after the genuine PostgreSQL cursor UPDATE succeeds, before its transaction commits. An independent PostgreSQL session queries pg_stat_activity and probes the subscriber row with FOR UPDATE NOWAIT. The test tags its own session and applies local idle-in-transaction timeout 3500ms, statement timeout 2500ms, and lock timeout 1000ms. Its cleanup always opens the gate, restores the original factory, explicitly attempts ROLLBACK and disconnect on only the tagged fixture session, and confirms the row lock is released.

## Exact evidence

| Experiment | Observation |
| --- | --- |
| Final safe default | **1 passed, 2 skipped in 9.65s**; syntax compilation passed, no PG instance |
| First opt-in client task cancellation | Actual UPDATE reached; adapter entered and finished its exit with CancelledError; PostgreSQL had no open transaction or row lock after cancellation; cursor remained 0 |
| Repeated opt-in client task cancellation | Actual UPDATE reached, adapter exit started and finished with recorded CancelledError; **before forced cleanup**, pg_stat_activity showed an open transaction and FOR UPDATE NOWAIT confirmed a held row lock; fixture-owned forced ROLLBACK/disconnect released it; cursor remained 0 |
| First ASGI http.disconnect message test | receive delivered disconnect 4 times; app produced HTTP 200 response frame, **cursor 11 committed**, no remaining row lock |
| Repeat ASGI http.disconnect message test | Same: 4 disconnect receive calls, HTTP 200 response frame, cursor 11 committed, no open transaction or lock |
| Final expanded opt-in suite | **3 passed in 47.72s**; isolated repeat ASGI signal **1 passed in 28.92s**. These passing tests contain explicit negative observations, not a disconnect-rollback guarantee |

The nondeterministic task-cancellation result is an observed **fixture adapter cleanup race**, not a verified production SQLAlchemy AsyncSession defect. The worker33 fixture's PgSession.__aexit__ in tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py (lines 360–366 at review) awaits asynchronous thread delegation for rollback and disconnect without cancellation shielding. A cancelled waiter may stop before cleanup is durably confirmed; this is consistent with the one stranded session observed. The test itself explicitly closed only its owned session. Full production engine cancellation is **not** certified.

The second result concerns the actual mounted ASGI route under simulated ASGI disconnect. Delivering http.disconnect does **not** necessarily cancel the handler or prevent the database ACK commit. A generated 200 response frame does **not** prove a disconnected client received it. Thus a human cannot infer rollback from network loss, and blindly retrying the same optimistic ACK is unsafe. The UI's existing UNKNOWN handling and independent readback remain essential.

## Minimal suggested follow-ups — **not implemented by worker32**

1. **Fixture cleanup:** In tests/qualification/test_durable_subscriptions_mounted_actual_pg_20261021.py, PgSession.__aexit__ around lines 360–366, ensure rollback plus disconnect run in a dedicated bounded cleanup task shielded against asyncio cancellation. On cancellation, await that cleanup to finish before re-raising; if the underlying connection is unavailable, close only the fixture-owned connection and report the result UNKNOWN. Worker33 owns that file.

2. **Best-effort production disconnect guard:** In src/ai_osop/api/routers/durable_supervision_subscriptions.py, acknowledge around lines 482–507, and src/ai_osop/memory/durable_supervision_subscriptions.py, _transaction around lines 159–189 and acknowledge, consider passing a **server-supplied, bounded** request.is_disconnected check into the ACK transaction. Check it immediately before COMMIT **after** current revocation/ROE revalidation; if disconnected, raise a denial to roll back. A single route check prior to the store call cannot close the post-UPDATE window. Do not accept a client-controlled proof of connection or bypass existing authorization.

   This is **best effort only**: disconnect can race the final check/commit; Request.is_disconnected behavior depends on ASGI server/transport; a lost response never proves whether COMMIT happened. Even after an improvement, cursor CAS, replica fencing, independent durable readback and UNKNOWN/no-blind-retry handling remain necessary. Independently test real SQLAlchemy AsyncSession, server network disconnect and postcommit result before claiming a production fix or exactly-once delivery.

## Commands

Safe default:

~~~powershell
.venv\Scripts\python.exe -m pytest tests/qualification/test_subscription_http_disconnect_lock_20261021.py -q -o addopts='' -rs
~~~

Opt-in disposable PG16:

~~~powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_DURABLE_MOUNTED_ACTUAL_PG16']='1'; raise SystemExit(pytest.main(['tests/qualification/test_subscription_http_disconnect_lock_20261021.py','-q','-s','-o','addopts=','--tb=short']))"
~~~

No original source, router, migration, worker33/42 fixture, main, UI or application infrastructure was modified.
