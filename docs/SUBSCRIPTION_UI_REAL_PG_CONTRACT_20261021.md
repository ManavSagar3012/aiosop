# Human UI manual-ACK API contract — private PostgreSQL16

**Date:** 2026-10-21  
**Test:** tests/qualification/test_subscription_ui_api_real_pg_contract_20261021.py

**Final measured results:** opt-in private PostgreSQL16 with mounted actual routes: **3 passed in 47.43s**. Default no-database execution: **1 passed, 2 skipped in 11.09s**. Python syntax compilation passed. No worker33 generic test cases were invoked in either run.

## Independent scope

The qualification uses the actual newly mounted main.app durable-supervision router and the production TypeScript UI service and panel source. It reuses worker33's private nonroot WSL PostgreSQL16 fixture rather than recreating its startup/schema or repeating its generic tests. The fixture starts and stops PostgreSQL over an owner-only Unix socket with TCP disabled, and invokes the real 0009/0014/0040 Alembic upgrades against minimal synthetic session/Task/event parents. The in-process HTTP client exercises the real mounted endpoint, actual JWT verification, signed ROE, PostgreSQL transaction store, and response envelopes.

JWTs are HS256 signed with a **test-only** key; Ed25519 ROE is signed under a **test-only** root enrolled only into this disposable qualification. They are not real independently enrolled production signers. The full supervision ORM is not migrated here; worker33's controlled predecessor-store adapter uses real PostgreSQL SQL to verify engagement/Task ownership. No UI browser rendering, production SSE stream, external target or real LLM/provider is exercised.

## New UI-specific checks

| Boundary | Exact tested behavior |
| --- | --- |
| UI acquire request | POST body contains replica_id and task_id only |
| UI read request | POST body contains replica_id, lease_id, generation, cursor, task_id, and limit=20 |
| UI manual ACK request | POST body contains the original binding plus expected_cursor equal to the read cursor and next_sequence equal to the **first displayed event** |
| Server-only lease authority | The UI does not submit lease_until or any signed authority in the body; the mounted API returns exact engagement/subscriber/replica/generation/cursor, expiry, at_least_once semantics and unobserved provider effect |
| UI identity/readback | Response engagement/subscriber and immutable lease values match the originally signed tenant scope; Cache-Control is private/no-store; an unrelated subject, other tenant and foreign senior cannot reuse the lease |
| Read is not ACK | Mounted read returns committed tenant/Task events in order with acknowledged=false; an independent PostgreSQL cursor read remains unchanged |
| Replicas and duplicate optimistic ACK | Second replica acquisition for the same named subscriber fails; first explicit ACK advances exactly one eligible event, a repeated old-cursor ACK fails, skipped and inconsistent ACKs fail |
| Second read | Begins after the committed cursor and remains unacknowledged; original lease ID, generation and replica ID are preserved |
| Server-side cancellation rollback | Test-owned session injects asyncio.CancelledError immediately **after actual PostgreSQL cursor UPDATE but before commit**; mounted request cannot claim success; independent readback verifies cursor remains unchanged |
| Revocation after signed bearer | After a valid fixture JWT and real fixture-signed ROE have been checked at the mounted router, a test-owned seam inserts an 0014 token digest or disables a subject in **real private PostgreSQL**; worker42 ACK is denied, original cursor retained and later read denied |

The same-subscriber replica requests and optimistic duplicate ACKs are submitted **sequentially**. Worker33's stdio bridge multiplexes client sessions through a single synchronous command dispatcher: truly concurrent duplicate INSERT waits on an uncommitted row and deadlocks the test bridge before the winning transaction can COMMIT. That limitation was observed in an initial failed attempt, and is not attributed to production PostgreSQL. Earlier direct-psycopg real-store qualification separately exercised simultaneous SQL CAS races. This task is specifically about the new UI/manual-ACK HTTP request format and readback identity.

## Important negative finding — browser task cancellation

An initial experiment cancelled the **client-side in-process HTTP task** while the test was artificially holding the server after a real UPDATE. The server transaction remained open, holding the subscription row lock and delaying a later HTTP readback. The temporary PG session was forcibly terminated **only within this fixture-owned disposable PostgreSQL instance** to release the lock. This is a **failed qualification** of client-disconnect rollback; it must not be reclassified as a pass. Cancelled browser fetch or a lost HTTP response **does not prove the server-side transaction rolled back**.

The revised successful test is deliberately narrower: it raises CancelledError **inside the server-side database session**, after the genuine SQL UPDATE, and confirms actual PostgreSQL rollback before any subsequent independent ACK. This qualifies server-observed cancellation rollback only, not all HTTP disconnects or lost acknowledgements. The UI correctly clears optimistic local state on an unknown mutating outcome and requires independent readback instead of blindly retrying. No exactly-once stream delivery or physical execution receipt is claimed.

## Commands

Safe default (database cases skipped):

~~~powershell
.venv\Scripts\python.exe -m pytest tests/qualification/test_subscription_ui_api_real_pg_contract_20261021.py -q -o addopts='' -rs
~~~

Explicit isolated PostgreSQL16:

~~~powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_DURABLE_MOUNTED_ACTUAL_PG16']='1'; raise SystemExit(pytest.main(['tests/qualification/test_subscription_ui_api_real_pg_contract_20261021.py','-q','-o','addopts=','-rs']))"
~~~

No existing migration, worker33/42 file, main router, production source, app DB, Docker, provider, scanner, external target or Git state was edited by this work.
