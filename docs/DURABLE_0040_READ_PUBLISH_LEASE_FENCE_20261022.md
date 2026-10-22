# 0040 durable subscriber publication lease/cursor fence — 2026-10-22

**Result:** Original shared backend patched, actual mounted ASGI + private PostgreSQL16 validated. **NOT production-certified or exactly-once client delivery.**

## Demonstrated production bug

`DurableSupervisionSubscriptions.read_batch` previously accepted a signed current replica lease with its earlier `lease.cursor`, then read events strictly after the *current database cursor*. After a prior ACK response was lost, the PostgreSQL cursor could have advanced from 0 to 11 even though the caller still held cursor 0. The old read path would project later events while the mounted `/read` API returned `cursor: 0`. That mismatch could confuse clients into treating a new, already-advanced cursor position as the original batch, rather than requiring explicit ambiguous-ACK recovery. Separately, both `/read` and `/cursor-readback` previously performed a final current bearer/ROE transaction without revalidating the **specific lease** still belonged to the original replica/lease ID/generation. A lease released or replaced between read and final publication could escape that second check.

## Source repair

- `src/ai_osop/memory/durable_supervision_subscriptions.py`: `read_batch` now requires `row.cursor_sequence == lease.cursor` before reading any events and rechecks this current cursor after the bounded event query while holding the same lease transaction. Changed/ambiguous cursors fail closed with `SubscriptionDenied`; use only the existing explicit `read_committed_cursor` recovery route. The fix performs no ACK, replay, Task execution or unrelated mutation.
- `src/ai_osop/api/routers/durable_supervision_subscriptions.py`: after revalidating current signed human/Task/ROE, final PostgreSQL transaction now uses `store._active` on **the same exact request lease**, including revoked/expired/foreign/replaced lease check, and compares cursor to original `body.cursor` for `/read` or first committed `current.cursor` for `/cursor-readback`. Both check a host-observed `request.is_disconnected()` immediately before projecting metadata. No response fields or automatic retries were added.
- The remaining last-PostgreSQL-transaction to ASGI socket-publication window is **not atomic**. `is_disconnected()` is best-effort; even HTTP 200 can be lost after commit, and a later revocation can race after the final check. Only committed cursor readback can disambiguate PostgreSQL state, never client receipt. Existing `/ack` precommit-disconnect and 0014 revocation table fencing remain unchanged.

## Actual qualification

`tests/qualification/test_0040_read_publish_live_lease_20261022.py` uses the existing explicit `OSOP_DURABLE_MOUNTED_ACTUAL_PG16=1` private nonroot Unix-only WSL PostgreSQL16 fixture with real migration 0009/0014/0040 tables, mounted FastAPI and real SQLAlchemy transaction paths, synthetic test-only Ed25519 signed current ROE/JWT. It acquires an owned lease at cursor zero, commits ACK to 11, then deliberately reuses the old lease cursor. **Mounted `/read` returns 409**, not a misleading success. Explicit `cursor-readback` returns the actual committed 11, reports client-ACK-delivery false and unknown-ACK retry unsafe; `/read` with that current lease succeeds and only includes events after sequence 11 belonging to that tenant. No external provider, target, app database, Docker, cloud API, native scanner or real keys were accessed.

**Observed:** focused store and mounted synthetic ASGI selection **31 passed, one optional PostgreSQL test skipped** by default; earlier 0040 private-PG mounted readback + new test first ran **2 passed/1 failed** solely due a test assumption that there were no later fixture events. The corrected test now checks strict monotonic tenant-bound sequencing, and a new **single-test private-PG16 run passed in 27.19 seconds**. Black formatting and scoped `git diff --check` were applied to edited files.

Remaining production work: independent physical multi-host lease and event-order qualification, current real signer enrollment, client disconnect/crash/reconnection ambiguity under host network failures, and authenticated real target owner/senior release. **Do not** equate local PostgreSQL COMMIT or any synthetic JWT with client delivery or production approval.

**FINAL CURRENT RELEASE DECISION: NOT PRODUCTION CERTIFIED / NOT READY.**
