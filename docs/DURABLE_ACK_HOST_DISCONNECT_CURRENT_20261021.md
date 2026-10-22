# Mounted 0040 ACK — host-only precommit disconnect recheck (2026-10-21)

**Release decision remains NOT PRODUCTION CERTIFIED / NOT READY.** This is a bounded best-effort mitigation for a confirmed ASGI disconnect-to-commit gap, not a transactional or physical client-receipt guarantee.

## Reproduced failure before correction

Worker32's separate original `tests/qualification/test_subscription_http_disconnect_lock_20261021.py` used the *actual mounted* `/supervision/engagements/{id}/subscriptions/{id}/ack` FastAPI handler, original 0040 store SQL, fixture bearer/Ed25519 signed ROE and genuine disposable nonroot Unix-only PostgreSQL16 (`0009`/`0014`/`0040` actual migrations, minimum predecessor parents). With `http.disconnect` delivered after genuine cursor UPDATE but before COMMIT, the application twice returned an **ASGI HTTP 200 frame** and committed cursor=11 despite a lost client. A frame is not proof that the client received ACK. Separately, cancelling the in-process httpx request task sometimes stranded only the custom test SQL adapter's PG transaction until explicit fixture-owned bounded rollback/disconnect. This does **not** prove a production SQLAlchemy AsyncSession cancellation defect.

## Implemented actual reachable admission fix

- `src/ai_osop/memory/durable_supervision_subscriptions.py`: the original `_transaction` accepts a **host-only optional** `precommit_disconnect` async callable for ACK. Following the complete cursor UPDATE, tenant/Task/lease/CAS fence, SQL `SHARE MODE NOWAIT` 0014 revocation table lock and second current signed bearer/ROE check, the callback runs under a **0.5-second time bound** and denies/rolls back when disconnected, erroring, timing out or returning a nonboolean. Other lease/read/revoke operations retain their existing signature and checks. The external HTTP body may not carry this callback, a fake connection flag or a waiver.
- `src/ai_osop/api/routers/durable_supervision_subscriptions.py`: the mounted ACK route supplies only a closure over its **own** FastAPI `Request`. Its `_host_ack_disconnected` first invokes Starlette's normal `is_disconnected` and, if this returns false, briefly polls the **post-body ASGI receive channel** (50ms) to catch a queued disconnect missed by Starlette's immediately-cancelled nonblocking receive probe; unexpected further body messages fail closed. This optional second poll is safe only because the strict earlier bounded route handler already consumed the original POST body. No client request parameter can supply the callback or unlock an action.
- `tests/test_durable_ack_disconnect_precommit_20261021.py`: imported real store+router tests with simulated transactional PostgreSQL check final ordering (`authorize` → revocation fence → `authorize` → HTTP disconnect), rollback on disconnected/failed/nonboolean/timeout, original single next-event ACK on healthy host and source probe's missed-queued-message fallthrough. This is **fake PG** testing, distinct from the genuine opt-in result below.

## Genuine private PostgreSQL follow-on — negative outcome narrowed

The same worker32 opt-in source, re-run after the *first* naïve `request.is_disconnected` callback, still returned **3 PASS**, but critically observed `http.response.start: 200`, **cursor=11 committed**, despite `http.disconnect` being delivered. Thus using `request.is_disconnected` **alone did not fix the actual scenario**. That failed outcome was not promoted to release evidence.

After adding the bounded post-body host ASGI receive check and retaining the exact same original test and disposable PG16 adapter, opt-in command:

~~~powershell
.venv\Scripts\python.exe -c "import os,pytest; os.environ['OSOP_DURABLE_MOUNTED_ACTUAL_PG16']='1'; raise SystemExit(pytest.main(['tests/qualification/test_subscription_http_disconnect_lock_20261021.py','-q','-s','-o','addopts=','--tb=short']))"
~~~

**Actual result: 3 passed in 43.74 seconds, exit 0.** The raw ASGI disconnect test recorded **6 delivered disconnect receives, `http.response.start: 409`, cursor 0, no open transaction and no row lock**. The in-process client-task cancellation still recorded `CancelledError`, a sometimes-open custom fixture backend transaction before its bounded explicit rollback/disconnect, and cursor=0. This is a real PostgreSQL transaction result for the ASGI signal, *not* a browser TCP FIN/RST or deployed multi-replica result.

## Inherent limits

The host can disconnect **after this last 50ms poll and before COMMIT or network publication**, so a lost HTTP result is always `UNKNOWN` until independently read back; do not retry the old exact optimistic ACK automatically. This check cannot prove a client rendered an event, an SSE frame was delivered, a remote process stopped, or a provider/target owner observed an effect. Fixture JWT and ROE keys are ephemeral, the SQL bridge is Windows/WSL-specific and the full production SQLAlchemy engine, enterprise IdP, two deployed API hosts and exactly-once network semantics are **not** qualified. Any real production release still requires independent original target-owner effects, multi-replica qualification and separately signed senior approval.
