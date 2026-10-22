# Native inert six-Go operator API — disjoint mounted-ready integration

**Date:** 2026-10-21  
**Original shared dirty repository:** `/burp_mcp/ai-osop`  
**Verdict:** API/router built and ASGI qualified; **the prime independently mounted it in `main.py` and added the lifespan shutdown hook** during this worker's qualification. **No host executable pins were installed here, no genuine Go PIDs were started by this test, and production is not certified.**

## Delivered (NEW FILES ONLY)

| File | Responsibility |
|---|---|
| `src/ai_osop/api/native_inert_fleet_control.py` | Host-only immutable six-pinned authority installation, serialized start/status/stop, cancellation-aware cleanup, process-safe generic state, explicit host shutdown hook |
| `src/ai_osop/api/routers/native_inert_fleet.py` | Existing `require_role("senior_operator")` signed-JWT guard, exact-body rejection, no query credentials, loopback/HTTPS transport fence; three independently mountable routes |
| `tests/qualification/test_native_inert_fleet_operator_api_20261021.py` | Real mounted-in-fixture FastAPI router + production signed local JWT dependency; isolated fake process backend without starting Go or using application DB |
| `docs/NATIVE_INERT_OPERATOR_MOUNT_20261021.md` | Deployment hook, test evidence, limitations and security gaps |

**This worker made no changes** to `main.py`, `system.py`, `protocol.py`, `native_inert_process_fleet.py`, prior tests, the frontend, workers, Go SDK, app databases, Docker, Git or any target. The prime concurrently edited its exclusively owned `main.py` to include the new router and call the shutdown hook.

## Precise senior-only HTTP contract

The router is `ai_osop.api.routers.native_inert_fleet.router`. The prime has now explicitly mounted it using `app.include_router(native_inert_fleet.router)`; the three endpoints are:

| Verb and path | Behavior (signed senior JWT required for every request) |
|---|---|
| `GET /system/native-inert-fleet/status` | Bounded, nonsecret process lifecycle projection; if independent host pins have **not** been provisioned, returns `host_unconfigured`, no PID claims |
| `POST /system/native-inert-fleet/start` | Explicit opt-in all-six start with *only host-supplied* reviewed binary SHA pins; no client payload; fails 503 before process construction if configuration/env authority absent |
| `POST /system/native-inert-fleet/stop` | Explicit stop/cleanup of only the supervisor-owned Popen handles; permanently closes this configured lifecycle, no auto restart or Action replay |

The routes depend on the existing `require_role("senior_operator")` and `verify_token` from `api/deps.py`: production-signed local HMAC JWT or validated, optionally introspected OIDC senior operator claims are required. An ordinary `operator`, `viewer`, expired/forged JWT, shared development API token and revoked senior token cannot trigger a process. When the existing durable operator revocation setting is mandatory, missing current revocation DB fails closed. The senior gate executes **before** any process method.

Additional route constraints: only numeric-loopback HTTP peer or HTTPS; exactly one bearer Authorization header; no URL query parameters, browser `Origin`, request body, content-type configuration, URL-provided path/port/target/key, or arbitrary service selection. A successful result includes only the six fixed Go service IDs and whether host-local inert PID/socket evidence was observed — **never executable paths, port values, PIDs, sha256 pins, signer credentials, original grant claims, targets or provider JSON.** FastAPI response has `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Errors are generic/sanitized; no exception/stderr/credential contents.

The only positive lifecycle is `running_inert_unavailable`. All responses explicitly set `mcp_initialized=false`, `signed_0033_witness_verified=false`, `native_target_execution_enabled=false`, `target_effect_verified=false`, `automatic_action_retry_authorized=false` and `production_certified=false`. `running_inert_unavailable` is **not** MCP READY and should never turn service pins green on an effect/authorization dashboard.

## Exact trusted host hook required from the prime

Importing the router or adding it to the FastAPI app is harmless: **no binaries are inspected and no subprocesses are launched**. There is intentionally **no HTTP endpoint** to upload, list, replace or select binary paths, SHA pins, signing roots, destinations or ports. No arbitrary environment JSON is parsed for those fields. The prime already added `app.include_router` and the shutdown helper call in `main.py`; **independent host authority injection remains intentionally absent**, so the senior `/start` endpoint still fails closed without it. The only way to make `start` available is a separately authorized **host bootstrap call**:

```python
from pathlib import Path
from ai_osop.api.native_inert_fleet_control import (
    HostInertFleetAuthority,
    install_host_native_inert_fleet_control,
    shutdown_host_native_inert_fleet_control,
)
from ai_osop.api.routers import native_inert_fleet
from ai_osop.mcp.native_inert_process_fleet import VerifiedGoBinary

# Prime-owned / reviewed application wiring, NOT implemented in this worker.
app.include_router(native_inert_fleet.router)

# Separately privileged host bootstrap (never from incoming request, from
# user-provided JSON, or imported automatically):
# pins = {exact_service_name: VerifiedGoBinary(
#     path=independently_reviewed_absolute_offline_exe,
#     sha256=independently_reviewed_lowercase_sha256) for all six}
# install_host_native_inert_fleet_control(
#     app, HostInertFleetAuthority(
#         build_root=independently_verified_absolute_build_directory,
#         binaries=pins,
#     ),
# )

# On the same app instance's *actual* lifespan shutdown, once the operator
# has installed the control, call:
# await shutdown_host_native_inert_fleet_control(app)
```

At request time, senior `POST /start` still requires `OSOP_NATIVE_INERT_PROCESS_FLEET_OPT_IN=1` from the **host operator**; the constructor must also receive its own `operator_opt_in=True` (the controller supplies it only after senior JWT and host-configuration checks). This is not an automatic startup setting. **Do not enable it in default environment or public deployment.**

`install_host_native_inert_fleet_control` validates a complete six-name mapping, absolute build root, service-matching absolute executable paths and lowercase SHA-256 pins, and makes a host-owned copy rather than trusting later mutation of the caller's dict. The lower-level **existing** `NativeInertProcessFleet` independently checks trusted directory/non-reparse boundaries, pinned SHA against executable bytes, PE header, correct Go `go version -m` identity, OS-only reduced child environment, ephemeral numeric-loopback socket/PID/owner identity and exact HTTP 503 inert health *before returning success*. No production Go compilation occurs; the operator supplies already built binaries. If the reviewed binary provenance or host configuration is absent, leave `/start` denied.

The control is one-shot per **app process**. `asyncio.Lock` serializes concurrent start/status/stop; duplicate start returns denial. It calls bounded synchronous owner lifecycle methods in a thread, **waits for outstanding process operation on HTTP cancellation**, and performs explicit cleanup before marking an unacknowledged or invalid start `unknown_closed`. A stopped/unknown lifecycle cannot be restarted remotely. Host shutdown must call `shutdown_host_native_inert_fleet_control(app)` from the app's existing lifespan because relying on unmounted or deprecated FastAPI shutdown events could leave children alive.

## Actual isolated test results

The test creates a fresh FastAPI app with **the real new router and the real production JWT verification dependency**, signed local HS256 JWTs with synthetic offline secrets, and a `NativeInertProcessFleet` **fake only at the OS/subprocess boundary**. It does **not** touch app DB, Docker, network providers, owned real binaries or remote targets.

The adversarial suite covers:

- Missing host config: senior `status` returns `host_unconfigured`; `start`/`stop` deny and no process is instantiated.
- Signed non-senior viewer/operator, shared dev token, absent bearer, expired JWT, wrong signing key and malformed bearer never construct the fleet.
- Existing operator revocation ledger set to revoked, or to current-DB unavailable, denies a senior JWT before any child construction.
- Body and Content-Type injection of custom binary/path/port/target, URL query parameters, nonloopback plaintext HTTP, browser Origin and duplicate Authorization headers all deny before process construction.
- Valid senior/operator-host configuration and dual opt-in returns six **redacted** observed inert processes, never PID/port/pin/target values; status works; explicit stop closes; concurrent/duplicate starts never run twice, and closed state cannot be restarted.
- A forged fake process report claiming verified target effect is rejected and leads to cleanup/UNKNOWN, never to signed authority or report promotion.
- Internal start error is redacted; a cancelled start waits for the worker and stops the owned fleet rather than leaving six subprocesses after a lost response; explicit host shutdown hook closes only its owned fleet.
- Host install rejects missing/extra/misnamed/relative or altered digest records; caller dict mutation cannot change already installed authority.

Reproduce from the original project using its virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_native_inert_fleet_operator_api_20261021.py -q --tb=short
.\.venv\Scripts\python.exe -m black --check src/ai_osop/api/native_inert_fleet_control.py src/ai_osop/api/routers/native_inert_fleet.py tests/qualification/test_native_inert_fleet_operator_api_20261021.py
```

**Observed (ASGI focused): 24 passed in 7.53s**, exit 0. In addition to the 23 isolated-router cases, the new final test imports the **actual current mounted `ai_osop.api.main.app`** with lifespan disabled, verifies exactly one registration of each route, and confirms that an ordinary signed `operator` JWT cannot start a process on the real mounted app (HTTP 403, zero process constructions). The tests use synthetic signed JWTs and mock process objects; **no actual Go processes are launched**. Previously existing `tests/test_native_inert_process_fleet_20261021.py` qualifies the lower-level process class only with separate opt-in; do not count its real child test as exercised by this worker. The route mount does not demonstrate independent 0033 source signature or deployment readiness.

**Final adjacent regression after prime's actual main mount:** The new API qualification plus the existing `tests/test_native_inert_process_fleet_20261021.py` returned **`62 passed, 1 skipped in 15.05s`** (exit 0). The sole skip was the existing real-Go launch test gated by `OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021=1`, which was not enabled. **Black `--check` passed for all three new Python files** (3 files unchanged). These results validate the mock OS-process path, actual imported FastAPI main route registration, and production signed-JWT authorization fence; *not* a native Go PID service in production.

## Remaining integration gaps and release restrictions

1. Prime owns `main.py` (router registration + actual app lifespan stop hook) and UI. Prime has separately mounted the route and supplied the shutdown call; they are **not modified by this worker**. Independent reviewed host-build pin injection is still required, so the mounted router currently provides signed-senior **read-only** unconfigured status and denial for start/stop.
2. No shared durable multi-replica process lease. This controller serializes **one FastAPI app-process** only; if multiple backend workers can accept the routes, each could host independent six-process instances. Keep the operator endpoint bound to a single secured host/process until global coordination, authenticated OS ownership and shutdown fencing are designed.
3. No independent signed 0033 PID/owner witness, Flow/Task/ROE/senior approval-to-Action source join, 0029 current native grant issuance/redemption, original artifact custody or target-owner effect. `psutil` OS telemetry stays **host-local and unsigned**.
4. Actual six Go SDK handlers remain **503/unavailable in unenrolled mode**. This API never initializes an MCP tool, invokes `/mcp/execute`, replays an UNKNOWN Action, runs a scan, touches paid provider credentials, or reports produced vulnerabilities or independently verified provider/target effects.
5. Process supervision is not an OS sandbox; the operator must independently verify binary provenance and trust the supplied local Go executables. The host PIN interface constrains configuration, but it does not cryptographically prove a reviewed supply-chain build or restrict arbitrary code already inside a trusted executable.

**Acceptance label: prime-mounted senior-only inert lifecycle interface, host-pin provisioning not configured or certified here, NOT LIVE-PID CERTIFIED IN THESE API TESTS, NOT PRODUCTION RELEASE CERTIFIED.**
