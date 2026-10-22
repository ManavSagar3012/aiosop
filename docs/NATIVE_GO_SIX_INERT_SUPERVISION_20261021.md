# Six native Go MCP processes: actual inert startup and ownership qualification

**Date:** 2026-10-21  
**Disposition:** **NOT PRODUCTION CERTIFIED / NOT READY for consequential execution**  
**Scope:** Original dirty `/burp_mcp/ai-osop`; only NEW `tests/qualification/test_native_go_six_supervised_inert_runtime_20261021.py` and this NEW report. No other source, migrations, old tests, central MCP registry/protocol/main, Docker, app database, Git, scanner, target, provider API, or credentials were touched or used.

## Bottom line

We **really compiled, started, observed and terminated** each of the six current Go `cmd` entrypoints as a distinct, **test-owned OS child process**, using **freshly built binaries** and **OS-selected ephemeral `127.0.0.1` ports**, never their six configured production ports. This is stronger than the previous Go SDK `httptest` or 11-name fake-loopback evidence.

All six exposed only an untrusted local **metadata-only** protocol boundary. They **cannot be marked MCP READY** without independent native grant/supervisor trust: `/health` returned HTTP 503; valid typed `/mcp/initialize` returned HTTP 200 with `status=unavailable`, `execution_enabled=false` and `authority_verified=false`; direct unsigned builtin `authority_status` returned HTTP 503 `native_execution_not_authorized` (or an explicitly unconfirmed connection reset from a request body the handler did not read). No native Action, signed one-use grant, worker redemption, resource offer, scanner handler, real provider, authenticated cancellation, or physical target effect occurred.

## Verified startup mapping

The six actual entrypoints use one real shared SDK `mcp-servers/go/sdk/server.go`; `Handler()` registers health, initialize, execute, and an independently signed supervisor-provisioning endpoint, but **does not route any legacy `Tool.Handler`**. Unconfigured `snapshotTools()` discloses legacy **metadata only** with conservative `requires_approval=true`, `scope_check=true` and risk classification, while `authority_status` is only advertized when `nativeConfig()` is independently provisioned. We do not provision it here. The only possible native execution route is an **inert signed/durably redeemed** `authority_status`, which is denied on every tested process.

| Actual compiled and started command | Existing default port **not used** | Test-only port override | Live process/HTTP outcome |
|---|---:|---|---|
| `cmd/recon-mcp` | 8082 | `OSOP_RECON_MCP_LOCAL_PORT` | Owned executable PID and socket; metadata only; 503/unavailable; no recon/search |
| `cmd/payload-mcp` | 8083 | `OSOP_NATIVE_MCP_LOCAL_PORT` | Owned executable PID and socket; metadata only; 503/unavailable; no payload generator |
| `cmd/nuclei-mcp` | 8084 | `OSOP_NATIVE_MCP_LOCAL_PORT` | Owned executable PID and socket; metadata only; 503/unavailable; **no Nuclei process or scan** |
| `cmd/shodan-mcp` | 8085 | `OSOP_NATIVE_MCP_LOCAL_PORT` | Owned executable PID and socket; metadata only; 503/unavailable; **no Shodan network call** |
| `cmd/threat-intel-mcp` | 8086 | `OSOP_NATIVE_MCP_LOCAL_PORT` | Owned executable PID and socket; metadata only; 503/unavailable; no external feed fetch |
| `cmd/security-bridge` | 8087 | `OSOP_NATIVE_MCP_LOCAL_PORT` | Owned executable PID and socket; metadata only; 503/unavailable; **no Nmap/SQLmap** |

The common `sdk.LocalPortAddress` validates canonical decimal ports 1024–65535, always returns `127.0.0.1`; Recon has a dedicated port helper with the same strict loopback/fail-on-invalid property. The test reserves a temporary IPv4 loopback socket on port 0, obtains the OS-assigned port, closes only that reservation and then launches one owned binary with the corresponding override. It **never binds a fixed application port** and runs children **sequentially**. The Go SDK independently reconstrains host binding. A narrow reservation-to-listen race is inherent to an OS-ephemeral port override; any unexpected bind/ownership failure makes the test fail, not report readiness.

## Proof levels: what was actually tested

### A. Offline build and process identity, not a fabricated listener

- `go version` was **go1.26.3 windows/amd64**. Each of the six current source directories was rebuilt with local `go build -buildvcs=false -trimpath -o <owned TemporaryDirectory>/name.exe ./cmd/name`. Existing prebuilt `.exe` files in the repository were intentionally **ignored** as potentially stale. `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOWORK=off`, and `GOFLAGS=-buildvcs=false` prevent module/toolchain download and VCS metadata generation. All binaries lived outside the original dirty repository and were removed with their owned temporary directory.
- The child process environment was constructed from a restricted set of Windows/Go runtime variables (PATH, OS system root and temporary/user/cache paths), with **no `OSOP_` key/issuer/redeem URL/service credential, no target or provider configuration and no HTTP(S)/ALL_PROXY**; it adds only the single authorized local port override. No signing root or supervisor producer was installed, including no fake key.
- For **each** running child, `psutil.Process(Popen.pid)` verified **same parent PID** as this pytest worker, **same Windows user**, **exact executable path** matching the freshly built owned binary, and a **process-owned TCP LISTEN socket** whose local address and port exactly matched the test-selected `127.0.0.1:<ephemeral>`. Checked the child's original process `create_time()` again after all HTTP probes to prevent accidental replacement evidence. Windows may attach an OS **`conhost.exe` console helper**; any other descendant (including a scanner subprocess) is rejected.
- All processes were terminated with a bounded `terminate()`/`communicate()` in `finally`; if termination failed, an owned-PID `kill()` provides cleanup while marking the test **failed**. Each successful test confirmed child PID no longer exists and its owned listener port no longer accepts connections. Separate early-start cancellation tests deliberately terminate a newly launched process **before observing readiness**, never presenting that aborted startup as successful. Separate invalid port `0` starts all exit **nonzero** without silently falling back to 8082–8087.

### B. Actual network responses from all six binaries

The tests use Python's genuine HTTP client, with proxy use explicitly disabled, to call only the process's own known `127.0.0.1:<ephemeral>` endpoint. There is **no target URL parameter** and no remote socket. The observations were consistent across all six:

| Request to actual running process | Response or conservative observation |
|---|---|
| `GET /health` | HTTP **503**, `status=unavailable`, exact `server_id`, `execution_enabled=false`, `authority_verified=false`, `source_side_signed_authority_unavailable`. **Not READY.** |
| `POST /mcp/initialize` with canonical object scope, credentials, metadata and session ID | HTTP **200**, but exact `server_id`, **`status=unavailable`**, empty capabilities, `execution_enabled=false`, `authority_verified=false`; available catalog is **not** a callable authority. |
| Malformed initialization: duplicate JSON keys, incorrect `session_id` type, >8192-byte body, GET instead of POST | HTTP **400** `invalid_initialize_metadata` for malformed JSON or **405** `method_not_allowed` for GET. No tool call. |
| `POST /mcp/execute` with **builtin inert** `authority_status`, `{}` and test-only `request_id`, repeated same ID | With no enrolled trust, HTTP **503** `native_execution_not_authorized`, `execution_enabled=false`, no result or signed receipt. Some Windows Go HTTP responses to a **non-consumed POST body** can yield `ConnectionResetError`: recorded as **unconfirmed transport outcome** only; **not a successful ACK**, never a reason to retry a live one-use Action. The test separately verifies HTTP **503** with a distinct empty-body POST; it does **not** retry the original request or ever provide a valid grant. |
| `POST /mcp/cancel` and `/mcp/request/status` with empty body | HTTP **404**; no native SDK route or signed stop/status readback. **404 is not a physical cancellation.** A payload-bearing request to an unmatched Go route can also encounter a Windows connection reset, which remains UNKNOWN. |
| Termination, close, invalid override, immediately aborted startup | Test-owned PID exits, socket closes; invalid port exits nonzero, never falls back to default; early-aborted process is **not** counted as healthy or initialized. |

Only the SDK-owned **inert `authority_status` name** was submitted to `/mcp/execute` without a grant. No request was sent for `scan`, `nmap`, `sqlmap`, `generate_payload`, `shodan_lookup`, `cve_lookup`, recon discovery, or another consequential legacy tool. The presence of those compiled closure definitions is not execution evidence; the SDK intentionally never dispatches them.

## Reproducible validation

In the original project directory, **default** mode makes **no Go build or process start**:

```powershell
py -3.11 -m pytest -p no:asyncio -q -x -o addopts= --confcutdir=tests/qualification tests/qualification/test_native_go_six_supervised_inert_runtime_20261021.py
```

**Observed source-only mode:** `1 passed, 18 skipped, 1 unrelated warning` (exit 0). The skip is deliberate, not evidence that six processes started.

To authorize only this disposable local, offline real-process qualification:

```powershell
$env:OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021 = '1'
py -3.11 -m pytest -p no:asyncio -q -x -o addopts= --confcutdir=tests/qualification tests/qualification/test_native_go_six_supervised_inert_runtime_20261021.py
```

**Observed FINAL opt-in run:** **19 passed, 0 failed, 0 skipped; 1 host pytest config warning; exit 0, 30.51 seconds.** This includes one source contract + six actual owned process HTTP/PID/socket tests + six invalid-port fail-closed process tests + six early-start process termination tests. Early attempts surfaced platform-specific Windows `conhost.exe` ownership and unread-POST-body TCP reset behavior; these were *not hidden*: the qualification was corrected to distinguish the non-scanner OS helper and UNKNOWN transport responses, and then the entire opt-in suite passed. The warning is the pre-existing project's `asyncio_mode` pytest config and the host's disabled plugin; no Go or Python execution tests failed in the final run.

## Certification boundary / unfinished 11-service integration

1. **This proves real six-process local inert SDK behavior only.** Neither `/health` nor initialization is READY in unprovisioned mode. A bootstrap TCP listener (or HTTP 200 that declares `status=unavailable`) **must not** be promoted to a usable `MCPRegistry` connection. This is not 6/6 native tool execution or an 11/11 fully wired application runtime.
2. **No live independent signed authority exists in this test.** Native Ed25519 one-use grant, PostgreSQL 0027 original Action, 0029 native redeem, 0030 original-byte offer, 0033 independently signed supervisor/worker identity and live PID/mount witness, and 0035/0037 SourceMap STATUS/grant binding are **not** exercised through the process; the latter SourceMap chain is itself known to fail closed without real grant issuer and host proof. An OS-owned PID/socket observation by `psutil` is **test-runner evidence**, not independently enrolled 0033 signed source testimony.
3. **No verified cancellation or ACK recovery.** Actual Go SDK processes expose **no** `/mcp/cancel` or `/mcp/request/status` handlers. Thus neither a returned 404 nor a Windows reset can prove stop or completion; the client must retain UNKNOWN and never reexecute a potentially consequential native Action after lost acknowledgement. This test intentionally provides no Action or cancellation grant.
4. **No provider/target effectiveness proof.** No legacy handler, browser, external Burp, Shodan, Nuclei, Scan, app DB, Docker, signed resource mount, remote socket or live target was invoked. There is no empirical provider execution, scanner readiness, independent target-owned testimony, physical effect or production integration parity.

**Next safe engineering requirement (not changed by this worker):** Host-only trusted configuration and durable independent Task/Flow/ROE/senior approval, source-original and 0033 current supervisor authority; rigorously scoped one-shot inert `authority_status` redemption and independently signed provider receipt; persist loss/cancellation UNKNOWN with current readback; only then separate authorized qualification of any deliberately reenabled native execution. Preserve the 503 / denied behavior in the meantime.
