# Operator eleven-service diagnostic ↔ real six-Go-process reconciliation

**Date:** 2026-10-21  
**Repo:** original heavily dirty `/burp_mcp/ai-osop`  
**Result:** **SOURCE CONTRACT PASS; LIVE PROCESS JOIN NOT RUN / OPT-IN ABSENT. NOT PRODUCTION READY.**

## Scope and concrete boundary

This disjoint qualification adds only:

- `tests/qualification/test_mcp_operator_real_go_process_reconciliation_20261021.py` — one always-on source/roster assertion and **two independently opt-in** real-process assertions.
- This report, `docs/MCP_OPERATOR_REAL_GO_PROCESS_JOIN_20261021.md`.

It reads the original `mcp-servers/go/sdk/server.go`, the six actual Go `cmd/*` entrypoints, existing worker40 `tests/qualification/test_native_go_six_supervised_inert_runtime_20261021.py` and `docs/NATIVE_GO_SIX_INERT_SUPERVISION_20261021.md`, and worker39 `scripts/qualification/mcp_eleven_inert_diagnostic_20261021.py`. It does **not** edit or call `main.py`, protocol production code, browser files, DB, Docker, external services, a target or any scanner. **No default Go process is started.**

### Evidence levels and interpretation

| Observation | Allowed conclusion | Explicitly **not** proven |
|---|---|---|
| Actual Go PID, exact executable identity, owner/user and owned `127.0.0.1` listening socket | Test runner observed **one running local process** | Native authorization, supervisor-signed 0033 production ownership, a working MCP connection, signed Action, scanner invocation |
| `GET /health` returns **HTTP 503** with `status=unavailable`, `authority_verified=false`, `execution_enabled=false` | Unenrolled process is correctly **not READY** | No reason to upgrade to registered or initialized merely because PID/socket exist |
| HTTP 200 `/mcp/initialize` with `status=unavailable` | Endpoint negotiated an explicit **unavailable** declaration | Initialization success, usable tool handler, signed Task / ROE / lease |
| Worker39 actual `MCPRegistry.register_server` through `diagnostic.diagnose` | `/health` HTTP 503 fails `connect()`; **`registered=false`, `initialized=false`, `state=unknown`, `inert_outcome=unknown`** | A successful register, safe `list_tools`, native execution, independent effect |
| Other five of configured 11 **not explicitly permitted** | **`state=not_allowed`**, no request to those endpoints | Down/up state of Burp, Browser, SourceMap, Cloud, Turbo |
| Source-only `item.Handler=nil` and missing native status/cancel endpoints | Legacy handlers cannot dispatch through current Go SDK HTTP; no signed provider stop readback | A remotely executed Nuclei/Shodan/recon/payload/security scan or verified stop |
| Negative no-grant/wrong-signature/lost-ACK test | Fail closed (`503` where observed) or **UNKNOWN** on socket reset or deliberately missing ACK; **no retry** | Successful signature admission, 0029 redemption, producer result, provider or target-owner effect |

The six Go processes in the roster are `recon-mcp`, `payload-mcp`, `nuclei-mcp`, `shodan-mcp`, `threat-intel-mcp`, and `security-bridge`. The other five (`burp-mcp`, `browser-mcp`, `source-map-mcp`, `cloud-mcp`, and `turbo-intruder-mcp`) are intentionally **unallowed** rather than falsely described as alive or unavailable.

### Opt-in process experiment — **not executed in default mode**

Under an explicit `OSOP_MCP_OPERATOR_REAL_GO_JOIN_20261021=1`, on Windows with `psutil` and a **locally runnable Go toolchain with all dependencies already cached**, the new suite is designed to:

1. Build exactly six current-source `.exe` binaries into a **temporary directory outside this shared dirty tree** using `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOWORK=off` and `-buildvcs=false`. **Preexisting binaries in `mcp-servers/go/*.exe` exist but are deliberately not trusted as current-source evidence.** Missing compiler/cache causes an explicit skip; source compilation failure not due to offline cache is a test failure. No downloads or Git changes.
2. Launch exactly six test-owned, short-lived subprocesses using a reduced child environment, each on a **different OS-selected numeric IPv4 loopback ephemeral port**, never hardcoded 8082–8087. Native issuer, redemption and supervisor settings are **absent** in this six-process cohort.
3. Observe exact executable PID ownership, parent/user, `127.0.0.1` LISTEN socket and 503 health. Call the real worker39 `diagnostic.diagnose({six explicitly owned ports})`, which constructs `MCPRegistry`; assert **eleven** sanitized entries, **six unknown/unregistered/uninitialized** and **five not allowed**. Independently check real Go HTTP 200-but-unavailable initialization (not via the failed registry connection). Never invoke a legacy tool or try to relabel 503 as READY.
4. Separately launch **one** test-owned Recon process with **ephemeral public test trust only** and an intentionally unreachable pinned local HTTPS redemption endpoint. Its 200 `configured_unverified` health and `authority_status`-only catalog are not production authority. Two different, exactly bounded inert `authority_status` requests use malformed/foreign-signer or expired foreign-signer signatures; each request ID is used **once**. Whether each receives 503 or Windows returns a TCP reset, no signature or grant is accepted as evidence. A final **single** no-grant POST is deliberately sent with its ACK discarded; this remains **UNKNOWN** and is **not retried**. No valid private signing root, signed Action, redemption service or provider exists.
5. Terminate **only test-owned PIDs** in bounded `finally` blocks and verify their loopback listeners close. Do not leak environment secrets, response bodies, native grant envelopes or stdout/stderr in reports.

**Limitation of the wrong-signer observation:** a deliberately foreign signed grant submitted under ephemeral test roots is a negative signature check, not a proof of current 0027/0029/0033 independent enrollment or live revocation. The *expired* token is also signed by the wrong key, so its rejection cannot specifically isolate the expiry check; proper current signer expiry and one-use replay require separate authorized durable test infrastructure. A deliberately discarded HTTP ACK provides no durable readback, cancellation or worker effect proof.

## Exact observations this turn

The process opt-in variable was **not set** in this environment. Existing repository Go binary files were observed (six `.exe` names); no assertion was made that their bytes matched current source or were safe to run. The new tests were invoked **without enabling opt-in**:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_mcp_operator_real_go_process_reconciliation_20261021.py -q -rs --tb=short
```

**Observed:** `1 passed, 2 skipped in 2.02s`, exit 0. Each process test skipped explicitly: `NO GO PROCESSES: explicit operator opt-in OSOP_MCP_OPERATOR_REAL_GO_JOIN_20261021=1 absent`. **Zero Go process PIDs or HTTP probes in this run.** The one passing test is a source/roster assertion, **not runtime evidence**.

With the preexisting worker39 **11-service inert diagnostic tests** included as adjacent regression (no process opt-in), the actual project `.venv` run was:

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_mcp_operator_real_go_process_reconciliation_20261021.py tests/qualification/test_mcp_eleven_inert_diagnostic_20261021.py -q -rs --tb=short
```

**Observed:** **`36 passed, 2 skipped in 3.70s`**, exit 0. The 35 additional passing tests cover **disposable fake** HTTP fleet behavior and do not convert the skipped Go process join to live evidence.

For a future operator-authorized *local* process qualification only (never run without permission):

```powershell
$env:OSOP_MCP_OPERATOR_REAL_GO_JOIN_20261021 = '1'
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/qualification/test_mcp_operator_real_go_process_reconciliation_20261021.py -q -rs --tb=short
Remove-Item Env:OSOP_MCP_OPERATOR_REAL_GO_JOIN_20261021
```

Do not count successful prior worker40 process runs toward this new operator diagnostic↔PID integration test. Their 19/19 scoped tests (in their separate report) are useful historical evidence, not a freshly executed result from this session.

## Safe acceptance gap

**No 11/11 working-end-to-end certification.** The actual Go processes without independently configured native authority remain `503 / unavailable` even if their PID and socket exist. The current diagnostic intentionally **does not send** a grant or `authority_status` because it only allows a separate zero-parameter, `READ_ONLY`, approval-free `list_tools` declaration; the Go SDK's `authority_status` is approval-gated and is deliberately excluded. A separate native grant would require real current durable 0027 original Action, 0029 signed one-use redemption, source-owned revocation, 0033 independently signed process/supervisor witness, and current original artifact/readback joins. Lost ACK and no `/mcp/request/status` stay UNKNOWN/no replay. No status from these tests demonstrates paid provider calls, recon work, vulnerability findings, independent target-owner effect, or production release readiness.

**Release classification: NOT PRODUCTION CERTIFIED / NOT READY.** Keep 503/unavailable classifications and the existing sign/approval/target-effect boundaries until separately authorized, properly enrolled infrastructure exists.

## Later same-day opt-in execution by prime

The default-mode observations above remain accurate for worker39's run. Prime
subsequently enabled the explicit *test-local-only* opt-in for the separate
`test_mcp_operator_real_go_process_reconciliation_20261021.py` qualification
on the approved Windows host, rebuilt the six native Go binaries using the
offline module cache and short-lived ephemeral localhost processes, and ran
the actual diagnostic↔PID reconciliation plus the inert wrong-signer/lost-ACK
case. **3 passed, 0 skipped in 31.06 seconds**, exit 0. The opt-in environment
variable was removed in the same PowerShell `finally` block. As asserted by
the suite, test-owned PIDs and sockets were cleaned; none occupied configured
service ports or executed a scanner. The six Go services remained **inert /
unavailable** (not authenticated READY); missing provider authorization,
independent signed effect, loss-ACK recovery and senior release remain blockers.
