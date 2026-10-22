# Six-native-Go inert process fleet — operator-controlled lifecycle

**Date:** 21 October 2026  
**Scope:** original heavily dirty `/burp_mcp/ai-osop`  
**Release verdict:** **UNMOUNTED, OPT-IN INERT PROCESS FEATURE — NOT SIGNED 0033 AUTHORITY AND NOT PRODUCTION CERTIFIED.**

## What was implemented

New, standalone `src/ai_osop/mcp/native_inert_process_fleet.py` implements `NativeInertProcessFleet` with explicit synchronous `start()`, `health()`, `stop()` / `close()` and `with`-context cleanup. It is deliberately **not imported into** `src/ai_osop/api/main.py`, startup, `MCPRegistry`, application schedules, native grant/redeem, or worker 0033. **No existing production file was edited.** The module does not compile binaries, create trust roots, sign grants, invoke MCP tools, launch a browser, or reach a target or provider.

Its intended six *Go SDK metadata-only* children, all required as one verified set, are `recon-mcp`, `payload-mcp`, `nuclei-mcp`, `shodan-mcp`, `threat-intel-mcp`, and `security-bridge`. These Go entrypoints currently expose inert HTTP status, but **no callable legacy `Tool.Handler`** via the SDK's MCP route. Their unprovisioned `/health` is HTTP **503** with `status=unavailable`, `authority_verified=false`, `execution_enabled=false`, and `reason=source_side_signed_authority_unavailable`.

### Operator gates and build provenance

All gates must be met *before a process is started*:

1. The caller deliberately constructs `NativeInertProcessFleet(operator_opt_in=True, ...)` **and** sets `OSOP_NATIVE_INERT_PROCESS_FLEET_OPT_IN=1`. Other values, missing env, Linux/unsupported platform or missing `psutil` fail closed. Constructing an object alone does not start anything.
2. Caller supplies **exactly six** `VerifiedGoBinary(path=Path(absolute_path), sha256=verified_64_lowercase_hex)` objects, plus `trusted_build_root=Path(absolute_absolute_root)`. All six files must be **direct non-symlink/non-reparse children** of the same verified root, named exactly `service.exe`; root may not overlap the application repository. Files have a size bound, PE/MZ header and operator-independent SHA-256 comparison. Binary bytes are rehashed before each spawn and during live ownership checks. **A file merely named `recon-mcp.exe` or an existing dirty-repository `.exe` is not trusted.**
3. `go version -m /absolute/path/service.exe` executes **the local Go build-info inspector only** (not the service), with `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local` and no provider configuration. Its output must name the exact `github.com/ai-osop/mcp-servers/cmd/<service>` package and `GOOS=windows`, `GOARCH=amd64`. Missing inspector / malformed build metadata / any renamed non-Go executable fails closed; **this module never builds or downloads**. These checks are useful local identity checks, not an independent code-signing authority or reproducible-build proof. The operator is responsible for verifying current source and the SHA pins separately.
4. The child inherits only an allowlisted subset of OS runtime variables plus the **single** `OSOP_RECON_MCP_LOCAL_PORT` or `OSOP_NATIVE_MCP_LOCAL_PORT` override. No app DB URI, OAuth/API key, paid-provider key, proxy, `OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON`, redemption root/URL/secret, 0033 supervisor enrollment or other `OSOP_` variables are inherited. Binaries are launched with no stdin/stdout/stderr capture or secret echo.
5. Each subprocess gets a unique OS-selected temporary numeric **`127.0.0.1`** port, never the six configured fixed ports, app ports or known DB ports. It must be a directly owned `subprocess.Popen` handle, with exact parent PID, matching same-user executable path, stable process creation time and **OS-attributed listening socket**. Unexpected scanner descendants fail; the only tolerated Windows helper is `conhost.exe`. If the health route responds with anything except strict bounded HTTP 503 inert/unavailable JSON, the fleet stops and refuses to relabel the process as ready.

### Runtime and failure semantics

`start()` validates all six supplied file identities *before* creating the first child. It then launches each owned process with a bounded bind wait; **only a not-yet-bound socket may be polled** during startup. PID mismatch, changed executable digest, uncertain OS ownership, a different HTTP response or missing prerequisite aborts immediately. After all six pass, `start()` returns six `InertProcessHealth` values, which deliberately fix `native_authority_verified=False`, `execution_enabled=False`, `target_effect_verified=False`, `production_certified=False`, `status='unavailable'`. A PID or listener is never described as `MCPRegistry` initialization or an executable scanner.

`health()` repeats host-local ownership/path/socket checks and sends only **`GET http://127.0.0.1:<owned_ephemeral_port>/health`**, with no redirects/proxies, bounded size, and strict duplicate-key/JSON validation. It never POSTs `/mcp/initialize`, `/mcp/execute`, `/native-supervisor/provision`, grant redemption or other effectful route. On failure it stops all owned children and closes the object. **There is no restart method, no re-issuing a lost MCP Action, no replay, no background monitor, and no automatic discovery or connection to the five other MCP services.**

`stop()` is explicit, idempotent and closes the object permanently. It terminates or, after a bounded timeout, kills **only the Popen handles it created** — never by service name, global PID search or TCP port. It checks child exit and released owned loopback port; a failed ownership/exit check is reported and the unresolved owned handle is retained so the operator can retry cleanup without starting new work. No automatic recovery is claimed.

### Safe manual integration hook (not activated)

Under a separately designed **senior-operator-only** control plane, *if and only if* six offline-built binaries and their independently reviewed SHA-256 values are available outside the repository, the lifecycle may be invoked explicitly. The sketch is illustrative: deliberately no ready-made environment settings or executable paths are inserted into application startup.

```python
from pathlib import Path
from ai_osop.mcp.native_inert_process_fleet import (
    NativeInertProcessFleet, VerifiedGoBinary,
)

# Caller must separately verify and supply all six exact service.exe files.
# pins = {name: VerifiedGoBinary(path=reviewed_absolute_path,
#                               sha256=independently_recorded_sha256) ...}
# The OSOP_NATIVE_INERT_PROCESS_FLEET_OPT_IN=1 gate must be deliberately set
# by a local operator; it is not enabled by app/bootstrap/default config.
with NativeInertProcessFleet(
    binaries=pins,
    trusted_build_root=Path(verified_absolute_build_directory),
    operator_opt_in=True,
) as owner:
    inert_process_observations = owner.health()  # OS PIDs + 503 ONLY
# All children have been asked to exit and cleanup checked.
```

This class must not be wired to FastAPI application lifespan or privileged Action dispatch without a distinct review of host custody, cancellation/stop evidence, permissions and process attestation. Do not use its outputs as 0033 signed PID witness or host-authorized task execution. In particular, its `InertProcessHealth` is **unsignable observation data**, not a grant, signer, ROE or source-of-truth state transition.

## Validation actually performed

New tests: `tests/test_native_inert_process_fleet_20261021.py`. The default tests exercise explicit-gate denial, six-entry allowlist/path/hash/symlink/non-Go rejection, real `go version -m` detection of a fake PE, environment scrubbing, unique ephemeral-port selection, strict mocked HTTP 503 parser (including denial of forged `execution_enabled`, forged authority, wrong server, redirects/oversized/duplicate/nonfinite input), direct fake-PID impersonation denial, missing OS ownership verifier, all-six mocked lifecycle success, partial start failure rollback, missing socket bounded timeout, ownership revocation cleanup, context manager cleanup, post-stop state, and retaining only unresolved owned handles.

```powershell
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/test_native_inert_process_fleet_20261021.py -q -rs --tb=short
.\.venv\Scripts\python.exe -m black --check src/ai_osop/mcp/native_inert_process_fleet.py tests/test_native_inert_process_fleet_20261021.py
```

**Observed (final focused):** **37 passed, 1 skipped** in 8.98 seconds, pytest exit 0. The one skip is the actual six-Go process launch test because `OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021=1` was not set. Black formatted both *new* files and its final `--check` passed on these two paths only. Prebuilt current worktree `.exe` files were **not run**. A separate read-only `go version -m` inspection of preexisting Recon binary showed `github.com/ai-osop/mcp-servers/cmd/recon-mcp`, Windows/amd64 metadata; that does not establish build freshness or authorize execution.

**Final adjacent regression:** New tests alongside prior `tests/qualification/test_mcp_operator_real_go_process_reconciliation_20261021.py`: **`38 passed, 3 skipped in 9.45s`**, exit 0, with the remaining two skips belonging to the older opt-in real-process reconciliation suite. Follow-up Black `--check` returned **2 files unchanged**. No unscoped production file or Go process was modified by this validation.

### Independently gated actual child test

The optional positive process test imports **worker40's existing** `rebuilt_binaries` fixture, which only rebuilds six current sources in a temporary directory using the local Go toolchain with `GOPROXY=off` and independently requires `OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021=1`. It then separately requires `OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021=1`, hashes those owned build outputs, and injects only the test-local supervisor opt-in. **Compiling occurs solely in worker40's already existing test fixture, never in this production supervisor.**

To run that process qualification only under affirmative operator authorization:

```powershell
$env:OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021 = '1'
$env:OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021 = '1'
.\.venv\Scripts\python.exe -m pytest -o addopts='' tests/test_native_inert_process_fleet_20261021.py -q -rs --tb=short
Remove-Item Env:OSOP_NATIVE_GO_SIX_REAL_PROCESS_20261021
Remove-Item Env:OSOP_NATIVE_INERT_PROCESS_FLEET_REAL_TEST_20261021
```

This was **not executed** in this worker's run; absent compilation permission, its result remains **SKIPPED**, not six production-ready servers. Do not extrapolate previous worker40 opt-in results to this new lifecycle.

## Release blockers and factual gaps

- No integration with operator RBAC, current Flow/Task/ROE approval, original 0027 Action or durable native 0029 redemption. No 0033 independently signed PID/supervisor source or durable host witness is produced; local `psutil` readings belong only to this host process.
- No native grant, no real `/mcp/execute`, no scanner dispatch or tool traffic. Six real executable processes, even if a future test passes, would remain **HTTP 503 / MCP unavailable** in unenrolled mode.
- No verified target-side effect, screenshot, source bytes, report promotion, authenticated stop/status ACK or physical cancellation. Missing ACK means **UNKNOWN / no replay**, not completion.
- There is no independently certified binary provenance, secure-build attestation or hardened OS sandbox. Go's embedded build metadata and separately supplied SHA pins are **local checks**, not a cryptographic guarantee that startup code is harmless. Use only binaries reviewed by an authorized operator.
- No claim of 11/11 MCP service readiness, genuine PentAGI functionality parity, autonomous exploit execution, or production release certification. The five non-Go fleet entries are explicitly outside this supervisor.

**Production verdict: NOT CERTIFIED; local inert process lifecycle API only, opt-in and deliberately unmounted.**

## Subsequent prime-run actual six-process qualification (2026-10-21)

The worker's earlier **not-executed** classification above describes its own
default run, not this later explicit opt-in. Prime invoked the opt-in genuine
offline six-Go rebuild + operator-owned inert process lifecycle on the approved
Windows host, with the two test environment switches scoped to a PowerShell
`try/finally` block and removed afterward.

The first real attempt failed *before any owned process launch*: `_validated_binaries`
compared full Windows `os.stat_result` before and after reading an executable.
File access can update `st_atime`, causing false file-substitution detection.
Prime repaired this by comparing identity-relevant device/inode/mode/size,
`st_mtime_ns` and Windows reparse attributes, **while retaining SHA256 validation
before AND after external build-info inspection**. New regression explicitly
changes access time (allowed) and file bytes/length (denied). The post-fix
unit/policy suite passed **38 tests** (one explicit real-process deselection).

The second opt-in real-process test then **PASSED (1/1, about 25.27s)**, using
six freshly offline-built owned temporary binaries, ephemeral numeric-loopback
ports, real Windows PID/exe/port provenance checks, 503 inert health and owned
shutdown. No configured production MCP port, signed grant, scanner, external
target, provider, application database, Docker or live cloud account was used.
The result certifies **only** isolated inert local process lifecycle. There is
no independently signed production `0033` process witness and the configured
fleet remains not production certified.
