# Eleven MCP transport and recovery boundaries — 2026-10-21

**Verdict: NOT PRODUCTION CERTIFIED / NOT READY.** This is new transport/recovery evidence **beyond** the prior `test_mcp_eleven_execution_truth_20261021.py` (13/13 passing). The original heavily dirty `/burp_mcp/ai-osop` source is the subject; this worker created **only** `tests/qualification/test_mcp_all_eleven_transport_recovery_20261021.py` and this document. No real scanner, unauthorized target, app database, paid/cloud API, Docker, privileged executor, migration, Git command, production file edit, native grant, independent signer or operator approval was used. A valid network handshake with a test process remains a **simulation**, not an installed provider's evidence.

## New actual observations

### 1. Real HTTP streaming, not a fake `response.json()`

The test creates one disposable, test-owned `aiohttp.web` listener at a time, bound only to `127.0.0.1` with an OS-selected ephemeral port. For every configured name in the real `MCPRegistry`/`MCPConnection`, a legitimate **inert** `READ_ONLY` `list_tools` is negotiated via `/health` and `/mcp/initialize`. The **real aiohttp ClientSession** sends one bootstrap-only `/mcp/execute`, whose server replies via `StreamResponse.prepare`, repeated `write` operations in 16-KiB chunks and `write_eof`, **without declaring `Content-Length`**. Thus the production `_bounded_execute_response_json` actually reads a decoded HTTP entity incrementally through `ClientResponse.content.read()`, instead of exercising only Python dict/test-double branches.

Four cases are individually run for **each of all 11 server IDs (44 cases)**:

| Transport case | Actual source behavior | Verified result |
|---|---|---|
| Duplicate nested `verified` JSON member in 200 chunked body | Real parser `_unique_execute_json_pairs` rejects duplicate keys at all depths, before Pydantic status or signed-proof promotion. | Outcome `unknown`; no result, no signed receipt; same request ID returns `duplicate_request`; fixture observed **one** original execute. |
| Valid JSON with **over 2 MiB** body, unknown length, chunked | `content.read` enforces `_MAX_EXECUTE_RESPONSE_BYTES = 2*1024*1024` on actual decoded entity bytes, not a claimed header size. | Outcome `unknown`; no replay, no signed effect, no status or cancel request. |
| Truncated success JSON under HTTP 200 | Parser rejects incomplete document; a transport success cannot establish original Action completion. | Outcome `unknown`; the first one-use request ID is not re-sent. |
| Contradictory HTTP 200 with `status=success`, `isError=true`, forged provider receipt and false independent-target-effect claim | Current `MCPConnection.execute` checks original HTTP envelope for contradictory status before constructing/settling a successful result. | Outcome `unknown`, no verified target-effect flag and no signed settlement metadata. |

All received messages and the exact original `request_id` are counted at the server. **Zero requests** reached the fixture's scanner-deny branch; the fixture only implements inert discovery and refuses every other tool. Zero `/mcp/cancel` or `/mcp/request/status` requests were sent by these fault cases. Duplicate suppression is **in this client process**: no second worker, PostgreSQL ledger, cross-replica dedupe or real executor is represented by this observation.

### 2. Namespacing, startup, reconnect, manifest revocation

- Two **separate** owned localhost test listeners advertise identically named `list_tools`; one is labeled `recon-mcp` and one `burp-mcp`. The real registry keeps distinct connection identities and passes `recon-mcp.list_tools` versus `burp-mcp.list_tools` into a **negative, fixture-only** budget callback. Both are rejected as `quota_exceeded` **without HTTP execution**, even with the same request ID. This is namespace/quota isolation, **not proof** of real Redis atomic budgeting or global request-ID uniqueness.
- A disposable Browser-labeled listener initially returns `/health=503`, causing `register_server` to reject it; after the **same listener** recovers, the actual registry can connect and negotiate. A later `initialize` returning `status=unavailable` **clears `_initialized`, `_tools` and `_capabilities` before any await**. Attempts to use the old tool fail without sending HTTP. A later successful reinitialize does **not** replay rejected actions or mint signed Task/Flow/ROE authority. The provider here is a listener **labeled** Browser, not Playwright or a real Browser session.
- The **actual `BurpMCPAdapter`** initializes with a synthetic *validly typed* metadata-only `get_proxy_history` declaration and two required negotiated capabilities on a distinct loopback fixture bearer. The same provider then reinitializes with a different `READ_ONLY` tool (`get_scan_issues`). The adapter's pinned manifest hash rejects the change, even though the new registry handshake is `ready`. A later failed reinitialize clears the registry manifest as well. **No Burp plugin was attached, no observation was signed, no target traffic was generated, no real operator authorization was provided, and no Burp execution was attempted.**
- A source-map-labeled registry fixture has its audit event callback return failure on `dispatch_accepted`. Even explicitly inert bootstrap discovery is denied with `audit_unavailable` **before `/mcp/execute`**; repeating the same ID stays `duplicate_request`. The callback simulates an unavailable writer and **does not constitute an actual PostgreSQL revocation, ACK or durable event commit**.

### 3. Receipt trust rotation, cancellation and recovery are not physical-stop proof

For `recon-mcp`, `burp-mcp`, `browser-mcp` and `source-map-mcp`, a **throwaway in-test Ed25519 key** signs a canonical **test** `confirmed_stopped` provider-status statement. The actual `_verified_remote_status` and `_verified_remote_cancel` functions accept the correctly bound assertion while its test public key is enrolled. They reject contradictory top-level HTTP statuses/errors, and both revert to `unknown` **immediately after trusted-key removal**. There is no real signer, durable Task approval, 0029 redemption, stopped PID, or owner-of-record physical-stop observer in this test. The brief success before local key removal is explicitly **test cryptographic identity**, not a production-ready cancellation certificate.

Native Python ASGI tests additionally verify that untrusted requests to **actual** Browser and SourceMap `/mcp/request/status` fail without proof (401 or 503) and cannot produce a signed stop. Actual Turbo Intruder and Cloud execute calls return HTTP 503 with error bodies under **unset source config**. Native Python is invoked through an in-process ASGI transport without lifespan/startup, Playwright, secret enrollment, scanner subprocess or any target. **A lost execution ACK remains UNKNOWN, not automatically cancelled.** Genuine cancellation remains blocked until independently authorized and durably observed through the real Task/Flow/revocation ledger.

## Current original source classification of all 11 slots

These are source-based production capability classifications. The Python TCP streaming proof above uses **11 synthetic service identities**, not installed production listeners. The additional Go SDK `httptest` proof below exercises actual shared **Go HTTP handler implementation**, not six compiled Go cmd processes.

| Slot | Current source and executable boundary | What is, and is not, now certified |
|---|---|---|
| `recon-mcp` :8082 | Go cmd → `mcp-servers/go/sdk/server.go`; `authority_status` requires valid signed, single-use, durably redeemed native grant. | SDK handler inert; no recon/scanner target execution. Recon-only 0033 resource admission remains separate. |
| `payload-mcp` :8083 | Same Go SDK; command's legacy payload closures do not cross current HTTP handler. | Inert signed grant status only; no actual payload generator. |
| `nuclei-mcp` :8084 (**critical**) | Same Go SDK; native `scan` closure unreachable via current authorized transport. | No live Nuclei execution or target effect. |
| `shodan-mcp` :8085 | Same Go SDK; Shodan command handler unreachable. | No external Shodan API request. |
| `threat-intel-mcp` :8086 | Same Go SDK, **Go** service configured in API, not the separate Python threat-intel module. | No live NVD/CISA feed call. |
| `security-bridge` :8087 | Same Go SDK; legacy sqlmap/nmap/etc handlers unreachable. | No consequential scanner operation. |
| `burp-mcp` :8081 | External provider through `src/ai_osop/adapters/burp_mcp.py`; exact ready capability, bearer, manifest and original Action required. | Adapter manifest rollover tested; no real Burp plugin/observation/provider receipt. |
| `browser-mcp` :8091 (**critical**) | `mcp-servers/python/browser_mcp.py`, independent bearer + original central browser source, tenant mount, signer and Playwright; journal-bound status. | Unauthenticated status denied; actual browser navigation/current independent target evidence untested. |
| `source-map-mcp` :8096 (**critical**) | `mcp-servers/python/source_map_mcp.py`; host original signed artifact, current independent STATUS, native bearer, signed local receipt. | Unauthenticated status denied; no original approved artifact read, grant replay or URL fetch. |
| `cloud-mcp` :8097 (**critical**) | **Updated source 2026-10-21**: `mcp-servers/python/cloud_mcp.py` now has **optional local Terraform/Checkov static IaC** scanning (`OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED=1`, pinned local tree and Python executable, separate bearer). Missing config → 503 `local_iac_unavailable`; valid output would explicitly say `CHECKOV_LOCAL_IAC_UNVERIFIED`, `live_cloud_account_verified=False`. | **Not accurately described as an always-disabled stub anymore.** Unconfigured denial actually tested, configured local IaC scanner **not** invoked. No cloud IAM account observation or signed live cloud effect. |
| `turbo-intruder-mcp` :8098 (**critical**) | `mcp-servers/python/turbo_intruder_mcp.py` explicitly 503 and `unavailable`, no actual independent race/single-packet proof. | Disabled; no race/target request. |

The six Go commands all construct the same hardened `sdk.NewServer(server_id)` and invoke `server.Run`; SDK `Handler` has no legacy `Tool.Handler` dispatch and routes only verified `authority_status` to signed grant redemption. `/health` may report configured local trust, **not scanner availability**. The current `server.go` marks `native_target_execution_enabled=false`, `target_contacted=false`, `provider_contacted=false` even for an accepted inert status grant. Actual Go SDK security tests are outlined below.

## Commands and measured evidence

Windows host has Go `go1.26.3 windows/amd64` and full Python 3.11 via `py -3.11`. Avoid the incompatible host pytest-asyncio collector using `-p no:asyncio`; the test file uses `asyncio.run` and automatically closes each listener.

```powershell
# Original /burp_mcp/ai-osop checkout
py -3.11 -m pytest -p no:asyncio -q -x -o addopts= --confcutdir=tests/qualification tests/qualification/test_mcp_all_eleven_transport_recovery_20261021.py

# In original mcp-servers/go subfolder, no module downloads permitted
$env:GOPROXY='off'; $env:GOSUMDB='off'; $env:GOTOOLCHAIN='local'
go test -count=1 -run 'Test(ReadOnlyClaimDoesNotGrantExecution|HighEffectNativeToolsNeverExecuteInParallelIncludingDuplicateNonce|InitializeMalformedOversizedAndBadMethodAreSafe|BrokenBodyDoesNotLeakParsingErrorOrTriggerHandlers|DuplicateAndUnknownJSONFieldsAndMalformedAuthorityRequestsDenied|AllRegisteredToolsBlockedEvenWithValidAuthorityStatusGrant|SingleUseGrantParallelAttemptAtMostOneSuccess|NativeGrantRejectsMalformedAndDuplicatedHeaderInstances|DurableValidatorRejectsRevokedOrCancelledActionGrant)' ./sdk
```

**Observed final focused Python run:** **54 passed, 0 failed, 0 skipped, 8 warnings, exit 0, 11.07 seconds**. The warnings stem from preexisting `asyncio_mode` pytest config, deprecated OpenTelemetry/websockets and native Browser FastAPI event handlers. The 54 tests comprise 44 parametrized 11-service real network streaming cases and 10 other negative transport/recovery cases, including four key-rotation identities.

**Observed selected Go SDK regression run:** `ok github.com/ai-osop/mcp-servers/sdk 2.975s`, exit 0, `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`. Selected native `httptest` regressions cover handler confinement, malformed and oversized requests, duplicate JSON and grant headers, parallel single-use redemption, and revoked/cancelled grants. These are **existing Go test implementations** run read-only for this work; this worker did not add, edit, or use them to launch six real Go cmd services. The controlled validator fixtures in these Go tests are not an independently enrolled production grant/revocation authority.

## Genuine outstanding work

For production readiness, centrally signed *current* Task/Flow/ROE and independent reviewed human approval must gate actual provider execution, with real durable PostgreSQL/redis reservation, per-replica lost-ACK, cancellation intent, current revocation and original-store readback. Real Go six command processes require host-only grant redeem + 0033 supervisor proof where appropriate, original signed receipt and invariant `target_contacted=false` unless a separately reviewed scanner is ever enabled. Burp needs a live enrolled plugin/provider observation; Browser needs actual signer/source/Playwright and independent target owner corroboration; SourceMap needs authorized immutable source and current STATUS; optional Cloud must be classified as **static local IaC, not live IAM**, and Turbo remains unavailable. No mock return, signature from an ephemeral fixture key, source metadata, provider HTTP 200, or local TCP/ASGI status can certify physical target effect or 11/11 true end-to-end execution.
