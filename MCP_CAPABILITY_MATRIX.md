# MCP Capability Matrix

**Generated:** 2026-06-24
**Scope:** MCP Reality Validation — determine whether AI-OSOP's tooling layer is REAL, PARTIAL, STUB, or BROKEN.
**Method:** For each MCP server — (1) service health, (2) tool registration, (3) executable availability, (4) harmless **local** capability test (no traffic to any engagement target), (5) classification.
**Target safety:** No requests were sent to `uat-bugbounty.nonprod.syfe.com`. All execution tests used a local throwaway HTTP server (`127.0.0.1:9099`) or local binaries.

## Classification legend

| Class | Meaning |
|-------|---------|
| **REAL** | Registers tools AND executes a real external tool/process that acts on its inputs. |
| **PARTIAL** | Executes a real tool, but with a defect that limits correctness (e.g. ignores parameters), OR real code blocked only by a missing dependency. |
| **STUB** | Responds to health/registration but returns canned/hardcoded data; no real execution. |
| **BROKEN** | Cannot serve, or its real code path fails at runtime (missing binary/module). |

## Matrix

| MCP Server | Port | Health | Tools Registered | Executable Present | Local Capability Test | Verdict |
|-----------|------|--------|------------------|--------------------|-----------------------|---------|
| **nuclei-mcp** (Go) | 8084 | ✅ ready | ✅ `scan` | ✅ `nuclei v3.8.0` (12,907 templates) | ✅ `/mcp/execute` ran a real template, **10 real findings** in 2.6s (after fix) | **REAL** |
| **burp-mcp** (Burp Suite Community + MCP ext) | 8081 | ✅ ready | ✅ 8 tools (`scan_target`, `get_proxy_history`, `send_http_request`, `intruder_attack`, …) | ✅ `BurpSuite.exe` running | ✅ `send_http_request` proxied a real HTTP/200 with live response body | **REAL** |
| **browser-mcp** (`browser_mcp.py`, Playwright) | 8091 | n/a (not launched) | ✅ `execute` (navigate/click/fill/screenshot/dom/HAR) | ⚠️ Chromium downloaded; `playwright` module **missing from `.venv`** (present in system Python) | ✅ Real Playwright navigation to local target → **HTTP 200**, title read (via system Python) | **PARTIAL** (real code; blocked in `.venv` by missing module) |
| **recon-mcp** (Go) | 8082 | ✅ ready | ✅ 8 tools (`nmap_scan`, `subfinder_enum`, `httpx_probe`, `amass_*`, `shodan_lookup`, `wayback_urls`, `tech_fingerprint`) | ❌ `nmap`, `subfinder`, `amass` **not installed** | ❌ `nmap_scan` returned **hardcoded `127.0.0.1:80,443`** for an arbitrary target — fabricated | **STUB** (mock data; no `os/exec` anywhere in source) |
| **security-bridge** (Go) | 8087 | not launched | ✅ `sqlmap`, `nmap` tools (real `os/exec`) | ❌ `sqlmap`, `nmap` **not installed** | ❌ would fail at runtime (missing binaries) | **BROKEN** (real code, no executables) |
| **payload-mcp** (Go) | 8083 | not launched | ✅ registered | n/a | not exercised (not in success criteria) | **UNVERIFIED** |
| **shodan-mcp / threat-intel-mcp** (Go) | 8085/8086 | not launched | ✅ registered | needs API keys | source returns mock/empty; keys unset | **STUB** (by source inspection) |
| **`mcp_stub.py`** (the launcher default for 8082–8098) | 8082-8098 | ✅ ready | ❌ `tools: []`, no `/mcp/execute` | n/a | no tools to execute | **STUB** (by design) |

## The critical finding

`launch_all.ps1` starts **`mcp_stub.py` on every MCP port (8082–8098)** — a pure no-op that answers `/health` and `/mcp/initialize` with an empty toolset. The **real** server implementations exist in the repo (`mcp-servers/go/cmd/*`, `mcp-servers/python/browser_mcp.py`) and were simply **never wired into the launch path**. So in the as-shipped runtime, the entire tooling layer is stubbed even though several real implementations are present and (as proven here) functional.

A second, subtler tier exists between "stub" and "real": **recon-mcp (Go)** registers a fully realistic tool surface but every handler returns hardcoded data. It passes a naive health+registration check yet executes nothing — the exact failure mode this validation is designed to catch.

## Capability vs success criteria

| Success criterion | Result | Evidence |
|-------------------|--------|----------|
| Recon MCP can execute a real tool | ❌ FAIL | recon-mcp returns hardcoded `nmap_scan` output; no `os/exec`; `nmap`/`subfinder` absent |
| Nuclei MCP can execute a real template run | ✅ PASS | `/mcp/execute` → 10 real findings, `template-id: http-missing-security-headers`, 2.6s |
| Browser MCP can execute a real Playwright navigation | ⚠️ PASS (capability) / blocked in `.venv` | Real Chromium nav HTTP 200 via system Python; `.venv` missing `playwright` |
| Burp MCP can execute a real API call | ✅ PASS | `send_http_request` proxied live HTTP 200 through Burp Suite |
| No heartbeat errors remain | ✅ PASS | `timedelta` import fixed; 0 errors over sustained runtime |
| No GraphMemory contract errors remain | ✅ PASS | `get_task_dependencies`/`get_task_dependents` implemented; 0 `graph_lookup_failed` |

---

## REMEDIATION UPDATE (2026-06-24, post-fix)

The sections above are the **original (as-found)** validation. After remediation the matrix changed as follows:

| MCP Server | Was | Now | What changed |
|-----------|-----|-----|--------------|
| recon-mcp | STUB (hardcoded mock) | **REAL** | Rewritten in native Go: TCP connect scan, HTTP probe+fingerprint, crt.sh subdomain enum, Wayback CDX. `nmap_scan(127.0.0.1)` now returns 24 *actual* open ports; reality probe = `real_execution_verified`. Old mock preserved as `main.go.mock.bak`. |
| nuclei-mcp | REAL (param bug) | **REAL** | Now honors `templates` (`-t`); targeted run 2.6s instead of full-set timeout. |
| browser-mcp | PARTIAL (no module in venv) | **REAL** | `playwright` installed in `.venv`; live navigation verified. |
| burp-mcp | REAL | **REAL** | unchanged. |

**Updated success-criteria result: 6/6 PASS.** Recon now executes real tools; browser runs under the API venv. See `TOOLING_CERTIFICATE.md`.

A new endpoint **`GET /health/tooling`** provides a live execution-level reality verdict per server, classifying each as `real_execution_verified` / `tools_registered` / `stub` / `suspect_mock` / `down`. Current snapshot: 4 real (recon, nuclei, burp, browser), 0 suspect-mocks, 7 auxiliary stubs (payload, shodan, threat-intel, security-bridge, source-map, cloud, turbo-intruder).
