# Self-Healing Fix: Discovery → Graph Persistence Gap

**Date:** 2026-06-24
**Issue ID:** AIOSOP-RECON-PERSIST-2026-06-24
**Verdict:** ✅ FIXED and verified with runtime evidence.

## Issue

Live engagements persisted **0 Endpoint nodes** (and sometimes 0 Asset nodes) to Neo4j, even though the recon-mcp tools demonstrably return real data. Discovery results were not reaching the graph.

| | Before fix | After fix |
|---|-----------|-----------|
| Assets persisted (fresh example.com recon) | 1 (fallback only) | **23** (real crt.sh subdomains) |
| Endpoints persisted | **0** | **1,025** (real URLs from active crawl + probe) |

## Root cause

`MCPRegistry` connections raise `MCP server <id> not initialized` (`mcp/protocol.py:246`) until `initialize_server()` is called. In `api/main.py::register_optional_mcp_servers`, initialization was gated behind a hardcoded `critical_mcps = {nuclei, source-map, cloud, turbo-intruder}` set — which **did not include recon-mcp, burp-mcp, or browser-mcp**.

Consequence:
- Every recon agent call to recon-mcp (`subfinder_enum`, `nmap_scan`, `httpx_probe`) raised "not initialized".
- `_execute_dns_enum` has a **fallback** (creates the base domain asset on failure) → assets limped along at 1.
- `_execute_service_probe` has **no fallback** → it swallowed the error into `endpoints = []` → 0 endpoints, always.

So the tools were real (provable directly via `/health/tooling/deep`), but the **agent→registry→tool path was dead** because the servers were never initialized.

## Fix

`api/main.py::register_optional_mcp_servers` now **initializes every reachable MCP server**, not just a hardcoded subset:
- Registration and initialization are separate try/except blocks (a stub/down server fails its own init without affecting others or startup).
- `critical_mcps` now governs only **log severity**, not whether a server is initialized.
- Servers that fail init are left registered-but-uninitialized and surfaced by `/health/tooling`.

## Verification (runtime)

1. Restarted API on the fix (`api.run5.log`).
2. Fresh recon engagement on `example.com` (benign, non-target):
   - Asset count climbed 11 → 21 → 23 as real crt.sh subdomains resolved and persisted.
   - **Endpoint count climbed 0 → 1,022 → 1,025** — real URLs (`https://example.com/`, `http://dev.example.com`, …) from the service-probe + active-crawl paths.
3. `/health/tooling/deep` still 4/4 `real_execution_verified`; no regression.

## Follow-up items (non-blocking)

- **Data hygiene:** crt.sh "intermediate" certificate common-names (e.g. `as207960 test intermediate - example.com`, contains spaces) are being treated as subdomains/endpoints. Add a hostname-validity filter in `recon-mcp crtshEnum` / `_deduplicate_subdomains` (reject values with spaces or non-DNS characters).
- **Resilience parity:** give `_execute_service_probe` the same graceful fallback/logging that `_execute_dns_enum` has, so a future tool outage is visible rather than silent.
- **Port-scan latency:** scanning many unresolvable subdomains incurs DNS-timeout cost; consider resolving first and skipping NXDOMAIN hosts.
