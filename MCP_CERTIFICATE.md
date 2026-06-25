# MCP_CERTIFICATE.md — AI-OSOP MCP Reality Certificate

## 1. MCP Classification Matrix
Every Model Context Protocol (MCP) server registered in the platform has been audited at runtime. The classification matrix below reflects the actual execution status on 2026-06-25:

| # | MCP Server | Port | Classification | Verification / Evidence |
|---|---|---|---|---|
| 1 | **recon-mcp** | 8082 | ✅ **REAL** | Native TCP connect scan of port 8200; httpx probe returned real 404 + uvicorn tech; crt.sh/wayback active. |
| 2 | **nuclei-mcp** | 8084 | ✅ **REAL** | Executes local `nuclei` binary in PATH; lists 1,368+ templates on disk; honors template severity filters. |
| 3 | **browser-mcp** | 8091 | ✅ **REAL** | Drives a real Playwright/Chromium session; takes valid binary PNG screenshots of local targets. |
| 4 | **burp-mcp** | 8081 | ✅ **REAL** | Proxies HTTP traffic through a live Burp Suite Professional listener; returns dynamic target responses. |
| 5 | **source-map-mcp** | 8096 | ✅ **REAL** | Performs real HTTP GET to targets, parses regex, and extracts sourceMappingURL/sourcemap JSON. |
| 6 | **shodan-mcp** | 8085 | ✅ **REAL** | Makes real HTTPS requests to `api.shodan.io`; returns honest API key errors. |
| 7 | **threat-intel-mcp** | 8086 | ✅ **REAL** | Makes real REST calls to NVD (CVE-2021-44228 returned 21KB JSON) and CISA KEV JSON APIs. |
| 8 | **security-bridge** | 8087 | ✅ **REAL** | **REPAIRED**. Unregistered all 6 fake/stubbed tools in Go source. Repaired `ffuf` to execute the real local binary. Rebuilt Go binary. Now exposes 3 tools (`sqlmap`, `nmap`, `ffuf`) which all execute real binaries. |
| 9 | **turbo-intruder-mcp** | 8098 | ❌ **STUB** | Simulated race-condition responses (no raw sockets, synthetic sleep of 0.1s). |
| 10 | **payload-mcp** | 8083 | ❌ **STUB** | Stubbed to `mcp_stub.py`. Real Python engine exists but is unwired. Go mock binary is disabled. |
| 11 | **cloud-mcp** | 8097 | ❌ **STUB** | Stubbed to `mcp_stub.py`. AWS IAM trust policies are simulated. |
| 12 | **session-memory-mcp** | 8090 | ❌ **STUB** | Stubbed to `mcp_stub.py`. Core memory persistence handled natively in Python. |
| 13 | **reporting-mcp** | 8092 | ❌ **STUB** | Stubbed to `mcp_stub.py`. Core PDF generation handled natively in Python. |
| 14 | **attack-graph-mcp** | 8093 | ❌ **STUB** | Stubbed to `mcp_stub.py`. Core Neo4j graph operations handled natively. |

---

## 2. Integrity Assurances
* **Zero Masquerading**: No stub or mock binary is registered as "REAL" or "PARTIAL". All stubs are honestly registered via `mcp_stub.py` (returning `tools: []`), preventing any false-positive capabilities.
* **Security Bridge Remediation**: Rebuilt `security-bridge.exe` to completely purge the 6 fake tools (`masscan`, `gobuster`, `nikto`, `wpscan`, `katana_crawl`, `js_analyze`) from the protocol registration. The `ffuf` tool was rewritten from a mock string to a real subprocess execution.
