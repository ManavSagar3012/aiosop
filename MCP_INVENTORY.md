# MCP Inventory — AI-OSOP Reality Verification Mission

> Generated: 2026-06-24  
> Mission: Determine whether every advertised MCP is REAL or merely appears operational.

## Executive Summary

| MCP Name | Port | Process | Executable | Startup Script | Reality Classification | Dependency Chain |
|---|---|---|---|---|---|---|
| recon-mcp | 8082 | Go binary | `mcp-servers/go/recon-mcp.exe` | `launch_real.ps1` | **REAL** | `nmap` (TCP connect), `httpx` (probe), `curl` (crt.sh), `curl` (wayback) |
| nuclei-mcp | 8084 | Go binary | `mcp-servers/go/nuclei-mcp.exe` | `launch_real.ps1` | **REAL** | `nuclei` CLI (must be in PATH; found at `C:\Users\HP\go\bin\nuclei.exe`) |
| browser-mcp | 8091 | Python (Playwright) | `mcp-servers/python/browser_mcp.py` | `launch_real.ps1` | **REAL** | Playwright + Chromium (installed in `.venv`) |
| burp-mcp | 8081 | Burp Suite + ext | `Burp Suite` (external) | `launch_real.ps1` (operator-launched) | **REAL** | Burp Suite Professional with MCP extension |
| source-map-mcp | 8096 | Python | `mcp-servers/python/source_map_mcp.py` | `launch_real.ps1` | **REAL** | `httpx` (HTTP fetch), `re` + `json` (parse) |
| shodan-mcp | 8085 | Go binary | `shodan-mcp.exe` (root) | `launch_real.ps1` (fixed) | **REAL** | `api.shodan.io` REST API (needs `OSOP_SHODAN_API_KEY`) |
| threat-intel-mcp | 8086 | Go binary | `threat-intel-mcp.exe` (root) | `launch_real.ps1` (fixed) | **REAL** | NVD API (CVE), CISA KEV JSON (no key required) |
| security-bridge | 8087 | Go binary | `security-bridge.exe` (root) | `launch_real.ps1` (fixed) | **PARTIAL** | `nmap` (NOT installed), `sqlmap` (NOT installed), `ffuf` (NOT installed); masscan/gobuster/nikto/wpscan/katana/js_analyze are **STUBBED** in Go code |
| turbo-intruder-mcp | 8098 | Python | `mcp-servers/python/turbo_intruder_mcp.py` | `launch_real.ps1` | **STUB** | Pure Python simulation (no raw sockets, no `ffuf`/`race` engine) |
| payload-mcp | 8083 | **Stub** | `mcp_stub.py` | `launch_real.ps1` | **STUB** | Go binary is a **mock** (hardcoded `<script>alert('mock-xss')</script>`, fitness 0.8). Real engine exists at `src/ai_osop/payload_engine/engine.py` but is **unwired**. |
| cloud-mcp | 8097 | **Stub** | `mcp_stub.py` | `launch_real.ps1` | **STUB** | Python script returns hardcoded AWS IAM data (no live cloud API) |
| session-memory-mcp | 8090 | **Stub** | `mcp_stub.py` | `launch_real.ps1` | **STUB** | No real Redis/Neo4j connection; returns simulated message |
| reporting-mcp | 8092 | **Stub** | `mcp_stub.py` | `launch_real.ps1` | **STUB** | No real reporting pipeline; returns fake URL |
| attack-graph-mcp | 8093 | **Stub** | `mcp_stub.py` | `launch_real.ps1` | **STUB** | No real Neo4j graph; returns empty simulated graph |

### Notes
- **Launcher source**: `launch_real.ps1` is the canonical launcher; `launch_all.ps1` and `launch_all_mcp.ps1` are deprecated.
- **Stub loop**: `launch_real.ps1` previously started `mcp_stub.py` on ports 8083, 8085, 8086, 8087, 8090, 8092, 8093, 8097. Post-repair, ports 8085, 8086, 8087 now start real Go binaries; the remaining 5 stay stubbed.
- **nuclei PATH issue**: `nuclei-mcp.exe` shells out to `nuclei`. The binary is at `C:\Users\HP\go\bin\nuclei.exe` but was not in the system PATH. The launcher was repaired to prepend it before starting the server.
