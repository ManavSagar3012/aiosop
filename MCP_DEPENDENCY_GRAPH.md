# MCP Dependency Graph — AI-OSOP

> Generated: 2026-06-24  
> Purpose: Every MCP classified as REAL, PARTIAL, or STUB must be explainable by its dependency tree. This graph documents what each MCP needs, whether that dependency is present, and why the classification follows from the dependency state.

---

## Dependency Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ **Present** | Dependency is installed, reachable, and exercised in execution tests |
| ⚠️ **Optional** | Dependency improves fidelity but the MCP is operational without it (e.g., API key for enriched data) |
| ❌ **Missing** | Dependency is required for real execution but is not present; this is why the MCP is PARTIAL or STUB |
| 🚫 **Not Applicable** | Dependency is not relevant to this MCP's execution model |

---

## 1. recon-mcp (:8082) — ✅ REAL

```
recon-mcp (Go binary)
│
├── TCP Connect Scan (fallback)
│   └── ✅ Go net/tcp.Dial — built into Go runtime
│
├── nmap_scan tool
│   ├── nmap CLI binary
│   │   └── ✅ Installed on host (system PATH)
│   └── masscan CLI binary
│       └── ⚠️ Optional — not installed, but TCP fallback works
│
├── httpx_probe tool
│   ├── httpx CLI binary
│   │   └── ✅ Installed on host (system PATH)
│   └── fallback: Go net/http.Client
│       └── ✅ Go standard library
│
└── subdomain_enum tool
    ├── crt.sh REST API
    │   └── ✅ Public HTTPS endpoint (no key required)
    └── wayback CDX API
        └── ✅ Public HTTPS endpoint (no key required)
```

**Classification driver**: All critical dependencies are present. Fallbacks exist for missing optional tools. Output is input-dependent. → **REAL**

---

## 2. nuclei-mcp (:8084) — ✅ REAL

```
nuclei-mcp (Go binary)
│
└── scan / list_templates tools
    ├── nuclei CLI binary
    │   └── ✅ Present at C:\Users\HP\go\bin\nuclei.exe
    │   └── ❌ Was NOT in server PATH at startup (fixed during mission)
    │   └── ✅ PATH now prepended in launch_real.ps1
    │
    ├── Nuclei Templates Store
    │   └── ✅ 1,368+ templates on disk at C:\Users\HP\nuclei-templates\
    │
    └── Go os/exec + encoding/json
        └── ✅ Go standard library
```

**Classification driver**: Real binary executed. Templates are on disk. Output is input-dependent (severity filter honored, template paths real). → **REAL**

---

## 3. browser-mcp (:8091) — ✅ REAL

```
browser-mcp (Python + Playwright)
│
├── Playwright Python package
│   └── ✅ Installed in .venv (site-packages/playwright)
│
├── Chromium browser binary
│   └── ✅ Downloaded by `playwright install chromium`
│
├── Python asyncio + FastAPI
│   └── ✅ .venv runtime
│
└── Screenshot / DOM / Navigate actions
    └── ✅ Playwright drives real Chromium process
```

**Classification driver**: Real browser automation engine. Screenshot is a valid binary PNG. Navigation produces real DOM. → **REAL**

---

## 4. burp-mcp (:8081) — ✅ REAL

```
burp-mcp (Python + Burp Suite Professional)
│
├── Burp Suite Professional GUI application
│   └── ✅ Installed and running on host (operator-launched)
│
├── Burp MCP Extension
│   └── ✅ Loaded into Burp Suite
│
├── HTTPX client (Python)
│   └── ✅ .venv runtime
│
└── Proxy / Replay / Request tools
    └── ✅ Requests are proxied through Burp's live listener
```

**Classification driver**: Real proxy interception. Response bodies contain live timestamps from target. → **REAL**

---

## 5. source-map-mcp (:8096) — ✅ REAL

```
source-map-mcp (Python + HTTP client)
│
├── httpx / requests (Python)
│   └── ✅ .venv runtime
│
├── re (regex) + json (stdlib)
│   └── ✅ Python standard library
│
└── fetch_and_parse_sourcemap / analyze_sourcemap
    └── ✅ Real HTTP GET to target URL
    └── ✅ Regex extraction of sourceMappingURL
    └── ✅ JSON parse of .map file
```

**Classification driver**: Real HTTP fetch and parse. Output is input-dependent (empty arrays for non-JS input, populated for JS with sourcemap). → **REAL**

---

## 6. shodan-mcp (:8085) — ✅ REAL (Honest-Empty)

```
shodan-mcp (Go binary)
│
├── api.shodan.io REST API
│   └── ✅ Public HTTPS endpoint reachable
│
├── OSOP_SHODAN_API_KEY env var
│   └── ⚠️ Optional — absent on this host
│   └── Without key: returns honest error "missing OSOP_SHODAN_API_KEY or domain"
│   └── With key: would return real Shodan search results
│
└── Go net/http + encoding/json
    └── ✅ Go standard library
```

**Classification driver**: Makes real outbound HTTPS call. Error handling is honest (not fabricated). With API key, would return real data. → **REAL**

---

## 7. threat-intel-mcp (:8086) — ✅ REAL

```
threat-intel-mcp (Go binary)
│
├── cve_lookup tool
│   └── NVD API (services.nvd.nist.gov)
│       └── ✅ Public HTTPS endpoint, no key required
│       └── ✅ Returned 21KB real CVE JSON for Log4Shell
│
├── kev_check tool
│   └── CISA KEV JSON feed (cisa.gov)
│       └── ✅ Public HTTPS endpoint, no key required
│       └── ✅ Returned in_kev: true for Log4Shell
│
└── Go net/http + encoding/json
    └── ✅ Go standard library
```

**Classification driver**: Real REST API calls to authoritative government sources. Response is genuine and input-dependent. → **REAL**

---

## 8. security-bridge (:8087) — ⚠️ PARTIAL

```
security-bridge (Go binary)
│
├── nmap tool
│   ├── nmap CLI binary
│   │   └── ❌ NOT installed on Windows host
│   │   └── ❌ Returns honest error: "nmap not installed"
│   │   └── Install: https://nmap.org/download.html (Windows installer)
│   └── Go os/exec
│       └── ✅ Present
│
├── sqlmap tool
│   ├── sqlmap CLI binary
│   │   └── ✅ Installed in .venv (C:\Users\HP\OneDrive\Desktop\burp_mcp\ai-osop\.venv\Scripts\sqlmap.exe)
│   │   └── ✅ PATH updated in launch_real.ps1 to include .venv\Scripts
│   │   └── ✅ Real execution verified: sqlmap banner, legal disclaimer, connection test all present in output
│   └── Go os/exec
│       └── ✅ Present
│
├── ffuf tool
│   ├── ffuf CLI binary
│   │   └── ✅ Installed via `go install` (C:\Users\HP\go\bin\ffuf.exe)
│   │   └── ✅ PATH updated in launch_real.ps1 to include go\bin
│   │   └── ❌ Was FAKE: LookPath succeeded but returned "Real ffuf execution would happen here" without executing
│   │   └── ✅ FIXED: Rebuilt Go source to actually call exec.Command("ffuf", args...)
│   │   └── ✅ Real execution verified: ffuf banner v2.1.0-dev, URL, wordlist, progress all present in output
│   └── Go os/exec
│       └── ✅ Present
│
├── masscan tool ── ❌ STUB (hardcoded empty hosts array in Go source)
├── gobuster tool ── ❌ STUB (hardcoded empty found array)
├── nikto tool ── ❌ STUB (hardcoded empty vulnerabilities array)
├── wpscan tool ── ❌ STUB (hardcoded empty findings array)
├── katana_crawl tool ── ❌ STUB (hardcoded empty endpoints/js_files)
└── js_analyze tool ── ❌ STUB (hardcoded empty routes/secrets)
```

**Classification driver**: 3 tools attempt real execution but fail honestly due to missing binaries. 1 tool (`ffuf`) is a fake (returns simulated success instead of error). 6 tools are pure hardcoded stubs in the Go source. → **PARTIAL**

**Path to REAL**: Install `nmap`, `sqlmap`, `ffuf`. Rewrite 6 stub handlers in `mcp-servers/go/cmd/security-bridge/main.go` to call real binaries or remove their tool registrations.

---

## 9. turbo-intruder-mcp (:8098) — ❌ STUB

```
turbo-intruder-mcp (Python)
│
├── execute_single_packet_attack tool
│   ├── Target URL (parameter)
│   │   └── 🚫 NEVER contacted — tool ignores the URL
│   ├── HTTP method (parameter)
│   │   └── 🚫 IGNORED — always returns same result
│   └── Implementation
│       └── ❌ asyncio.sleep(0.1) — synthetic latency
│       └── ❌ Fixed response_bytes = 15 — hardcoded {"status":"ok"}
│
├── execute_spa_race tool
│   ├── concurrent_requests (parameter)
│   │   └── 🚫 IGNORED — only affects asyncio.sleep duration slightly
│   └── Implementation
│       └── ❌ asyncio.sleep(0.5) — synthetic latency
│       └── ❌ Same hardcoded 15-byte response
│
└── httpx / aiohttp (Python)
    └── ✅ Present in .venv but NOT USED by the handler
```

**Classification driver**: No real HTTP requests are made to the target. Latency is fake. Response is identical for all inputs. → **STUB**

**Path to REAL**: Rewrite handlers to use `httpx` or `aiohttp` to send actual concurrent requests to the target URL, or wrap a real tool like `ffuf -t` or `race-the-web`.

---

## 10. payload-mcp (:8083) — ❌ STUB

```
payload-mcp
│
├── Option A: Go binary (payload-mcp.exe) — NOT STARTED (deliberately)
│   ├── generate_payload tool
│   │   └── ❌ Returns <script>alert('mock-xss')</script> for EVERY vuln_type
│   ├── mutate_payload tool
│   │   └── ❌ Returns same hardcoded payload regardless of input
│   └── evaluate_fitness tool
│       └── ❌ Returns fitness = 0.8 for EVERY input
│   └── Classification: MOCK (masquerades as real but is hardcoded)
│
├── Option B: Python stub (mcp_stub.py) — CURRENTLY RUNNING
│   └── Returns tools: [] — honest about being a stub
│
└── Option C: Real engine (NOT WIRED)
    └── src/ai_osop/payload_engine/engine.py
        └── ✅ 20KB real implementation exists
        └── ❌ No MCP server exposes it
        └── ❌ No import path from any MCP to this engine
```

**Classification driver**: The only available MCP server is a mock with hardcoded output. The real engine exists but is unreachable. The honest stub is preferable to the mock. → **STUB**

**Path to REAL**: Create a new Python MCP server (`payload_mcp_server.py`) that imports `from ai_osop.payload_engine.engine import PayloadEngine` and exposes `generate_payload`, `mutate_payload`, `evaluate_fitness` as real tools. Remove the Go binary from the build pipeline.

---

## 11. cloud-mcp (:8097) — ❌ STUB

```
cloud-mcp (Python)
│
├── analyze_iam_trust_policies tool
│   ├── AWS account_id (parameter)
│   │   └── 🚫 IGNORED — always returns same hardcoded ARN
│   └── Implementation
│       └── ❌ arn:aws:iam::123456789012:role/Admin (hardcoded)
│       └── ❌ No boto3 call, no AWS credential check
│
├── discover_privesc_paths tool
│   ├── AWS account_id (parameter)
│   │   └── 🚫 IGNORED — always returns same hardcoded graph
│   └── Implementation
│       └── ❌ Hardcoded "Admin" -> "S3FullAccess" -> "DataBucket" path
│
└── boto3 / azure-identity / google-cloud (Python)
    └── ❌ NOT installed in .venv
    └── ❌ NOT used by the handler
```

**Classification driver**: No live cloud API calls. All outputs are hardcoded. Input parameters are ignored. → **STUB**

**Path to REAL**: Install `boto3`, `azure-identity`, `google-cloud`. Implement handlers that call real IAM APIs with proper credential handling. Return honest errors when credentials are missing (like shodan-mcp does).

---

## 12. session-memory-mcp (:8090) — ❌ STUB

```
session-memory-mcp (Python)
│
├── store_session_data tool
│   └── ❌ Returns "Operation successful (Simulated)" — no Redis write
│
├── retrieve_session_data tool
│   └── ❌ Returns "Operation successful (Simulated)" — no Redis read
│
├── delete_session_data tool
│   └── ❌ Returns "Operation successful (Simulated)" — no Redis delete
│
└── Redis / PostgreSQL connections
    ├── redis-py
    │   └── ✅ Installed in .venv
    └── asyncpg
        └── ✅ Installed in .venv
    └── ❌ NOT imported or used by session_memory_mcp.py
```

**Classification driver**: Database libraries are present but unused. All operations are no-ops with simulated success messages. Data is not persisted. → **STUB**

**Path to REAL**: Import `redis.asyncio` or `asyncpg`. Connect to the configured Redis/Postgres URIs from `OSOP_REDIS_URI` / `OSOP_POSTGRES_URI`. Implement actual CRUD operations. Return real data or honest connection errors.

---

## 13. reporting-mcp (:8092) — ❌ STUB

```
reporting-mcp (Python)
│
├── generate_report tool
│   └── ❌ Returns fake URL: http://localhost:8200/reports/{eng_id}.pdf
│   └── ❌ No PDF generation, no file written
│
├── submit_report tool
│   └── ❌ Returns "Report submitted to simulated platform"
│   └── ❌ No real HackerOne / Bugcrowd API call
│
└── PDF engine / ReportLab / WeasyPrint
    └── ❌ NOT installed in .venv
    └── ❌ NOT used by reporting_mcp.py
```

**Classification driver**: No report files are generated. URLs are fabricated. No real platform submission occurs. → **STUB**

**Path to REAL**: Install `reportlab` or `weasyprint`. Generate actual PDFs to a configurable directory. Wire to `bug_bounty_adapter.py` for real platform submission (with `OSOP_BUG_BOUNTY_SIMULATION=false` gating).

---

## 14. attack-graph-mcp (:8093) — ❌ STUB

```
attack-graph-mcp (Python)
│
├── query_graph tool
│   └── ❌ Returns empty nodes + edges + "Graph query executed (Simulated)"
│
├── add_node tool
│   └── ❌ Returns "Operation successful (Simulated)"
│
├── add_edge tool
│   └── ❌ Returns "Operation successful (Simulated)"
│
└── Neo4j Python driver (neo4j)
    ├── ✅ Installed in .venv (via `pip install neo4j` or similar)
    └── ❌ NOT imported or used by attack_graph_mcp.py
    └── ❌ No connection to OSOP_NEO4J_URI
```

**Classification driver**: Graph database driver is present but unused. All graph operations are no-ops. No data is persisted to Neo4j. → **STUB**

**Path to REAL**: Import `neo4j`. Connect to `OSOP_NEO4J_URI`. Implement Cypher `MATCH`/`CREATE` queries. Return real graph data or honest connection errors.

---

## Cross-MCP Dependency Map

```
AI-OSOP Core Platform
│
├── API Gateway (FastAPI, port 8200)
│   └── ✅ Mature
│
├── Orchestrator
│   └── ✅ Mature
│
├── Agent Ecosystem
│   └── ✅ Mature
│
├── Memory Tiers
│   ├── Redis (Hot)
│   │   └── ✅ Docker container running
│   ├── PostgreSQL + pgvector (Warm)
│   │   └── ✅ Docker container running
│   └── Neo4j (Graph)
│       └── ✅ Docker container running
│
└── MCP Adapters (14 servers)
    ├── REAL Layer (7) ── Core Offensive Workflow
    │   ├── recon-mcp ──→ nmap, httpx, crt.sh, wayback
    │   ├── nuclei-mcp ──→ nuclei CLI, templates
    │   ├── browser-mcp ──→ Playwright, Chromium
    │   ├── burp-mcp ──→ Burp Suite Professional, MCP extension
    │   ├── source-map-mcp ──→ httpx, regex, json
    │   ├── shodan-mcp ──→ api.shodan.io, API key (optional)
    │   └── threat-intel-mcp ──→ NVD API, CISA KEV feed
    │
    ├── PARTIAL Layer (1) ── Bridge with Missing Bricks
    │   └── security-bridge ──→ nmap ❌, sqlmap ❌, ffuf 🚫 (fake), 6 stubs ❌
    │
    └── STUB Layer (6) ── Simulation Only
        ├── turbo-intruder-mcp ──→ asyncio.sleep ❌ (no raw sockets)
        ├── payload-mcp ──→ engine.py exists ✅ but unwired ❌
        ├── cloud-mcp ──→ boto3 ❌, hardcoded ARNs ❌
        ├── session-memory-mcp ──→ redis-py ✅ but unused ❌
        ├── reporting-mcp ──→ reportlab ❌, fake URLs ❌
        └── attack-graph-mcp ──→ neo4j driver ✅ but unused ❌
```

---

## Dependency → Classification Rules

| Rule | Classification | Example |
|------|---------------|---------|
| All critical deps present + exercised → output varies by input | **REAL** | recon-mcp, nuclei-mcp, browser-mcp |
| All critical deps present but optional dep missing → honest-empty behavior | **REAL** | shodan-mcp (no API key → honest error) |
| Some critical deps present + some missing → honest errors for missing, stubs for others | **PARTIAL** | security-bridge (nmap/sqlmap missing → honest error; 6 tools are pure stubs) |
| Critical deps present in environment but NOT used by handler → simulated output | **STUB** | session-memory-mcp (redis-py installed but unused) |
| Critical deps missing + handler returns hardcoded data regardless of input | **STUB** | turbo-intruder-mcp (no HTTP client used; fixed response), cloud-mcp (no boto3; hardcoded ARNs) |
| Real implementation exists elsewhere but unwired to MCP server | **STUB** | payload-mcp (engine.py exists but no MCP server imports it) |

---

## Quick-Reference: Install Commands to Promote PARTIAL → REAL

| MCP | Dependency | Install Command | Platform |
|-----|-----------|----------------|----------|
| 8 | security-bridge | `nmap` | ❌ Missing | Download installer from https://nmap.org/download.html | Windows |
| 8 | security-bridge | `sqlmap` | ✅ **Fixed** | `.venv\Scripts\pip.exe install sqlmap` + PATH update in `launch_real.ps1` | Cross-platform |
| 8 | security-bridge | `ffuf` | ✅ **Fixed** | `go install github.com/ffuf/ffuf/v2@latest` + Go source rebuild + PATH update | Cross-platform |
| payload-mcp | Payload Engine | Wire `src/ai_osop/payload_engine/engine.py` into a new Python MCP server | Code change |
| cloud-mcp | boto3 | `.venv\Scripts\pip.exe install boto3` | Cross-platform |
| session-memory-mcp | redis-py | Already installed; **wire it** into `session_memory_mcp.py` | Code change |
| reporting-mcp | reportlab | `.venv\Scripts\pip.exe install reportlab` | Cross-platform |
| attack-graph-mcp | neo4j | Already installed; **wire it** into `attack_graph_mcp.py` | Code change |

---

## Notes

- "Honest-empty" (like shodan-mcp without an API key) is **REAL** because the server attempted a real connection and failed gracefully. A stub would return fabricated data or a generic success message.
- "Library installed but unused" (like redis-py for session-memory) is **STUB** because the presence of the dependency does not matter if the handler never calls it.
- The dependency graph is the **single source of truth** for why an MCP is classified the way it is. If a dependency is installed later, the MCP should be re-tested and re-classified.
