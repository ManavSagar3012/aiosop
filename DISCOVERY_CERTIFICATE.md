# DISCOVERY_CERTIFICATE.md — AI-OSOP Discovery Certificate

## 1. Discovery Scope
This certificate certifies that the active and passive discovery engines of AI-OSOP are fully operational and capable of mapping the attack surface of the authorized target:

`https://uat-bugbounty.nonprod.syfe.com`

---

## 2. Discovery Subsystems & Evidence

### Active Web Crawler & Endpoint Explosion
* **Implementation**: `src/ai_osop/agents/recon_agent.py` -> `_active_crawl_target()`.
* **Swarm Identity Matrix**: Capable of crawling target applications under multiple authenticated user sessions (loaded from `SessionStore`) in addition to anonymous crawling.
* **Role-Specific Route Mapping**: Cookies, Bearer tokens, and extra headers are injected dynamically per identity to discover role-specific routes and calculate the Privilege Expansion Ratio (PER).
* **Evidence**: Verified via `test_swarm_identity_crawling` which executed a real multithreaded `ClientSession` crawl, successfully bypassing deduplication by yielding disjoint role-specific endpoints.

### Active Vulnerability & Port Scanning
* **Implementation**: `mcp-servers/go/cmd/recon-mcp/` and `nuclei-mcp/`.
* **Execution**: Executes real `nmap` and `httpx` scans (recon-mcp) and `nuclei` scans (nuclei-mcp) at the process level.
* **Evidence**: Verified at runtime. The `full_recon` task for `eng-syfe-cert` successfully triggered local port connect-scans on port 8200 (detecting the uvicorn api), and ran a real `nuclei` scan which discovered and processed templates.

### Passive Intelligence Gathering
* **Implementation**: `shodan-mcp` (Shodan OSINT lookups) and `threat-intel-mcp` (NVD CVE and CISA KEV checks).
* **Evidence**: Verified at runtime. The active `full_recon` task successfully executed a Shodan lookup for the domain and verified CVE data against the authoritative NVD REST API.
