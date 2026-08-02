# AI-OSOP MCP Servers & Tool Health Audit Report

**Engagement ID:** `eng-20260714135632-syfe-live-v3`
**Engagement Target:** `https://uat-bugbounty.nonprod.syfe.com/`

---

## 1. MCP Server Connection Status & Errors

During the engagement, five targeted MCP servers were audited for connection status and error codes. All five failed to connect on their local ports due to a Connection Refused error (services not running locally on the workstation).

* **`browser-mcp` (Port `8091`)**: **FAILED**. Startup connection failed (attempt 1/1). On-demand connection attempts during XSS scans (attempts 1/6 to 5/6, then 6/6 exhausted) failed with `Cannot connect to host 127.0.0.1:8091 ssl:default [The remote computer refused the network connection]`. Once exhausted, the circuit breaker opened, leading to subsequent failures with `circuit breaker is open` or `MCP server browser-mcp not initialized`.
* **`payload-mcp` (Port `8083`)**: **FAILED**. Startup connection and all 6 retry attempts failed with `The remote computer refused the network connection`. Status logged: `registration/init failed`.
* **`threat-intel-mcp` (Port `8086`)**: **FAILED**. Startup connection and all 6 retry attempts failed with `The remote computer refused the network connection`. Status logged: `registration/init failed`.
* **`cloud-mcp` (Port `8097`)**: **FAILED**. Startup connection and all 6 retry attempts failed with `The remote computer refused the network connection`. Status logged: `registration/init failed`.
* **`turbo-intruder-mcp` (Port `8098`)**: **FAILED**. Startup connection and all 6 retry attempts failed with `The remote computer refused the network connection`. Status logged: `registration/init failed`.

*Note: `burp-mcp` (8081), `recon-mcp` (8082), and `nuclei-mcp` (8084) successfully registered on startup.*

---

## 2. Tool Execution Trace (Runtimes, Timeouts & Retries)

A total of **15 tasks** were audited across Postgres, Neo4j, and the logs:

1. **`full_recon` (`task-838b3107b54c`)**: Completed in **44 seconds** wall-clock. 0 retries. Successfully Crawled target, registering 255 raw endpoints (64 persisted in-scope).
2. **`sqli_scan` (`task-df4e5cedf2a6`, `task-879cc66707ef`, `task-462cce4676a4`)**: Completed in **9–12 seconds** active execution (44–51s wall-clock). 0 retries. Successfully executed real `sqlmap` against `/post`, `/log-in`, and `/post-json`. Result: Clean.
3. **`xss_scan` (`task-d39d01a996cf`, `task-93dab31e666a`, `task-0214f481d4fd`)**: Completed in **~2 seconds** active execution (44s wall-clock). 0 retries. Bypassed browser due to browser-mcp outage.
4. **`csrf_scan` (`task-3ee1cd4a24a3`, `task-7ad924794c96`, `task-a40fd5444c45`)**: Completed in **<1 second**. 0 retries. Bypassed by applicability checks.
5. **`jwt_scan` (`task-8deed774cb76`, `task-e8776dd1881d`, `task-cd656c6170b3`)**: Completed in **<1 second**. 0 retries. Bypassed by applicability checks.
6. **`burp_scan` (`task-f975620b86b6`)**: Completed in **<1 second**. 0 retries. Status degraded.
7. **`nuclei_scan` (`task-267c64833a89`)**: Stalled in `running` status (Postgres) after running for **48 seconds** due to API daemon crash/termination.

---

## 3. Degraded or Skipped Tool Executions

1. **`burp_scan` active scan null warning**: Montoya API failed with `Cannot invoke "burp.api.montoya.scanner.audit.Audit.addRequest(...)" because the return value of "burp.api.montoya.scanner.Scanner.startAudit(...)" is null`. Active scanning degraded completely.
2. **`xss_scan` browser-mcp connection refused**: Fell back to raw HTTP reflection checks due to `browser-mcp` (Playwright) being unreachable, creating a coverage gap for DOM-based XSS.
3. **`csrf_scan` GET method bypass**: Correctly skipped by the Applicability Engine (`Read-only HTTP method (GET); CSRF is not applicable`).
4. **`jwt_scan` no token bypass**: Correctly skipped by the Applicability Engine (`no token in scope`).
5. **`nuclei_scan` stalled due to daemon crash**: Task `task-267c64833a89` remained stalled/orphaned due to uvicorn termination at `19:30:06`.
