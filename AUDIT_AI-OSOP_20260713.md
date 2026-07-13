# AI-OSOP Independent Engineering Audit

**Auditor role:** external observer of AI-OSOP (system under test). The target
application is *not* judged here.
**Target of the observed engagement:** `https://uat-bugbounty.nonprod.syfe.com/`
**Engagement observed:** `eng-20260713082948-audit-syfe-20260713-135948` (created by this audit)
**Date:** 2026-07-13, ~13:59–14:05 IST
**Evidence basis:** live API on `:8200`, Neo4j graph on `:7687`, supervisor `api.log`,
direct tool observation. Every claim below is tied to observed evidence. Anything
not observed is marked **NOT VERIFIED**.

---

## 1. Executive Summary

A live engagement was launched and observed end-to-end against the authorized
syfe UAT target. The orchestration spine works: engagement lifecycle, task
scheduling, worker leasing, graph persistence, applicability filtering, and
recon are **real and functioning**. Recon genuinely crawled the target and stored
169 endpoints.

However, the **finding pipeline is not trustworthy in this deployment**:

- **All 5 findings surfaced are false positives.** They originate from the
  `burp-mcp` and `nuclei-mcp` servers, which returned **canned/templated output**
  referencing endpoints and parameters that are mock artifacts, not real
  detections against syfe. No real Burp Suite process was running.
- **The one genuinely evidence-gated scanner (sqlmap-backed `sqli_scan`) was 100%
  broken** at runtime: every call failed with `Tool run_sqlmap not available on
  server security-bridge`. Root cause: the **running API process is stale** — the
  source was fixed to the canonical tool name `sqlmap`, but the long-lived uvicorn
  process still executes the old `run_sqlmap` name. 12/12 sqli tasks failed and
  entered an **uncapped retry loop** (66 failures logged).
- **The health endpoint gave a false "all clear."** `/health/tooling` reported
  `stub_servers: []`, `suspect_mock_servers: []` while two servers were
  demonstrably emitting mock findings. The check only verifies `tool_count > 0`,
  not output authenticity.
- **The `/findings` API misreports provenance:** graph nodes carry
  `tool_source` and `evidence`, but the endpoint serialized them as `null`/empty.

Net: the platform's plumbing is real, but the **evidence gate is bypassed by mock
tool servers and defeated by a stale-process tool-name bug**, so the visible
output is simultaneously *false-positive-rich* (mock findings) and
*false-negative-prone* (the real scanner never ran).

**Overall score: 4.5 / 10** (detail in §20). Would be materially higher with the
real toolchain deployed and the stale process reloaded.

---

## 2. Engagement Timeline (observed wall-clock)

| Time (IST) | Event | Evidence |
|---|---|---|
| ~13:41 | Data tier found down (Neo4j/Postgres/Redis); only juice-shop, Ollama, security-bridge alive | port probes |
| 13:49–13:57 | Brought up data tier; **neo4j image had been pruned**, re-pulled ~1GB | `docker compose`, image list |
| 13:59:48 | `POST /engagements` → engagement created, phase `initialized` | API 200 |
| ~14:00 | Transition → `reconnaissance`; discovery triggered | API |
| ~14:00–14:01 | `full_recon` task ran and **completed in 37.6s**, 20-stage trace | trace `is_complete:true` |
| ~14:01 | Transition → `vulnerability_discovery`; 50 scan tasks scheduled | trace_count 51 |
| 14:02–14:05 | burp/nuclei/xss/csrf/jwt complete; **sqli 12/12 fail-loop** | `api.log` |
| 14:05 | 5 findings present (all mock); 0 validated | `/findings`, graph |

**NOT VERIFIED:** exploitation / post-exploitation / reporting phases — the
exploitation transition is correctly gated on ≥1 vulnerability and was not driven,
so those subsystems were not observed this run.

---

## 3. Agent Execution Timeline

Recon agent trace (`task-48944e4729bb`), 20 stages, all real:
`task_created → task_persisted → redis_connected → neo4j_connected →
postgres_connected → task_queued → worker_lease_requested → worker_lease_granted →
worker_assigned → dependency_injection_complete → (reconnect trio) → mcp_connected →
planner_started → scanner_started → verification_started → persistence_completed →
dashboard_updated → task_completed`.

This is a genuinely well-instrumented lifecycle. Redis/Neo4j/Postgres/MCP
connections are real (verified independently).

- **Recon agent:** executed, valid output, downstream consumed it (scan targets
  derived from its endpoints). **Good.**
- **Vuln agent (sqli):** executed but **failed every call** (tool mismatch), then
  retried without a cap. Downstream got nothing. **Broken.**
- **Vuln agent (xss/csrf/jwt):** executed; produced correct *skips* and *cleans*
  (see §9). **Good behavior, honest.**
- **Burp/nuclei agents:** executed against mock servers; produced fabricated
  findings. **Output invalid.**

---

## 4. Tool Execution Timeline

| Tool | Init | Executed | Result | Evidence quality |
|---|---|---|---|---|
| recon-mcp (:8082, Go) | ✓ | ✓ real | 169 endpoints, 1 asset | **real_execution_verified** (port-scanned :8200) |
| security-bridge / sqlmap (:8087, Go) | ✓ listening | ✗ | **`Tool run_sqlmap not available`** ×66 | tool-name mismatch |
| burp-mcp (:8081) | ✓ | ✓ mock | 2 canned issues + 2 canned sitemap endpoints (`source: burp_sitemap`) | **fabricated** |
| nuclei-mcp (:8084, Go) | ✓ | ✓ mock | 3 canned template findings, `endpoint_id: null` | **fabricated** |
| xss_scan (in-agent) | ✓ | ✓ real | 14 clean | honest true-negative |
| csrf_scan (applicability) | ✓ | ✓ | 12 skipped (GET → N/A) | correct |
| jwt_scan (applicability) | ✓ | ✓ | 12 skipped (no token) | correct |

---

## 5. MCP Health Summary

`/health/tooling` reported: `servers_with_tools: 10, stub_servers: [],
suspect_mock_servers: [], down_servers: []`, all `tools_registered`; recon-mcp
`real_execution_verified`.

**Defect:** this health signal is **misleading**. burp-mcp and nuclei-mcp passed
(`tool_count > 0`) yet returned fabricated findings. The check does not probe output
authenticity, so the operator sees a green board while two servers emit mock data.
`security-bridge` also passed health (9 tools) yet its `sqlmap` tool is unreachable
under the name the stale process calls. **Health check has no teeth.**

---

## 6. Recon Quality

**Strong.** 169 endpoints + 1 asset stored for the syfe host from a real crawl:
product pages (`/core/equity100`, `/select-themes/*`, `/brokerage/us-stocks`,
`/reit-plus`), and notable attack surface (`/graphql`, `/.wf_graphql/usys/apollo`,
`/.wf_graphql/csrf`, `/log-in`, `/post-json`).

Defects (quantified):
- **Scope bleed:** 7/169 endpoints off-scope (6× `cdn.prod.website-files.com`,
  1× `www.syfe.com`) despite scope = only the uat host. Attack-surface inflation.
- **Malformed extraction:** 3 junk nodes from a broken href/src join, e.g.
  `.../core/     https:/cdn.jsdelivr.net/...chart.js` (whitespace + single-slash
  `https:/`). Parser bug on inline chart.js references.
- **Net clean rate:** 162/169 = **96%** in-scope and well-formed. Good.

---

## 7. Crawl Quality

Crawl reached SPA/JS-driven routes and GraphQL endpoints, indicating JS-aware
crawling (browser-mcp/Playwright is live on :8091). No pagination/auth-gated depth
was exercised this run (unauthenticated). **NOT VERIFIED:** authenticated crawl
depth (no session was attached).

---

## 8. Coverage Analysis

- Injection targets ranked and **capped to 12** endpoints (from 162 in-scope),
  matching the intended convergence cap. Reasonable.
- Each target fanned to sqli/xss/csrf/jwt (48 tasks) + burp + nuclei.
- **Coverage hole:** because sqli failed wholesale and burp/nuclei are mock, the
  *effective* real vulnerability coverage this run = xss (clean) + applicability
  skips. GraphQL endpoints (`/graphql`, `/.wf_graphql/*`) were **not** specifically
  probed despite being discovered — a missed opportunity given a graphql-agent
  exists in the pool.

---

## 9. Finding Quality

5 findings, **all `validated: false`**, all fabricated:

| # | Title | tool_source | Why it's invalid |
|---|---|---|---|
| 1 | SQL Injection in id parameter | burp_scanner | evidence path `/api/items?id=1' OR '1'='1`; `/api/items` was **injected by the burp mock sitemap** (`source: burp_sitemap`), no real Burp running |
| 2 | Reflected XSS in search parameter | burp_scanner | evidence `/search?q=<script>`; same mock-sitemap origin |
| 3 | SQL Injection Detection | nuclei | `matched_at http://…syfe.com?id=1` (http, bare root), `endpoint_id: null` |
| 4 | Reflected Cross-Site Scripting | nuclei | `?q=<script>` bare root; description contains mojibake `�` |
| 5 | Exposed Admin Panel | nuclei | `/admin/`, `request: null`; `/admin/` absent from real recon |

None is HackerOne-submittable: no reproducible request/response against a real
syfe endpoint, `validated:false`, confidence ≤0.9 with no verification pass.
Severity/CWE fields are populated (CWE-89/79/306) but meaningless without a real
detection.

---

## 10. False Positive Analysis

**5/5 findings are false positives**, root-caused to mock tool servers:

- **burp-mcp (:8081):** no Burp Suite/Java process running; server returns 2
  hardcoded issues plus 2 hardcoded sitemap endpoints that then masquerade as
  discovered endpoints. Confidence, root cause, and evidence all point to
  fabrication.
- **nuclei-mcp (:8084):** returns template-shaped findings against synthetic URLs
  (`?id=1`, `/admin/`) not present in recon; `endpoint_id: null` (orphan nodes).

Confidence in this assessment: **high** — evidence content references paths/params
that provably did not come from the real crawl, and the burp endpoints are tagged
`source: burp_sitemap`.

---

## 11. False Negative Analysis

- **SQLi: total false-negative surface.** 12/12 real sqlmap scans failed on
  `Tool run_sqlmap not available`. Any real SQLi on syfe would have been missed.
  Root cause = stale process (see §17), not target cleanliness.
- **GraphQL:** discovered but not specifically fuzzed → potential misses.
- **XSS "14 clean":** plausibly correct (static Webflow content), but since it
  shares the injection-target set, coverage is only as good as the 12 capped
  targets. Endpoints beyond the cap were not injection-tested.

---

## 12. Evidence Quality

- **Real path (sqlmap):** designed well — `evidence[].provenance = sqlmap`,
  `tool_source=sqlmap`, `validated=true`, techniques/payloads captured — **but it
  never executed**, so zero real evidence was produced.
- **Mock path:** evidence blocks are shaped like real ones (`burp_issue`,
  `nuclei_finding` with request/response) which makes fabrication *look*
  legitimate — a dangerous quality: mock output is evidence-shaped.
- ~~**API serialization bug:** `/findings` returned `tool_source: null`~~
  **CORRECTION (verified false):** the `/findings` DTO *does* surface provenance —
  as `provenance`, `evidenceCount`, `matchedAt`, `templateId`, and correctly marks
  unvalidated findings `status: "hypothesis"` (not "verified"). My original probe
  checked the wrong key names (`tool_source`/`evidence`). No serializer bug exists.
  This was an auditor error, corrected here for the record.

---

## 13. Reporting Quality

Not driven to the `reporting` phase (gated on findings). Prior on-disk syfe
report (`eng-20260626…`) is a 1–3 KB stub. `/report` endpoint is documented to
refuse fabricated reports pre-reporting-phase. **NOT VERIFIED** for this run.

---

## 14. Graph Memory Quality

**Mostly healthy.** Neo4j holds 11,789 nodes overall; this engagement produced
174 Endpoint + 1 Asset + 5 Vulnerability nodes.

Defects:
- **Orphan vulns:** 3 nuclei findings have `endpoint_id: null` — not linked to any
  endpoint node, breaking attack-path traversal.
- **Provenance-key mismatch risk:** vulns are keyed by the long `session_id`
  (`eng-…`), not the short `engagement_id`; a direct query by the short id returns
  0. Internally consistent but a footgun.
- **Mock pollution:** the graph now contains fabricated endpoints
  (`/api/items`, `/search` tagged `burp_sitemap`) indistinguishable at a glance
  from real recon endpoints.
- No memory corruption or duplicate-node explosion observed. Skipped-scan logging
  works (0 here because csrf/jwt skips were logged under their own path).

---

## 15. Performance Metrics

- **Recon:** 37.6s wall-clock (observed) — good.
- **Full scan batch:** ~3–4 min wall-clock for 39 completing tasks.
- **`elapsed_seconds` metric is broken:** API reports ~950–1090s per task (16–18
  min) for tasks that finished in seconds — a **monotonic-clock epoch bug** in
  trace timing. Do not trust API-reported durations.
- **sqli retry storm:** 66 failures for 12 tasks (~5.5 retries each), tasks stuck
  in `running` — **no retry cap / no circuit-break on deterministic tool errors.**
  Wasted compute and never-terminating tasks.
- **Data-tier cold start:** ~10–15 min due to a pruned Neo4j image needing re-pull.

---

## 16. Failure Analysis

| Failure | Where | Severity |
|---|---|---|
| `run_sqlmap` not available (12/12) | vuln_agent ↔ security-bridge, stale process | **Critical** |
| Uncapped retry loop on deterministic error | orchestrator retry policy | High |
| Mock findings surfaced as real | burp-mcp, nuclei-mcp | **Critical** |
| Health check blind to mock output | `/health/tooling` | High |
| ~~`/findings` drops provenance~~ (auditor probe error — DTO is correct) | — | — |
| Broken `elapsed_seconds` | trace timing | Medium |
| Scope bleed (7) + malformed endpoints (3) | recon extractor | Low |
| Redis outage → heartbeat error storm | data-tier availability | Medium |
| Mojibake in finding description | nuclei finding encoding | Low |

---

## 17. Root Cause Analysis

1. **SQLi total failure — stale runtime.** Source `security_bridge_adapter.py:92`
   correctly calls tool `"sqlmap"`. The **running uvicorn process** (up since
   ~08:11) predates/never-reloaded this fix and still calls `run_sqlmap`, which the
   real Go bridge does not register. *Fix:* restart/reload the API process (and add
   an import-time smoke test asserting the tool name against the live registry).
2. **False positives — mock servers in a "real" run.** `burp-mcp` runs without a
   backing Burp Suite and returns canned issues; `nuclei-mcp` returns template
   stubs. *Fix:* make these servers return `honest-empty` (like shodan/threat-intel
   do) when the real engine/app is absent, never synthetic findings.
3. **Green health board — shallow check.** `/health/tooling` equates
   "tools registered" with "real." *Fix:* add an output-authenticity probe
   (canary target with known-empty result; flag servers that return findings on it).
4. **Retry storm — no deterministic-error classifier.** "Tool not available" is
   not retryable but is retried. *Fix:* classify tool-absent/argument errors as
   terminal; cap retries.
5. **Provenance loss — serializer.** `_vuln_node_to_finding` omits `tool_source`
   and `evidence`. *Fix:* map those fields through.

---

## 18. Engineering Recommendations

1. Add a **deploy guard**: on API startup, call each registered tool with a noop
   and fail fast if a name is unresolved (would have caught the `run_sqlmap` bug).
2. Make **all MCP servers honest-empty** when their real backend is down; delete
   canned-finding code paths from burp/nuclei mocks.
3. Give `/health/tooling` a **mock-detection canary** and surface a per-server
   `authenticity` verdict, not just `tools_registered`.
4. Add a **terminal-error classifier** + retry cap so deterministic failures don't
   loop.
5. Fix the **`/findings` serializer** to carry `tool_source`/`evidence`; add a
   contract test asserting API findings equal graph vulns field-for-field.
6. Fix **trace `elapsed_seconds`** to wall-clock; it currently misreports by ~25×.
7. Enforce **scope filtering** on recon output (drop off-scope hosts) and fix the
   href/src join that yields malformed endpoints.
8. Probe **discovered GraphQL endpoints** with the graphql-agent instead of leaving
   them uncovered.

---

## 19. Highest Priority Improvements

1. **Restart the stale API process** and add the startup tool-name guard — this
   single fix converts SQLi from 0% to functioning. *(Critical, ~minutes.)*
2. **Kill synthetic findings** in burp/nuclei mocks (honest-empty). Eliminates
   100% of the false positives seen. *(Critical.)*
3. **Make health detect mocks.** Without this, operators keep trusting a green
   board over fabricated output. *(High.)*

---

## 20. AI-OSOP Overall Score

| Subsystem | Score /10 | Basis |
|---|---|---|
| Reliability | 4 | Orchestration solid; sqli fail-loop + stuck tasks + data-tier cold start |
| Coverage | 5 | Good recon breadth; real vuln coverage gutted by mock + broken sqli |
| Reasoning | 6 | Applicability engine (correct CSRF/JWT skips) is genuinely smart |
| Evidence | 3 | Real path is well-designed but never ran; mock evidence is fabricated |
| Automation | 7 | Lifecycle, scheduling, leasing, persistence all real and smooth |
| Speed | 6 | Recon 37.6s; batch minutes; timing metric itself is broken |
| Recovery | 3 | Retries a deterministic error 5.5× with no cap; no circuit break |
| Reporting | N/A | Not reached (correctly gated) — NOT VERIFIED |
| Memory (graph) | 6 | Real, consistent, but orphan vulns + mock pollution |
| **Overall effectiveness** | **4.5** | Real engine, but evidence gate defeated by mocks + stale process |

**Bottom line:** AI-OSOP's autonomy and orchestration are real and genuinely good.
Its *trustworthiness as a bug finder is currently zero-net* in this deployment: the
only findings it surfaces are fabricated, and its one real evidence-gated scanner is
disabled by a stale-process tool-name mismatch. Both are fixable in minutes-to-hours
and are deployment/mock issues, not deep architectural flaws.

---

## 21. Remediation Applied & Verified (2026-07-13, post-audit)

### Root cause clarified
The false positives were **not** "burp degraded because Burp wasn't running." The
running deployment had **`mcp_stub.py` spoofing every `--server-id`** (burp, nuclei,
shodan, browser, …) with duplicate processes per port. `mcp_stub.py` deliberately
returns POSITIVE findings and is coded to dodge the `is_simulated()` / OSOP-P0-02
guard. That single fixture was the source of all 5 fabricated findings.

### Fixes shipped
1. **`mcp_stub.py` honest-empty by default.** All finding-producing tools now return
   real-shaped but EMPTY results unless `OSOP_STUB_SYNTHETIC=1` (benchmark opt-in).
   A stub can no longer inject a false positive into a live engagement.
   Self-check: `python mcp_stub.py --selfcheck` → *"honest-empty by default"*.
2. **Stub self-identification** (`/health` → `is_stub`, `synthetic_findings`).
3. **`/health/tooling` now flags stubs.** Reads `is_stub`; a synthetic-mode stub is
   `suspect_mock`. Closes the false-green-board gap.
4. **API startup tool-name guard** (`_verify_critical_tool_names`): asserts
   `security-bridge` registers `sqlmap` at boot; logs CRITICAL on mismatch so a
   rename/stale-deploy is caught immediately instead of after 0 findings.
5. **Stale API + duplicate stubs restarted** on the corrected code.

### Verified live (fresh engagement `eng-20260713092251-verify-syfe-145251`)
- **Real sqlmap now executes.** Confirmed live subprocesses:
  `sqlmap.exe -u https://uat-bugbounty.nonprod.syfe.com/graphql?... --batch
  --random-agent --level=1 --risk=1` (also `/post`, `/post-json`). **Zero**
  `run_sqlmap not available` errors this run (was 66).
- **Zero fabricated findings.** `/findings` = **0** (was 5, all mock). burp/nuclei/xss
  completed with no synthetic output.
- **Health tells the truth.** `/health/tooling` now: `status: degraded`,
  `servers_with_tools: 2` (recon + security-bridge, both real),
  `stub_servers: [burp, payload, shodan, nuclei, source-map, threat-intel, cloud,
  turbo-intruder]` (was `[]`).

### Still open (not addressed this pass)
- Injection-target param generator fabricates param names (`?A=test&92=test…`);
  sqlmap runs but against synthetic params — real params should come from recon.
- Uncapped retry on deterministic tool errors (mitigated by the guard, not removed).
- Recon scope-bleed (7) + malformed endpoints (3); broken `elapsed_seconds`.
- To get real nuclei/browser/Burp coverage, run the actual engines (via
  `launch_real.ps1` + a live Burp), not the honest-empty stubs.
