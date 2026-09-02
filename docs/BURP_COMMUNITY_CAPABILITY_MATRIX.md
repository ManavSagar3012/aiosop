# Burp Suite Community Capability Matrix — AI-OSOP Hybrid Integration

**Status:** Implemented and tested (BURP-COMMUNITY-001, 2026-08-31)
**Tests:** `tests/test_burp_community_workflow.py` (26 tests, mocked Community extension)

## Licensing posture (read this first)

AI-OSOP works **fully** with the free, legally usable **Burp Suite Community**
edition — **without bypassing Burp's licensing, without patching Burp
binaries, without unlocking paid features, and without making Burp impersonate
Pro**. Community is used strictly as licensed:

* Every API AI-OSOP calls on Community is one PortSwigger makes available to
  Community users through the official Montoya extension API.
* Capabilities PortSwigger sells as Pro (Scanner audits, Intruder attack
  execution, Collaborator, Organizer) are **never invoked on Community**. The
  platform *detects* their absence and routes that work to **AI-OSOP's own
  open-source / internally implemented components**.
* If you hold a valid Burp Pro license, the identical workflow automatically
  uses Burp's native engines — no configuration, no code change.

The single source of truth for the routing table is
`src/ai_osop/adapters/burp_capabilities.py` (`CAPABILITY_ROUTES`); a test
guard asserts this document stays in sync with it.

## How edition detection works

The extension (`burp-extension/`, v0.2.0) probes its own Burp at load time —
`Scanner.startAudit()` returns null on Community, `collaborator()` /
`organizer()` are Pro-only — and exposes the truth via the `get_version` MCP
tool. The Python adapter (`BurpMCPAdapter.get_capabilities()`) caches this
snapshot (120 s TTL) and resolves `edition_family`:

| Condition | `edition_family` | Active scanning runs on |
|---|---|---|
| Pro, scanner probe succeeded | `pro` | **Burp Scanner** (native crawl+audit) |
| Community, or any Burp without a working scanner | `community` | **nuclei-mcp + web_audit** (AI-OSOP engines) |
| burp-mcp unreachable | `unreachable` | **nuclei-mcp + web_audit**; Burp passive layer skipped, reason recorded |

Pre-v0.2.0 extensions (no `get_version`) are handled by an execution-level
fallback probe: `scan_target` answering `started` implies Pro; `probe_completed`
implies Community. Anything inconclusive fails safe to internal routing — the
worst case is a deduplicated duplicate scan, never a silent no-scan.

## Capability matrix — who provides what

| Capability | Burp Pro | Burp Community | Provided by (Community) |
|---|---|---|---|
| proxy_history | supported | supported | Burp (unchanged) |
| sitemap | supported | supported | Burp (unchanged) |
| live_traffic | supported | supported | Burp (unchanged) |
| http_engine | supported | supported | Burp (unchanged) |
| scope_sync | supported | supported | Burp (unchanged) |
| repeater_handoff | supported | supported | Burp (unchanged) |
| decoder_handoff | supported | supported | Burp (unchanged) |
| websockets | supported | supported | Burp (unchanged) |
| extension_persistence | supported | supported | Burp (unchanged) |
| **active_scan** | supported (Scanner.startAudit) | unavailable (Pro-only) | **nuclei-mcp + web_audit differential** |
| **intruder_attack_execution** | supported | UI tab only (attack run is Pro) | **burp(ui-handoff) + turbo-intruder-mcp + intruder_fuzz differential** |
| **collaborator_oob** | supported | unavailable (Pro-only) | **oast-mcp** |
| **organizer_findings_ui** | supported | unavailable (Pro-only) | **Neo4j attack graph + findings ledger** |

### Capability notes

* **active_scan** — Burp Scanner is Pro-only; on Community the `burp_scan`
  task routes active auditing to nuclei-mcp (template scan with catch-all
  false-positive triage, scope attribution, finding-intelligence dedup, SAN
  auto-chaining) and the deterministic web_audit differential engine
  (SQLi/XSS/SSTI probes with control baselines, form-POST surface,
  Playwright-rendered SPA pass, JS-bundle endpoint/secret extraction,
  session-replay for authenticated surface, OAST blind-SSRF confirmation).
* **intruder_attack_execution** — Community still receives the Intruder UI
  hand-off for the operator, while the payload set executes deterministically
  through Burp's own HTTP engine (Community-supported) with AI-OSOP
  differential judgment (SQL error signatures, SSTI evaluation, auth-bypass
  deltas) minting validated findings; turbo-intruder-mcp remains the
  race-condition engine (`race_limit_scan`).
* **collaborator_oob** — on Community `collaborator_payload` transparently
  mints an AI-OSOP oast-mcp token through the same interface (equivalent
  out-of-band detection, no Burp license involved); provenance is recorded in
  the response (`provider: aiosop-oast`).
* **organizer_findings_ui** — on Community `sync_to_organizer` degrades
  gracefully: the request/response pair is still captured through Burp's site
  map via the HTTP engine, and every AI-OSOP finding already persists to the
  Neo4j attack graph + findings evidence ledger, so nothing is lost without
  the Pro UI.

## What is preserved across editions (same interfaces, same workflow)

* **Findings & evidence** — every engine (Burp issues, nuclei, web_audit,
  intruder_fuzz) mints the same `Vulnerability` model with full evidence
  (request/response deltas, probes, OAST callbacks).
* **Validation** — findings require a behavioral delta or an out-of-band
  callback; `validated=True` is never set from a template echo alone.
* **Deduplication** — all sources merge through the finding-intelligence
  fingerprint layer; one root cause appears once, evidence unioned, member IDs
  preserved via `correlated_ids`.
* **Reporting** — the graph, ledger, and six-file report artifact set are
  edition-independent.
* **Scope enforcement** — the signed engagement scope gates every request on
  every transport (Burp engine and internal httpx alike), fail-closed.

## Degradation contract (never null, never an error raise)

| Scenario | Behavior |
|---|---|
| Burp Community, all internal engines up | Full scan: Burp passive layer + nuclei + web_audit, merged + deduped |
| Burp Community, nuclei down | web_audit still scans; `degraded_components` records `{"component": "nuclei-mcp", "reason": ...}`; task succeeds |
| Burp entirely down | `scan_mode: internal_routed`; nuclei + web_audit still scan; Burp passive layer skipped with reason |
| Collaborator unavailable + oast down | Structured `{"status": "unavailable", "reason": ...}` payload with remediation note — not an exception |
| Organizer unavailable | `status: degraded` result; pair captured via site map; findings persist to graph/ledger |

## Pipeline scheduling (phase entry, `orchestrator/phase_monitor.py`)

Phase entry into `vulnerability_discovery` probes Burp's capabilities once and
schedules per-asset scans without duplicating work across editions:

| Edition at phase entry | `burp_scan` scheduled | standalone `web_audit` scheduled |
|---|---|---|
| Burp Pro | yes — Burp's native audit (timeout 600s+) | yes — differential complement (pre-existing behavior) |
| Burp Community | yes — passive layer + inline nuclei + inline web_audit @ max_urls=25; budget = `nuclei_mcp_timeout + 600s` so the inline engines finish instead of retry-storming | **no** — the inline pass IS the differential sweep; a second task would duplicate every probe |
| burp-mcp down | yes — `internal_routed` mode | yes — restores the full max_urls=25 differential sweep |

Direct task submission (CLI/API/tests) is unaffected: a manually-submitted
`burp_scan` always runs the capability-driven hybrid flow.

## Observability

* `GET /health/tooling/deep` — the Burp channel reports one of:
  * `real_execution_verified` (Pro scanner confirmed started)
  * `community_verified_internal_scanning` (Community passive layer verified +
    internal nuclei coverage verified live) — **counts as a verified channel**
  * `scan_unavailable` (neither Burp's scanner nor internal coverage provable)
* Every `burp_scan` task result carries `burp_edition`, `scan_mode`,
  `capability_routing` (the resolved matrix, verbatim), `internal_components`,
  and `degraded_components` — full transparency about which engine delivered
  which capability.
* `intruder_fuzz` results carry `attack_mode`, per-payload `execution_results`
  (with the transport used: `burp_http_engine` / `aiosop_httpx`), and
  confirmed findings.

## What is deliberately NOT implemented

* No license bypass, crack, or key generation for Burp Pro — refused
  categorically and repeatedly (see project memory: license boundary).
* No patching of Burp binaries or JVM classes, no reflection into Burp's
  internals, no feature-flag or config tampering to unlock paid modules.
* No making Community report itself as Pro, and no calling Pro-only Montoya
  endpoints on a Community install.
* No scraping of Burp's proprietary scan checks — the alternatives are
  AI-OSOP's own engines (nuclei templates, deterministic differentials), which
  are open-source or internally implemented and legally unencumbered.

If your engagement needs Burp Pro's proprietary scanner checks themselves,
the only legal path is purchasing a Pro license — the platform will then use
it automatically.
