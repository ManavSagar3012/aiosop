# AIOSOP — Bug-Bounty Readiness Gap Report

_Re-audited 2026-07-21 against branch `fix/mock-findings-honest-stub-tool-guard` @ `5f1cd7a9`, with the full stack live (Neo4j/Postgres/Redis/API + Juice Shop)._

**Method.** Seven parallel deep-dive auditors (one per subsystem), each finding cited to `file:line`, then an **adversarial verify pass** that re-opened every cited location and tried to *refute* each blocker/major before it survived here. Two dimensions (detector-quality, reporting) failed to return and were audited inline instead. Where a verifier corrected a severity, this report uses the corrected one. This supersedes the previous report, which was written against an earlier tree — the codebase has since changed materially (M1 governance landed on the deterministic path; the SSTI/CSRF detectors were reworked; five new testers were added).

---

## Bottom line

The single most important finding is new and confirmed by runtime check: **the autonomous pipeline does not run end-to-end — it is broken, not merely unproven.** A canonical-id vs session-id key mismatch makes every automatic phase transition raise "Session not found", so an engagement never advances past its starting phase on its own. Everything downstream (recon → scan → report) only runs when a human hand-drives each phase via the API.

Separately, the M1 governed-egress work is real and well-built, but it covers only **one of the two** live target-traffic paths. The autonomous agent fleet and the recon crawler — the *default* scan surface — still fire ungoverned traffic with no per-request scope check, no rate limit, and no research-identity header.

The good news, and it's real: the two false-positive detectors from the last report (SSTI, CSRF) are now genuinely fixed, the deterministic detection core is production-quality, the reliability machinery is well-built, and the mock-finding guard holds. So the gaps are concentrated in **orchestration glue** and **governance coverage**, not in the detection engines.

Until the blockers below land, AIOSOP remains **manual/scoped-assist only** — never turned loose autonomously on a live program.

---

## SOLID — do NOT rebuild these

- **Governed egress hook** (`safety/governed_client.py:71-123`) — fail-closed scope, per-request rate limit, research header, audit, with a runnable self-check. Hooks httpx request events so no verb slips past; degrades to a plain client when guards are omitted.
- **Deterministic scan path, end-to-end governed** (`api/routers/engagements.py:195-246` → `deterministic_scan.py` → oracles + authed `SessionClient`). This is the reference wiring every other path should copy.
- **Deterministic discovery + oracles** — `bootstrap_discovery` (multi-source: wordlist + spec/robots/sitemap + JS-literal + param links, deduped, fully governed), `url_intelligence`, `openapi_ingest`, and the SQLi/injection/JWT/IDOR oracles remain evidence-gated (`deterministic_scan.py:1258`, `core/*oracle*.py`).
- **SSTI + CSRF detectors — now fixed** (was B4 in the last report). SSTI uses an evaluation oracle (`{{7*7}}`→`49` with a control `{{7*8}}` that must NOT yield `49`, `ssti_agent.py:29-45`); CSRF now requires a cross-site state change to actually succeed with a foreign Origin/Referer (`csrf_agent.py:128-163`). No longer reflection/heuristic false-positive generators.
- **Reliability machinery** (`SOLID-7`) — double-timeout stranding fixed at root (`base.py:388-404`), reaper excludes pending tasks (`recovery_service.py:54-85`), terminal-allowlist phase completion fails safe, no-vuln reroute terminates the mission instead of looping (`orchestrator.py:803-975`).
- **Mock-finding guard** (`COV-5`) — every finding write funnels through `add_vulnerability`/`_batch`; `is_simulated()` is multi-signal and default-closed (`graph_memory.py:297,592`, `models.py:124-152`). Simulated findings genuinely cannot reach the graph on default config.
- **Real-DB CI + tooling-reality gate** — CI stands up real Neo4j/Postgres/Redis; the `qualification/` suite hard-fails if an MCP server reverts to a stub (`tooling-reality.yml`).
- **API auth** — fail-closed JWT/bearer (`api/deps.py`). Internal (non-target) clients correctly left un-scoped (`GOV-8`).

---

## BLOCKERS — must fix before any autonomous or real-program use

### BLK-1 — Autonomous pipeline is broken (canonical-id vs session-id key mismatch)
`phase_monitor.py:224` passes `session.canonical_engagement_id` (the short `scope.engagement_id`) to `engagement_manager.transition_phase`, but `_sessions` is keyed by the **full** `session_id` (`eng-<ts>-<canonical>`, written at `engagement_manager.py:65,81` and `recovery_service.py:203`). The lookup misses, `transition_phase` raises "Session not found" (`engagement_manager.py:162-164`), the monitor records a failure and gives up after 5 attempts. **Runtime-verified.** PHASE_POLICY auto-advance (INITIALIZED→RECON→…→REPORTING) only schedules per-phase work from inside `transition_phase`, so the engagement never leaves its starting phase autonomously. This is exactly why `benchmarks/juiceshop/README.md` says the full pipeline is unproven and the memory note records "0 findings / stranded pipeline". The regression shipped green because the tests mock `transition_phase` and key `_sessions` by the wrong id (`TEST-3`, `test_engagement_id_unification.py:94,135,174`).
**Fix:** resolve engagement_id→session before the `_sessions` lookup, or key `_sessions` by the canonical id consistently — small and localized. Add an integration test that creates an engagement the production way and asserts the monitor advances it.

### BLK-2 — Autonomous agent fleet fires ~30 ungoverned httpx clients (governance bypassed on the main scan path)
`governance_hook` is threaded through exactly 5 non-test files; **zero** agents receive it (`api/main.py:560-627` registers the full fleet). Raw target-traffic clients: `ssrf_agent.py:75/81`, `vuln_agent.py:805,1148,1377,1596,2500,2602,2860,3052`, `csrf_agent.py:138`, `ssti_agent.py:100`, `saml_agent.py:52`, `takeover_agent.py:56`, `graphql_agent.py:109,216`, `race_scanner.py:53`, plus core testers (`jwt_tester`, `oauth_reset_tester`, `nosql_tester`, `cache_poisoning_tester`, `open_redirect_tester`, …). Worse, `base.py:368` rate-limits **per task** not per request (one token while a task fires dozens of probes), and `base.py:583-588` `_validate_task`'s scope check is a literal no-op (`pass`). So the entire autonomous scan surface egresses with no per-request scope recheck, no research header, and effectively no rate limit — the exact three disqualifying gaps M1 exists to fix, left unfixed on the larger path.
**Fix:** give agents a governed client (a shared `SessionClient`/governed httpx built from the engagement scope + politeness limiter + research header), and make `_validate_task` actually enforce scope.

### BLK-3 — Recon crawler bypasses governance entirely (raw aiohttp) and is the *default* autonomous traffic
`recon_agent._active_crawl_target` uses raw `aiohttp.ClientSession` (`recon_agent.py:893,902,1079`; also `:382` form-fetch, `:417` openapi ingest) — and `governance_hook` is httpx-only, so aiohttp cannot use it. `phase_monitor.py:249` schedules `full_recon` autonomously on RECON entry, so this ungoverned path sends the **first and broadest** wave of target traffic (page fetches, JS pulls, form GETs across up to 20 pages × N identities × M subdomains) with no rate limit and no research header.
**Fix:** route the agent crawler through a governed client (either move it to the governed httpx seam, or add an aiohttp-level equivalent of the scope/rate/header trace).

---

## MAJOR

- **MAJ-1 (SEAM-2) — dead phase/task safety gate.** Same key mismatch: `task_scheduler.py:328,349` look up `_sessions.get(task.engagement_id)` with the short id → always `None` → `assert_task_allowed` (which restricts exploit-validation to the EXPLOITATION phase) never runs. Defense-in-depth that appears active in code is inert.
- **MAJ-2 (SCOPE-1) — crawler scope filter bleeds to lookalike hosts + leaks creds.** `recon_agent.py:906,948,962` gate on `netloc.endswith(domain)`, so `evilsyfe.com`.endswith(`syfe.com`) is True — the crawler fetches the lookalike page *and* sends its injected auth cookies/bearer (`:884-891`) to it. The correct check (`ScopeEnforcer.host_in_scope`) exists but is applied only at persist time. Off-scope egress + credential leakage to attacker-glued hosts.
- **MAJ-3 (COV-3) — bounty report silently merges distinct critical findings.** `finding_signature` (`bounty_report.py:84-93`) keys on `class|path|param`; url-less classes (confirmed: `exposed_secret`) collapse to `exposed_secret||` for every finding, so 3 distinct live credentials (AWS+Stripe+GitHub) become 1 report row with 2 CRITICALs dropped — even though persistence keeps them distinct (dashboard shows 3). Lost-income *and* correctness defect; invisible when compared against the dashboard.
- **MAJ-4 (COV-PARAM-1) — no active parameter mining.** Discovery is passive-only (`url_intelligence.extract_params:197` reads existing query/path params; forms from static HTML). No Arjun/ParamMiner-style probing (grep for `arjun|paramspider|param.?fuzz` = 0 hits). Hidden `debug=`/`admin=`/`url=` params — where many real bounties live — are undiscoverable, and the oracles inherit the blind spot.
- **MAJ-5 (COV-SPA-1) — no JS execution; richest paths never auto-scheduled.** Native crawlers do static parse + regex only. The JS-aware options (katana content_discovery, OpenAPI ingest) exist but `phase_monitor` never schedules them autonomously — only `full_recon` and a browser HAR capture. Modern SPA routes computed at runtime are systematically under-discovered.
- **MAJ-6 (GOV-6) — secret_verifier auto-uses leaked creds against third-party APIs, ungoverned.** `secret_verifier.py:403-411` sends a discovered credential to its provider (github/aws/stripe/…) via an unthrottled, unaudited `httpx.AsyncClient` with no identity header. Correctly out-of-engagement-scope, but some programs forbid using found creds — needs an explicit policy gate + audit.
- **MAJ-7 (COV-1, test) — autonomous LLM planning loop is never exercised in CI.** The only test that drives `think()→LLM→provider` (`test_real_llm_planning.py`) is skipped by default and in CI (no `OSOP_RUN_REAL_LLM`, no key). Prompt-format regressions, output-parse breakage, and provider drift all pass green. Combined with BLK-1, **no run — mock or real — has ever driven recon→report autonomously.**

---

## MINOR (hardening / hygiene)

- **MIN-1 (GOV-5)** — research header is **off by default** (`config.py:329-334` empty); a default-config governed run still sends no `X-HackerOne-Research` header. Make it a hard pre-flight gate for programs that mandate it, not a silently-empty setting. _(Verifier downgraded from major: safe-by-default, fails safe.)_
- **MIN-2 (COV-4, integrity)** — `is_simulated()` is enforced only at the persistence funnel; the report/metrics layers trust it blindly. If `OSOP_ALLOW_SIMULATED_FINDINGS` is ever set (self-test) or a future writer skips the funnel, simulated findings render into reports unmarked. Add a redundant report-layer skip.
- **MIN-3 (COV-1, integrity)** — the engagement-id dual-key **read** workaround is applied to only 1 of 5 readers; the bounty-report generator, reporting agent, and benchmark export each read a single id form and can under-report if any writer keys under the other form. Root fix is one id at the source, not a dual-key read bolted onto some readers.
- **MIN-4 (PERSIST-4)** — durable/Temporal executor marks tasks terminal but never writes that to Neo4j; the reaper reconciles once as a band-aid. The live agent path is fine — this bites only durable/recovered tasks.
- **MIN-5 (GATE-5)** — the VULNERABILITY_DISCOVERY MCP-readiness gate degrades to advisory when the MCP registry is empty (`phase_monitor.py:196-198`), so a "hollow" discovery phase can look complete.
- **MIN-6 (COV-3, test)** — the bug-finding capability gate (recall floor on Juice Shop) silently skips in CI because its result files are untracked; it only enforces where an operator ran `bench.py` first.
- **MIN-7 (COV-BUDGET-1)** — crawl budgets are flat hard-coded constants (20 pages/identity, 8 seed pages) with no scope-configurable override; large in-scope apps are silently under-covered.
- **MIN-8 (GOV-7)** — governed scope gate fails **open** on an empty request host (`governed_client.py:96`); low real-world exposure but should fail closed.
- **MIN-9 (oauth_reset host-header)** — `oauth_reset_tester` marks host-header-poisoning `confirmed=True` on reflection of the poisoned Host (`:131-142`); accepted as a lead, but true confirmation needs the reset email, so it's a slightly generous "confirmed".

---

## How the previous report's items moved

- **B1/B2/B3 (scope / rate / research-header on the scan path)** — *half-fixed.* The deterministic path is now fully governed and bounty-safe (2 req/s). The **agent fleet + recon crawler** are not (BLK-2, BLK-3) — the bigger, default traffic path.
- **B4 (false-positive detectors)** — **resolved.** SSTI and CSRF are now evidence-gated; the new testers are evidence-dict based (one minor caveat, MIN-9).
- **M1 (governed client)** — built and proven on the deterministic path; **incomplete** across agents/recon (that's BLK-2/BLK-3).
- **M2 (engagement_id/session_id split-brain)** — now understood to be the **root cause of BLK-1** and MAJ-1; a partial "canonical id" migration left the `_sessions` registry key and several readers unmigrated.
- **M3 (autonomous pipeline unproven)** — upgraded to **BLK-1: broken, not just unproven** (runtime-confirmed).
- **M4 (LLM planning untested)** — **confirmed** (MAJ-7).
- **M5 (reporting completeness)** — the reporting pipeline is largely complete (deterministic PoC, integrity hashing, simulated guard) but has the **report-dedup defect** (MAJ-3) and simulated-in-report gap (MIN-2).

---

## Recommended sequence

1. **BLK-1** — fix the `_sessions` keying so auto phase-advance works. Smallest change, unblocks *everything* autonomous, and re-enables MAJ-1's dead safety gate as a side effect. Add the missing integration test.
2. **BLK-2 + BLK-3** — extend governance to the agent fleet and the recon crawler (shared governed client; make `_validate_task` enforce scope; govern aiohttp recon). This is what makes autonomous traffic in-policy.
3. **MAJ-3** — fix the report-dedup signature so distinct url-less criticals aren't merged away (align it with the persistence dedup key).
4. **MAJ-2** — route the crawler's fetch decisions through `host_in_scope` (stop the lookalike-host credential leak).
5. **MAJ-4 / MAJ-5** — add active parameter mining and auto-schedule the JS-aware discovery paths (katana / OpenAPI) to close the real-world coverage gap.
6. **MAJ-7 + MIN-6** — turn on a real-LLM planning test and the capability gate in CI so "autonomous" is actually regression-covered.
7. Minors as hardening.

Until at least steps 1–2 land, AIOSOP should run **manual/scoped-assist only** — the individual (now-solid) oracles against operator-chosen endpoints — never autonomous against a live program.
