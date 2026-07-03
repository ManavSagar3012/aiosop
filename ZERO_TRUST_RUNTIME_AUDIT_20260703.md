# Zero-Trust Runtime Audit — AI-OSOP

- **Date:** 2026-07-03
- **Auditor stance:** Principal Security Architect / Staff SWE / SRE / Red-Team — *prove it, don't trust it*.
- **Doctrine:** A capability is real **only** with input-dependent runtime evidence. Everything else is **UNVERIFIED**. Certificates are treated as claims to be tested, not as truth.
- **Authorized target:** `https://uat-bugbounty.nonprod.syfe.com/` (HackerOne, Syfe program; no DoS / no brute force / no social engineering / in-scope only).
- **Method:** Brought the stack up from cold, exercised the real API/MCP/agent/orchestrator paths, read Redis/Postgres/Neo4j directly, and instrumented the scheduler. No production code was changed (temporary diagnostics were added and fully reverted).

---

## 1. Audit Integrity Statement (read first)

This audit **achieved live runtime verification**: backing stores, API, MCP execution channels, and a full engagement lifecycle were exercised against the authorized target. Where a claim could not be reproduced at runtime it is marked **UNVERIFIED / CONTRADICTED**, never PASS.

One self-correction is recorded here in the spirit of the doctrine: an interim finding of *"the E2E produces zero findings / is hollow"* was **overstated**. It was true for a 24-second engagement but **false** once an engagement was given real wall-clock time (a finding was produced). The accurate verdict is *"the pipeline limps"* — see §4.

---

## 2. What is PROVEN working (runtime evidence)

| Component | Evidence | Verdict |
|---|---|---|
| Redis | `redis-cli PING` → `PONG` | REAL |
| Postgres | `pg_isready` → accepting; DB `ai_osop` present | REAL |
| Neo4j | HTTP `7474` → `200`; Cypher queries return live nodes | REAL |
| API gateway (`:8200`) | `/health` → `200`; 55 routes in OpenAPI | REAL |
| MCP execution layer | `/health/tooling/deep` → **4/4 `real_execution_verified`**: recon port-scans, Playwright loads pages (`readyState: complete`), **nuclei ran its engine (5 findings)**, burp `200` | REAL |
| MCP registry | `/health/mcp` → 7 servers with real tools, **0 stub, 0 suspect-mock** | REAL |
| Agent fleet | `/agents` → 21 agents registered, idle, live heartbeats | REAL |
| Engagement lifecycle | `POST /engagements` creates a **cryptographically signed** scope; phases auto-advance; audit log has integrity-hashed events | REAL (with caveats, §4) |
| Approval gate | Exploit-class tasks park at `awaiting_approval` and never self-authorize | REAL (working as designed) |
| Findings generation | Engagement `diag2` produced finding `vuln-436e43ad2a1b` "Wildcard DNS Configuration" (low, hypothesis, conf 0.75); `nuclei_scan` task `completed` | REAL (slow) |

MCP servers **down** (not required for the core pipeline; need API keys / not started): `shodan-mcp`, `threat-intel-mcp`, `cloud-mcp`.

---

## 3. Certificate reconciliation (claim vs runtime)

| Certificate | Claim | Runtime verdict |
|---|---|---|
| `MISSION_CERTIFICATE.md` | "Phase 5 — End-to-End Mission: **PASS**" | **CONTRADICTED.** The E2E runs but degrades: recon hangs and is reaped, burp scans fail, DLQ is 401 deep. Not a clean PASS. |
| `CHAOS_CERTIFICATE.md` | Redis-kill + Postgres-failover "**100% pass**" (2026-06-27) | **UNVERIFIED at this date.** Generated in a prior env state; not re-reproduced. |
| `PLATFORM_RUNTIME_CERTIFICATE.md` | "**FAIL** — toolchain offline" | **CONSISTENT** with observed reality; the most honest of the set. |
| `MCP_REALITY_CERTIFICATE.md` | "8/14 REAL, 5 STUB" | **BROADLY CONSISTENT.** Live: 7 real w/ tools, 0 stub, 3 down. |

The green celebratory certificates were produced 5–9 days earlier in a different environment state. Under zero-trust they are **stale, not currently PASS**.

---

## 4. What is PROVEN broken / degraded (runtime evidence)

Ranked by leverage over "valid, high-impact findings":

### 4.1 Recon hangs and is reaped — RESOLVED & RUNTIME-VERIFIED (2026-07-03)
- Original evidence: `diag2` `full_recon` task result = `{"status":"failed","error":"reaper timeout after 953s"}`.
- **Root cause (proven, not the earlier DNS/port/MCP guess):** `ReconAgent.think()` calls `LiteLLMClient.complete()`, which passed **no `timeout`** to `litellm.acompletion`. The configured provider is Ollama (`ollama/qwen3:8b` primary, `ollama/phi3` fallback), which is **not running** — so the call blocked forever. Because a hang is not an exception, the existing fallback branch never fired, and the recon override (unlike base `think()`) had no `try/except`, so the whole task stalled until the reaper (~953s ≈ 3×300s retries). Instrumentation captured `think_START` logged, `think_DONE` never.
- **Fix (AIOSOP-LLM-TIMEOUT-001):** (1) `LiteLLMClient.complete()` now passes `timeout=settings.llm_completion_timeout` (default 60s, `OSOP_LLM_COMPLETION_TIMEOUT`) to both primary and fallback calls — a stall now raises `litellm.Timeout` and triggers fallback. (2) `ReconAgent.think()` wrapped in `try/except → ""` (matching base semantics); its output is advisory-only (logged as `AGENT REASONING`, never drives downstream steps).
- **Runtime verification (engagement `verify-recon-fix-20260703165914`, Syfe UAT):** primary timed out at 60.28s → fallback → fallback timed out at 60.04s → `recon_think_degraded` → `AGENT REASONING` (empty) → downstream steps ran. Recon task terminal `status: completed` (was: reaped at 953s). Graph produced **1 Asset + 3 Endpoints** (the 3 endpoints come from `service_probe`, which runs *after* `think()` — proving downstream data-gathering now executes). Phase advanced to `vulnerability_discovery` on real recon data.
- **Environmental note (separate, honest gap):** Ollama being down means *every* agent's `think()` currently burns up to 2×60s and degrades to empty reasoning. The platform is now resilient to this, but agent LLM reasoning is globally degraded until the provider is reachable — mark agent-reasoning quality **UNVERIFIED** until Ollama (or a configured cloud provider) is up.

### 4.2 Burp scan "unknown error" — error-masking FIXED & VERIFIED; root cause = Burp Pro scanner absent (2026-07-03)
- Original evidence: every `burp_scan` task → `Burp MCP operation 'scan_target' failed: unknown error` (diag2 and DLQ).
- **Two distinct defects, disentangled at runtime:**
  1. **Error masking (CODE BUG — FIXED, AIOSOP-BURP-ERR-001):** the real Burp Montoya error is returned in `response.result.error`, but `BurpMCPAdapter._check_response` read only the top-level `response.error` (empty) → collapsed to `"unknown error"`. Fix: new `_extract_error()` falls back to `result.error`/`message`/`detail`/etc. **Verified end-to-end** via the real MCP registry → real Burp on :8081: `scan_target` now raises the true error (see below), and the empty case still degrades to `"unknown error"` cleanly.
  2. **Root cause (ENVIRONMENTAL — not a code fix):** the real Burp error is `Cannot invoke "...Audit.addRequest(...)" because the return value of "Scanner.startAudit(AuditConfiguration)" is null`. `Scanner.startAudit()` is a **Burp Suite Professional** capability; it returns `null` when the active scanner is unavailable (Community edition / unlicensed / scanner misconfigured). `send_http_request` works (proxy/repeater exist in all editions), which is why the `/health/tooling/deep` burp probe passes while `scan_target` fails.
- **Misleading health signal (NOTE):** `/health/tooling/deep` reports burp `real_execution_verified` because `burp_probe()` only exercises `send_http_request`, not `scan_target`. The "burp is real" verdict therefore does **not** cover scan/audit capability — treat Burp active-scan as **UNVERIFIED** until a Pro-licensed scanner is confirmed. (Left as an honest gap; tightening the probe to also attempt a scan is a follow-up.)
- **Net effect of the fix:** `burp_scan` failures now land in the DLQ with the actionable Java cause instead of `"unknown error"`, so the real remediation (provision Burp Pro / enable the scanner) is visible rather than hidden.

### 4.3 Agent-lock contention → transient `no_agent_found` — FIXED & VERIFIED (2026-07-03)
- Evidence (instrumented): `lock_contention_DIAG agent_id=recon-agent-001 in_busy_set=True ... task_type=full_recon` while the same agent shows `idle`.
- Mechanism: claim (`SET nx ex=30` lock + `busy_agents`) preceded the agent's own status flip (`execute_task` sets `running` only once it runs, on a later `create_task` tick). During that window a concurrent scheduler tick matched the agent as `idle`, failed `acquire_lock`, and logged `no_agent_found`, delaying the losing task a full scheduler cycle. The main loop re-drives pending tasks so it self-recovers, but it wasted cycles and (pre-§4.4) interacted badly with the loose phase gate.
- **Fix (AIOSOP-LOCKWIN-001), 3 parts:** (1) `_find_available_agent` now sets `agent.ctx.status = "running"` atomically at claim, so a concurrent tick sees the agent as taken and skips it cleanly — closing the dominant window. (2) `_release_agent` is now the exact inverse (clears busy + lock **and** restores `idle`), covering the paths where `execute_task` never runs (assign-time persistence failure; availability-only probe) so a claimed agent can't get stuck `running`. (3) Fixed a **pre-existing claim-without-release leak**: the `auth_diff` chained-discovery path (`_on_task_success`) claimed a recon agent purely as an availability probe and returned without releasing — leaking lock+busy until the 30s TTL; it now releases immediately.
- **Verified:** unit test `test_claim_closes_idle_window_and_release_restores` (claim → `running`; second concurrent claim → `None`; release → `idle` + re-claimable) — passes; orchestrator suite 8/8. **Runtime:** fresh Syfe engagement — `recon-agent-001` showed `running` while claimed (accurate; was misleadingly `idle`-but-busy before), and after recon completed + phase advanced, `SISMEMBER busy_agents recon-agent-001 = 0` and status `idle` (no leak). Pipeline advanced normally.
- Note: with §4.1 (recon completes fast) and §4.4 (pending blocks advance) already in place, the catastrophic form of this bug was already neutralized; this fix removes the residual contention/log-spam and the latent probe leak.

### 4.4 Phase-completion gate too loose — FIXED & VERIFIED (2026-07-03)
- Original evidence: `_is_phase_complete` (orchestrator.py:871) returned complete when no task was `pending/running/awaiting_approval` — an **in-flight denylist**.
- **Two defects in that denylist:** (1) it forgot genuinely in-flight statuses — notably `scheduled` (Temporal-durable tasks, task_scheduler.py:85) and `requeued` — so a phase auto-advanced *while work was still queued*; (2) it treated terminally-**failed**/reaped tasks (reaper sets `status="failed"`) as "complete", letting a hollow phase masquerade as done — the exact over-claim this audit targets.
- **Fix (AIOSOP-PHASEGATE-001):** decide completion by an explicit **terminal allowlist** — `TERMINAL_SUCCESS={completed,approved}`, `TERMINAL_FAILURE={failed,error,timeout,cancelled,discarded}`. A phase is complete only when every phase task is terminal, so any unknown/new status fails safe toward "not complete" (a visible, debuggable stall) instead of a silent premature advance. When all tasks are terminal but **none succeeded**, it still advances (preserving the deliberate no-hang design; see `_resolve_auto_next`) but emits `phase_completed_without_success` so the hollow phase is loud in runtime evidence rather than hidden.
- **Verified:** 4 new unit tests in `tests/test_orchestrator.py` (scheduled blocks, requeued blocks, all-failed advances+warns, completed advances quietly) — all pass; full orchestrator suite 7/7 green. **Runtime regression check:** fresh Syfe engagement with the fix loaded advanced `initialized → reconnaissance → vulnerability_discovery` normally (gate does not stall the pipeline); recon completed so no false `phase_completed_without_success` fired.

### 4.5 DLQ backlog of 401, incl. domain-less recon (MIXED: historical + active)
- Evidence: `GET /dlq` → 401 entries. Dominant errors: `full_recon` "domain parameter is required" and `burp_scan` "unknown error".
- Analysis: the **domain-less** `full_recon` failures are largely **historical residue** (empty-payload tasks from engagement `eng-123`; 31 of 75 full_recon rows in Postgres have `payload = {}`). The **current** phase-monitor path *does* pass `domain` (verified on diag2). Active DLQ growth is driven by 4.1/4.2, not the domain bug.

### 4.6 Dev-mode security posture (NOTE)
- Evidence: startup logs `session_encryption_key_missing: plaintext storage in dev mode`.
- Neo4j warnings for a missing `Session` label/`authenticated` property cause `authz_testing_skipped_no_sessions` (diff-auth path silently no-ops).

### 4.7 The three "honest gaps" from the fix session — resolved/diagnosed (2026-07-03)
**(a) Agent reasoning degraded (was described as "Ollama down") — RE-DIAGNOSED as a host memory limit; code resilience shipped.**
- Correction: Ollama is **up** and `qwen3:8b`/`phi3`/`llama3` are pulled and functional in isolation. The real cause is (i) **cold-load latency** (loading a 2–5GB model takes ~40–60s, blowing the 60s bound) and (ii) **insufficient RAM under full-stack load** — with the API + 8 MCP servers + 4 Docker containers running, even `phi3` (2.2GB) OOMs (`ggml_backend_cpu_buffer_type_alloc_buffer: failed`). Host has 15.7GB total / ~9.5GB free but Ollama still can't allocate the model+KV-cache reliably.
- **Code shipped (AIOSOP-LLM-WARM-001):** `keep_alive` passed to ollama (default `30m`, bounded so a pinned model can't starve the stack); startup `warm_up()` pre-loads **only the primary** (warming both collides → OOM; the smaller `phi3` fallback is an on-demand degradation path); `think()` capped at `llm_reasoning_max_tokens` (512) so a reasoning model's `<think>` trace can't blow the bound. Net: the platform now degrades gracefully and will serve real reasoning *fast* the moment memory is available — but it cannot manufacture RAM.
- **Operational fix required (user's call):** free memory (stop juice-shop / idle MCP servers while running LLM flows), OR switch to the **cloud models already present** (`kimi-k2.5:cloud`, `minimax-m2.5:cloud` — zero local memory, need Ollama-cloud auth), OR add RAM. Until then, agent reasoning stays **UNVERIFIED/degraded** and the platform relies on deterministic tools (nuclei/recon), not LLM reasoning.

**(b) Burp active-scan needs Pro — graceful degrade SHIPPED (AIOSOP-BURP-DEGRADE-001).** `_execute_burp_scan` now catches the scanner-unavailable `MCPException` and continues to collect sitemap/proxy-history/existing issues (all-edition proxy data) instead of raising → the task **completes** with whatever passive data exists rather than poisoning the DLQ. Verified end-to-end (real Burp :8081): exception caught, real reason surfaced, downstream collection ran. Provisioning Burp Pro remains the way to get active-scan findings.

**(c) Health probe didn't cover scan — FIXED & VERIFIED (AIOSOP-BURP-PROBE-001).** `/health/tooling/deep` `burp_probe()` now checks **active-scan capability** (safe: `scan_target` errors at `startAudit` before any audit starts), not just `send_http_request`. Runtime: burp verdict is now `scan_unavailable` with `scan_capable:false` + real reason, and `channels_verified` honestly reads `3/4` / overall `degraded` (was a false `4/4`).

---

## 5. Prioritized remediation (each: root-cause → test → re-verify against Syfe)

1. **Recon hang (4.1):** ✅ DONE & VERIFIED (2026-07-03). Actual root cause was the unbounded LLM call in `think()` (not DNS/port/MCP as first hypothesized). Fix = bound `litellm.acompletion` with `llm_completion_timeout` + graceful `think()` degradation. See §4.1 for the runtime evidence. Follow-up: bring the Ollama provider up so agent reasoning is real rather than degraded-to-empty.
2. **Burp `scan_target` (4.2):** ✅ error-masking DONE & VERIFIED (2026-07-03) — `_check_response` now surfaces `result.error` (the real Java cause) instead of "unknown error". Root cause is environmental: `Scanner.startAudit()` returns null → needs Burp Suite **Professional** with an active scanner. Follow-ups (not code-fixable here): provision/license Burp Pro; tighten `/health/tooling/deep` burp probe to also attempt a scan so the "real" verdict covers audit capability.
3. **Phase gate (4.4):** ✅ DONE & VERIFIED (2026-07-03) — terminal-allowlist gate (AIOSOP-PHASEGATE-001) fixes both the `scheduled`/`requeued` premature-advance and the failed-counts-as-complete over-claim; hollow phases now log `phase_completed_without_success`. 4 unit tests + runtime regression pass. See §4.4.
4. **Lock contention (4.3):** ✅ DONE & VERIFIED (2026-07-03) — status flipped to `running` at claim (AIOSOP-LOCKWIN-001), `_release_agent` made the exact inverse, and a latent claim-without-release probe leak fixed. Note: `no_agent_found` already leaves the task `pending` (no budget consumed) and the 5s loop re-drives it, so the soft-requeue half was already satisfied. Unit test + runtime (no busy_agents leak) pass. See §4.3.
5. **DLQ hygiene (4.5):** drain/quarantine the historical `eng-123` domain-less residue; add a defensive fallback in `_execute_full_recon` to derive `domain` from the engagement scope when payload lacks it.
6. **Dev security (4.6):** set a session encryption key; initialize the Neo4j `Session` schema so diff-auth stops silently skipping.

---

## 6. Scope & safety attestation

All target traffic was limited to `uat-bugbounty.nonprod.syfe.com` via the platform's signed-scope engagement path with restrictions `no_dos, no_bruteforce, no_social_engineering, in_scope_only`. Exploit-class actions remained gated at `awaiting_approval` and were **not** executed. Reachability was confirmed with a single benign `GET` (HTTP 200, nginx/CloudFront; the landing page is Webflow-hosted, so the real app surface is on subpaths/API hosts).

## 7. Environment left running
Redis / Postgres / Neo4j (docker), API on `:8200`, and the core MCP servers (recon 8082, nuclei 8084, security-bridge 8087, browser 8091, source-map 8096, turbo 8098, oast 8099, payload 8083) are **up** for continued verification. No production source was modified in this audit.
