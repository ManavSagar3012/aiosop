# AIOSOP End-to-End Capability Verification — Engineering Report

**Date:** 2026-07-10  **Branch:** feat/sprint0-p1-recon-multiplier
**Target under test (SUT):** AIOSOP  **Benchmark target:** https://ginandjuice.shop/ (authorized PortSwigger practice range)
**Engagement:** `eng-20260710165305-e2e-gj-20260710-165305`

> Scope note: this is **one** instrumented benchmark pass. It establishes a runnable baseline, ships one verified fix, and identifies the #1 bottleneck with root cause. The continuous-improvement loop (fix bottleneck → re-benchmark → compare) is multi-pass by nature; the next iteration is queued as a recommendation, pending go-ahead.

---

## 1. Executive Summary

AIOSOP began this session **non-runnable**: its API (port 8200) — the spine every task flows through — was down, so no benchmark could execute. After bringing the API up (all Docker infra was already healthy), a live engagement against ginandjuice.shop demonstrated that the **discovery and orchestration layers work end-to-end**, but the **scanner execution layer is effectively non-functional**: scanner tasks hang until reaped at their 300s timeout, producing ~zero findings while saturating all concurrency slots.

- ✅ **Recon works**: `full_recon` completed in 25s, discovering **179 endpoints** on the live target.
- ✅ **Planner + orchestration work**: fanned out a 100-task scanner matrix (25× each xss/sqli/csrf/jwt) + nuclei + burp + recon; workers pulled and executed tasks; the stuck-task reaper correctly reaped 66 hung tasks.
- 🔴 **Scanners are the bottleneck**: `agent_success_rate = 0.0`. xss/jwt/csrf each: ~2 nominal "done" (one masked empty), ~21–22 **failed** via "reaper timeout after ~327s". No scanner produced a real finding.
- 🔴 **Burp active scan is broken**: `startAudit()` returns null → NPE, silently degraded to a no-op (0 findings).
- 🟠 **Correctness bug**: the scheduler records empty/None scan output as `{"status":"success","raw":null}` — masking dead scans as passes.
- ✅ **Fixed + verified this pass**: `/health/metrics` 500 → 200.

---

## 2. Platform Health (baseline, evidence-backed)

| Subsystem | State | Evidence |
|---|---|---|
| AIOSOP API (8200) | ❌ down → ✅ up | `netstat`/curl 000 → `/health` 200 after `supervise_api.py` |
| Redis (6379) | ✅ | `docker ps` `ai-osop-redis` Up; `/health/platform` healthy |
| Postgres (**15432**) | ✅ | `docker ps` Up; `\dt` → 9 tables. (Host port is 15432, not 5432 — earlier "down" was a wrong-port false alarm) |
| Neo4j (7474/7687) | ✅ | `docker ps` Up; `/health/platform` healthy |
| Ollama (11434) | ✅ fast | live completion **1.08s** (`gpt-oss:20b-cloud`); warm-up log ok. **Not** a bottleneck. |
| Juice Shop (3000) | ✅ | HTTP 200 (local ground-truth target available for future pass) |

## 3. MCP Health Matrix

`/health/mcp`: **10/10 servers with tools, 0 stub / 0 mock / 0 down.**

| MCP | Tools | | MCP | Tools |
|---|---|---|---|---|
| security-bridge | 9 | | recon-mcp | 8 |
| burp-mcp | 8 | | payload-mcp | 3 |
| nuclei-mcp | 2 | | threat-intel-mcp | 2 |
| shodan-mcp | 1 | | source-map-mcp | 1 |
| cloud-mcp | 1 | | turbo-intruder-mcp | 1 |

**Gap:** per-server `status`, latency, retry-count, and failure-count are `null` — the MCP health surface reports presence/tool-count only, not the startup/handshake/latency/retry telemetry the audit requires. Runtime defects surface only in logs, e.g. `burp-mcp` `scan_target` NPE and `shodan-mcp` OSINT validation error — neither is reflected in `/health/mcp` (still "healthy").

## 4. Agent Execution Matrix

49 agents registered (worker_count 49). Scanner fleet has 2 instances of each of 13 scanner types (pool, not duplicate — confirmed by distinct `assigned_agent_id`, e.g. `vuln-agent-001..005`, `csrf-agent-001/002`).

| Agent type | Scheduled | Completed | Failed (reaped) | Real findings |
|---|---|---|---|---|
| recon | 1 | 1 | 0 | 179 endpoints ✅ |
| vuln_analysis (xss/sqli) | 50 | 2 nominal | 22 (xss) / sqli in-flight | 0 |
| csrf_scanner | 25 | 2 nominal | 21 | 0 |
| jwt_scanner | 25 | 2 nominal | 21 | 0 |
| nuclei | 1 | 1 | 0 | 0 |
| burp (via MCP) | 1 | 1 (degraded) | 0 | 0 (NPE no-op) |

"Nominal completed" includes at least one `{"status":"success","raw":null}` — a masked empty result, **not** a real success.

## 5. Scheduler / Queue / Worker Analysis

- Concurrency ceiling ≈ 9–10 (matches `benchmark_config.concurrency_level: 10`).
- **Head-of-line blocking**: 9 scanner tasks squat all slots for the full 300s timeout each. Queue grew 72→92 pending during observation while `running` stayed pinned at 9 and `completed` at 2.
- Effective scanner throughput ≈ **0 findings / 5-min batch** — worst-case utilization.
- **Reaper (reliability sprint) works**: reaped 14, 50, 2 = 66 stuck tasks, freeing slots. It is currently the *only* thing terminating hung scanners.

## 6. Root Cause Analysis

**Primary (bottleneck): scanner agents block on un-timed inner operations.**
- Ollama excluded (1.08s live). Tasks sit at 221–231s then fail at ~300–329s with `reaper timeout` — i.e. they run to the task-level budget doing no useful work.
- Timeout discipline is inconsistent in the agent code: `csrf_agent.py:79` uses `client.get(..., timeout=10.0)`, but `vuln_agent.py:78` and `:716` issue bare `await client.get(url)` with no explicit timeout, and multiple `browser_adapter.navigate/execute_action` calls can block on a browser outage (a previously documented hang mode). With no inner timeout, only the 300s reaper stops them.

**Secondary (correctness): success-masks-empty.** `task_scheduler.py:151` & `:546` wrap any non-dict return as `{"status":"success","raw":result}`. A scan returning `None`/empty is persisted as success with `raw:null`, inflating "completed" and hiding the failure from `agent_success_rate`.

**Tertiary (capability dead): Burp active scan.** `burp.api.montoya…Scanner.startAudit(AuditConfiguration)` returns null → `Audit.addRequest(...)` NPE. Degrades to no-op; `/health/mcp` still reports burp "healthy".

## 7. Fix Shipped This Pass — `/health/metrics` 500 → 200

**Defect:** `health.py:66-69` read `._value.get()` on Prometheus metrics; `TASK_THROUGHPUT` is a `Counter` (no `._value`) → `AttributeError` → 500. **Fix:** read via the public `collect()` API (type-agnostic), skipping the `_created` sample.

| | Before | After |
|---|---|---|
| `GET /health/metrics` | 500 (AttributeError) | **200**, live JSON |
| Live payload | — | `active_engagements:1.0, task_throughput:2.0, agent_success_rate:0.0` |

Verified twice: (1) direct import repro of the old crash + new helper returning floats for Counter and Gauge; (2) live HTTP 200 after worker restart. The now-working `agent_success_rate:0.0` independently corroborates the scanner finding.

## 8. Ground-Truth Comparison

No local manifest exists for the external ginandjuice.shop target, so coverage is measured against *executed vs. scheduled*, not vs. a vuln list. For a manifest-scored recall number, the next pass should use local **Juice Shop :3000** (`benchmark_config.yaml`: 100 vulns, expected_recall 0.88) — it is up and ready.

| Capability | Expected | Observed | Verdict |
|---|---|---|---|
| Endpoint discovery | yes | 179 endpoints | ✅ executed |
| Scanner execution (xss/sqli/csrf/jwt) | findings | 0 findings, hang→reap | 🔴 failed |
| Burp active scan | findings | NPE no-op | 🔴 failed |
| Persistence (PG tasks/results) | yes | tasks + results written | ✅ executed |
| Reaper / recovery | yes | 66 reaped | ✅ executed |

## 9. Engineering Recommendations (priority order)

1. **[#1 bottleneck] Enforce per-operation timeouts inside scanner agents.** Give every outbound `httpx` call an explicit `timeout=` (e.g. 10–20s) and wrap `browser_adapter` calls in `asyncio.timeout(...)` well under the task budget, so a dead scanner **fails fast and frees its slot** instead of squatting 300s. Standardize via a shared helper so no call site can omit it. *Expected effect:* scanner throughput and `agent_success_rate` rise from ~0.*
2. **[correctness] Stop masking empty scans as success.** In `task_scheduler.py`, treat `None`/empty/`raw:null` scan output as `failed` (or `no_result`), so metrics reflect reality and retries can trigger.
3. **[capability] Fix Burp active scan.** `startAudit()` returning null indicates AuditConfiguration/licensing/project-state issue in the burp-mcp bridge; surface it as MCP-unhealthy rather than silent degrade.
4. **[observability] Deepen `/health/mcp`.** Populate per-server status/latency/retry/failure so runtime MCP defects (burp NPE, shodan validation error) show up in health, not only logs.

## 10. Before vs. After (this pass)

| Metric | Before | After |
|---|---|---|
| AIOSOP API | down | up + supervised |
| `/health/metrics` | 500 | 200 (live telemetry) |
| Benchmark executable? | no | yes (ran end-to-end) |
| Recon capability | unverified | ✅ 179 endpoints |
| Scanner capability | unverified | 🔴 identified: hang→reap, 0 findings (RCA + fix plan) |

## Appendix — Evidence Artifacts
- `benchmarks/baseline_20260710/*.json` — raw health/observability captures
- `api.boot.log` — API worker log (burp NPE, reaper counts, warm-up)
- `gj_bench.log` — e2e runner
- Postgres `tasks` table, engagement `eng-20260710165305-e2e-gj-20260710-165305`
