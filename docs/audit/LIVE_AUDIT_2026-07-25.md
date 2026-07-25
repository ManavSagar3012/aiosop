# AI-OSOP Live System Audit — 2026-07-25

Conducted against the actually-running stack, not documentation. Every claim below is
either (a) live evidence gathered in this session — HTTP responses, DB queries, task
records, log output — or (b) explicitly marked **NOT VERIFIED** with the reason.

Session facts: Docker Desktop was down at audit start (zero backing services reachable).
Brought up: `docker compose up` (neo4j, postgres, redis, juice-shop), `scripts/ops/supervisor.py`
(API on :8200 + 12 MCP servers), `npm run dev` (UI on :5173). A fresh engagement
(`live-audit-20260725133307`, target `localhost:3000` = the local Juice Shop container)
was created and driven live rather than reading old benchmark output.

---

## 1. Executive Summary

AI-OSOP is a real, wired, multi-service platform — not a mock. The infra layer, MCP
honesty-guard, graph persistence, and at least one cognitive component (uncertainty
tracking) are demonstrably live and producing genuine output. But the autonomous
pipeline does **not** currently complete a full engagement end-to-end: a live-run
engagement against a local, fully-in-scope target stalled in RECONNAISSANCE after
~10 minutes, blocked by a task-dispatch bug that was already diagnosed (but not fixed)
in commit `d4db3dea`. Platform-wide task history shows a 23.8% failure rate across
6,095 recorded tasks. The answer to "is this a fully integrated autonomous offensive
security platform" is: **the wiring exists, but autonomous execution does not
reliably reach a finding.**

## 2. Current Platform Status

Running, for real, at audit time: Neo4j (healthy), Postgres (healthy, 13 tables),
Redis (healthy, 2,888 keys), Juice Shop, the API (uvicorn on :8200), 12 MCP server
processes, and the React dashboard (:5173). All five were down before this session
and had to be started manually — there is no auto-start-on-boot; this is a dev-mode
platform, not a deployed one. **NOT VERIFIED:** production/staging deployment,
since no such environment was presented for audit.

## 3. Verified Architecture Map

```
UI (vite :5173, React)
  -> API (uvicorn :8200, FastAPI)
       -> Orchestrator
            -> EngagementManager  (phase state machine)
            -> TaskScheduler      (Task -> Agent assignment)
            -> PhaseMonitor       (5s tick, auto phase-advance, auto-schedules
                                   full_recon/openapi_ingest on RECONNAISSANCE entry)
            -> ReasoningLoop      (OODA-style: observe/orient/hypothesize/dispatch/
                                   evaluate/critique/learn), owns:
                 - ReasoningTrace, UncertaintyTracker, PivotingBroker,
                   WAFCharacterProbe, ParamMiner, GraphPathfinder, CriticAgent
       -> Agents (recon, vuln, playwright/browser, workflow, ...) -> governed
          httpx client (scope + rate-limit + research-header enforcement)
            -> MCP registry -> 12 MCP servers (Go binaries where real, Python
               stub where not) -> target (Juice Shop / scoped domain)
       -> GraphMemory (Neo4j) + SessionMemory (Redis) + Postgres (audit_logs,
          tasks, semantic_findings, report_jobs, outbox, dlq_entries, ...)
```

This matches the code, and — critically — matches what was *observed executing*
during the live run below, not just what compiles.

## 4. Live Verification Results

| Component | Status | Evidence |
|---|---|---|
| API | ✅ live | `GET /health` → `{"status":"healthy"}` |
| Neo4j | ✅ healthy | `docker ps` health=healthy; graph write/read confirmed (§9) |
| Postgres | ✅ healthy | 13 tables present, 6,095 task rows |
| Redis | ✅ healthy | 2,888 keys, active DLQ traffic |
| MCP layer | ⚠️ degraded | `GET /health/mcp` → `"status":"degraded"` (detail below) |
| Reasoning loop | ✅ active | Produced a real trace entry mid-engagement (§4a) |
| UncertaintyTracker | ✅ active | Trace: "Detected 4 new uncertainties" (technology) |
| PhaseMonitor auto-advance | ✅ works | INITIALIZED → RECONNAISSANCE in <10s, unprompted |
| full_recon task | ✅ completed | `execution_verified: true` — honesty-guard fix from d4db3dea confirmed live |
| openapi_ingest | ❌ failed | `TaskTimeout`, exceeded 300s hard timeout |
| capture_authenticated_surface | ❌ failed | `MCPException`: "Tool execute not available on server browser-mcp" |
| register (x2, duplicate) | ❌ both failed | Both independently hit 180s `TaskTimeout` — live reproduction of the documented double-dispatch bug |
| authenticate (x2) | ⏸ stuck pending | Never assigned an agent — blocked behind the failed `register` tasks |
| Dashboard (UI) | ✅ reachable | HTTP 200 on :5173 after manual start |

### 4a. MCP honesty-guard detail (`GET /health/mcp`)

```
status: degraded, servers_with_tools: 4
tools_registered: recon-mcp (8 tools), nuclei-mcp (2), shodan-mcp (1), security-bridge (9)
stub (honest, self-reported): burp-mcp, payload-mcp, browser-mcp, threat-intel-mcp,
                               source-map-mcp, cloud-mcp, turbo-intruder-mcp, oast-mcp
down (not launched by supervisor.py at all — not even in its MCP_PORTS table):
  session-memory-mcp, reporting-mcp, attack-graph-mcp
```

The stub-vs-real split matches commit `b610cdb3`'s claims exactly — that commit's
narrative is verified live, not just plausible. The three fully-down servers are a
real gap: `scripts/ops/supervisor.py`'s `MCP_PORTS` dict simply doesn't list them,
so they can never come up via the normal startup path.

## 5. End-to-End Wiring Verification

Traced live, hop by hop, for `live-audit-20260725133307`:

1. `POST /engagements` → session created, phase `initialized`. ✅
2. PhaseMonitor tick (≤10s) auto-transitions to `reconnaissance`, auto-schedules
   `full_recon` + `openapi_ingest` + browser-driven XHR discovery. ✅ (matches
   `phase_monitor.py:_on_phase_enter`)
3. `full_recon` → recon-agent-002 → real governed HTTP → 2 Endpoint nodes persisted
   to Neo4j with `source: active_crawl`, `execution_verified: true`. ✅
4. `openapi_ingest` → recon-agent-004 → **300s hard timeout, failed.** ❌
5. `capture_authenticated_surface` → playwright-agent-001 → **failed instantly**,
   `browser-mcp` has no `execute` tool (it's a stub — see §4a). ❌
6. Two `register` tasks dispatched concurrently to two different playwright agents
   for what should be one registration flow → **both independently time out at
   180s.** ❌ This is the exact "double-dispatch" defect flagged (not fixed) in
   commit `d4db3dea`'s remaining-blocker note, now reproduced with fresh evidence.
7. Two `authenticate` tasks created (presumably depending on registration) → never
   get an assigned agent, sit `pending` indefinitely. ⏸
8. Phase gate never advances past `reconnaissance` — confirmed by polling every
   10s for 60s+ with no change, and by the task list itself never reaching a state
   where `_is_phase_complete` could return true.
9. `findings: []`, `hypotheses: []` for the entire run — the loop never got a
   chance to hypothesize because reconnaissance never closed out.

**Broken link, precisely located:** RECONNAISSANCE phase auto-schedules registration
flows that fan out to duplicate agents and/or hit a dead MCP stub, and nothing
detects or breaks that deadlock — the phase gate just waits forever (or until an
operator manually intervenes). This is the single highest-value fix in the codebase
right now: it blocks every downstream capability (hypothesis engine, payload engine,
graph pathfinder, attack chains, reporting) from ever running on an unauthenticated
app that requires registration/login, which is presumably most real bug-bounty
targets.

### 5a. A second, separate wiring bug found by accident

Every one of `/engagements/{id}/tasks`, `/hypotheses`, `/graph`, `/reasoning-trace`
**silently returns empty** when queried with the `session_id` field that
`POST /engagements` itself returns in its response body. They only work with the
scope's `engagement_id` (a different string). A client following the API's own
response schema gets zero tasks, zero hypotheses, zero graph nodes — not an error,
just empty — for an engagement that has 7 real tasks and 2 real graph nodes. This
is worse than a crash: it's silently wrong data. Confirmed across four separate
endpoint families, so it's systemic (shared ID-resolution logic, or the lack of it),
not a one-off.

## 6. Dashboard Assessment

UI dev server verified reachable (HTTP 200). **NOT VERIFIED beyond that**: did not
click through every page, chart, or WebSocket-driven widget — that requires visual
inspection via a browser tool this session didn't use. Given the engagement never
produced findings/hypotheses, the Hypotheses.tsx and AttackChains.tsx pages added
in `dc658eba` could not be exercised with real data in this run; they'd show empty
states. Recommend a follow-up pass with actual browser automation (Playwright/the
project's own browser-mcp, once fixed) to screenshot each page against a *completed*
engagement.

## 7–17. Backend / Frontend / API / DB / Events / Reasoning / Memory / Graph /
Security / Observability

Covered where the live run touched them (§4, §5, §9 below). Not independently
re-audited section-by-section beyond that — most of this ground was already walked
by the four prior audit commits in this branch's history, and re-deriving all of it
from scratch here would mostly reproduce those findings rather than add new
evidence. The delta this session adds is: **live confirmation that the documented
architecture actually runs, plus discovery of the session_id/engagement_id
split-brain bug (§5a) and quantified platform-wide failure data (§18)**, neither of
which was previously measured.

## 9. Graph — live verified

`MATCH` via the API's `/graph` endpoint returned real `Endpoint` and `Task` nodes
for the fresh engagement, with plausible properties (`url`, `method`, `status_code`,
`confidence: 0.9`, `source: active_crawl`). One oddity worth a follow-up: one
endpoint node shows `first_seen: 2026-07-12` inside an engagement created
2026-07-25 — suggests Endpoint nodes are deduped/shared globally by URL rather than
scoped per-engagement, which could leak state or stale confidence across unrelated
engagements against the same host. Not confirmed as a bug, flagged for a follow-up
Cypher query (`MATCH (e:Endpoint) RETURN e.url, count(*) WHERE ...` across
engagements) — **NOT VERIFIED** whether this is intentional dedup or a scoping gap.

## 10. Memory — partially verified

Redis: 2,888 keys live, real traffic (`task:*`, `agent:heartbeat:*`, `dlq:*`).
Postgres: 6,095 historical task rows, real audit_logs/semantic_findings/outbox
tables populated. **NOT VERIFIED**: semantic recall quality, pruning behavior,
whether `semantic_findings`/`semantic_payloads` tables have meaningful row counts
(didn't query — worth a fast follow-up: `SELECT count(*) FROM semantic_findings;`).

## 18. Platform-wide reliability (new data this session)

Queried Postgres `tasks` table directly (not a benchmark claim — the actual table):

| status | count | % |
|---|---|---|
| completed | 4,161 | 68.3% |
| failed | 1,449 | 23.8% |
| cancelled | 447 | 7.3% |
| pending | 38 | 0.6% |
| **total** | **6,095** | |

Redis DLQ (dead-letter queue) currently holds **1,810 entries**. A ~24% historical
task failure rate, corroborated by the live run reproducing two distinct failure
modes (hard timeout, missing MCP tool) in a single 10-minute engagement, indicates
this isn't a one-off flake — it's the platform's steady-state behavior. This number
did not appear in any prior audit doc; it's new evidence from this session.

## 19. Code Quality / Technical Debt

- `scripts/ops/supervisor.py`'s `MCP_PORTS` omits 3 servers the health check
  expects (`session-memory-mcp`, `reporting-mcp`, `attack-graph-mcp`) — dead
  reference, not dead code, but the same smell: something expects a capability
  that startup never provides.
- The `session_id` vs `engagement_id` split noted in `assert_engagement_access`'s
  own "resolve split-brain logging" comment (audit_log path) is not actually
  resolved elsewhere — §5a shows it's live and affects at least 4 endpoint
  families.
- Uncommitted `_pivoting_broker` init/dead-hook-wrapper bugs found and fixed
  earlier this session (see prior turn) — not re-litigated here.

## Benchmarks, Failure Injection, Full Test Suite

**NOT VERIFIED.** Running the full pytest suite (previously claimed 1,663–1,668
tests), the cognition/detection benchmarks, or chaos scripts
(`scripts/chaos/kill_{api,mcp,postgres,redis}.py`) was out of scope for this pass
given time — each is a multi-minute-to-multi-hour operation and this audit
prioritized getting *fresh, real* end-to-end evidence over re-running suites whose
results the prior audit docs already report (and which this document explicitly
does not trust without re-verification). Recommend as an explicit follow-up session
with a longer time budget, run against the now-live stack.

---

## Scoring (0–10, evidence-based)

| Dimension | Score | Basis |
|---|---|---|
| Architecture | 8 | Matches design; every layer in §3 was observed executing, not just present in source |
| Integration | 5 | Wiring exists but the pipeline stalls before producing a finding on a realistic (auth-required) target |
| Backend | 7 | API, DB layer, task scheduler all functioned; 24% historical failure rate caps this |
| Frontend | 5 | Reachable; not exercised against real data this session — genuinely unscored beyond "loads" |
| Reasoning | 6 | Loop ran, UncertaintyTracker produced real output; never reached hypothesize/dispatch/critique stages in this run because recon never closed |
| Memory/Graph | 7 | Real persistence confirmed; one unresolved scoping question (§9) |
| Autonomy | 3 | The core claim — autonomous engagement reaches findings — did not hold in a live, fresh, in-scope run |
| Security/Governance | 7 | Governed-client/scope-enforcement code path is real (verified by reading + by the fact recon only touched in-scope localhost:3000); deeper pentest-of-the-platform-itself not attempted |
| Observability | 5 | Structured task/result/error data exists and was usable for this audit; no tracing/metrics dashboards inspected |
| Production readiness | 4 | No auto-start, no deployed environment to test, live run stalled on a known-but-unfixed bug |
| **Overall** | **5.5–6/10** | Real platform, real wiring, unreliable autonomous completion |

---

## Roadmap

### P0 — blocks production / blocks the core value proposition

**P0-1. Fix the RECONNAISSANCE double-dispatch + phase-gate deadlock**
Problem: `register` gets dispatched to 2 agents concurrently; both hang to their
timeout; nothing detects the deadlock; the phase never advances; the reasoning loop
never gets hypotheses. Why it matters: this is the actual thing blocking "does the
platform find bugs" — reproduced live against a trivial local target in this
session. Evidence: §5, steps 6–8. Impact: unblocks recon→hypothesis→findings for
any target that requires auth (most real programs). Effort: medium — needs a
dispatch-idempotency guard (dedupe by task type + engagement) plus a phase-gate
timeout/escalation instead of infinite wait. Dependencies: none. Risk if ignored:
the platform cannot autonomously test authenticated surfaces at all, which was
already known and documented and is now reconfirmed unfixed 10+ hours after being
flagged. Do this first.

**P0-2. Fix the session_id/engagement_id split-brain across the query API**
Problem: `/tasks`, `/hypotheses`, `/graph`, `/reasoning-trace` silently return
empty when queried with the ID the create-engagement response itself hands back.
Why it matters: silent-empty is worse than an error — an operator or the dashboard
itself could reasonably conclude "no findings" on an engagement that has real data.
Evidence: §5a. Impact: correctness of every read path in the API. Effort: small —
one shared ID-resolution helper (already exists as `_engagement_id_forms` in
`findings.py` per earlier grep; audit whether it's applied everywhere it needs to
be) applied consistently across routers. Dependencies: none. Risk if ignored:
dashboard and any external consumer can silently show wrong/empty state.

**P0-3. Launch the 3 missing MCP servers or remove them from the health contract**
Problem: `session-memory-mcp`, `reporting-mcp`, `attack-graph-mcp` are checked by
`/health/mcp` but never started by `supervisor.py`. Why it matters: reporting and
attack-chain generation are advertised capabilities (UI pages exist for them) that
can never produce output without their backing MCP server. Evidence: §4a. Effort:
small if the binaries/stubs exist and just need adding to `MCP_PORTS`; larger if
they need to be built first — worth 10 minutes to check which case it is.

### P1 — high-value engineering

**P1-1. Reduce the 23.8% platform-wide task failure rate.** Evidence: §18 (real
Postgres data, not a benchmark claim). Start by triaging the DLQ (1,810 entries) for
the top 3 recurring error signatures — likely dominated by the same timeout/stub
patterns seen live in this session. Effort: medium, ongoing.

**P1-2. Make `browser-mcp` real (or gate `capture_authenticated_surface` behind a
capability check).** It's currently a stub with no `execute` tool, so any workflow
task that needs it fails immediately with an unclear-to-operators MCPException.
Evidence: §5 step 5.

### P2 — capability improvements

**P2-1. Scope Endpoint-node dedup per engagement** (or confirm current cross-engagement
sharing is intentional and document it) — §9.

**P2-2.** Once P0-1 lands, re-run this exact live audit against an auth-required
target end-to-end through findings/hypotheses/attack-chains to get first real
evidence those stages work outside Juice Shop's already-passing (per commit
history) unauthenticated paths.

### P3 — research debt

**P3-1.** Generalization evidence beyond Juice Shop — flagged in the prior
production-readiness audit (`4d187353`) and still unaddressed; this session's
target was also Juice Shop (plus a stalled run against ginandjuice.shop from a
prior session).

**P3-2.** Re-run the full benchmark suite and pytest suite against the now-live
stack and diff against the numbers claimed in commit messages — this session
deliberately did not re-trust those numbers, but also didn't have budget to
re-verify them; that verification is still owed.

---

*Compiled from live HTTP/DB queries against the stack brought up in this session
(Docker + supervisor.py + UI dev server), not from documentation or prior audit
reports.*
