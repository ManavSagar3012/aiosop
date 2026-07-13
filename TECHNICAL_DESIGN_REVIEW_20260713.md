# AIOSOP — Technical Design Review & Autonomous Roadmap

**Date:** 2026-07-13
**Branch:** `feat/sprint0-p1-recon-multiplier` @ `e7c77d1`
**System under test:** AIOSOP itself (benchmark target `ginandjuice.shop` is only an instrument)
**Reviewer role:** Chief Architect / Principal SWE / Principal OffSec / Principal SRE / Eng Director

> **Evidence policy.** Every score and recommendation below cites either (a) current source, (b) a
> benchmark log/engineering report on disk, or (c) the knowledge graph. Where a claim rests on
> point-in-time memory rather than re-verified code, it is marked *(memory)*. Nothing here is
> recommended because it "sounds useful."

---

## The one-sentence finding

**AIOSOP is a reliable orchestration machine bolted to a detection vacuum.** Everything upstream of
"attack the target and observe a true/false verdict" works and is stable. The verdict step runs
against **mock MCP stubs that return uniformly negative**, and even a positive mock is dropped by a
safety guard — so **verified findings = 0 on every run**. For a bug-bounty platform, that is the
entire ballgame.

**Primary evidence:**
- Latest E2E log `benchmarks/iter2_20260711/improved_after_20260712-181036.log`: recon completes,
  4 scan tasks report `completed`, and every poll line reads `Vulnerabilities Found: 0`.
- `src/ai_osop/memory/graph_memory.py:285-290` — `add_vulnerability` guard (OSOP-P0-02) refuses any
  `vuln.is_simulated()` finding unless `settings.allow_simulated_findings` is true.
- `src/ai_osop/core/config.py:288-290` — `allow_simulated_findings` **defaults to `False`**.
- `src/ai_osop/agents/vuln_agent.py:52,593` — a **real** sqlmap path exists
  (`SecurityBridgeAdapter.run_sqlmap`), but the benchmark stack boots mock MCP servers
  (`scripts/ops/supervisor.py`, `mcp_supervisor.py`), so the real path is not exercised end-to-end.

Consequence: the "0 findings" symptom currently has **at least three independent sufficient causes**
stacked on top of each other (negative mocks, the simulated-findings guard, no real scanner in the
benchmark loop). You cannot attribute or fix them until you isolate them — which is what the roadmap
below does, one variable at a time.

---

# Phase 1 — Current State (by subsystem)

Graph: 3157 nodes / 23439 edges / 389 files / 16 communities, langs python·go·java·js·ts
(`list_graph_stats`, `get_architecture_overview`). Committed tree is a sparse baseline; richer
behavior lives in a large WIP layer *(memory: project_codebase_split)* — verify method/model
existence in both source and tests before relying on it.

| Subsystem | State (evidence) |
|---|---|
| **Orchestrator** | Phase machine INITIALIZED→RECON→VULN_DISCOVERY→…→COMPLETED, auto-advances via `_phase_monitor`. Engagement-create crash (dict-mutation) fixed; phases advance cleanly in latest log. |
| **Scheduler** | Timeout budgets retuned (sqli 120→900s, scanners 300→600s; `ENGINEERING_REPORT_20260711.md`). Recent commit `79c8b75` capped injection targets 25→12 to force convergence. Still over-schedules: prior run 104 tasks / 4 completed at 1200s timeout *(memory)*. |
| **Worker pool** | 67-agent pool, 16 concurrent scanners (was 9). Agent leak + zombie-engagement hijack fixed *(memory: reliability_sprint)*. |
| **MCP ecosystem** | 10/10 servers register tools — **but as stubs**. Real Go servers (`mcp-servers/go/cmd/*`: shodan, threat-intel, nuclei) + Java Burp extension exist. `session-memory/reporting/attack-graph` MCPs are local-adapter-only, registering them remotely is dead code *(memory)*. |
| **Agents** | RECON (works: 218 endpoints *(memory)*), VULN_ANALYSIS (real sqlmap wired), EXPLOIT, PAYLOAD, REPORTING, plus WIP WORKFLOW/attack-chain/visual/context agents. Recent fixes: ssrf/websocket API mismatch (`e7c77d1`), jwt token-less skip (`cd2c89e`). |
| **Planner / Coverage / Applicability** | PHASE_POLICY + TASK_AGENT_MAP drive task minting. Applicability now ranks targets by injectability (`79c8b75`). Coverage engine over-scales relative to worker throughput. |
| **Neo4j graph** | `Vulnerability` nodes, endpoint links, ground-truth audit, Neo4j-backed dedupe. Structurally sound; **receives zero findings in practice**. |
| **PostgreSQL** | Durable task lifecycle, restart/chain resume recovery *(memory: reliability_sprint)*. |
| **Redis** | `busy_agents`, task keys, session TTL 24h→2h to stop stale accumulation. |
| **Memory / Learning brain** | P2a semantic findings memory + P2b calibration feedback loop *(memory: p2_learning_brain)*. **Starved**: with 0 findings there is no signal to learn from; `ConfidenceCalibrationEngine` not yet in live scoring. |
| **Recon pipeline** | Strongest subsystem. Maps 218 endpoints, completes reliably. |
| **Scanner pipeline** | Mock stubs, uniformly negative. This is the failure locus. |
| **Attack-chain logic** | `attack_chain_agent` (WIP), validation schedules a task; unexercised against real findings. |
| **Dashboard** | 38 React/TS components *(memory S441)*; renders task/finding counts — currently all zero. |
| **Benchmark framework** | Mature: many dated runs, two `ENGINEERING_REPORT_*` docs, raw logs, ground-truth audit. Good instrument. |
| **Ground-Truth Engine** | Audits known targets (`sqli_productId`, `xss_searchTerm`) *(memory)*; never fires positive because nothing reaches it. |
| **Reliability** | Durable lifecycle, stuck-task reaper, restart recovery, chaos validation, **1082 tests pass / 1 skip / 0 fail** (`ENGINEERING_REPORT_20260711.md`). |
| **Known defects** | 0 findings (headline); disk chronically ~100% full crashes the stack ~4×/session *(memory: recon_hang_fix / restarts)*; coverage over-scale; all `think()` degraded when Ollama-cloud is down. |

---

# Phase 2 — Engineering Assessment (0–10, evidence-scored)

Scores are **capability-in-practice**, not lines-of-code. A subsystem that is well-built but starved
of input scores high on quality and low on delivered value — both are shown.

| Subsystem | Matur. | Reliab. | Complete | Scale | Maintain. | BB value | Impl. quality | Why (evidence) |
|---|---|---|---|---|---|---|---|---|
| Orchestrator | 8 | 8 | 8 | 6 | 7 | 7 | 8 | Phase machine stable; crash fixed; auto-advance verified in log |
| Scheduler | 7 | 7 | 7 | 5 | 7 | 6 | 7 | Budgets tuned; still over-schedules vs throughput |
| Worker pool | 7 | 8 | 7 | 6 | 7 | 6 | 7 | 67 agents, leak fixed; 16 concurrent |
| MCP ecosystem | 5 | 7 | 4 | 6 | 6 | **2** | 5 | Registers 10/10 **but stubbed**; real servers unwired in bench |
| Recon | 8 | 8 | 7 | 6 | 7 | **8** | 8 | 218 endpoints, completes |
| Scanner pipeline | 3 | 6 | 3 | 5 | 6 | **1** | 4 | Mock stubs, uniformly negative |
| Vuln/exploit agents | 6 | 6 | 6 | 5 | 6 | 5 | 7 | Real sqlmap wired but not exercised e2e |
| Neo4j graph | 7 | 8 | 7 | 6 | 7 | 5 | 7 | Sound schema; receives 0 findings |
| Postgres/Redis | 7 | 8 | 7 | 6 | 7 | 5 | 7 | Durable lifecycle; TTL fixed |
| Memory/Learning | 5 | 6 | 5 | 5 | 6 | **2** | 6 | Built but starved (no finding signal) |
| Ground-Truth Engine | 5 | 6 | 5 | 6 | 6 | 4 | 6 | Never fires positive |
| Coverage/Applicability | 4 | 5 | 5 | 4 | 5 | 4 | 5 | Over-scales; injectability ranking new |
| Attack-chain | 3 | 4 | 3 | 4 | 5 | 3 | 5 | WIP, unexercised |
| Dashboard | 6 | 7 | 6 | 6 | 6 | 4 | 6 | Renders zeros |
| Benchmark framework | 7 | 7 | 7 | 6 | 6 | 7 | 7 | Good instrument; many runs |
| Reliability/Tests | 8 | 8 | 7 | 6 | 7 | 6 | 8 | 1082 green; chaos-validated |

**Read of the table:** the *left* columns (maturity/reliability/quality) are 6–8 almost everywhere.
The *"BB value"* column collapses to 1–2 exactly at the scanner/MCP/learning row. The platform's
engineering is genuinely good; its **delivered offensive value is gated on a single broken link.**

---

# Phase 3 — Capability Assessment (autonomous BB workflow)

| Capability | Status | Where value is lost |
|---|---|---|
| Reconnaissance | ✅ Strong | — |
| Endpoint discovery | ✅ 218 endpoints | — |
| Parameter extraction | ✅ (injectability ranking) | — |
| Auth handling | 🟡 Phase-1 session auth + Phase-2 diff-auth built *(memory)*; unexercised against findings | downstream starvation |
| Scanner orchestration | ✅ schedules, budgets OK | — |
| Payload generation | 🟡 payload_agent + evolutionary tests exist | not validated against real responses |
| **Verification / verdict** | ❌ **mock stubs → always negative** | **PRIMARY LOSS** |
| Evidence collection | 🟡 schema + report exporters exist | nothing to collect |
| Exploit validation | 🟡 sqlmap CONFIRMED-finding path coded | never triggered in bench |
| Attack chaining | ❌ unexercised | no findings to chain |
| Business-logic testing | ❌ minimal | — |
| Prioritization | 🟡 calibration engine built, not live | no outcomes to calibrate |
| Reporting | ✅ generates reports | reports contain 0 findings |

**Single biggest capability loss:** the **verdict step** (scanner execution → true/false → persisted
`Vulnerability`). Every capability to its right (evidence, exploit, chain, learn, prioritize) is
architecturally present but **input-starved**. Fixing the verdict step unblocks ~6 downstream
capabilities at once — the highest-leverage point in the system.

---

# Phase 4 — Gap Analysis (ranked by engineering impact)

1. **[BLOCKER] No real detection in the benchmark loop.** Mock MCP stubs return negative; real Go/CLI
   scanners exist but aren't wired into the run. → *0 findings, always.*
2. **[BLOCKER] Simulated-findings guard + default config make even a positive mock invisible.**
   `graph_memory.py:290` × `config.py:289` (`allow_simulated_findings=False`). → you can't even
   prove the persistence/audit/dashboard path works.
3. **[HIGH] Coverage over-scaling vs worker throughput.** 104 tasks / 4 completed at 1200s *(memory)*;
   partial fix (25→12) landed but unproven at benchmark scale.
4. **[HIGH] Learning/calibration starved.** Real value only after findings flow; premature to tune.
5. **[MED] Operational fragility.** Disk ~100% crashes ~4×/session; all `think()` degrades on Ollama
   outage. Preflight added but the class of "external dependency down → silent hang" recurs.
6. **[MED] Dead/duplicated surface.** Local-only MCPs registered as remote; large WIP/committed split
   invites "lost changes." Complexity without delivered value.
7. **[LOW] Attack-chain / business-logic / visual agents.** Built ahead of the inputs that feed them.

**Unnecessary complexity to resist adding to:** more MCP servers, more scanner *types*, more agents,
more learning machinery — all of it multiplies a pipeline that currently produces nothing.

---

# Phase 5 — Roadmap (prioritized, gated)

Principle: **convert "0 findings" from a 3-cause ambiguity into a single-variable, provable pipeline,
then replace the mock with reality one scanner at a time.** No breadth work until one real finding
flows end to end.

## Milestone 1 — Prove the finding pipeline (isolate persistence/audit/dashboard)

**Objective.** Make one simulated finding travel scanner → `Vulnerability` node → API → ground-truth
audit → dashboard, with nothing else changed.
**Why first.** Cheapest possible change; removes 2 of the 3 stacked causes so M3 debugging has one
variable. Proves the whole right-hand half of the system in isolation.
**Expected outcome.** Dashboard and `GET /engagements/{id}/findings` show ≥2 findings; Neo4j has the
nodes; ground-truth audit marks `sqli_productId=found`, `xss_searchTerm=found`.

**Tasks**
1. Make the mock executor param-aware: `productId`→`injectable:True`+dbms/param; `searchTerm`→reflected
   XSS hit. (Locate the mock executor used by the benchmark stub servers under
   `scripts/ops/*` / `mcp-servers/python/*`; grep `injectable`.)
2. Set `OSOP_ALLOW_SIMULATED_FINDINGS=True` **for this milestone only** (env, not code default).
3. No other change.

**Verification** — unit: mock returns injectable for `productId`, negative for a control param.
Integration: one engagement, assert ≥2 findings via API. DB: `MATCH (v:Vulnerability {engagement_id})
RETURN count(v)` ≥2. Dashboard: finding count > 0. Regression: full suite still 1082-green.
**Completion (objective):** ≥2 persisted ground-truth findings, queryable via API **and** Neo4j;
ground-truth audit shows both expected classes `found`.
**Go/No-Go:** if findings don't appear with the guard *open* and mocks *positive*, the persistence
path itself is broken — **STOP and fix that**; do not touch real scanners until this passes.

## Milestone 2 — Right-size coverage to worker throughput

**Objective.** A 1200s run reaches ≥80% task completion while preserving all M1 findings.
**Why.** A pipeline that never drains can't be measured; convergence is a prerequisite for recall/
precision numbers to mean anything.
**Expected outcome.** Ground-truth targets always in scope; long tail of low-value params capped.

**Tasks:** validate the 25→12 cap at benchmark scale; prioritize parametrized high-value endpoints;
ensure ground-truth targets are never capped out.
**Verification:** timed run; completion ratio from scheduler counters; findings count unchanged from M1.
**Completion:** ≥80% task completion at 1200s **and** M1 findings still present.
**Go/No-Go:** if <80% completion, do not proceed — throughput will mask real-scanner results in M3.

## Milestone 3 — Wire ONE real scanner end-to-end (sqlmap)

**Objective.** Produce ≥1 **real** finding (`is_simulated()==False`, `tool_source=sqlmap`) on the
authorized target, with `allow_simulated_findings=False`.
**Why.** This is the actual mission. The real path already exists (`vuln_agent.run_sqli_scan` →
`security_bridge.run_sqlmap`); M3 is about running it in the benchmark loop instead of the stub, not
building new code.
**Expected outcome.** The guard rejects nothing (finding is real); dashboard shows a genuine SQLi.

**Tasks:** boot the real security-bridge scanner in the benchmark stack instead of the mock for
`sqli_scan`; keep every other tool mocked; set `allow_simulated_findings=False`; confirm timeout
budget (900s) still fits real sqlmap latency (~650–700s min, per `ENGINEERING_REPORT_20260711.md`).
**Verification:** integration run; assert a `Vulnerability` with `tool_source=sqlmap` and
`is_simulated()==False`; execution trace shows a real sqlmap subprocess; ground-truth audit marks
`sqli_productId=found` from the real tool.
**Completion:** ≥1 real, non-simulated sqlmap finding on the authorized target, guard closed.
**Go/No-Go:** if 0 real findings, this is the mission's core defect — **STOP**, root-cause the real
sqlmap path (timeout / bridge / MCP transport) before adding any second scanner.

## Milestone 4 — Recall/precision baseline + second scanner (nuclei or XSS)

**Objective.** Establish the first real recall/precision numbers against ground truth, then add one
more real scanner and re-measure.
**Why.** Only now is there a signal to optimize; this is where the learning/calibration brain finally
has data.
**Completion:** documented recall/precision on the ground-truth set for ≥2 real scanners; calibration
engine ingesting real outcomes.
**Go/No-Go:** proceed to breadth (more scanners, attack-chaining, business logic) only after recall is
measured and non-zero for two independent tools.

---

# Phase 6 — Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| **"Prove-the-pipeline" mocks leak into real runs** and inflate results | **High** | `allow_simulated_findings` stays env-gated & default-false (already is); assert `is_simulated()==False` in M3+ acceptance; never commit the env flag on |
| Real scanner latency exceeds budget → reaped → looks like "no finding" | High | Confirm 900s ≥ observed sqlmap min before M3; separate "reaped" from "negative verdict" in telemetry |
| Coverage over-scale hides real results behind a non-draining queue | Med | M2 gate blocks M3 until ≥80% completion |
| Operational: disk 100% / Ollama down → silent hang mid-run | Med | Disk preflight (≥5GB) already noted; add explicit "external dep down" fast-fail so hangs surface as errors, not zeros |
| WIP/committed split → "lost changes" after stash | Med | Never `git stash` here *(memory)*; grep source+tests before assuming a symbol exists |
| Premature breadth (new scanners/agents) multiplies a zero-yield pipeline | Med | Roadmap gates forbid breadth before M4 |

---

# Phase 7 — Final Engineering Recommendation

1. **Project maturity: ~60%.** Orchestration, reliability, recon, persistence, tests are 6–8/10 and
   chaos-validated (1082 green). The machine is real.
2. **Autonomous BB capability: ~15%.** Recon/discovery/scheduling are strong, but the verdict step —
   the thing that makes it a bug-bounty platform — yields **0 real findings**. Everything downstream
   is input-starved.
3. **Biggest remaining weakness:** the detection/verdict layer runs on mock stubs; no real scanner
   produces a persisted finding in the benchmark loop.
4. **Biggest engineering opportunity:** the real sqlmap path already exists — wiring it into the run
   is integration, not invention. High payoff, low new code.
5. **Highest-ROI improvement:** **Milestone 1** (param-aware mock + open guard). A tiny diff that
   proves the entire right half of the system and collapses a 3-cause failure into one variable —
   making M3 tractable.
6. **What NOT to work on yet:** new MCP servers, new scanner types, new agents, attack-chaining,
   business-logic testing, dashboard polish, and learning/calibration tuning. All of them multiply a
   pipeline that currently outputs nothing. Resist every one until M4.
7. **Next milestone:** **M1 — Prove the finding pipeline.**
8. **Why M1 before everything:** "0 findings" today has three stacked sufficient causes. You cannot
   fix or even attribute the real-scanner defect (M3) while two other causes can independently
   produce the same zero. M1 removes the two cheap causes for near-zero cost and turns the mission's
   core problem into a single-variable, provable experiment. It is the smallest change that makes all
   subsequent measurement honest.

---
*Verified against current source (`config.py`, `graph_memory.py`, `vuln_agent.py`), the latest E2E
log, and `ENGINEERING_REPORT_20260711.md`. Claims resting on point-in-time memory are marked. Treat
file:line citations as of `e7c77d1`; re-verify before editing.*
