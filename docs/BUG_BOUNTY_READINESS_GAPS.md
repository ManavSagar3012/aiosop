# AIOSOP — Bug-Bounty Readiness Gap Analysis

_Audited 2026-07-20 against branch `fix/mock-findings-honest-stub-tool-guard` @ b068dd90._

Scope of this audit: what stands between AIOSOP today and being trusted to
produce **submittable, in-policy bug-bounty findings** — autonomously or
semi-autonomously — against a real program (reference target: Syfe on HackerOne).

Every item below was verified by reading the code first-hand and is cited with
`file:line`. Four parallel deep-dive agents (orchestrator, reporting, coverage,
test-honesty) were dispatched but died on an API quota limit before returning;
those four areas are marked **(needs deeper audit)** where my own pass was
shallower. Nothing here is assumed — unverified areas are labelled as such.

---

## What is genuinely SOLID (do not rebuild)

- **Deterministic oracles** — SQLi (`core/sqli_oracle.py`), injection/traversal/
  redirect/SSRF/XXE (`core/injection_oracles.py`), JWT forgery
  (`core/jwt_tester.py`), IDOR via differential auth (`core/diff_auth_engine.py`).
  Evidence-gated: a finding is validated only on an objective signal. These are
  the real capability core and were live-proven against Juice Shop.
- **Scope enforcement** (`safety/scope.py:33`) — exclusion-first, suffix match,
  IP-range, non-recursive `host_in_scope` for hot loops. Good.
- **Rate limiter** (`safety/rate_limiter.py:48`) — real token bucket, global/
  target/tool tiers, hard acquire timeout.
- **Docker sandbox** (`safety/scope.py:299`) — real per-engagement bridge network
  + iptables egress, not a stub.
- **API auth** (`api/deps.py:109`) — JWT or constant-time bearer, fail-closed
  (dev fallback removed).
- **Auth-passthrough scanning** — just landed + live-proven (`benchmarks/live_auth_passthrough.py`).

---

## BLOCKERS — must fix before ANY real-program traffic

### B1. Safety layer is bypassed by the actual scan path
`core/deterministic_scan.py` oracles fire raw `httpx` at whatever URL is in the
graph. There is **no per-request scope re-check** and **no rate-limiter call**
inside the scan loop. Scope is validated once at engagement creation
(`api/routers/engagements.py:37`), never per-request.
- Risk: a mis-attributed / poisoned graph endpoint → out-of-scope request with
  zero guard. On a real program that is an instant rules violation.
- Fix: enforce `host_in_scope(url)` on every request and route every probe
  through the rate limiter (see B2, B5).

### B2. No per-request rate limiting on scan traffic
`RateLimiter.acquire()` gates **task** admission (`agents/base.py:368`), not
individual HTTP probes. One scan task = up to 60 candidates × N payloads, fired
as fast as the event loop allows. Defaults are also throughput-tuned: 50 req/s
global, 10 req/s per target (`safety/rate_limiter.py:56-59`).
- Risk: reads as an automated attack / DoS — Syfe explicitly disqualifies "any
  automated attack techniques on production" and DoS. This alone bars autonomous
  use on that program.
- Fix: per-request throttle on the egress path; bounty-safe defaults (≤~2 req/s
  per target, configurable per engagement).

### B3. Mandatory research header is not implemented anywhere
Grep for `X-HackerOne-Research` / `wearehackerone` = **0 hits**. The program
requires `X-HackerOne-Research: <username>` on prod traffic and a
`@wearehackerone.com` signup email. AIOSOP cannot currently comply.
- Fix: inject the header on every outbound request; carry it in engagement config.

### B4. False-positive-prone detectors in the "breadth" agents
Several non-core agents flag on weak heuristics, not confirmed exploitation:
- **SSTI** (`agents/ssti_agent.py:56`) — `if template in response.text`: checks
  the payload was **reflected**, not **evaluated**. `{{7*7}}` echoed back ≠ SSTI.
  Pure false-positive generator.
- **CSRF** (`agents/csrf_agent.py:80-87`) — flags "no CSRF token string in
  response" as a potential vuln (`confirmed: False`), no working PoC, no check
  that the endpoint is actually state-changing + cookie-authed.
- Risk: submitting these = unreproducible reports = reputation/removal on H1.
- Fix: gate every reportable finding behind a real oracle (evaluation proof for
  SSTI, a working cross-site PoC for CSRF), or mark them lead-only and never
  auto-submit. **(coverage of all ~20 agents needs the deeper audit that got
  quota-killed — SSTI/CSRF are confirmed; others unverified.)**

---

## MAJOR — needed for trustworthy semi-autonomous operation

### M1. No central governed egress client
42 separate `httpx.AsyncClient(...)` instantiations across agents/oracles, no
single chokepoint. B1/B2/B3 cannot be fixed in one place — every call site is
an independent egress.
- Fix: one governed async client (scope + rate + research-header + audit) that
  all agents and oracles must use. This is the enabling refactor for B1–B3.

### M2. engagement_id / session_id split-brain
`agents/base.py:330` aliases `session_id = task.engagement_id`, then findings are
written with `session_id` as the `engagement_id` (base.py:757, 916, 934, +others).
A recent commit added dual-key **reads** to compensate rather than unifying the
ID — a patch over the symptom.
- Risk: findings written under one key, searched under another → silently missing
  findings in reports. (Prior observation #621: "graph is empty" symptom.)
- Fix: unify on a single canonical id end-to-end; delete the dual-key workaround.

### M3. Full autonomous pipeline is unproven (needs deeper audit)
`benchmarks/juiceshop/README.md` states plainly the benchmark proves the engines
in isolation and does NOT prove "the full autonomous pipeline (API + Neo4j +
agents + LLM planning)". Recent commits reference findings "stranded" on 300s
timeouts and a double-timeout race (base.py:388). Root-cause vs patched status of
the orchestrator/scheduler/phase-monitor was the target of a dispatched agent
that died on quota — **re-run that audit.**
- Fix: an end-to-end scorecard run (`benchmarks/score_engagement.py`) of a real
  orchestrated engagement, not just isolated oracles.

### M4. No end-to-end LLM-planning test (needs deeper audit)
Suspicion (unconfirmed — the test-honesty agent died): the suite mocks the LLM
(`OSOP_MOCK_LLM`) everywhere, so the real planning loop may never be exercised in
CI. If true, "autonomous" behavior is untested.
- Fix: at least one gated integration test that drives a real (small) LLM through
  a full plan→scan→report cycle.

### M5. Reporting completeness unverified (needs deeper audit)
`core/bounty_report.py` / `report_generator.py` / `poc_generator.py` produce
reports, but completeness (working copy-pasteable PoC, real request/response
evidence attached, CVSS computed vs hardcoded, evidence_vault real storage) was
the reporting agent's remit — it died on quota. **Re-audit before trusting output
for submission.**

---

## MINOR / hygiene

- `cli.py:65` `list_engagements` is a stub (`# This would query the API`).
- 53 `placeholder`/`stub` markers across `src/` — triage which are load-bearing.
- Rate-limiter defaults (M-adjacent) should ship bounty-safe, not throughput-safe.
- N+1 persistence patterns in `vuln_agent.py` / `recon_agent.py` (perf, not
  correctness; multiple prior observations).

---

## Recommended sequence

1. **M1 (governed egress client)** first — it's the seam that makes B1/B2/B3
   one-place fixes instead of 42.
2. **B1 + B2 + B3** on top of M1 — this is the minimum to be *in-policy*.
3. **B4** — gate or quarantine the false-positive detectors so nothing
   unreproducible can auto-submit.
4. **M2** — unify the id so findings actually survive to the report.
5. Re-run the **quota-killed audits (M3/M4/M5)** — orchestrator maturity,
   test honesty, reporting completeness — before claiming autonomous readiness.

Until B1–B4 land, AIOSOP should run **manual/scoped assist only** (individual
oracles against operator-chosen endpoints), never autonomous against a live
program.
