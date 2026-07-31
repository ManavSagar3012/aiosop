# AI-OSOP — Honest Readiness Gate (2026-07-31, live evidence)

Generated against the live stack (Neo4j + Postgres + Redis + 13 MCP servers +
Ollama + OWASP Juice Shop) on branch `feat/real-discovery-and-agent-loop`.

This document defines the *readiness gate* for "genuinely bug-bounty-ready". Each
line links to its proof or its open blocker. It deliberately avoids the
platform's own habit of writing self-attestation certificates: everything below
is either queryable from the live stores right now or explicitly listed as open.

## The canonical result (live, reproducible)

The decisive run is `eng-20260731042529-dbg-stall-002` against the live Juice Shop:

- Phase path: reconnaissance -> vulnerability_discovery -> exploitation.
- Scanner fleet fired (not the deterministic probe): sqli_scan completed once,
  xss_scan completed 3 times, nuclei/burp/jwt/csrf/ws raced and timed out.
  Exploit path: generate_payloads -> exploit_validation pending (beyond timeout).

### Validated real findings (proof in Neo4j)

| ID | vuln_type | severity | validated | evidence (verbatim excerpt) |
|---|---|---|---|---|
| vuln-c42c07806df7 | sqli (auth_bypass) | critical | TRUE | payload `' OR 1=1--`; server returned a session JWT (`technique: auth_bypass`, `http_status: 200`, JWT token captured) |
| vuln-c7c41a991559 | race_condition | high | TRUE | /rest/basket double-check race (details in node) |

These came from the agent/tooling pipeline, not the deterministic probe, and
each carries raw HTTP evidence (request + response + JWT).

Deterministic probe (separate validation): recall 1.0 / precision 1.0 / FP 0 on
Juice Shop; the CI detection regression gate scorer reports `validated_recall=1.0`.
This is the "0 findings" claim falsified, with a reproducible artifact.

## Where the platform is genuinely stopped (honest gaps)

1. **Hypothesis gate livelock**
   - The reasoning loop keeps regenerating open hypotheses; the phase monitor's
     bounded gate fires `hyp_gate_bound_exceeded_advancing` repeatedly but the
     phase stays in reconnaissance for thousands of ticks (provt-004 + dbg-stall-002
     both stalled in recon on auto-path). A manual transition works and the
     pipeline flows end-to-end on manual kick. (Evidence: /tmp API log scan showing
     `hyp_gate_open_hypotheses=4 waited_ticks=3304`.)
   - Root cause: the reasoning loop's hypotheses aren't being marked resolved by
     the evaluate path often enough; phase monitor assumes a short wait and then
     retries forever.

2. **Scanner hard-timeout (300s/600s)**
   - `sqli_scan`, `csrf_scan`, `jwt_scan`, `xss_scan`, `_upload_scan` individually
     fail roughly 30-70% of the time on `agent execution exceeded 300s/600s hard
     timeout` (per Postgres `tasks` status history). Fundamental cause is a cold,
     memory-starved default host. The reasoning_fallback model already swapped
     (qwen3:8b -> llama3) — the reboot logs on 2026-07-30 show the timeouts fell
     from 100+/day to 0 after the model switch, but the live vuln fleet still
     hits the 600s ceiling on shared-agent-queue contention.
   - Mitigation in place but unverified at scale: `browser_mcp_max_concurrency=4`
     and task_scheduler claim-locks stopped crash-loops, so the timeouts are now
     capacity-driven, not deadlock-driven.

3. **MCP honest-stub guard (550 trials) rejecting real scanners**
   - The deterministic-scan guard `MCP tool contract unavailable: ...` is still
     firing for burp/nuclei when scanning with deterministic scans. The new
     capability preflight correctly identifies tool-missing conditions, but this
     breaks the "always scan" path. Fix is pending (schedule regular scanners
     through the same executor).

4. **Reporting is never reached on autopilot**
   - Because recon never advances on its own, reporting never runs
     automatically. The /engagements/{id}/report endpoint currently 404s for
     run-002 because it wasn't kicked to reporting manually.

## What's verified working end-to-end (live)

- FastAPI gateway + auth (JWT, RBAC via `senior_operator`).
- Scope enforcement + governed egress (scope-check hook) on target traffic.
- TLS governance: `resolve_tls_verify` (W5) enforces verify-by-default + audited
  opt-in, proven against the test matrix and the live Ollama smoke harness.
- MCP capability preflight + execution gate (W3): deterministic tool-contract
  enforcement (fail-closed) on the execute path, observed declining live against
  missing tool registrations.
- Reasoning-token budget + reasoning-model routing (W7): `llm_reasoning_model`
  config drove a real LLM loop turn (think_with_tools live-invoke proof in
  `benchmarks/results/w1_tool_loop_live_proof.json`).
- LLM-driven hypothesis selection (W2/roadmap#4): the reasoning loop now picks
  the SQLi hypothesis over the dir-listing hypothesis (live proof in
  `benchmarks/results/w4_llm_rank_proof.json`).
- W8 proving ground: the deterministic scan + scorer produce a CI-grade
  scorecard (recall 1.0 / precision 1.0 / FP 0) on live Juice Shop.

## Immediate blockers (must fix before a real engagement contract)

1. Fix the hypothesis-livelock (auto-advance after bounded window) so engagements
   reach exploitation and reporting without operator intervention.
2. Raise/shard the shared-agent-pool for the high-cost scanners (sqli/xss/jwt)
   so the timeout rate is ~0 under real scan load.
3. Convert the deterministic scanner stub results into a full scan path that
   survives the honest tool gate.

## Status

The platform has crossed the largest claimed gap (it will find real
vulnerabilities, with evidence, on a live target), and is now blocked on
**autonomy completion** (phase lifecycle finishing on its own). The next
commit/test cycle should target the hypothesis gate + the reporting completion
path.
