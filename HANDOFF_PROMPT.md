# AI-OSOP — Session Handoff

We are continuing work on **AI-OSOP** (AI Offensive Security Orchestration Platform) at
`C:\Users\HP\OneDrive\Desktop\burp_mcp\ai-osop`, branch `fix/mock-findings-honest-stub-tool-guard`.
The previous session crashed on a Claude Code API bug (`400 messages: text content blocks
must be non-empty`) — no work was lost, but I need you to pick the thread back up.

## Hard rules (carry these through everything)
- Everything must be REAL. No mocked outputs, no simulated findings, no fabricated evidence,
  no assumed test passes. If something can't be verified, say **"NOT VERIFIED"** rather than
  speculating.
- Verify on disk / by execution before claiming any result. Never mark work complete without
  evidence.
- Do not restart shared services (Neo4j, Postgres, Redis, Docker data tier) without asking me
  first.

## What just landed (verified on disk)
- **Scope-rejection bug fixed and committed** (`cb19e3e`): the security-bridge was rejecting
  in-scope targets. Two root causes — (1) Go `domainMatches()` in `mcp-servers/go/sdk/server.go`
  compared `localhost` against `localhost:3000` (fixed with `net.SplitHostPort`); (2) Python
  looked up sessions by bare `engagement_id` instead of full `session_id` (fixed with a new
  `store_engagement_id_mapping()` / `get_session_state_by_engagement_id()` resolver in
  `src/ai_osop/memory/session_memory.py`, wired in `engagement_manager.py`, `vuln_agent.py`,
  `context_manager_agent.py`). `security-bridge.exe` was rebuilt.
- **First real scored E2E numbers** against local OWASP Juice Shop (`localhost:3000`, authorized
  Phase-7 target). Canonical scorer, both runs in `benchmarks/results/`:
  - `juice-e2e-611e6a3d` (pre-fix): recall 0.20, precision 1.00, TP=1 (mass_assignment), FN=4.
  - `juice-e2e-63844f55` (post-fix): recall **0.40**, precision 1.00, TP=2 (**sqli** JS-001 @0.98,
    mass_assignment JS-005 @0.50), FN=3, FP=0, evidence_completeness **0.0**.
  - `.last_engagement_id` = `juice-e2e-63844f55`.

## Uncommitted work to reconcile first
`git status` will show: modified `benchmarks/results/juice-e2e-63844f55-scorecard.json` and
`.skill_stats.json`; untracked `.last_engagement_id`, `.tmp_score/`, `COMPREHENSIVE_ASSESSMENT.md`,
`benchmarks/results/juice-e2e-611e6a3d-{findings,scorecard}.json`.
Review these, then commit the benchmark artifacts + assessment (or tell me they should be
git-ignored). `.tmp_score/` is scratch — decide keep vs. ignore.

## Next objectives, in priority order
1. **Close the 3 false negatives.** Identify which 3 of the 5 Juice Shop ground-truth vulns
   (see the benchmark manifest / ground truth) are still missed, and root-cause *why* per the
   pipeline stage (planning / parameter extraction / crawl depth / applicability filter / tool
   failure / auth). Fix the highest-leverage one and re-run the E2E to measure recall movement.
2. **Fix `evidence_completeness = 0.0`.** Even the true positives carry no request/response/
   screenshot artifacts. Make findings attach real evidence so they're HackerOne-graded. This is
   a release blocker.
3. **Regression-guard the win.** Ensure the scope-fix and scoring are covered so recall can't
   silently regress; wire an automated scorecard on significant changes.
4. Then resume the broader roadmap I set earlier — P0 correctness (execution-contract validation,
   parameter-extraction pipeline, planner must never fabricate scan targets, Burp/tool execution
   verification, finding validation before persistence), P1 reliability (container recovery,
   scheduler responsiveness, MCP readiness gating), P2 coverage (authenticated crawling,
   GraphQL/Next.js specialization, broader task generation).

## How to run the E2E (from the prior session)
- Bring the stack up (MCP fleet via `mcp_launch_all.py`, API via `start_api.py` on `:8200`);
  Juice Shop on `localhost:3000`.
- Driver: `run_juice_engagement.py` (mints an operator JWT from `OSOP_JWT_SECRET`, creates the
  engagement, runs it end-to-end).
- Score: `benchmarks/score_engagement.py` against the exported findings; results land in
  `benchmarks/results/<engagement-id>-scorecard.json`.

Start by running `git status` and reading the two scorecards + the benchmark ground-truth
manifest, confirm the numbers above are real, then proceed with objective 1.
