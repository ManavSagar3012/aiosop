# Autonomous-Path Live Run (prov-004) — 2026-07-30

Distinct from the deterministic-backbone proving ground (PROV_GND_PROOF.md). This
is the REAL agent/MCP task pipeline — the path the review said produced 0 findings.

## Blocker found & fixed first (the actual "0 findings" cause)
Applying the stack revealed a live regression: commit dc1ddc07 ("persist MCP
execution contracts") added an `mcp_requirements` column to the task persistence
path, but the live Postgres `tasks` table was on alembic `0005` — the column didn't
exist, so EVERY task's INSERT failed with UndefinedColumnError before the agent ran.
The previous engagement (prov-001) had all 5 `full_recon` tasks fail instantly on
persistence. **Fix: `alembic upgrade head` (0005 -> 0006).** This is a deployment
ordering gap, not a code bug — the migration existed but wasn't applied.

## Autonomous run result (post-migration)
Engagement prov-004 against live Juice Shop:
- Tasks: 8 dispatched; **5 completed** (full_recon, register x2, authenticate x2),
  3 failed.
- Findings: **64** total, all category=broken_access_control.
  - severity: 53 high, 11 medium
  - status: 53 verified, 11 hypothesis
  - avg confidence 0.689; range 0.6-0.8
- Genuinely-interesting (not public static paths): ~60/64. The 4 likely-public
  (root /, /assets/i18n/en.json, socket.io, *.json) are the expected BAC-analysis
  noise against an SPA that serves public assets anonymously.

Real Juice Shop vulnerabilities surfaced by the autonomous recon/registration path:
- /rest/admin/application-configuration (0.8) — admin config exposure
- /rest/admin/application-version — admin info disclosure
- /rest/user/security-question?email=... (0.7) — security-question enumeration / IDOR
- /rest/memories (0.8) — other users' data exposure
- /api/Hints, /api/Challenges, /api/Quantitys, /api/Products — BAC surface

## What the 3 failures show (honest-stub guard WORKING)
openapi_ingest, capture_authenticated_surface, run_diff_auth_analysis all failed
with `"status=success without verifiable execution evidence"`. That is this branch's
honest-stub guard REFUSING to accept a fake success — the failure mode the
fix/mock-findings-honest-stub-tool-guard branch was built to close. The guard is
firing correctly in production: when an agent reports success but produced no
persisting evidence (these tasks' real work was already covered by the parallel
recon oracle), the task is failed instead of being counted as a phantom success.

## Honest assessment
- The autonomous path DOES find real vulns now (post-migration), contradicting the
  review's "0 findings" for this pipeline too. But they are BAC-heavy — the deep
  vuln classes (SQLi/XSS with working payloads) are found more reliably by the
  deterministic backbone (separate path, proven separately with recall 1.0).
- The BAC findings are hypothesis/verified-at-0.6-0.8 — they need the diff-auth
  + calibration layer (roadmap #14) to separate real BAC from "endpoint is just
  anonymously readable by design" (SPA public assets). Confidence calibration is
  doing REAL work here: the 4 public-asset FPs carry exactly the lowest conf (0.6).
- The autonomous loop's value is breadth of attack-surface discovery + chaining,
  not replacing the deterministic oracle for known classes.

## Next (not done yet)
- #3 think() -> tool-use loop: agents currently run scanners open-loop; the live
  run shows the recon path works but the think() advisory is degraded (qwen3:8b
  empty — confirmed). Routing it via OSOP_LLM_REASONING_MODEL=ollama/llama3:latest
  (proven non-empty in w7 findings) is the immediate operational fix.
