# W8 / Roadmap #7 — Real-Finding Proving Ground (LIVE, 2026-07-30)

The review's central doubt was "0 demonstrated real findings ... no reproducible
evidence the product can find real vulnerabilities." This run answers it
empirically against the live stack.

## Setup
- Target: OWASP Juice Shop, live container (localhost:3000).
- Platform: API running locally from this branch's code; Redis/Postgres/Neo4j +
  13 MCP servers up; deterministic backbone (`POST /engagements/{id}/scan/deterministic`,
  mode=suite), which bypasses the LLM task lifecycle and runs the real detection
  oracles + governed egress.
- Evidence artifacts (committed):
  - `benchmarks/results/prov_gnd_scan_20260730_154020.json` — raw scan output.
  - `benchmarks/results/prov_gnd_scorecard.json` — CI detection-gate scorer output.

## Result — the CI detection-gate scorer, exact CI args
```
poetry run python benchmarks/score_engagement.py \
  --findings benchmarks/results/prov_gnd_scan_20260730_154020.json \
  --manifest benchmarks/ground_truth/juice_shop.yaml \
  --out benchmarks/results/prov_gnd_scorecard.json \
  --min-recall 0.4 --min-validated-recall 0.2 --max-fp 0
```
```
recall=1.0  validated_recall=1.0  precision=1.0
TP=5  FN=0  FP=0  extras=5  evidence_completeness=1.0  mock_llm=false
```

Gate thresholds were recall>=0.4, validated_recall>=0.2, fp<=0.  The run exceeds
every threshold.

## What it actually found (validated, non-simulated, complete evidence)
Manifest positives matched (TP), each with verified proof artefacts:
- JS-001 sqli auth bypass (`/rest/user/login`, `' OR 1=1--`, server issued a real
  session JWT for an injected identity — token_prefix recorded).
- JS-002 sqli (search endpoint, DB error excerpt).
- JS-003 broken access control (FTP directory listing exposed).
- JS-004 jwt_abuse (forged token, technique + token evidence).
- JS-005 mass_assignment (admin-role registration + persisted-role readback).

Genuine extras (not manifest negatives; routed to triage, not counted FP):
idor (conf 0.9), xss (conf 1.0), broken_access_control x2, authentication_weakness.

## Honest framing (what this does and does NOT prove)
- It PROVES the deterministic detection backbone finds real, validated,
  reproducible vulnerabilities on a real target — recall 1.0, precision 1.0, FP 0
  against the CI manifest. The "0 findings" claim does not survive contact with
  this run.
- It does NOT yet prove the *agent/LLM loop* (W1/W2/W8's autonomous path) finds
  them — that path is the ReasoningLoop + think() tool-use loop, which this scan
  deliberately bypassed. That loop is the next live-validation target (#3/#4).
- The CI gate's committed reference findings (`juice-e2e-63844f55-findings.json`)
  are from 2026-07-16 — this fresh run supersedes them as the current evidence.
