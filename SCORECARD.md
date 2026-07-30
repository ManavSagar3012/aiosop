# AI-OSOP — Scorecard Baseline & Progress Notes

This file tracks what we *know* about the platform's test and capability posture. It replaces
unverifiable certificates with the exact reproduction command that produced each number.

## Test Suite Baseline

Run locally on branch `feat/real-discovery-and-agent-loop` at 2026-07-31:

```bash
.venv/Scripts/python.exe -m pytest tests/ -q --no-cov -p no:cacheprovider --timeout=120
# -> 15 failed, 1746 passed, 6 skipped, 83 warnings
```

| Item | Count | Note |
|---|---|---|
| Total tests | 1,767 | `1746 + 15 + 6` |
| Pass rate | 98.8% | 1,746 / 1,761 executed |
| Failing tests | 15 | **Pre-existing**, not introduced by this session |
| Skipped tests | 6 | Optional/real-LLM/infra paths gated by fixtures |

### The 15 pre-existing failures (verified on baseline main branch)
These fail on `main` and have not been altered by this work; they cover:
- `test_detector_overclaim_hardening_*` / `test_dom_xss_scan_*` (XSS/DOM-XSS deterministic oracles)
- `test_orchestrator.py::test_transition_phase*` (phase-transition fixture/logic)
- `test_retry_requeue::*` (scheduler/retry queue push order)
- `test_safety_approval_authority::*` (approval recovery semantics)
- `test_adversarial_audit::*` (isolation/recovery)
- `test_session_memory_mcp.py::test_session_memory_flow`

They are all functional components whose out-of-band dependencies (graph state, MCP mocks, browser harness)
do not match the test expectations on `main`. They were NOT touched or "fixed" in this session; any scorecard
claiming them green needs those environments.

## Capability Scores — reworked with honest derivation

Scores are rated against a 0–10 rubric tied to tests I ran this session (not on "we intend to").

| Dimension | Score | Basis |
|---|---|---|
| Test pass rate (repo-wide) | 9.9 | 98.8% on a real run; -0.1 for the 15 known failures that still need owners |
| Reasoning loop is real | 5.5–6.0 | Code exists, tests pass. It is bounded to one tool call per LLM turn, observations are propagated, and policy rejections are recorded. A full multi-turn planner with replan-after-failure is not present — that is real code, not a claim. |
| Code quality / maintainability | 7.0–7.5 | mypy/ruff config is strict; >1,300 tests; much of the structure is clean. The UI has ~20 untracked/unmodified edits that need their own commit trail. |
| Security hardening | 5.0 | scope enforcer exists and blocks bad domains; prompt defense regex-based originally but now normalized (NFKD), delimiters, classifier flagging, exfil signature. Needs the calibration suite real live run to move above 6. |
| Coverage floor discipline | 7.0 | floor is now 70 in pyproject. This signals intent. Actual measured coverage against the suite needs a clean in-environment run to state a single number; `pytest --cov` will report the new number only with a closed floor. |
| Overall engineering maturity | **6.5–7.0** | Composite of the rows above. 9.0+ claims require fixing the 15 failures, an actually green live-LLM bench, and published coverage >70% numbers from the repo. |

## What you can reproduce tonight (deterministic)

```bash
# 1. Invoke the suite
ls .venv/Scripts/python.exe && .venv/Scripts/python.exe -m pytest tests/ -q --no-cov -p no:cacheprovider --timeout=120

# 2. Spot-check the new wiring (must all pass)
.venv/Scripts/python.exe -m pytest tests/test_action_loop.py tests/test_spa_harvester.py \
  tests/test_spa_harvest_dispatch.py tests/test_prompt_defense_structure.py \
  -q --no-cov -p no:cacheprovider

# 3. Confirm new reasoning loop behavior end-to-end on the offline smoke path
.venv/Scripts/python.exe -m pytest tests/test_action_loop_replan.py -q --no-cov -p no:cacheprovider
```

If any of those numbers change, this file's scoring rows were derived from a prior commit — do not propagate them.