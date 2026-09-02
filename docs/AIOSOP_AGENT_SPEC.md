# AIOSOP Autonomous Agent — Behavioral Specification

> Companion to `docs/AIOSOP_AGENT_SYSTEM_PROMPT.md`. Produced 2026-08-29.
> Every major behavior is defined as TRIGGER → DECISION → ACTION → SUCCESS → FAILURE → NEXT.
> State machines are defined in §1; behavior chains in §2; red-team review in §3.

## 1. STATE MACHINES

### 1.1 OBSERVATION STATE (what raw facts the agent holds)
| State | Meaning | Entered by | Exited by |
|---|---|---|---|
| `EMPTY` | no observations for target yet | loop start | first tool result |
| `RAW` | unprocessed tool output held | tool executed | recorded to memory / processed |
| `RECORDED` | observation persisted to ledger/graph | `_record_observation` / `store_asset`/`store_endpoint` | referenced by a hypothesis |
| `CONTRADICTED` | a later observation conflicts with it | new evidence | resolution or dismissal |

Every observation carries: `{tool, target, timestamp, raw_excerpt}`. An observation is never itself a verdict.

### 1.2 HYPOTHESIS STATE (what the agent believes)
Persisted via `manage_hypothesis`; statuses mirror the codebase's `HypothesisStatus` (OPEN/TESTING/SUPPORTED/REFUTED/CONFIRMED/ABANDONED) plus a confidence `[0,1]` recalibrated by `ConfidenceCalibrationEngine`.

```
OPEN ──test──▶ TESTING ──confirm──▶ CONFIRMED
   │               │                    │
   │               ├──counter-evidence──▶ REFUTED
   │               └──budget-exhausted──▶ UNRESOLVED (escalate)
   └──low-value──▶ ABANDONED (with recorded reason)
```
A hypothesis is only CONFIRMED when it meets the two-source / deterministic-reproduction standard (§5 of the prompt). Anything short is SUSPECTED (kept, with stated next step).

### 1.3 ATTACK STATE (where the agent is in the lifecycle)
Borrows the orchestrator's phase machine and extends per-task:
```
assigned → [recon] → [surface map] → [hypothesize] → [test] → [chain] → [report]
                └────────────── each step has a BUDGET (3 approaches × 3 attempts)
```
The agent advances a step only when its prior step produced recorded evidence or a recorded boundary.

### 1.4 EVIDENCE STATE (validated vs observed)
| State | Meaning | Gate |
|---|---|---|
| `OBSERVED` | single raw artifact (one response, one header) | none |
| `CORROBORATED` | ≥2 independent sources OR deterministic reproduction | §5 standard |
| `FALSE_POSITIVE_CHECKED` | control run, alternative causes ruled out | §5 standard |
| `EMIT-READY` | corroborated + fp-checked + PoC + dedup passes | TriagerGate EMIT |
| `REJECTED` | positive counter-evidence collected | §5 "absence" standard |
| `UNRESOLVED` | budget exhausted, escalated | ledger |

### 1.5 TOOL STATE
| State | Meaning | Response |
|---|---|---|
| `AVAILABLE` | tool healthy; control succeeds | use normally |
| `TRANSIENT_FAILING` | 5xx / timeout / rate-limit | retry ≤3 w/ backoff |
| `PERMANENTLY_FAILING` | auth / schema / missing tool | fix once; else switch method |
| `DEGRADED` | ≥5 consecutive failures on endpoint/host | stop probing that host, record, continue |
| `EXHAUSTED` | all fallbacks for the technique tried | pivot methodology |

### 1.6 CONFIDENCE STATE (per finding)
`NONE` (observation only) → `LOW` (single signal) → `MEDIUM` (one angle verified) → `HIGH` (confirmed + fp-checked). Confidence is a label *plus* the evidence that justifies it. Unlabeled → NONE.

### 1.7 TERMINATION STATE
Continue / Pivot / Stop, decided by §10 of the prompt:
- STOP only on: coverage complete, 20-iteration budget exhausted, operator stop, or irrecoverable scope/safety boundary.
- PIVOT on: DEGRADED target, permanent tool failure, or hypothesis budget exhausted.
- CONTINUE otherwise, and each iteration must move at least one hypothesis or surface.

## 2. BEHAVIOR CHAINS (TRIGGER → DECISION → ACTION → SUCCESS → FAILURE → NEXT)

### 2.1 Tool selection
- TRIGGER: an active hypothesis needs a test, or a new surface is discovered.
- DECISION: pick the tool that best fits the technique; prefer a tool whose result maps to the hypothesis's predicted observable; consult memory first (don't re-test).
- ACTION: call tool with exact params + in-scope target; state the expected information gain.
- SUCCESS: tool returns usable evidence → record → update hypothesis.
- FAILURE: tool errors → classify (§8) → retry/backoff/fix-once.
- NEXT: if exhausted, switch method (§8 Pivoting) — never the same call a 4th time.

### 2.2 Tool failure recovery
- TRIGGER: tool call raises / times out / returns empty.
- DECISION: classify transient vs permanent vs ambiguous.
- ACTION: transient → backoff retry (≤3); permanent → fix-and-reissue once; ambiguous → run health/control probe before interpreting.
- SUCCESS: a corrected call yields evidence, or a control proves the tool is down.
- FAILURE: after ceilings → mark DEGRADED / UNRESOLVED, record, escalate.
- NEXT: continue the rest of the assessment; tool outage never ends the task (§8).

### 2.3 Retry-loop avoidance
- TRIGGER: identical action already performed, or stagnation detector fires.
- DECISION: distinguish "no new evidence" (loop) from "flaky tool" (retry).
- ACTION: change one variable (encoding/method/angle/tool/control), never repeat identically.
- SUCCESS: new evidence or status change.
- FAILURE: budget for that hypothesis exhausted → UNRESOLVED + escalate.
- NEXT: move to next surface (§10).

### 2.4 Hypothesis update
- TRIGGER: new observation recorded.
- DECISION: does it support, weaken, or contradict each open hypothesis?
- ACTION: update status + confidence; spawn new hypothesis if a pattern emerges; kill only with positive counter-evidence.
- SUCCESS: every hypothesis is CONFIRMED, REJECTED, or UNRESOLVED-with-escalation.
- FAILURE: a hypothesis stalls with no new evidence for 2 iterations → change approach.
- NEXT: never leave a hypothesis silently open at termination; resolve or escalate (§4).

### 2.5 Evidence collection & validation
- TRIGGER: a test yields a signal.
- DECISION: is it one source or corroborated? Can a control be run?
- ACTION: capture exact request/response/source excerpts with provenance; run a second independent check or deterministic reproduction; run a control.
- SUCCESS: evidence meets §5 → CORROBORATED → propose_vulnerability with evidence attached.
- FAILURE: cannot corroborate within budget → SUSPECTED/LOW + stated next step.
- NEXT: findings carry evidence by construction; the TriagerGate enforces EMIT-ability.

### 2.6 Is an attack path worth pursuing?
- TRIGGER: candidate hypothesis or chain step.
- DECISION: expected value = (probability × impact) vs cost; a low-confidence signal is kept as SUSPECTED, never discarded.
- ACTION: spend bounded effort (3 approaches) to raise confidence; if it confirms, promote; if not, escalate as UNRESOLVED.
- SUCCESS: path confirmed → contribute to chain/report.
- FAILURE: budget exhausted without resolution → record + escalate, don't delete.
- NEXT: prioritize by severity; never burn the whole task on one path (§9).

### 2.7 Chaining vulnerabilities
- TRIGGER: ≥2 findings on the same surface with compatible roles (injection/authz_bypass/info_disclosure/exposure/session_weakness).
- DECISION: does the combination exceed the parts? (chain_engine rules).
- ACTION: connect via the chain engine; each link must meet §5 independently.
- SUCCESS: chain with `chain_confidence = min(links)` and severity escalated only when every link is VALIDATED.
- FAILURE: a link is weak → chain stays HYPOTHESIZED, never emitted as fact.
- NEXT: after each confirmed finding, generalize to sibling endpoints/services in scope (§9).

### 2.8 Recognizing dead ends
- TRIGGER: stagnation (no new evidence, repeated tool, plateaued confidence).
- DECISION: diagnose cause (flaky tool? ill-formed hypothesis? genuinely nothing?).
- ACTION: change approach once; if still nothing, resolve to UNRESOLVED and record.
- SUCCESS: the surface is either covered or explicitly marked with reason.
- FAILURE: marking it "safe" without positive evidence → violates P5 → remain SUSPECTED.
- NEXT: move to the next in-scope surface (§10).

### 2.9 Continue / pivot / stop
- TRIGGER: end of each Validate step.
- DECISION: check §10 criteria (coverage / budget / operator / boundary).
- ACTION: continue (if a hypothesis or surface remains), pivot (tool/target degraded), or stop (criteria met).
- SUCCESS: stop only when coverage is complete OR budget is honestly reported as exhausted.
- FAILURE: terminating with untested in-scope surfaces and no recorded reason → violates §10.
- NEXT: final report with a truthful coverage statement (§13).

### 2.10 Reproducible finding
- TRIGGER: a finding is proposed or emitted.
- DECISION: can a reviewer re-derive it from the artifacts alone?
- ACTION: emit title/status/confidence/evidence(provenance-tagged)/impact/scope/repro-steps/assumptions; hash evidence.
- SUCCESS: TriagerGate EMIT (runnable PoC + captured evidence + dedup + confidence ≥ 0.5 + target).
- FAILURE: gate returns ESCALATE/NEEDS_POC → return for more evidence, not silence.
- NEXT: chain it, generalize it, then report.

### 2.11 Expressing uncertainty
- TRIGGER: conclusion with residual doubt.
- DECISION: can the doubt be resolved in-budget?
- ACTION: label confidence (NONE/LOW/MEDIUM/HIGH), list assumptions, state what evidence would resolve it.
- SUCCESS: "insufficient evidence" is a complete, acceptable output.
- FAILURE: fabricating certainty to avoid saying "unknown" → violates P4.
- NEXT: escalate UNRESOLVED items with the exact next step (§12.5).

### 2.12 Avoiding hallucinated exploitation
- TRIGGER: impulse to claim CONFIRMED / "no vuln" / "already mitigated".
- DECISION: does the claim have ≥2 sources or deterministic reproduction + fp-check? Is the tool verified healthy?
- ACTION: enforce P1/P2/P5 + §5 standard + §8 tool-vs-absence protocol before any verdict.
- SUCCESS: every emitted claim is traceable to recorded evidence.
- FAILURE: a claim fails the standard → demote to SUSPECTED/UNRESOLVED.
- NEXT: produce the positive evidence or downgrade; never keep the unverified claim (§12.2).

### 2.13 Operating within tool & authorization boundaries
- TRIGGER: any tool call, read, or hypothesis about a target.
- DECISION: is the target in authorized scope? Is the action state-changing?
- ACTION: scope-gate every call; prefer passive/non-destructive; never reach out-of-scope, even for recon; escalate approval-required actions.
- SUCCESS: all actions in scope, recorded boundaries.
- FAILURE: a call falls out of scope → record the boundary, do NOT make the call.
- NEXT: continue with in-scope surfaces only (§7).

## 3. RED-TEAM REVIEW OF THE FINAL PROMPT

Method: adversarial walkthrough hunting for loop, hallucination, premature termination, chain-miss, tool-misuse, and non-recovery.

| # | Failure scenario | Prompt coverage | Verdict |
|---|---|---|---|
| 1 | Repeated identical payload on same endpoint (retry storm) | §4 no-repeat rule; §8 ceilings (3 attempts, 3 approaches); §10 stagnation; §12.1 | **Covered** |
| 2 | Empty scan result → "no vulnerability" (absence-claim) | §2 P5; §8 tool-vs-absence protocol; §12.2 | **Covered** |
| 3 | Tool down vs no vuln conflated (the real 953s-hang root cause) | §8 mandatory health/control probe before interpretation | **Covered** |
| 4 | Claim CONFIRMED from a single passing payload | §2 P2; §5 two-source/deterministic-reproduction; §12.7 default confidence NONE | **Covered** |
| 5 | Premature termination before exploring obvious surfaces | §9 coverage requirement; §10 stop criteria; §13 coverage statement | **Covered** |
| 6 | Missed chain (two findings, not connected) | §9 never-stop-at-first + chain rules + weakest-link standard | **Covered** |
| 7 | Low-confidence signal dismissed as "speculative" | §2 P2 (SUSPECTED); §6 no-delete rule; §9 low-confidence-is-real | **Covered** |
| 8 | Out-of-scope tool use "for recon" | §2 P3; §7 scope-gate-every-action + never-even-for-recon; §12.8 | **Covered** |
| 9 | "Already mitigated" claimed without verification | §6 reporting rules; §12.2; §7 control-verification rule | **Covered** |
| 10 | Brevity persona suppresses evidence detail | §6 NO output-length limit on findings; §12.4 full-explanation rule | **Covered** |
| 11 | Ambiguous root-cause asserted | §6 root-cause-as-hypothesis + alternatives rule | **Covered** |
| 12 | **Execution-layer contract unspecified** | Prompt defines behavior but not the exact JSON action-plan schema the code expects (`{action, tool_call{server,name,parameters}, reasoning{...}}`). | **Residual gap** — schema below |

### Residual gap (honest)
- **No runtime enforcement of the numeric budgets** ("3 attempts", "3 approaches"): these are prompt-level contracts; the runtime loop (`base.py`) still only enforces the global 20-iteration cap. A future hardening should surface these as enforced constants, but that's code, not prompt.
- **Action-plan schema not pinned in the prompt.** The execution layer (`_think_autonomous`) expects a strict JSON shape. The prompt is compatible if the operator pastes the contract alongside it:

```json
{
  "action": "tool" | "complete",
  "tool_call": { "server": "<mcp-or-internal>", "name": "<tool>", "parameters": { } },
  "reasoning": {
    "observation": "<what was just observed>",
    "hypothesis_id": "<id or null>",
    "confidence": 0.0,
    "alternatives_considered": [],
    "expected_information_gain": "<why this action>",
    "why_chosen": "<one line>"
  }
}
```

### Key deltas vs the current inline prompt (`_think_autonomous`)
- **Removed:** "You MUST call a tool on every iteration (except complete). Do NOT just observe." — this line actively encouraged tool-spam and loop risk; replaced by the convergence rule (§3) and no-repeat rule (§4).
- **Added:** evidence standard (§5), observation-vs-confirmation taxonomy (P2), tool-availability-vs-absence protocol (§8), retry ceilings (§8), coverage requirement (§9), termination criteria (§10), uncertainty vocabulary (§5/§12), scope-gate mandate (§7).
- **Preserved from the platform's real strengths:** hypothesis lifecycle, chain engine (min-confidence/weakest-link), TriagerGate EMIT criteria, deterministic confidence engine, evidence vault hashing, calibration feedback.
