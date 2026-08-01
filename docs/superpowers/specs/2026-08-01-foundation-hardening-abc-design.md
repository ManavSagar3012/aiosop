# Foundation Hardening — Steps A/B/C Design

- **Date:** 2026-08-01
- **Status:** Approved (user, 2026-08-01)
- **Branch:** `feat/real-discovery-and-agent-loop`
- **Scope:** Fix broken untracked state, then complete roadmap Steps A (instrumentation), B (real-target corpus benchmark), C (target-interface hardening). Steps D/E/F are explicitly out of scope except the single `organization_id` field seeded for E.

## 0. Background

The six-step "path to 10" roadmap was audited against the working tree. A1–A4 scaffolding exists (validation ledger, A2 metrics, corpus benchmark, MCP input gate) but is only partially wired: metrics have no production emitters, the ledger is only called from `base_vuln_agent`, the corpus benchmark self-certifies without a runner, and the MCP gate fails open on unknown tools. Two untracked test files are broken: `tests/test_tenant_isolation.py` expects `ScopeDefinition.organization_id` (absent from `models.py`), and `tests/test_post_exploit_agent.py` currently passes once run alone (agent module correctly defines `ReconOp`/`SurfaceState`/`suggest_next_moves`; the earlier "ImportError" hypothesis was wrong — verified 2026-08-01 with `pytest tests/test_post_exploit_agent.py`: 5 passed).

**Verified facts the design relies on:**
- `validation_ledger.py:71` already has `transition(event_id, to_state, reason)`; states at line 21 are `detected | validated | manual_review | escalated | chain_executed | chain_failed`.
- `mcp/protocol.py:139` — `check_params` does `if not allowed: return` (fail-open on unknown tool).
- `action_loop.py` — `ActionLoop._complete(messages)` is the single LLM call choke-point (`litellm` client behind it); `run()` tracks `LoopState`.
- `corpus_benchmark.py` — `CorpusBenchmark(entries)`, `run(agent_runner=None)` echoes ground truth when no runner (self-certifying); real scoring mode must require a runner or findings input.
- `core/models.py:291` — `ScopeDefinition` has fields `engagement_id, domains, ips, exclusions, allowed_techniques, restrictions, approval_required_for, testing_window_*, authorization_ref, signature`; no `organization_id`.

## 1. Section 1 — Quick fix (unblocks suite)

**Change:** add one field to `ScopeDefinition` in `src/ai_osop/core/models.py`:

```python
organization_id: str = "default"
```

- Not included in `_signing_payload()` — tenant assignment is an IAM concern, not part of the signed scope manifest.
- Default `"default"` preserves single-tenant behavior everywhere (`tenant_isolation.tenant_scope` maps falsy → `"default"` consistently).
- Serialization check `model_dump()["organization_id"]` must pass (pydantic default, automatic).

**Result:** `tests/test_tenant_isolation.py` (4 tests) green; `tests/test_post_exploit_agent.py` (5 tests) already green, untouched.

## 2. Section 2 — Step A: Validation ledger funnel + metrics wiring

### 2.1 Ledger state reconciliation

Keep existing states; add the roadmap funnel vocabulary as first-class:

- New terminal state `successful_chain` (chain completed end-to-end with validated outcome).
- `chain_executed` semantics unchanged (a hop executed); `executed` is **not** added — `chain_executed` already covers it.
- Legal transition set added as a module constant in `validation_ledger.py`:

```python
LEGAL_TRANSITIONS = {
    "detected": {"validated", "manual_review", "rejected"},
    "validated": {"chain_executed", "escalated"},
    "manual_review": {"validated", "rejected"},
    "chain_executed": {"successful_chain", "chain_failed"},
    "escalated": {"validated"},
    "chain_failed": {"detected"},
    "successful_chain": set(),
    "rejected": set(),
}
```

- `ValidationLedger.transition()` gains enforcement: raise `WorkflowTransitionError` (existing exception hierarchy) on illegal transition. Rationale: the ledger is only trustworthy if it can't encode impossible funnels.

### 2.2 Call sites wired

| Event | Where | Transition recorded |
|---|---|---|
| Exploit validated | `exploit_agent.py` (ExploitValidationAgent) `_execute` success | `detected → validated` |
| Chain hop executed | `chain_executor_agent.py` per hop | `validated → chain_executed` |
| Chain completed | `chain_executor_agent.py` after all hops validate | `chain_executed → successful_chain` |
| Chain aborted | `chain_executor_agent.py` on hop failure | `chain_executed → chain_failed` |

`ChainExecutorAgent` receives the ledger via constructor (dependency injection, mirrors the existing `graph_memory` / `_exploit` injection); default `None` preserves testability.

### 2.3 Metrics — production emitters

New/updated in `core/metrics_a2.py`:

- `ai_osop_a2_chain_hop_seconds{chain_id, hop_idx}` — new Histogram; emitted per hop in `ChainExecutorAgent`.
- `ai_osop_a2_tool_calls_total{tool, outcome}` — **production call site**: emitted in `MCPExecutionGate` invocation path (single choke-point) in `mcp/protocol.py` where each tool call is authorized; `outcome ∈ {allowed, denied_scope, denied_params, denied_approval, error}`. This gives per-tool success for `fetch`, `sqli_oracle`, `spa_harvest`, and all others for free.
- `ai_osop_a2_finding_llm_tokens_total{model, vuln_class}` — new Counter. Emitted in `ActionLoop.run()`: token deltas across iterations attributed to the finding context passed in `LoopState` (vuln_class label only; no finding_id label — cardinality guard, raw finding correlation stays in the ledger).
- Existing `time_chain_execution{chain_id}` context manager gets used by `ChainExecutorAgent` for whole-chain wall time.

## 3. Section 3 — Step B: Corpus benchmark with real gate

### 3.1 Dataset

New directory `benchmarks/corpus/` with JSON files. Each entry serializes `GroundTruthEntry` plus provenance:

```json
{
  "id": "h1-2380705-idor",
  "vuln_class": "idor",
  "endpoint": "/api/v1/teams/{team_id}/members",
  "method": "GET",
  "expected_result": "accepted",
  "reference_exploit": {"pattern": "diff_auth", "notes": "swap team_id across two accounts"},
  "severity_expected": "high",
  "confidence": 0.95,
  "source_url": "https://hackerone.com/reports/2380705",
  "withdrawn": false
}
```

Seed with **20 entries**: ~12 curated from public HackerOne disclosures (IDOR, reflected XSS, graphql introspection, mass assignment — classes the platform already tests), ~8 synthetic negatives (`expected_result: "rejected"`, e.g. benign UUID-swap that returns 404).

### 3.2 Scoring mode + gate

`CorpusBenchmark` changes:

- `run(findings=...)`: **new scoring path** — accepts a list of actual findings (endpoint, vuln_class, outcome) and computes per-class TP/FP/FN, returning `{"precision": float, "recall": float, "per_class": {...}, "evaluated": int}`.
- `run(agent_runner=...)`: existing path retained but **may not** fall back to `_matches_expected` self-echo when scoring; self-echo retained only for a `dry_run=True` parameter (explicit).
- `withdrawn=True` entries are excluded from scoring and `count()`.

**Gate test** in `tests/test_corpus_benchmark.py` (new test, name `test_corpus_precision_recall_gate`): loads `benchmarks/corpus/`, runs scoring against a deterministic fixture findings list representing current best-known platform behavior, asserts `precision >= 0.90 and recall >= 0.90`. Peer review note: fixture must be regenerated from a real platform run once, then pinned; test documents its provenance in the docstring.

### 3.3 Leak protection

`FindingCorpusService.ingest` refuses entries with `withdrawn=True` (hard error). Corpus JSON files get a header comment field `"_policy": "public disclosures only; no live client data"` — enforced by a schema-level test asserting every entry has a `source_url` matching `hackerone.com/reports/` or `synthetic://`.

## 4. Section 4 — Step C: Fail-closed input gate + JS weaponization check

### 4.1 Fail-closed MCP params gate

`mcp/protocol.py`:

- `check_params` flips to default-deny: unknown tool → raise `MCPException`-family error (`ScopeValidationError` fits: input rejected at boundary) instead of `return`.
- Registration path: `MCPAdapterBase` gains optional class attr `input_schema: Dict[str, Dict[str, type]]` (arg → allowed type tuple). On `MCPSession.initialize_server`, the adapter's schema merges into `MCPExecutionGate._ALLOWED_PARAMS`/`_ALLOWED_TYPES` for its declared tools. Adapters without schema declared **still execute** but only with read-only scope (`trust_server_scope=True` path); write/exploit tools without schema are blocked. This is the migration-friendly middle ground — full block would break every optional adapter at once.
- Existing traversal/quote/semicolon string checks remain and apply to all tools.

### 4.2 JS weaponization assessment

`agents/js_analyzer_agent.py` gains `weaponization_assessment(bundle_content: str, secrets_found: int) -> Dict[str, Any]`:

- **Sink/source pattern pairs** — list of (source, sink) regex pairs:
  - `location.hash|location.search|document.referrer|window.name|postMessage` → `innerHTML|document.write|eval|Function|setTimeout\(.*string`
  - `document.cookie|localStorage|sessionStorage` → `fetch|XMLHttpRequest|navigator.sendBeacon` (exfil)
- Score: `0.0–1.0`. +0.3 per live-verified secret (cap 0.6), +0.2 per confirmed sink/source pair (cap 0.4).
- Output feeds task payload: `{"weaponization_score": float, "pairs": [...], "verified_secrets": int}`.
- ExploitValidation task fan-out from JS findings requires `weaponization_score >= 0.4` (threshold constant `JS_EXPLOIT_THRESHOLD`); below threshold findings stay in graph as informational.

### 4.3 What Step C explicitly defers

Full per-call containerization of every MCP adapter (tart/qubes/per-tool sandboxes) is a separate follow-up; existing `SandboxManager` continues to cover the exploit-validation path.

## 5. Error handling

- Illegal ledger transition → `WorkflowTransitionError` with context `{event_id, from_state, to_state}`.
- MCP gate rejection → `ScopeValidationError` with `{"tool": ..., "reason": ...}`; surfaced as existing `deny` metric outcome.
- Corpus load: malformed entry → `ValueError` at `GroundTruthEntry.__post_init__` (existing); missing source_url policy → `ValueError` in loader test.
- Weaponization assessment is best-effort: bundle fetch failure → score 0.0, never exceptions into the agent loop.

## 6. Testing

- Quick fix: existing `test_tenant_isolation.py` 4 tests pass.
- A: extend `tests/test_validation_ledger.py` with legal/illegal transition tests; extend `tests/test_chain_executor_agent.py` and `tests/test_a2_metrics.py` asserting registry output contains new series after a simulated hop run.
- B: `test_corpus_precision_recall_gate` (+ synthetic-only mode so CI needs no network); `FindingCorpusService` withdrawal rejection test.
- C: extend `tests/test_mcp_execution_gate.py` — unknown tool rejects; adapter-declared schema accepts; new `tests/test_js_weaponization.py` with inline bundle fixtures per pair family.
- Full suite: `poetry run pytest --no-cov` must stay green (baseline: 1798 passed / 4 skipped per commit 43b82cf5).

## 7. Out of scope

- Step D (anchored reasoning fine-tuning) — needs dataset/infra not present.
- Step E (Keycloak, tenant JWT claims, WORM audit, vector shards) — only the `organization_id` seed field lands now.
- Step F (HIBP, KMS envelope crypto, LLM financial audit trail) — needs AWS + HIBP access.
- Per-tool container sandboxes (Step C phase 2, see §4.3).

## 8. Work order for the implementation plan

1. Quick fix (`organization_id`) — land first, makes suite green.
2. Step A (ledger transitions + wiring, metrics emitters) — receipts become real.
3. Step B (corpus dataset + scoring + gate) — now measurable by A's receipts.
4. Step C (fail-closed gate + weaponization) — input hardening on top of a measured base.

Each is a separately landable commit series.
