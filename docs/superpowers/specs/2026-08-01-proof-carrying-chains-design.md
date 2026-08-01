# Proof-Carrying Chains — Exploit Capability Tranche Design

- **Date:** 2026-08-01
- **Status:** Approved (user, 2026-08-01)
- **Branch:** `feat/real-discovery-and-agent-loop`
- **Scope:** One integrated tranche across three exploit-capability dimensions approved by the user: confirmation depth (Piece 1 & 3), chain execution (Piece 2), and one new blind exploit class family (Piece 3). Payload evolution is touched only where the new oracle feeds template fitness. Explicitly out of scope: new client-side chain archetypes, race-condition exploitation (turbo-intruder), GraphQL-specific exploitation, a new client-side chains suite.

## 0. Background

The user asked for "exploit-capability enhancements" and approved a three-piece integrated tranche. Ground-truthed against the working tree:

**Verified facts the design relies on:**

- `src/ai_osop/agents/exploit_agent.py:50-206` — `ExploitValidationAgent._validate_exploit` enforces `approval_id` (line 59-60), runs a real curl in a Docker sandbox (`_execute_in_sandbox`, line 208), confirms via per-class response signatures (`_sig_*`, lines 294-470) with an OAST canary short-circuit at lines 510-516, and records `detected → validated` on injected `ValidationLedger` (lines 158-164).
- `exploit_agent.py:225` — sandbox egress is pinned to `allowed_domains=[]` / `allowed_ips=[]` (DNS-only). Targets must be reachable on the default bridge network (localhost / docker-internal); no in-scope allow-list is plumbed from the engagement scope.
- `src/ai_osop/agents/chain_composer_agent.py:32-47` — `ChainComposerAgent._execute` finds graph chains and runs a single LLM `think()` with **no scope, technique, or phase admissibility filter**, then returns them for downstream execution.
- `src/ai_osop/agents/chain_executor_agent.py:42-112` — `ChainExecutorAgent._execute` iterates hops, calls an injected `_exploit.validate_exploit(...)` facade, records per-hop `chain_executed`/`chain_failed` ledger transitions (lines 71-99), and writes a flat `chain_run` list. It **does not abort** on a failed hop — it keeps executing the rest of the chain and treats a mixed result as success. There is no evidence persistence.
- Phase gating has a **dead/policy-shadow bug**: `core/config.py:601` and `core/enums.py:218` each define a `PHASE_POLICY` with `requires_manual_approval=True` for EXPLOITATION — but **neither is imported anywhere** (grep-verified 2026-08-01: zero `config.PHASE_POLICY` / `enums.PHASE_POLICY` usages). The live table is `Orchestrator.PHASE_POLICY` (`orchestrator.py:61-86`), which uses different key names (`manual_approval`/`auto_next`) and sets every phase to `manual_approval: False`. Only per-task `approval_id` gates exploitation today.
- `src/ai_osop/adapters/bug_bounty_adapter.py:325+` — `submit_finding(finding: Dict, platform, *, live_submit_approved=False)` fails closed unless `live_submit_approved=True` per call, takes a free-form dict with only `id/program_handle/title/description/impact` consumed, and performs **zero redaction or report formatting** — both are net-new in this design.
- `src/ai_osop/adapters/oast_mcp.py:22-57` — `OASTAdapter.register(label, context)` mints a token and stores an **arbitrary JSON provenance dict** echoed back verbatim in `poll`/`drain` results. Namespacing is a *caller-side schema* addition, not a server change.
- `src/ai_osop/safety/scope.py:445-447, 514` — `SandboxManager.create_sandbox` accepts a `network_policy.egress.allowed_domains` list and programs the iptables container chain from it. `ExploitValidationAgent` currently passes `[]` (`exploit_agent.py:225`), so fixing live-target reachability is a matter of plumbing the engagement's `ScopeDefinition.domains` into that call — the sandbox primitive is already there.
- `src/ai_osop/core/validation_ledger.py:17` — `LEGAL_TRANSITIONS` exists with states `detected | validated | manual_review | escalated | chain_executed | chain_failed | successful_chain | rejected`; `transition()` enforces legal mutation and raises `WorkflowTransitionError`.
- `src/ai_osop/safety/scope.py:671-715` — `AuditIntegrity` exposes `sign_event(AuditEvent) -> str` and `verify_chain(events) -> bool` implementing HMAC-chained tamper-evident signing keyed by `signing_key: bytes`.
- **Lab target**: no composed vulnerable app exists in-repo. `benchmarks/juiceshop/bench.py` + `benchmarks/ground_truth/juice_shop.yaml` + `benchmarks/juiceshop/README.md` define a bring-your-own Juice Shop convention on `http://localhost:3000` with a ground-truth scorer — the tranche adopts this convention rather than adding a permanently composed target. `tests/qualification/conftest.py:139-222` provides ephemeral `http.server` fixtures (`local_target`, `js_target`) used for deterministic in-process testing.

## 1. Piece 1 — Evidence & Receipts Layer

The foundation: every exploit validation and every chain hop produces a signed, redaction-ready receipt the platform (and later a bug-bounty report) can stand behind without re-running the exploit.

### 1.1 New module `src/ai_osop/evidence/`

Three focused units, each independent of agent internals (module files on disk; unit names describe responsibility, not a fixed file-per-class layout):

- **Receipt models (`models.py`)** — `ReceiptArtifact` and `ExploitReceipt` (pydantic, `snake_case`):

```python
class ReceiptArtifact(BaseModel):
    artifact_id: str            # "art-<sha256[:12]>" content-addressed
    kind: str                   # "http_request" | "http_response" | "screenshot" | "oast_interaction" | "console_log"
    sha256: str
    blob_path: str              # relative to the evidence root
    redaction_map: Dict[str, str] = {}   # original_value -> redacted_label, for bounty export
    captured_at: datetime

class ExploitReceipt(BaseModel):
    receipt_id: str             # "rcpt-<uuid>"
    engagement_id: str
    vuln_id: str
    approval_id: str
    hop_idx: Optional[int]      # None for standalone validations, set for chain hops
    chain_id: Optional[str]
    verdict: str                # "confirmed" | "not_confirmed" | "inconclusive"
    confidence: float
    confirmation_note: str
    oracle_signals: Dict[str, Any]  # per-signal detail: {"body_signature": 0.85, "oast_hit": true, ...}
    artifacts: List[ReceiptArtifact]
    request_summary: Dict[str, Any] # method, url, headers(redacted), body(redacted)
    response_summary: Dict[str, Any]
    scope_hash: str             # sha256 of the ScopeDefinition signing payload at validation time
    timestamp: datetime
    prev_receipt_hash: str = "" # per-engagement HMAC chain link (see store.record)
    integrity_sig: str = ""     # HMAC-Chained receipt signature (see store.record)
    simulated: bool = False     # mirrors Vulnerability.is_simulated gate
```

- **`store.py`** — `ReceiptStore`. Persists receipts + artifact blobs. Constructor-injected `db` (Postgres pool), `integrity: AuditIntegrity`, and `evidence_root: Path` (default `./evidence/`). Methods:
  - `async record(receipt: ExploitReceipt) -> str` — writes blobs to `evidence_root/<engagement_id>/<artifact_id>` and the receipt row to a new `exploit_receipts` table; computes a per-engagement HMAC-chained signature over the receipt (linking to the previous receipt for the engagement via `prev_receipt_hash`) using the injected `AuditIntegrity` HMAC key, and stores it in `integrity_sig`. Receipts are a separate chain from `AuditEvent` records — `AuditIntegrity._last_hash` is not shared with the audit ledger.
  - `async get(receipt_id) -> ExploitReceipt`
  - `async for_vulnerability(vuln_id) -> List[ExploitReceipt]`
  - `async for_engagement(engagement_id) -> List[ExploitReceipt>` — feeds reporting and Piece 2 chain assembly.
  - `async verify_chain(engagement_id) -> bool` — replays HMAC chain for tamper detection.
  - `async export_bundle(vuln_id, redact_secrets: bool = True) -> Dict[str, Any]` — bounty-grade output: markdown report body + `{"artifact_manifest": [...]}` + request/response summaries, shaped for `BugBountyAdapter.submit_finding`. Redaction is enforced at capture time (§1 `redaction.py`): stored artifacts are already scrubbed, so `redact_secrets=True` is the default presentation and `redact_secrets=False` only un-redacts non-secret context labels — originals of cookies/tokens are never re-emitted in an export. **Never auto-submits**: caller passes `live_submit_approved=True` to the adapter separately after operator review.
- **`redaction.py`** — secret scrubbing used at capture time: cookies, `Authorization`/`X-Api-Key`/etc. headers, and any value matching known credential patterns are stored as `{"redacted": "<label>"}` with originals only in the HMAC-covered blob path. Follows `safety/prompt_defense.py` conventions for untrusted content.
- **`migrations.py`** — one `CREATE TABLE IF NOT EXISTS exploit_receipts (...)` in the `engagement_state.py` migration style (no Alembic in this repo). Indexes on `(engagement_id)`, `(vuln_id)`, `(receipt_id)`.

Feature-flagged and defaults off:

```python
evidence_receipts_enabled: bool = Field(default=False, validation_alias="OSOP_EVIDENCE_RECEIPTS_ENABLED")
evidence_root: str = Field(default="./evidence", validation_alias="OSOP_EVIDENCE_ROOT")
```

Default-off because receipt capture touches every outbound exploit request; rollout is per-engagement/per-environment. The spec's live-verification gate (§4) sets it `True`.

### 1.2 Wire into `ExploitValidationAgent`

- `_validate_exploit` builds an `ExploitReceipt` after `_confirm_by_response` returns, **before** publishing `feedback.payload_validated`. Receipt contains the full curl request/response, oracle signals (`_sig_*` score + `oast_hit` boolean), scope hash from the injected `ScopeDefinition`, and `approval_id`.
- Receipt recording is best-effort post-verdict (same pattern as ledger at lines 158-164: log warning on failure, never flip the exploit result).
- The published `feedback.payload_validated` message gains `receipt_id` so downstream consumers (PayloadMutationAgent fitness, reporting) can correlate.
- **Complexity guard:** `exploit_agent.py` is ~535 lines today; if Piece 1 + Piece 3 push it past ~700 lines, the `_sig_*` heuristics move into a sibling `_confirm.py` mixin/helper rather than growing the file. This is a targeted extraction of code being modified, not a general refactor.
- `ReceiptStore` injected onto the agent by the runtime alongside the existing `ledger` (constructor attribute, `= None` default preserves existing test harnesses).

## 2. Piece 2 — Chain Executor Hardening

Make multi-hop execution honest about partial success, admissibility, and evidence.

### 2.1 Composer admissibility filter

`ChainComposerAgent` gains a policy gate before returning chains:

- Injected with the engagement `ScopeDefinition` (already resolvable via `ctx`).
- `allowed_techniques` is the live field name on `ScopeDefinition` (`core/models.py:291`); the composer matches each hop's vuln class against it (with the documented class synonyms — e.g. `idor` ≈ `bola`, `xss` ≈ `cross_site_scripting`).
- Each candidate chain is filtered: every hop's vuln class must appear in `scope.allowed_techniques` (or the chain is dropped, not annotated — see below), the chain must not require an approval tier the engagement hasn't granted, and auto-scheduled chains must not outrun the current phase.
- The LLM `think()` analysis is preserved but runs **after** filtering so it reasons only over admissible chains. Inadmissible chains are dropped from the executor's input and logged with reason (`chain.filtered` audit events carry the dropped hop list).

### 2.2 Executor: abort, partial-chain state, per-hop receipts

`ChainExecutorAgent._execute` changes:

- **Abort on hop failure**: break out of the hop loop on the first `not validated` or exception. Record the failure receipt, mark the chain `chain_failed` (ledger transition from the current hop's state per `LEGAL_TRANSITIONS`), with the abort detail (hop index, vuln_id, exception/redacted reason) captured in the receipt and the agent result payload. Do **not** execute downstream hops on evidence that is already contradicted. Today's continue-and-succeed-silently behavior is the bug this fixes. "Partial chain" is observable state via the ledger + chain-run receipt list — no new `ChainStatus` enum is introduced.
- **Per-hop receipts**: every hop that attempts `_exploit.validate_exploit` records an `ExploitReceipt` carrying `chain_id` and `hop_idx`, plus the exploit facade's own receipt `receipt_id` (Piece 1), into `ReceiptStore`. Chain receipts are additive evidence, not a rollback — the platform never deletes validated exploit proof, it appends the contradiction.
- **Escalation recording**: on successful `chain_executed` hops, write an `EscalationPath`/`AttackChain` node update into `graph_memory` so the attack graph reflects *proven* multi-hop reachability, not just discovered vulnerability proximity.
- `supports_task_type` updated for a new `abort_chain` task so an operator can stop an in-flight chain cleanly.

### 2.3 Phase-policy single source of truth

- Delete **both** dead shadow tables: `core/config.py:601-631` `PHASE_POLICY` **and** `core/enums.py:218-249` `PHASE_POLICY` (neither is imported anywhere; both replicate the same `requires_manual_approval` shape and disagree with the orchestrator's live `manual_approval`/`auto_next` keys). Grep-verified 2026-08-01: zero usages of either shadow.
- Add to `Orchestrator.PHASE_POLICY` a surgical gate: **phase entry** into `EXPLOITATION` sets `manual_approval: True` and `auto_next: None`, and the orchestrator's auto-advance halts before entering EXPLOITATION until an operator approves via the existing approval flow (same `ApprovalGate`/`ApprovalCoordinator` mechanism the per-task gate uses). Exiting EXPLOITATION stays auto (`auto_next: POST_EXPLOITATION`) once entered. Key names unify on the orchestrator's live `manual_approval`/`auto_next`; the config-shadow vocabulary (`requires_manual_approval`/`automatic_next_phase`) is removed, not ported, to avoid two spellings of the same gate.
- Operational note: engagements whose testing loops depend on unattended end-to-end runs must now pre-approve the EXPLOITATION phase (or run with a scope that skips it via the existing zero-vulnerabilities reroute in `_resolve_auto_next`). The phase-gate behavior delta must be covered by an updated `tests/test_phase_autoadvance.py` case.

## 3. Piece 3 — Blind-Oracle Expansion (OAST namespace hardening)

One new class family, done right: extend the existing SSRF/RCE OAST oracle to blind XSS, blind SQLi, and blind SSTI, with provenance carried end-to-end.

### 3.1 Caller-side OAST schema (no server change)

`OASTAdapter.register` already stores an opaque `context` dict. This piece standardizes the keys callers must set:

```python
OAST_CONTEXT_SCHEMA = {
    "engagement_id": str,
    "vuln_class": str,          # "blind_xss" | "blind_sqli" | "blind_ssti" | "ssrf" | "rce"
    "injection_point": str,     # header | param:<name> | body | dom:<selector>
    "payload_hash": str,        # sha256 of the actual payload content (don't store live secrets in OAST context)
}
```

Validation enforced adapter-side: unknown or missing keys raise `ScopeValidationError`-family errors on mint so a blind finding can always be attributed to the exact probe.

### 3.2 Confirmation for blind classes

`ExploitValidationAgent._confirm_by_response` gains blind-class dispatchers that **only** accept OAST proof (no body heuristics — the whole point is the response is empty):

- **blind_xss**: `verify` requires an OAST interaction *and* (for DOM-triggerable sinks) a `browser-mcp` callback hit correlated by token. Confidence 0.97 on dual correlation, 0.6 on OAST-only (renderable-but-unproven DOM execution).
- **blind_sqli**: OAST DNS/HTTP interaction carrying the token; requires the payload to have been a dialect-appropriate OOB primitive (e.g., `xp_dirtree`/`LOAD_FILE`-style DNS exfil for MSSQL/MySQL, `dblink` for Postgres). Confidence 0.9 on interaction.
- **blind_ssti**: OAST interaction after a template-render token fetch; body signature still checked as defense-in-depth for non-blind SSTI. Confidence 0.9 on interaction.

The existing `oast_hit` short-circuit at `exploit_agent.py:510-516` becomes a namespace-aware lookup: poll the token minted for this vuln class + injection point, not "any interaction".

### 3.3 Payload engine hook (minimal)

`AdaptivePayloadEngine.PayloadTemplateLibrary` gains template stubs for the three blind classes so generated payloads embed the minted OAST token/callback_url. The genetic loop is unchanged; fitness updates flow through the existing `feedback.payload_validated` event which now carries per-class OAST proof via the receipt.

## 4. Verification (live-verified bar adopted by the user)

The agreed acceptance standard: no mock-only "done".

1. **Unit/integration**: per-piece pytest coverage (receipt persistence + HMAC chain + redaction; composer admissibility + executor abort/record; blind oracle dispatch against canned OAST interactions). All deterministic, no network.
2. **Lab verification against Juice Shop** (`benchmarks/juiceshop/`): with the engine's known vuln classes validated end-to-end — payload → sandbox execution → oracle verdict → `ExploitReceipt` on disk and Postgres → `verify_chain` True. Blind-XSS/SQLi/SSTI are additionally verified against a purpose-built sink fixture in `tests/qualification/` following the existing `local_target` / `js_target` conftest pattern (an ephemeral `http.server` route that performs a callback on trigger, mirroring `OASTAdapter`), plus a documented manual run against the external Juice Shop convention (`docker run -p 3000:3000 bkimminich/juice-shop`, per `benchmarks/juiceshop/README.md:39-49`).
3. **Abuse/regression gates**: scope-excluded chain hop is refused by the composer; executor abort leaves `chain_failed` ledger state; redacted export contains no raw secrets; phase gate blocks EXPLOITATION entry without approval.
4. **Full suite green**: `poetry run pytest` with no new failures; quality gates `black`, `isort`, `flake8`, `mypy` clean on touched files.

## 5. Error handling & safety model

- All new exceptions inherit from the existing `OSOException` tree; OAST schema violations raise `ScopeValidationError` (existing `ScopeException` subclass), receipt persistence failures raise `MemoryException`-family `GraphQueryError`-adjacent errors.
- Receipt capture never mutates the exploit verdict; failure is logged and the event publishes without `receipt_id`.
- The executor's abort path sets `chain_failed` via the existing ledger legality rules (as defined in §2.2); a chain with a `chain_failed` hop never transitions to `successful_chain`.
- Redaction at capture means submitted bounty reports can't leak session cookies/tokens even if an operator overrides `redact_secrets=False` at export time (they only un-redact labels' metadata, not stored secrets — originals remain blob-only and HMAC-covered).

## 6. Out of scope (explicit)

- Race-condition exploitation (turbo-intruder), new client-side chain archetypes, GraphQL-specific exploitation.
- Auto-submission of receipts to bug-bounty platforms — `export_bundle` prepares, `BugBountyAdapter.submit_finding(live_submit_approved=True)` submits, and only after operator review.
- Multi-tenancy expansion of `exploit_receipts` (single `engagement_id` scoping is sufficient for this tranche).
