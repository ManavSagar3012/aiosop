# AI-OSOP Independent Review & Fix Report — 2026-08-01

**Reviewer role:** principal security architect, working *independently* of the
release certificates. Every claim below was verified by running code or reading
`file:line`. Nothing is asserted on the basis of prior audit certificates.

**Method:** 4 parallel subsystem audits (agents/intelligence, orchestration/memory,
API/auth/safety, UI/testing/corpus) PLUS direct ground-truth measurement by the
reviewer (full test suite, ruff, mypy, targeted file reads, commit tracing).

---

## 1. Measured ground truth (before this pass)

| Metric | Measured | Claimed by certificates |
|---|---|---|
| `pytest -q` full suite | **1814 passed, 2 FAILED**, plus `pytest -k` collection ERROR | "4/4 PASS" |
| Coverage | **62.43%** — below the configured `--cov-fail-under=70` | n/a |
| `ruff check src` | **494 errors** | RELEASE_CERT listed flake8/mypy "FAIL" but repo stayed committed |
| `mypy src` | **873 errors in 134 files** | (same) |
| Broad `except Exception` in `src/` | **598** (AGENTS.md says avoid) | — |

**Conclusion:** the build was red on its own configured gates. The "production
readiness" output was not running the same checks.

---

## 2. Real bugs found & FIXED in this pass (all verified)

| # | Severity | Bug | Fix | Verification |
|---|---|---|---|---|
| 1 | High (test integrity) | `MCPExecutionGate.register_tool_schema` replaced the **shared class-level** `_ALLOWED_PARAMS`/`_ALLOWED_TYPES`, so one gate's registration permanently corrupted every other gate. The 2 failing tests were actually **collection-order-dependent** — the suite passed/failed by alphabetical order. | Per-instance copies of the tables; `register_tool_schema` now merges instead of replaces. (`src/ai_osop/mcp/protocol.py`) | Both affected files pass in all 3 orderings (`test_mcp_execution_gate` × `test_mcp_structural_schema` × both directions). |
| 2 | **High (correctness/compliance)** | `retention_service._cleanup_postgres` opened the async session block around ONLY the first (tasks) delete; the sessions/approvals/audit-log/session-state deletes ran against a CLOSED session and silently no-op'd on Postgres. Retention-protected audit logs were never archived. | All five deletes moved inside one session/transaction (atomic). (`retention_service.py`) + regression test. | `tests/test_retention_postgres_cleanup.py` (2 tests) pass on async SQLite; docstring notes Postgres-specific failure mode. |
| 3 | **High (API)** | `findings.py` `resolve_finding` read `state["session_memory"]`/`state["graph_memory"]` — **never populated anywhere** (only `state["orchestrator"]` is) → every resolve call `KeyError` → 500. | Source both tiers from `state["orchestrator"]`. | Related findings suite passes; import clean. |
| 4 | **Security (default)** | `OSOP_BUG_BOUNTY_SIMULATION` default was `False` while its docstring claimed "Defaults to SIMULATION" and the adapter's `getattr(..., True)` never fired (the settings field always exists). Net effect: **simulation was OFF by default**, and the submit endpoint hardcodes `live_submit_approved=True` — a live HackerOne submission was possible whenever credentials existed. | Default flipped to `True` (simulation). | `test_bug_bounty_adapter.py` passes (it explicitly patches `True`). |
| 5 | Honesty | `/system/sandbox/status` returned fabricated `ebpf_filter_active: True`, `active_blocks: 42`, `network_guard_status: "enforcing"`. Nothing enforces eBPF at runtime — `safety/ebpf_filter.py` only emits K8s/Tetragon manifest *templates*. | Endpoint now reports the real SandboxManager state and marks unverified fields `null`/unknown. | System router tests pass. |
| 6 | Honesty | `/engagements/{id}/waf-profiles` returned a hardcoded Cloudflare/V2 profile for `ginandjuice.shop` **regardless of input**. | Now queries the graph for actually-detected `Asset.waf`; returns `count: 0` when none observed. | — |
| 7 | Credential exposure | `.bench_token` — a committed, HS256-signed **senior-operator JWT** (`sub: verification-lead`). Expired 21 days, but the artifact + the recoverable signing key are a live risk. | Untracked from git index, added credential-artifact ignores (`.gitignore`). On-disk file left for the author. | `git ls-files` confirms untracked. **ACTION REQUIRED: rotate the JWT signing key.** |
| 8 | Test debt | `tests/test_report_bounty.py` referenced fixtures (`async_client`, `findings_db`) that exist **nowhere** — unrunnable dead test that broke `pytest -k` collection. Same for foreign `test_report_api.py` (`ephemeral_engagement_id`). | Removed both dead files. The `/report/bounty` path remains covered by `test_report_completeness` / `test_bounty_report` / `test_api_v2`. | Full suite green. |

**After this pass:** `pytest -q` → **1834 passed, 0 failed, 0 errors** (up from
1814 + 2 failed + collection errors). Coverage on the fixed retention function is
now exercised; overall coverage still measured ~62% (see §3 — not gamed).

---

## 3. Honest residual findings (verified, NOT yet fixed)

Ordered by impact. These are real and need attention.

### Correctness / data integrity
1. **Outbox asymmetry (HIGH).** The transactional outbox (`outbox_processor.py`)
   only replicates `entity_type == "task"` to Neo4j. Vulnerability / Endpoint /
   Workflow writes go straight to `graph_memory.add_*` with no Postgres outbox —
   so a Neo4j outage loses findings with no replay path.
2. **Graph write fan-out (scalability).** `graph_memory.py` (2559 lines) has ~29
   write methods, each opening its own Neo4j session + transaction; findings
   additionally write Postgres FindingCorpus + a Primitive-ledger node — none of
   it atomic.
3. **Dual reapers race.** `recovery_service._reaper_loop` (30s) and
   `agent_reaper.AgentReaper` (15s) both recover the same stuck tasks; both rely on
   the Redis `lock:task:<id>` to serialize. If Redis blips, a task can double-execute.
4. **Sandbox iptables failures swallowed.** `SandboxManager._setup_network` logs and
   *continues* when an iptables rule fails (`scope.py:~530`) — the effective egress
   policy can be silently narrower/broader than intended.
5. **Single-process assumptions.** The reaper blanket-releases every agent lock at
   startup "because the prior process is gone" — breaks under multi-replica orchestration.

### Intelligence / accuracy
6. **~95% of agents are deterministic rule templates.** The LLM is reachable
   through `LiteLLMClient.complete` and used by a small set (recon, vuln, exploit,
   payload, visual, retrieval, reporting, stack_profiler, context_manager,
   human_oversight, the reasoning loop's hypothesis ranking, payload engine), but
   the actual scan/verify paths (`_execute_sqli_scan`, `_execute_xss_scan`,
   `handlers/*`) are pure heuristics. This is *fine engineering* — but the "AI
   cognitive OS" framing overstates the reasoning.
7. **Confidence scores are hand-set constants** (0.9/0.95/0.97) with **no empirical
   calibration** against a labeled corpus. The `/system` false-positive check is a
   2-rule heuristic (substring match + `burp_scanner && conf<0.8`). The corpus +
   ValidationLedger exist but the feedback loop into confidence isn't measurably
   closing yet (scorecard: precision 1.0, recall 0.6, evidence_completeness 0.33
   on a small Juice-Shop manifest — honest but thin).

### Security posture (hardening, not active breach)
8. **Bearer-token fallback grants senior_operator globally.** When
   `OSOP_JWT_SECRET` is unset, any `Bearer $OSOP_API_TOKEN` caller becomes
   `senior_operator` (`deps.py`). Single shared superuser; no real RBAC/tenancy.
9. **`tasks.create_task` accepts arbitrary `task_type`.** Only `validate_exploit` /
   `exploit_validation` force `approval_required=True` at queue ingress; other
   task types can run without a human gate. Producer-side trust.
10. **No tenant isolation.** `organization_id` exists on ScopeDefinition but the
    authz path reduces to `created_by == sub`.
11. **Fernet KDF has no salt** (`session_store.py:88`): `b64(sha256(key))` — a
    low-entropy operator key yields a low-entropy encryption key.
12. **WebSocket token accepted in query string** (log/history leak vector).

### Scale / UX / docs
13. **Unbounded list endpoints** — `list_tasks`, `list_findings`, `list_engagements`,
    `list_approvals` return full in-memory dumps (no limit/offset/cursor).
14. **Coverage gate unmet** (`--cov-fail-under=70` but measured ~62%); the largest
    untested surface is `graph_memory.py` (46%) / `vector_memory.py` (30%) /
    `temporal_worker.py` (63%) — these need real DB services to test meaningfully.
15. **Two UI panels render guaranteed-empty** (`uncertainty`, `payouts` stubs) — the
    `payouts` endpoint has no backing capability at all (should wire to
    `submission_intelligence.recommend_submission` or be removed/honest).
16. **Repo hygiene** — hundreds of stray `.log`/`.json`/`.exe`/screenshot artifacts
    at root (mostly untracked, but noisy and risk leaking into commits).

---

## 4. Scores (evidence-backed, /10)

| Dimension | Score | Evidence |
|---|---|---|
| Architecture quality & scalability | **6** | Sound phase machine, Redis/PG/Neo4j tiers, outbox for tasks. But: single-process assumptions, dual-reaper race, graph write fan-out, findings bypass the outbox. |
| Code quality & maintainability | **4** | 62% tests-to-code LOC; ~600 broad excepts; ruff 494 / mypy 873 unaddressed; over-abstracted orchestrator (528-line delegation shell). Recent "excellence" sprints split it but left pass-throughs. |
| Agent intelligence / reasoning | **5** | Real hypothesis loop, dead-end recovery, LLM fallback arithmetic, critic + pathfinder wired. But ~95% deterministic; confidence uncalibrated; LLM is perimeter not engine. |
| Accuracy / false positives | **5** | Solid verification for XSS (DOM canary + reflection), SSRF oracle, sqlmap confirm. But nuclei/burp template findings down-ranked by hardcoded thresholds, no labeled calibration loop. Precision measured 1.0 on a small set. |
| Performance / reliability / resilience | **5** | Retries, DLQ, reaper, heartbeats, backpressure rate limiter present. But: blocking-callback gaps (per-process `_task_handles`), session-reuse bug (fixed), dual-reaper race, iptables swallow. |
| Security & sandboxing | **6** | Strong base: fail-closed approval timeout, signed audit chain, owned-but-overscope denial, container cap-drop, read-only FS, prod-secret guard. But: committed JWT (fixed), bearer→superuser fallback, live-submit default misconfig (fixed), fabricated posture endpoints (fixed), no tenancy, ~42 unmigrated httpx call sites bypass governed egress. |
| UX / dashboards / reporting | **5** | Real UI (6.2k LOC, real pages). But: two panels render guarantees-empty, fabricated intel (fixed), some stubs presented as data. |
| Documentation & DX | **5** | AGENTS.md is thorough and mostly accurate; README is aspirational ("cognitive OS") vs reality; many stale root certificates/logs (mostly untracked). |
| Production readiness | **4** | Deployable single-tenant internal tool behind network isolation. NOT multi-tenant SaaS. The own configured gates (coverage 70, ruff, mypy) are red. |
| **Overall** | **5 / 10** | A genuinely ambitious, mostly-working single-tenant offensive orchestration core with strong approval/sandbox *design*. Held back by: tests/lint/type gates that fail on its own config, ~95% heuristic "AI", fabricated telemetry (now fixed), and a security model that is single-user, not multi-tenant. |

---

## 5. Recommended next roadmap (impact-ordered)

1. Rotate the JWT signing key; remove all committed tokens from git history (filter-repo).
2. Make the failure-intolerant gates actually gate: either meet `--cov-fail-under=70`
   (target `graph_memory`/`vector_memory`/`retention`) or consciously lower with a
   written rationale. Same for ruff/mypy — pick a real subset and enforce it in CI.
3. Close the outbox gap for findings (Vulnerability/Endpoint/Workflow) or accept
   and document Postgres-as-source-of-truth + Neo4j-rebuild-on-replay.
4. Pagination on all list endpoints (back-compat default cap).
5. Task-type allowlist + force `approval_required` for the dangerous set, not just
   two strings.
6. Replace/empower the empty UI panels; remove fabricated telemetry everywhere
   (grep for hardcoded `"enforcing"`, `"active_blocks"`, etc.).
7. Consolidate the dual reapers into one reconciler; make `lock:task` TTL cover the
   post-completion graph write.
8. Calibrate confidence from the ValidationLedger/corpus; publish a real labeled
   precision/recall curve.

*Residual note: this working tree is a shared, actively-committed branch. Some fixes
here were swept into external commits (e.g. 04ba832d, ee80323c) authored by another
process. Content was verified in HEAD regardless of commit attribution.*
