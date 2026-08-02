# AI-OSOP — Remaining Score-Movers to 10/10 (executable plan)

**Date:** 2026-08-01 · **Branch:** `feat/real-discovery-and-agent-loop` · **Base:** `3d5f55e0`

This is a **forward-looking execution plan**, not a certificate. Every claim below is
tied to `file:line` or a measured number. It exists because the four items that
actually move the score require a live Neo4j/Postgres/Redis stack, a labeled corpus,
or a whole-tree lint pass — none of which can be honestly verified from a chat session.
Do **not** mark any item done until its stated acceptance check passes on the real stack.

## Measured baseline (independently verified 2026-08-01, not self-reported)

| Metric | Value | Source |
|---|---|---|
| `ruff check src` | **494 errors** | run |
| `mypy src` | **~873 errors / 134 files** | run |
| broad `except Exception` | **599 across 110 files** | grep |
| coverage | **~62%** vs configured `--cov-fail-under=70` (RED) | run |
| pytest collected | **1843** | run |
| Honest overall score | **~6/10** (was 5 pre-session) | evidence-backed review |

## Shipped this session (verified: tests + ruff-clean; swept into commits by a concurrent process)

1. **Sandbox egress fails closed** — `safety/scope.py` `_apply_egress_rules()` raises `SandboxException` on any iptables failure instead of warn-and-continue. Was wide-open if the terminal `-j DROP` failed. Tests: `tests/test_sandbox_failclosed.py` (3) + corrected `test_safety_isolation.py`.
2. **`list_engagements` pagination** — `api/routers/engagements.py` `limit`/`offset`, default cap 200. Was an unbounded in-memory dump.
3. **Session-key stretching** — `auth/session_store.py` scrypt KDF via `MultiFernet` (legacy sha256 kept as decrypt fallback → no data loss). Was `Fernet(b64(sha256(key)))`, instant to brute-force. Tests: `tests/test_session_encryption_kdf.py` (3).
4. **Reaper double-reap closed (sequential half)** — `reliability/agent_reaper.py` writes its requeue back to `orch._tasks`, so `RecoveryService._reap_stuck_tasks` no longer re-reaps a task already requeued. Tests: `tests/test_reaper_inmem_sync.py` (2). **Residual:** the *concurrent* window still wants a shared per-task lock (see item 5).

---

## Item 1 — Findings outbox (CRITICAL: data-loss). ✅ SHIPPED + PROVEN ON LIVE STACK (2026-08-01).

**Status.** Implemented and verified against the running Neo4j+Postgres. A Neo4j
outage during a finding write now durably queues the finding to the Postgres outbox
(`SessionMemory.enqueue_outbox`) and `OutboxProcessor` projects it to Neo4j on recovery;
the old path raised and lost it. Files: `memory/graph_memory.py` (`outbox_sink` hook +
`_write_vulnerability_cypher` + `add_vulnerability` durability net + `_from_outbox` guard),
`memory/session_memory.py` (`enqueue_outbox`), `memory/outbox_processor.py` (vulnerability
projection branch), `api/main.py` (lifespan wiring). Regression: 241 graph/outbox/vuln
tests pass. Live proof: `tmp/verify_findings_outbox.py` — 6/6 PASS (outage→queued in PG,
recovery→projected to Neo4j, contrast→old behavior loses it). **Remaining:** extend the
same pattern to `add_endpoint`/workflow writes; promote the tmp proof to a marked
integration test.

### Update 2026-08-02 — endpoint + asset outbox COMPLETED + PROVEN ON LIVE STACK.
- `add_endpoint`/`add_asset` gained a `_from_outbox` guard + enqueue `model_dump(mode="json")`;
  `OutboxProcessor` gained `endpoint`/`asset` projection branches (mirroring `vulnerability`).
- **Real pre-existing bug found + fixed** via the live proof: `add_asset` passed `metadata` (a dict)
  raw into Cypher → Neo4j rejects map properties → **every asset write failed**. Now `json.dumps(metadata)`
  (AIOSOP-ASSET-MAPPROP). The mock-based unit test asserted the raw dict (the value the live DB rejects)
  and was updated to the JSON its own name already promised.
- Live proof `tmp/verify_endpoint_asset_outbox.py`: 8/8 PASS (outage→queued in PG, recovery→projected to Neo4j).
- **STILL OPEN: attack_path.** Its producer (`graph_memory.py` ~:989) enqueues a *minimal custom payload*
  (`node_ids`/`edges`/…), NOT a model dump, AND enqueues UNCONDITIONALLY (on success, not just on failure).
  So the naive "reconstruct AttackPath + call add_attack_path(_from_outbox=True)" fix is WRONG twice:
  (a) `AttackPath(**payload)` raises (missing required fields); (b) without a `_from_outbox` guard the
  projector re-enqueues every tick → infinite outbox growth even with healthy Neo4j. The correct projector
  must RE-RUN the LEADS_TO Cypher from `node_ids`+`edges`, and `add_attack_path` needs a `_from_outbox`
  guard on its unconditional enqueue. Left for a coordinated session (touches actively-churning code).

**Problem.** `memory/outbox_processor.py:59` replicates **only** `entity_type == "task"` to Neo4j.
`Vulnerability`/`Endpoint`/`Workflow` writes go straight to `graph_memory.add_*` (Cypher). A Neo4j
blip during a scan loses those findings with no replay path. A single finding write also spans
Neo4j + Postgres `FindingCorpus` + Primitive-ledger in **separate** transactions (non-atomic).

**Change.**
1. In `graph_memory.add_vulnerability` / `add_endpoint`, at the point of the Postgres `FindingCorpus`
   write, enqueue `OutboxORM(entity_type="vulnerability", entity_id=vuln.id, action="upsert",
   payload=vuln.model_dump(mode="json"))` in the **same** PG session/transaction (so PG commit is atomic).
2. In `OutboxProcessor.process_batch`, add `elif entry.entity_type in ("vulnerability","endpoint")`
   branches that call a **new** `graph_memory._project_vulnerability(vuln)` — the raw Cypher `MERGE` only.
   **Trap:** do NOT call `add_vulnerability` from the processor — it re-enqueues an outbox row → infinite loop.
   The projector must be the graph-only writer.
3. Treat Postgres as source-of-truth for findings; Neo4j is a projection rebuilt from the outbox.

**Acceptance.** Start a scan, kill Neo4j mid-scan, let it recover: every finding persisted to PG appears
in Neo4j after the processor drains, zero loss, dedup intact. Regression test with real containers.

## Item 2 — Gates actually green. Effort: L. Needs: whole-tree pass (coordinate — do NOT run mid-churn).

**Problem.** 494 ruff / ~873 mypy / 62% coverage — the build is red on its **own** configured gates,
and `RELEASE_CERTIFICATE.md` recorded lint/type "FAIL" while the repo shipped. `ruff --fix` yields
nothing (only `--unsafe-fixes`), so these are real, not formatting.

**Change (do NOT lower the gate — that is the certificate anti-pattern).**
1. `ruff check src --statistics` → fix zero-behavior-risk codes first (`F401` unused imports, `F841`
   unused vars, `F541` f-strings without placeholders) in one pass.
2. The ~599 `BLE001` broad-excepts (which `AGENTS.md` itself forbids): fix per-module in small PRs,
   each choosing specific exception types + running that module's tests. Never blanket-swap.
3. mypy: enable `--strict` per package incrementally; start with `safety/`, `auth/`, `api/`.
4. Wire `ruff`, `mypy`, and `--cov-fail-under=70` as **blocking** CI gates on every commit.

**Acceptance.** `ruff check src` → 0, `mypy src` → 0, coverage ≥70, all blocking in CI.
**Coordination:** this is a whole-tree sweep; run it only when the branch's deps/config are stable.

## Item 3 — Close the calibration loop. Effort: M–L. Needs: labeled corpus (cannot be fabricated).

**Problem.** Confidence values are hardcoded constants (`deterministic_scan.py:353` `0.98`,
`oast_correlation.py:128` `0.97`, `sqli_oracle.py:408` `0.9`, …). `ConfidenceCalibrationEngine`
**records** outcomes (`graph_memory.py:822` `calibration_engine.record_outcome`) but the emitted
confidence at detection time is never derived from it — the loop is open.

**Change.**
1. Build a ground-truth-labeled corpus (Juice-Shop + a second authorized target; each finding
   tagged true/false positive).
2. Replace literal `confidence=0.9x` at emission sites with
   `calibration_engine.calibrated_confidence(detector_id, raw_signal)` sourced from the recorded outcomes.
3. Publish a real precision/recall curve over the corpus.

**Acceptance.** A reproducible P/R curve on a surface materially larger than the current tiny manifest
(scorecard today: precision 1.0, recall 0.6 on a handful of Juice-Shop findings).

## Item 4 — Prove one autonomous E2E engagement (the 10-decider). Effort: M. Needs: live stack + authorized target.

**Problem.** `benchmarks/live_e2e_governed_scan.py` proves the *governed deterministic* path.
A full **autonomous** engagement driving itself recon→report through the phase monitor against a
live target has **never** been run (`docs/BUG_BOUNTY_READINESS_GAPS.md` hardening item #1 admits this).

**Change / Acceptance.** One green autonomous run: recon → vuln discovery → (approval-gated) →
reporting, scope held throughout (no out-of-scope egress), findings persisted and a report rendered
from real data. Capture the run log + evidence vault as the proof artifact.

## Item 5 — Consolidate the two reapers (finishes item 4 of the shipped list). Effort: M. Needs: live Redis integration test.

**Problem.** `RecoveryService._reap_stuck_tasks` holds **no** task lock; `AgentReaper._recover_agent`
locks only `agent-recovery:{agent_id}`. Disjoint locks → the concurrent window is unguarded.
(The sequential re-reap was already closed this session via the `_tasks` writeback.)

**Change.** Introduce a shared, non-blocking per-task lock `task-recovery:{task_id}` (unique token value,
owner-checked release) that **both** reapers acquire before mutating a task; skip if not acquired.
Longer term, collapse both into a single reconciler. **Trap:** `tests/test_recovery_service.py` mocks
`session_memory` as a plain `MagicMock`; adding an `await ...acquire_lock()` there requires setting
`orch.session_memory.acquire_lock = AsyncMock(return_value=True)` in that suite first.

**Acceptance.** Integration test with real Redis: a task on a dead agent past its timeout is recovered
**exactly once** under both reapers running concurrently.

---

## Definition of done for 10/10

- Items 1–5 complete with their acceptance checks green **on the live stack**.
- Multi-tenant authz real (not `created_by == sub`); tenancy work is in progress (`8fe0057f`, `3d5f55e0`).
- Zero fabricated telemetry anywhere (grep for hardcoded `"enforcing"`, `"active_blocks"`, fixed WAF profiles).
- README/marketing language matched to reality (a 10 is earned by *removing* claims until each survivor is true).
- **Delete the `*_CERTIFICATE.md` / `*_READINESS.md` docs**; replace with one CI-generated `STATUS.md`
  driven by actual `pytest`/`ruff`/`mypy`/scorecard output. The self-certification culture is the single
  biggest credibility drag on genuinely good engineering.

## Coordination note

This is a shared, actively-committed branch; a parallel process commits (incl. dependencies) concurrently.
Re-check `git status` before each edit. Un-tracked files get swept into unrelated commits here — land
work in small, reviewed units and prefer a worktree for any whole-tree pass (item 2).
