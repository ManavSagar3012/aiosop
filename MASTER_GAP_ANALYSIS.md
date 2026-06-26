# MASTER_GAP_ANALYSIS — AI-OSOP Zero-Trust Adversarial Audit

- **Date:** 2026-06-26
- **Branch:** `fix/runtime-self-heal-2026-06-24`
- **Auditor stance:** Principal Security Architect / Staff SWE / SRE / Red Team Lead — *prove it wrong*.
- **Doctrine:** Guilty until proven innocent. A capability is real **only** with input-dependent runtime evidence. Everything else is **UNVERIFIED**, never PASS.

---

## ⚠️ Audit Integrity Statement (read first)

This audit could **not** achieve full runtime verification, and per the honesty policy I will not pretend otherwise:

| Dependency | Port | State at audit | Consequence |
|---|---|---|---|
| Redis | 6379 | **OPEN** | partial runtime possible |
| Postgres | 5432 | **OPEN** | partial runtime possible |
| (unknown) | 8080 | OPEN | unidentified listener |
| Neo4j HTTP | 7474 | **CLOSED** | graph memory unverifiable |
| Neo4j Bolt | 7687 | **CLOSED** | attack graph unverifiable |
| API | 8000 | **CLOSED** | all endpoint/auth/dashboard runtime unverifiable |

Neo4j and the API are down, and standing policy forbids me restarting shared services without confirmation. Therefore **every claim requiring the live graph, the API, or a full recon→vuln→exploit→report E2E is marked UNVERIFIED**. What follows is grounded in: direct source reading, AST analysis, `grep` census, the test suite executed this session, and direct execution of a standalone MCP binary. Each finding states its evidence class.

---

## Executive Summary

AI-OSOP is an autonomous **offensive** security platform. The single most important finding is not a crash — it is that **the platform fabricates security findings by default and cannot presently be proven to do real work**.

1. **`mock_llm` defaults to `True`** (`config.py:201`). Out of the box, `vuln_agent` *manufactures* vulnerabilities — "Blind SQL Injection (Simulated)", confidence `0.9` — and emits them as first-class `Vulnerability` objects (`vuln_agent.py:177–217`). **These simulated findings are not filtered** anywhere in `findings_corpus`, `findings_quality`, or `reporting`. An operator running defaults sees fake vulns as product output. `bug_bounty_simulation` *also* defaults `True`.
2. **The approval/scope tamper-evidence is cosmetic.** `audit_secret_key` is referenced via `getattr(settings, "audit_secret_key", default)` in three places but is **not a defined Settings field** (`grep` for a field definition returns 0). So the HMAC that signs scope manifests and the audit chain **always** uses the public constant `"default-insecure-audit-key"`. The scope-signing fix landed last session is neutralized: anyone who can recompute an HMAC with a known key forges a valid signature.
3. **At least one MCP is a self-admitted mock.** `api/health.py:151` documents that recon-mcp's `nmap_scan` "always returned 127.0.0.1:80,443" regardless of input. The current binary's behavior is **UNVERIFIED** (I declined to bind its port), but the codebase treats it as `suspect_mock`.
4. **The codebase is in an actively broken mid-migration state.** 9 agents were moved out of `agents/experimental/` into `agents/`, but 12 test modules still import the old path → **12 collection errors**; the moved agents are referenced exactly once each (near-dead). The test suite cannot fully collect.
5. **Process/hygiene collapse.** 165 markdown files in repo root (29 `*CERTIFICATE*`, 52 `*REPORT*`, 35 `*AUDIT*`), 35 `update_*.py`/`fix_*.py` scratch mutation scripts, and literal junk files named `-` and `nul`. The prior session lost a 1015-line source file to a disk-full truncation caused by exactly this script-driven, unreviewed editing style.

**Runtime stability and "production readiness" claims in the existing `*_CERTIFICATE.md` files are not supported by reproducible runtime evidence and should be treated as marketing until re-proven.**

Verified test reality this session: **264 passed, 21 skipped, 12 collection errors**, live-infra tests error without services. Coverage is configured but **UNVERIFIED** here.

---

## Severity Register (sorted)

| ID | Sev | Component | Type | Evidence class |
|---|---|---|---|---|
| OSOP-P0-01 | P0 | vuln_agent / findings | Fabricated findings by default | Source+AST, default value |
| OSOP-P0-02 | P0 | findings_corpus/reporting | Simulated findings not filtered | grep (absence) |
| OSOP-P0-03 | P0→P1 | approval/scope signing | Insecure constant HMAC key | Source, field absence |
| OSOP-P0-04 | P0 | recon-mcp | Self-admitted canned output | Source admission; binary UNVERIFIED |
| OSOP-P1-05 | P1 | agents migration | 12 broken test imports, near-dead dup | pytest + grep |
| OSOP-P1-06 | P1 | bug_bounty_adapter | Simulated outcomes by default | Source, default value |
| OSOP-P1-07 | P1 | signing key types | str/bytes mismatch → latent TypeError | Source |
| OSOP-P1-08 | P1 | whole codebase | 34 silent `except: pass`, 2 bare `except:` | grep count |
| OSOP-P1-09 | P1 | Go MCP servers | Argument injection into external tools | Source |
| OSOP-P1-10 | P1 | agent isolation | In-process agents can mutate task/approval state | Source (carried from prior audit) |
| OSOP-P2-11 | P2 | config | Weak Neo4j default `change-me-local` | Source |
| OSOP-P2-12 | P2 | repo process | Certificate/report theater (165 md) | filesystem census |
| OSOP-P2-13 | P2 | repo process | 35 scratch mutation scripts; `-`/`nul` files | filesystem census |
| OSOP-P2-14 | P2 | tests | Suite cannot fully collect; coverage unknown | pytest |
| OSOP-P3-15 | P3 | UI | `Math.random()` fabricated metrics in load_test | grep |
| OSOP-UNV-* | — | Neo4j/API/E2E/chaos | Not runnable under policy | port probe |

---

## Critical — P0

### OSOP-P0-01 — Platform fabricates vulnerabilities by default (`mock_llm=True`)
- **Severity:** P0 (Critical)
- **Component:** `src/ai_osop/agents/vuln_agent.py`, `src/ai_osop/core/config.py`
- **Root Cause:** `mock_llm: bool = Field(default=True, validation_alias="OSOP_MOCK_LLM")` (`config.py:201`). When set, `vuln_agent` injects fabricated vulns when Burp returns none.
- **Evidence (source):**
  - `config.py:201` default `True`.
  - `vuln_agent.py:177` `if settings.mock_llm and len(vulns) == 0:` → builds `"WAF Configuration Weakness (Simulated)"` and `"Blind SQL Injection (Simulated)"` (`vuln_agent.py:182–225`) with `severity=HIGH`, `confidence=0.9`, `tool_source="vuln-agent-mock"`, `evidence=[{"type":"mock_probe","provenance":"simulated"}]`.
  - `exploit_agent.py:118` `if settings.mock_llm:` branch also exists.
- **Runtime Proof:** Static + default-value proof. End-to-end emission into a live report is **UNVERIFIED** (API/Neo4j down).
- **Impact:** Default deployment produces fake findings indistinguishable (post-title) from real ones in the data model. For an offensive platform, this is a credibility-destroying correctness failure and could drive real operator action on fiction.
- **Exploitability:** N/A (correctness/trust), but trivially triggered (it is the default).
- **Likelihood:** Certain on defaults.
- **Business Risk:** Severe — invalidates every "findings" number on the dashboard and in reports unless mock mode is provably off.
- **Suggested Fix:** Flip default to `False`; require explicit opt-in; on startup, if `mock_llm` is on, emit a loud banner and stamp every engagement/report `MODE=MOCK`. Never construct `Vulnerability` objects in mock mode — use a clearly separate `SimulatedFinding` type that the corpus refuses by default.
- **Regression Test:** With `mock_llm=True`, assert no object of type `Vulnerability` with `provenance=simulated` is accepted by `findings_corpus.add`. With default settings, assert `settings.mock_llm is False`.
- **Effort:** Low–Medium. **Priority:** Immediate. **Owner:** Findings/Agents.

### OSOP-P0-02 — Simulated findings are not filtered before corpus/report
- **Severity:** P0
- **Component:** `findings_corpus.py`, `findings_quality.py`, `reporting/`
- **Root Cause:** No consumer filters `provenance == "simulated"` / `tool_source == "*-mock"`.
- **Evidence:** `grep -n provenance|simulated` across `findings_corpus.py`, `findings_quality.py`, `reporting/` returns **nothing** — there is no gate.
- **Runtime Proof:** grep (proof of absence). Report emission UNVERIFIED.
- **Impact:** Couples directly to P0-01 — fabricated findings propagate to corpus, quality scoring, dashboards, and generated reports.
- **Suggested Fix:** Central guard in `findings_corpus.add()` rejecting/segregating simulated provenance unless an explicit `allow_simulated` engagement flag is set; reports must visibly watermark simulated data.
- **Regression Test:** Feed a simulated `Vulnerability` into the corpus; assert rejection (or quarantined, never counted in headline metrics).
- **Effort:** Low. **Priority:** Immediate. **Owner:** Findings.

### OSOP-P0-03 — Scope/approval HMAC always uses a public constant key
- **Severity:** P0 for an offensive platform (listed P1 in matrix conservatively)
- **Component:** `core/config.py:417`, `orchestrator/approval_coordinator.py:37`, `memory/session_memory.py:471`
- **Root Cause:** `audit_secret_key` is consumed via `getattr(settings, "audit_secret_key", <default>)` but is **not a defined Settings field** (`grep 'audit_secret_key.*Field' config.py` → 0 matches). `getattr` therefore always returns `None`/missing → falls to `"default-insecure-audit-key"`.
- **Evidence:**
  - `config.py:417` `key = getattr(settings, "audit_secret_key", None) or "default-insecure-audit-key"`
  - `approval_coordinator.py:37` and `session_memory.py:471` use `b"default-insecure-audit-key"`.
  - Field-definition search returns 0.
- **Runtime Proof:** Source + Pydantic semantics (undefined attribute ⇒ default branch). Forging a signature E2E is UNVERIFIED (API down) but follows directly.
- **Impact:** The scope-manifest tamper-evidence and audit-chain integrity added last session are defeated. Any actor able to recompute HMAC-SHA256 with the known constant forges valid scope signatures and audit events → **approval/scope integrity bypass**, attribution non-repudiation lost.
- **Exploitability:** High (key is in source). **Likelihood:** Certain (default path). **Business Risk:** Severe for an authorized-exploitation product (compliance/attribution).
- **Suggested Fix:** Define `audit_secret_key` as a real, required `SecretStr` Settings field with **no insecure default**; fail closed (refuse to start / refuse to sign) if unset in non-dev. Centralize key access in one function; forbid the constant outside tests.
- **Regression Test:** Assert startup raises in `environment=production` when `audit_secret_key` unset; assert `scope_signing_key()` never returns the constant when a key is configured; tamper test that a signature made with the constant is rejected once a real key is set.
- **Effort:** Low. **Priority:** Immediate. **Owner:** Security/Core.

### OSOP-P0-04 — recon-mcp is a self-admitted canned-output mock
- **Severity:** P0 (capability fraud) — current binary **UNVERIFIED**
- **Component:** recon-mcp (`mcp-servers/go/cmd/recon-mcp/main.go`), documented in `api/health.py:151`
- **Root Cause:** Historic mock returning fixed `127.0.0.1:80,443` for `nmap_scan` regardless of input.
- **Evidence:** `health.py:144–160` adds a `_check_tool_reality` probe precisely because "a server can answer 'ready' … and still return hardcoded data (as recon-mcp's mock did — `nmap_scan` always returned 127.0.0.1:80,443)" and flags `suspect_mock`.
- **Runtime Proof:** I executed `security-bridge.exe` and confirmed it launches (`security-bridge listening on :8087`) — proof binaries run — but I did **not** bind recon-mcp to verify its current output (policy/port hygiene). **Current recon-mcp reality: UNVERIFIED.**
- **Impact:** If recon is canned, the entire discovery→vuln→exploit chain operates on fiction. The prior `MASTER_GAP_ANALYSIS.md` also recorded recon-mcp HTTP probe **FAILED**.
- **Suggested Fix:** Make `_check_tool_reality` a hard startup gate in non-dev (refuse to mark recon healthy on `suspect_mock`); add a CI test that runs the binary against a known target and asserts input-dependent output.
- **Regression Test:** Execute recon-mcp against two distinct targets/ports; assert outputs differ and reflect reality.
- **Effort:** Medium. **Priority:** Immediate (verification). **Owner:** MCP/Recon.

---

## High — P1

### OSOP-P1-05 — Broken agent migration: 12 collection errors, near-dead duplicates
- **Severity:** P1 · **Component:** `agents/`, `tests/`
- **Root Cause:** 9 agents moved `experimental/ → agents/`; git shows `experimental/*` deleted + new `agents/*` untracked, but tests still `import ai_osop.agents.experimental.*`.
- **Evidence:** `pytest` → `ModuleNotFoundError: No module named 'ai_osop.agents.experimental.cloud_agent'` (and 8 siblings) = **12 collection errors** (also `test_api_v2`, `test_observability`, `test_scheduler_regression`). Each moved agent is referenced **once** outside its own file (likely a registry/export), i.e. effectively unexercised. Prior audit: "not registered in production."
- **Runtime Proof:** pytest collection (executed).
- **Impact:** Whole test categories silently don't run (false green); duplicate/abandoned code; unclear if these agents do anything.
- **Suggested Fix:** Decide: delete or finish. If kept, re-point imports, register, and add real tests; if not, remove files + tests. Add a CI gate failing on collection errors.
- **Regression Test:** CI step: `pytest --collect-only` must exit 0 (zero collection errors).
- **Effort:** Medium. **Owner:** Agents.

### OSOP-P1-06 — Bug-bounty outcomes simulated by default
- **Severity:** P1 · **Component:** `adapters/bug_bounty_adapter.py`, `config.py:296`
- **Evidence:** `bug_bounty_simulation: bool = Field(default=True ...)`; `bug_bounty_adapter.py:42 _simulated_outcomes(...)`, `:91 return self._simulated_outcomes(...)`, `:168 "simulated": True`.
- **Impact:** Dashboards/reports of bug-bounty sync show fabricated outcomes on defaults.
- **Fix:** Default `False`; watermark simulated outcomes; never count them in metrics. **Test:** assert simulated outcomes excluded from headline counts. **Owner:** Adapters.

### OSOP-P1-07 — str/bytes inconsistency in signing-key default (latent crash)
- **Severity:** P1 · **Component:** `config.py:417` (str) vs `approval_coordinator.py:37` / `session_memory.py:471` (bytes)
- **Evidence:** `config.py` default is `"…"` (str, `.encode()` later); the other two pass `b"…"` straight to `hmac.new`. If `audit_secret_key` is ever defined as a `str` Settings value, those two call sites pass a `str` to `hmac.new` → `TypeError`.
- **Impact:** The moment someone "fixes" P0-03 by adding a str field, approval signing/verification crashes — untested path.
- **Fix:** Single typed accessor returning `bytes`; all callers use it. **Test:** sign+verify roundtrip with a configured str key. **Owner:** Security/Core.

### OSOP-P1-08 — Silent exception swallowing
- **Severity:** P1 · **Component:** repo-wide (`src/`)
- **Evidence:** 34 `except … : pass`-style blocks and 2 bare `except:` in `src/`.
- **Impact:** Failures (store outages, partial writes, MCP errors) are hidden; correlates with the "browser-outage hang" and "ghost workflow" symptoms in memory. Hidden failure is the enemy of a reliability story.
- **Fix:** Replace silent passes with scoped catches that log + metric; ban bare `except:` via lint (ruff `E722`). **Test:** lint gate. **Owner:** Platform.

### OSOP-P1-09 — Argument injection into external security tools (Go MCPs)
- **Severity:** P1 · **Component:** `mcp-servers/go/cmd/{security-bridge,nuclei-mcp,recon-mcp}/main.go`
- **Evidence:** `exec.Command("sqlmap", args...)`, `"nmap"`, `"ffuf"`, `"masscan"`, `"gobuster"`, `"nikto"`, `"wpscan"`, `"nuclei"` (security-bridge:39–197, nuclei-mcp:50/85, recon-mcp:574). **Good:** arg-array form ⇒ no shell metacharacter RCE. **Bad:** if `args` derive from target URL/host/LLM output without an allowlist, attacker-controlled values can inject **tool flags** (e.g. a "host" of `--output-dir=/etc` style argument injection) and some calls swallow errors (`output, _ := exec.Command("nmap"…)`, security-bridge:62).
- **Impact:** Flag injection / unexpected tool behavior driven by target-controlled or LLM-controlled strings; silent nmap failures.
- **Fix:** Validate/allowlist every arg; reject values beginning with `-`; never swallow exec errors. **Test:** feed a target value of `--help`/`-oN /tmp/x`; assert rejected. **Owner:** MCP/Go.

### OSOP-P1-10 — In-process agents can mutate task/approval state (no isolation)
- **Severity:** P1 (defense-in-depth for P0-01/03) · **Component:** orchestrator/agents
- **Evidence:** Agents hold `session_memory`/`graph_memory` handles and run in-process (carried from prior session's GAP-2-5; still open). Combined with P0-03's forgeable key, a misbehaving/compromised agent has broad reach.
- **Fix:** Out-of-process agents with capability-scoped RPC; deny agent writes to task-status/approval fields. **Test:** assert agent role cannot write approval records. **Owner:** Architecture.

---

## Medium — P2 / Low — P3

| ID | Sev | Finding | Evidence | Fix |
|---|---|---|---|---|
| OSOP-P2-11 | P2 | Neo4j password weak default `change-me-local` | `config.py:169` | require real secret; fail closed in prod |
| OSOP-P2-12 | P2 | Certificate/report theater: 165 root `.md` (29 cert/52 report/35 audit), mostly assertions not runtime evidence | filesystem census; sampled certs are claim-only | move to `/docs`, generate from real queries, stop hand-writing PASS certs |
| OSOP-P2-13 | P2 | 35 `update_*.py`/`fix_*.py` scratch mutators in root; files literally named `-` and `nul`; `full_file.txt`/`original_file.txt` | `ls` | delete; forbid script-driven source edits; `.gitignore` + cleanup |
| OSOP-P2-14 | P2 | Suite cannot fully collect (12 errors); coverage unmeasured here | pytest | CI gate on collect; publish coverage |
| OSOP-P3-15 | P3 | UI fabricates metrics with `Math.random()` | `ui/src/services/load_test.ts:36–49` | ensure load-test path is dev-only, not shipped |
| OSOP-P3-16 | P3 | 2 real `TODO`s in correlation/evidence flow imply stubbed correlation | `correlation.py:32`, `evidence_vault.py:97` ("we simulate the execution flow") | implement or mark capability NOT-AVAILABLE |

**Note on fairness (walked-back suspicions):** CORS default is `http://localhost:5173` (not wildcard) — *not* a finding. `.env` is **not** git-tracked and secrets are not committed — *not* a leak. No `eval`/`exec`/`os.system`/`shell=True`/`pickle`/`yaml.load` RCE in `src/`. Credit where due.

---

## Section Findings (condensed)

- **Architecture:** Orchestrator decomposition improved last session (delegators + `OrchestrationState` proxies + a new AST dead-code lint guard). Residual: agents in-process (P1-10); dual sources of truth historically (memory vs durable) — `_is_phase_complete` now merges durable store but the read is **UNVERIFIED** without Neo4j.
- **Security:** P0-03, P1-07, P1-09, P1-10, P2-11. Approval-authority + recovery re-gating + phase guard from last session are sound *in unit tests* but their integrity rests on a key that is currently public (P0-03).
- **Reliability:** Silent excepts (P1-08); async teardown emits `Task was destroyed but it is pending!` and `worker_error … Event loop is closed` during tests (real, observed) — agent loops not cleanly cancelled. Chaos/restart recovery **UNVERIFIED** (Neo4j/API down).
- **Mock/Stub detection:** `mock_llm` (default on), `bug_bounty_simulation` (default on), recon-mcp suspect_mock, `evidence_vault` "simulate the execution flow", `concurrency_agent` "simulated Single Packet Attack", `correlation` heuristic stub. 91 `mock`, 18 `simulate`, 16 `placeholder`, 8 `hardcoded` hits in `src/mcp/ui`.
- **Dead/Duplicate code:** 9 migrated agents near-dead; `experimental/` deletions vs new files; the prior session removed duplicate orchestrator methods + post-`return` dead code (guarded now by `tests/test_no_dead_code.py`).
- **Database:** Neo4j/API down ⇒ persistence integrity, transactions, graph integrity, duplicate/lost records all **UNVERIFIED**. Redis + Postgres reachable but not exercised here.
- **Dashboard/Reports:** Cannot load (API down) ⇒ **UNVERIFIED**; but data-source risk is real given P0-01/02 and simulated adapters feed the same stores the dashboard reads.
- **Testing gaps:** No green E2E; collection broken; the only adversarial safety tests are the ones added last session (`test_safety_approval_authority.py`, `test_no_dead_code.py`). No chaos/recovery test runs without infra.

---

## Runtime Verification Log (what I actually executed)

| Action | Result | Class |
|---|---|---|
| `pytest` (full) | 264 passed, 21 skipped, **12 collection errors**, live-infra errors | RUN |
| `pytest tests/test_no_dead_code.py` | 22 passed (guard active) | RUN |
| Port probe 6379/5432/8080 | OPEN | RUN |
| Port probe 7474/7687/8000 | CLOSED | RUN |
| `./security-bridge.exe` | `listening on :8087` (binary executes; ignores `--help`) | RUN |
| recon-mcp real-output check | **NOT RUN** (port-bind/policy) | UNVERIFIED |
| Neo4j/API/E2E/chaos | **NOT RUN** (services down, no-restart policy) | UNVERIFIED |

---

## FINAL SCORECARD (0–10, brutally honest)

| Area | Score | Justification |
|---|---:|---|
| Architecture | 5 | Decomposition improving; agents un-isolated; dual-truth residue |
| Security | 2 | Default-public signing key defeats approval/scope integrity; argument injection |
| Reliability | 3 | Silent excepts, unclean async teardown, chaos UNVERIFIED |
| Scalability | 3 | UNVERIFIED; in-process agents + fire-and-forget tasks bound headroom |
| Observability | 4 | Structlog/otel present (otel default off); failures swallowed |
| Maintainability | 3 | 165 root md, 35 scratch mutators, `-`/`nul` files, broken migration |
| Code Quality | 4 | Real logic exists, but mocks/sim flags + dead code + 36 silent catches |
| Discovery | 2 | recon-mcp suspect_mock; pipeline UNVERIFIED |
| Finding Quality | 1 | Fabricates findings by default and doesn't filter them |
| Dashboard | 3 | UNVERIFIED; upstream data-source integrity compromised |
| Reporting | 2 | Certificate theater; reports can carry simulated data |
| Runtime Stability | 3 | Partial infra; API/Neo4j down; teardown errors |
| Production Readiness | 2 | Not deployable: P0-01/02/03 + broken tests |
| Developer Experience | 3 | Script-driven edits, disk-full data loss, false-green tests |
| **Overall Product** | **2.5** | Real scaffolding, but default fabrication + cosmetic safety + unverifiable runtime |

---

## Stabilization Roadmap (do in order; nothing ships before #4)

1. **Kill default fabrication (P0-01/02, P1-06):** default `mock_llm=False` and `bug_bounty_simulation=False`; corpus rejects/quarantines `provenance=simulated`; startup banner + report watermark when sim is on.
2. **Make safety real (P0-03, P1-07):** define `audit_secret_key` as a required `SecretStr`, fail closed in prod, single bytes accessor, remove the constant.
3. **Prove or pull the MCPs (P0-04):** hard `suspect_mock` startup gate + CI input-dependence test for recon-mcp (and the rest).
4. **Unbreak the suite (P1-05, P2-14):** fix/remove the migrated agents; CI gate on `pytest --collect-only` and on coverage.
5. **Then:** silent-except sweep (P1-08), Go arg-allowlisting (P1-09), agent isolation (P1-10), repo hygiene (P2-12/13), and a **real infra-up E2E + chaos run** to convert the UNVERIFIED rows to evidence.

---

## What remains UNVERIFIED (and how to verify)

Bring up Neo4j + the API (with your confirmation), set `mock_llm=False`, run a real engagement against an authorized target, and capture: recon output diffs across targets, vuln findings with non-simulated provenance, an approval gate exercised end-to-end, a forced Redis/Neo4j/Postgres restart with recovery, and a generated report cross-checked against the three stores. Until then, treat discovery, findings, dashboard, reporting, recovery, and chaos as **claims, not capabilities**.

*Prepared adversarially. Where I could not prove it, I did not pass it.*
