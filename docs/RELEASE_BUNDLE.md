# AI-OSOP Release Bundle

**Branch:** `pr-4-branch`
**Base:** `main` (HEAD at `b96f341b`)
**Generated:** 2026-08-30
**Session:** Planning Phase 5 commit groups for a staged release.

---

## Summary

This release bundle captures 5 coherent commit groups (A-E) from the `pr-4-branch` workstream. The codebase has evolved from a sparse baseline to a rich autonomous remediation system with LLM provider resilience, a findings pipeline, golden-path validation, system prompts, and a red-team agent. The `.gitignore` is dangerously thin (only `*.bundle`) -- the first action item below addresses that.

---

## .gitignore update (REQUIRED before any commit)

The current `.gitignore` contains only `*.bundle`. Everything else leaks into `git status`. The recommended minimal addition:

```
# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
.venv/
.mypy_cache/
.pytest_cache/
.ruff_cache/
.coverage

# Logs & runtime artifacts
*.log
*.err
*.out
.runlogs/
.runtime/
.audit/
.tmp_score/
tmp/

# Environment & secrets
.env
.env.backup
.env.bak.*
agent_password123
*.key
*.pem

# Build artifacts
*.exe
dist/
build/
.vite/
node_modules/

# IDE & editor
.swo
.swp

# Generated reports & evidence
reports/test-session/
dashboard_evidence/
validation-artifacts/
evidence_vault/
benchmarks/
benchmark/
certs/
reliability/
observability/
recon-screenshots/
bin/

# Phase artifacts
.phase_*
.phase_a_*
.phase_d_*
.phase_e_*

# Misc
.mimosa/
.superpowers/
.zcode/
.claude-flow/
.tmp_score/
scratch/
lab/
helm/
k8s/
postman/
migrations/
nul
```

---

## Commit Group A: Autonomy Core

**Scope:** Config, models, orchestrator pipeline, phase monitoring, engagement management, strategic planner, tool call validator, API main, session manager, and supporting tests.

### Files

| Status | File | Description |
|--------|------|-------------|
| M | `src/ai_osop/core/config.py` | Core configuration (non-LLM sections) |
| M | `src/ai_osop/core/models.py` | Data models, Pydantic schemas |
| M | `src/ai_osop/core/session_manager.py` | Session lifecycle management |
| M | `src/ai_osop/core/triager_gate.py` | Task triage gating |
| M | `src/ai_osop/orchestrator/distributed_bus.py` | Event bus for distributed agents |
| M | `src/ai_osop/orchestrator/engagement_manager.py` | Engagement lifecycle |
| M | `src/ai_osop/orchestrator/orchestrator.py` | Main orchestrator loop |
| M | `src/ai_osop/orchestrator/phase_monitor.py` | Phase state monitoring |
| M | `src/ai_osop/orchestrator/task_scheduler.py` | Task scheduling + retry |
| M | `src/ai_osop/agents/strategic_planner_agent.py` | Strategic planning agent |
| M | `src/ai_osop/safety/tool_call_validator.py` | Tool call safety validation |
| M | `src/ai_osop/api/main.py` | FastAPI app entrypoint |
| M | `src/ai_osop/api/health.py` | Health check endpoint |
| M | `src/ai_osop/api/routers/engagements.py` | Engagements CRUD router |
| M | `src/ai_osop/api/routers/dlq.py` | Dead-letter queue router |
| M | `tests/test_orchestrator.py` | Orchestrator tests |
| M | `tests/test_api_v2.py` | API v2 tests |
| ? | `src/ai_osop/orchestrator/event_pipeline.py` | Event pipeline (new) |
| ? | `src/ai_osop/safety/scope_gate.py` | Scope gate (new) |
| ? | `src/ai_osop/core/chain_engine.py` | Chain engine (new) |
| ? | `src/ai_osop/core/benchmark.py` | Benchmark utilities (new) |
| ? | `src/ai_osop/core/attack_taxonomy.py` | Attack taxonomy (new) |
| ? | `src/ai_osop/core/confidence_engine.py` | Confidence calibration (new) |
| ? | `src/ai_osop/core/exploit_engine.py` | Exploit engine (new) |
| ? | `src/ai_osop/core/impact_engine.py` | Impact assessment (new) |
| ? | `src/ai_osop/core/service_intel.py` | Service intelligence (new) |
| ? | `src/ai_osop/core/report_renderer.py` | Report renderer (new) |
| ? | `src/ai_osop/core/model_router.py` | Model router (new) |
| ? | `tests/test_scope_gate.py` | Scope gate tests |
| ? | `tests/test_strategic_planner.py` | Strategic planner tests |
| ? | `tests/test_session_manager.py` | Session manager tests |
| ? | `tests/test_benchmark.py` | Benchmark tests |
| ? | `tests/test_benchmark_ci_gate.py` | Benchmark CI gate tests |
| ? | `tests/test_outcome_sync.py` | Outcome sync tests |
| ? | `tests/test_tool_reality_gate.py` | Tool reality gate tests |
| ? | `tests/test_retry_budget_runtime.py` | Retry budget runtime tests |
| ? | `tests/test_buzz_inspired.py` | Buzz-inspired architecture tests |
| ? | `tests/test_confidence_engine.py` | Confidence engine tests |
| ? | `tests/test_exploit_engine.py` | Exploit engine tests |
| ? | `tests/test_model_router.py` | Model router tests |
| ? | `tests/test_report_renderer.py` | Report renderer tests |
| ? | `tests/test_service_intel.py` | Service intel tests |
| ? | `tests/test_js_discovery_loop.py` | JS discovery loop tests |

### Suggested commit message

```
feat(autonomy): core orchestrator, config, session manager, and safety pipeline

- Add event pipeline, scope gate, chain engine, and confidence calibration
- Extend session manager with durable lifecycle and restart recovery
- Add attack taxonomy, impact/exploit/service-intel engines
- Add model router, report renderer, benchmark utilities
- Wire strategic planner, tool call validator, and triager gate
- Add engagement CRUD, DLQ router, and health endpoint
- Cover all new modules with tests (strategic planner, session manager,
  scope gate, benchmark, confidence engine, exploit engine, etc.)
```

---

## Commit Group B: LLM Red Team

**Scope:** Red-team agent that probes LLM endpoints for safety, prompt injection, and misbehavior.

### Files

| Status | File | Description |
|--------|------|-------------|
| ? | `src/ai_osop/agents/llm_red_team_agent.py` | Red-team agent (new) |
| ? | `tests/test_llm_red_team_agent.py` | Red-team agent tests |

### Suggested commit message

```
feat(llm-red-team): add red-team agent for LLM safety probing

- Introduce llm_red_team_agent.py with prompt injection, jailbreak,
  and misbehavior detection tests
- Add comprehensive test coverage for all probe types
```

---

## Commit Group C: System Prompt

**Scope:** Agent system prompt specification, prompts module, agent base class, and documentation.

### Files

| Status | File | Description |
|--------|------|-------------|
| M | `src/ai_osop/agents/base.py` | Agent base class (system prompt wiring) |
| ? | `docs/AIOSOP_AGENT_SYSTEM_PROMPT.md` | System prompt definition (new) |
| ? | `docs/AIOSOP_AGENT_SPEC.md` | Agent specification (new) |
| ? | `src/ai_osop/agents/prompts.py` | Prompt templates module (new) |
| ? | `tests/test_agent_system_prompt.py` | System prompt tests |

### Suggested commit message

```
feat(system-prompt): agent system prompt, spec, and prompt templates

- Add AIOSOP_AGENT_SYSTEM_PROMPT.md defining the agent prompt contract
- Add AIOSOP_AGENT_SPEC.md with full agent specification
- Add prompts.py with reusable prompt templates and composition helpers
- Extend base agent class to load and apply system prompts
- Add test_agent_system_prompt.py covering prompt rendering
```

---

## Commit Group D: Golden Path + Findings Ledger

**Scope:** Golden-path target and CI gate, findings ledger, validation engine, findings corpus/knowledge/quality, vuln agent, findings router, and associated tests.

### Files

| Status | File | Description |
|--------|------|-------------|
| M | `src/ai_osop/agents/vuln_agent.py` | Vulnerability discovery agent |
| M | `src/ai_osop/api/routers/findings.py` | Findings CRUD router |
| ? | `golden_path_target.py` | Golden-path target definition (new) |
| ? | `golden_path_ci_gate.py` | Golden-path CI gate (new) |
| ? | `src/ai_osop/core/findings_ledger.py` | Findings ledger (new) |
| ? | `src/ai_osop/core/validation_engine.py` | Validation engine (new) |
| ? | `src/ai_osop/core/findings_corpus.py` | Findings corpus (new) |
| ? | `src/ai_osop/core/findings_knowledge.py` | Findings knowledge base (new) |
| ? | `src/ai_osop/core/findings_quality.py` | Findings quality scoring (new) |
| ? | `src/ai_osop/core/finding_impact.py` | Finding impact assessment (new) |
| ? | `src/ai_osop/core/finding_intelligence.py` | Finding intelligence (new) |
| ? | `tests/e2e/test_golden_path_finding.py` | Golden-path E2E test |
| ? | `tests/test_validation_engine.py` | Validation engine tests |
| ? | `tests/test_finding_impact.py` | Finding impact tests |
| ? | `tests/test_finding_intelligence.py` | Finding intelligence tests |

### Suggested commit message

```
feat(golden-path+ledger): findings pipeline, validation, and golden-path CI gate

- Add golden_path_target.py and golden_path_ci_gate.py for CI gating
- Add findings_ledger.py, findings_corpus.py, findings_knowledge.py,
  findings_quality.py for the findings pipeline
- Add finding_impact.py and finding_intelligence.py for impact/intel
- Add validation_engine.py for result validation
- Refactor vuln_agent.py for findings integration
- Extend findings router with new endpoints
- Add E2E golden-path test and validation engine tests
```

---

## Commit Group E: LLM Provider

**Scope:** LLM client with fallback chain, provider configuration in config.py, and fallback chain tests.

### Files

| Status | File | Description |
|--------|------|-------------|
| M | `src/ai_osop/core/llm_client.py` | LLM client with fallback chain |
| M | `src/ai_osop/core/config.py` | LLM provider configuration section |
| ? | `tests/test_llm_fallback_chain.py` | Fallback chain tests (new) |

### Suggested commit message

```
feat(llm-provider): resilient LLM client with fallback chain and provider config

- Refactor llm_client.py with provider fallback (Ollama -> OpenRouter -> Qwen)
- Add LLM-specific configuration section to config.py (providers, timeouts,
  retry parameters)
- Add test_llm_fallback_chain.py covering fallback scenarios
```

---

## Infra & Dependencies (no group)

These files are modified/untracked but do not fit into the 5 commit groups. They may be committed separately or as part of the groups above.

| Status | File | Notes |
|--------|------|-------|
| M | `.env.example` | Example env template |
| M | `launch_real.ps1` | Startup script |
| M | `mcp-servers/python/mcp_stub.py` | MCP stub update |
| M | `poetry.lock` | Dependency lock update |
| M | `pyproject.toml` | Project config update |
| M | `scripts/monitor_engagement.py` | Engagement monitor script |
| M | `ui/src/components/shared/NetworkHealth.tsx` | UI network health |
| M | `ui/src/hooks/useAlertService.ts` | UI alert service |
| M | `ui/src/services/network.ts` | UI network service |
| ? | `src/ai_osop/agents/service_agent.py` | Service agent (new) |
| ? | `scripts/check_ui_backend.py` | UI backend check (new) |
| ? | `scripts/monitor_qosmos.py` | QoS monitoring (new) |
| ? | `scripts/run_api_debug.sh` | API debug script (new) |
| ? | `scripts/start_stack_liveverify.ps1` | Stack live verify (new) |

---

## Security Notes

1. **`.env` contains a real API key** -- the `.env` file is untracked (`??`) and MUST NOT be committed. The `.gitignore` update above adds `.env` to the ignore list.
2. **`.env.backup` and `.env.bak.202535`** are also untracked and contain the same key -- they are covered by the `.env.backup` and `.env.bak.*` patterns in the recommended `.gitignore`.
3. **`agent_password123`** is an untracked file that should be gitignored and deleted.
4. **`k8s/secrets.yaml`** may contain secrets -- it is covered by the `k8s/` pattern in the recommended `.gitignore`.

---

## Release Order

The recommended commit order is:

1. **E** (LLM provider) -- foundational dependency for all agents
2. **A** (Autonomy core) -- core infrastructure
3. **C** (System prompt) -- agent prompt contract
4. **B** (LLM red team) -- safety testing
5. **D** (Golden path + ledger) -- validation and findings pipeline

Each group is independently reviewable and mergable, though groups A and C have a soft dependency (agents use the system prompt defined in C).