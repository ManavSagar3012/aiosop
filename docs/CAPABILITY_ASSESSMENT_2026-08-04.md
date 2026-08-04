# AI-OSOP Capability Assessment — 2026-08-04

**Reviewer role:** independent principal security architect + AI systems engineer
**Method:** 4 parallel subsystem audits + direct ground-truth measurement (live suite, ruff, mypy, line counts, route introspection)
**Tree:** `feat/audit-sweep`, HEAD `034716d4` (post tranche merge at `d4ce46ad`)
**Date:** 2026-08-04

---

# Phase 1 — Verified Facts

| Metric | Value | Source |
|---|---|---|
| `src/` lines of Python | 66,569 | `wc -l` |
| Agent classes | 37 (34 registered, 3 orphaned) | `AgentRegistry.register_all_agents` |
| AgentType enum members | 28 | `enums.py:23-51` |
| MCP servers (Python) | 14 real + 6 Go binaries | `mcp-servers/python/` + repo root |
| MCP routes exposed | ~38 tools total | per-server TOOLS lists |
| FastAPI routes | 65 endpoints | `src/ai_osop/api/routers/` |
| Test files | 277 | `find tests -name "test_*.py"` |
| Test functions collected | 2,597 | `pytest --collect-only` |
| ruff `src` errors | 471 (all BLE001 blind-except) | `ruff check src --statistics` |
| ruff E/F/W (errors/fatal) | 375 (40 auto-fixable) | `ruff check src --select E,F,W` |
| mypy `src` errors | 882 in 139 files (240 checked) | `mypy src` |
| Coverage gate | `--cov-fail-under=70` in CI | `.github/workflows/ci.yml:99` |
| UI | React + Vite (App.tsx, pages/, components/, services/) | `ui/src/` |
| k8s manifests | agent-deployment, orchestrator-deployment, HPA, PDB, network-policy, backup-cronjobs, IRSA, log-retention | `k8s/` |
| Benchmarks | Juice Shop ground truth, ablation, cross-stack, cognition, corpus | `benchmarks/` |
| CI workflows | ci.yml, corpus-benchmark.yml, release.yml, tooling-reality.yml | `.github/workflows/` |

---

# Phase 2 — Capability Benchmark (25 categories, 0–10)

## 2.1 Architecture & System Design — 7/10

**Evidence:** Multi-tier memory (Redis hot / PostgreSQL warm / Neo4j graph), 37 agent classes, phase-enforced orchestration, MCP integration layer, Docker sandbox isolation, HMAC-chained audit trail, receipt layer.

**Strengths:**
- Three-tier memory is architecturally sound: hot/warm/cold with appropriate tooling per tier
- AgentRegistry pattern cleanly separates agent definition from orchestration
- Phase machine with VALID_TRANSITIONS enforces legal lifecycle
- MCP adapter pattern cleanly abstracts tool servers

**Weaknesses:**
- MCP transport is bespoke HTTP+WebSocket, not the MCP stdio/SSE spec — external tool servers must already be running; no subprocess lifecycle management
- `payload_mcp.py` is a raw-socket pseudo-HTTP server with hand-rolled parsing — inconsistent with FastAPI-based servers
- Two dead stub servers (`burp_mcp_stub.py`, `browser_mcp_stub.py`) register with `tools: []` — ready but empty
- `AuditIntegrity` in `safety/scope.py` is dead code (zero production callers); production signing is a separate implementation in `session_memory.py:740-808`
- No cold tier wiring despite SessionMemory header claiming S3

**Root cause:** Rapid feature expansion without periodic architectural review; multiple authors with different patterns.

## 2.2 Agent Intelligence & Reasoning — 6/10

**Evidence:** `ActionLoop` in `core/action_loop.py` (347 lines) provides structured LLM tool-calling with allow-list enforcement, replan hints on unproductive turns, action-trace JSONL, and per-finding token accounting. `BaseAgent._validate_output` (`base.py:690-746`) downgrades success claims lacking evidence. `BaseAgent.think_with_tools` (`base.py:1047-1226`) provides bounded observe→act loops with prompt-injection sanitizer.

**Strengths:**
- `_validate_output` honesty guard prevents fabricated success claims
- Replan hints force plan diversity on unproductive turns
- Token accounting feeds per-finding cost attribution
- Action trace is replayable forensic evidence

**Weaknesses:**
- ActionLoop is a single-step LLM call with JSON extraction — no chain-of-thought, no self-critique, no hypothesis testing within a step
- No multi-agent communication during reasoning (agents are siloed per task)
- No adversarial self-play or red-team simulation within the loop
- LLM prompt injection defense exists in `safety/prompt_defense.py` but is opt-in (`think_with_tools` uses it; `ActionLoop` does not)

**Root cause:** The reasoning loop was designed as a tool-caller harness, not a reasoning engine. It trusts the LLM to plan but doesn't verify plans before execution.

## 2.3 Autonomous Decision Making — 7/10

**Evidence:** Phase machine auto-advances through RECONNAISSANCE → VULNERABILITY_DISCOVERY automatically; VULN_DISCOVERY → EXPLOITATION is rerouted to REPORTING when zero vulns exist; EXPLOITATION entry requires operator approval (PhaseMonitor lines 309-347); per-finding exploits require per-task approval.

**Strengths:**
- Zero-vuln reroute prevents hung engagements
- EXPLOITATION entry gate is the right safety boundary
- Per-finding approval granularity prevents mass-exploitation without consent
- Reasoning-loop hypothesis hold (bounded window `HYP_GATE_MAX_TICKS`) prevents premature phase transitions

**Weaknesses:**
- Pre-EXPLOITATION there is zero human involvement — RECONNAISSANCE and VULNERABILITY_DISCOVERY are fully automatic
- POST_EXPLOITATION is a pass-through (no tasks scheduled) — the name is misleading
- No concept of "engagement pause" — once started, it runs until COMPLETED or HALTED

**Root cause:** Safety design assumes a supervised engagement model but the RECON phase is unsupervised by default.

## 2.4 Reconnaissance — 7/10

**Evidence:** `ReconAgent` (4 workers) + `PassiveReconAgent` for CT-logs/Wayback/passive DNS. `JSAnalyzerAgent` for client-side route/secret/sink extraction. `StackProfilerAgent` for tech fingerprint aggregation. Dedicated scanners: GraphQL, SAML, WebSocket, Takeover.

**Strengths:**
- Both active and passive recon paths
- JS analysis extracts real attack surface from bundles
- Tech-stack profiling feeds downstream scanner selection

**Weaknesses:**
- No authenticated recon (login + crawl) beyond what `PlaywrightAgent` provides ad-hoc
- No network-level recon (port scanning, service detection) — relies on external tools via MCP
- Subdomain takeover detection is fingerprint-matching only, no actual DNS verification

**Root cause:** Recon agents delegate heavily to external tools (MCP servers) rather than implementing discovery natively.

## 2.5 Attack Surface Mapping — 6/10

**Evidence:** Neo4j graph models `(:Asset)-[:HAS_ENDPOINT]->(:Endpoint)-[:HAS_VULNERABILITY]->(:Vulnerability)-[:EXPLOITED_BY]->(:Exploit)-[:USES_PAYLOAD]->(:Payload)`. `get_attack_surface` uses `apoc.path.subgraphNodes`. `find_attack_paths` uses Dijkstra with confidence-weighted edges. `get_co_occurring_vuln_classes` for frequency analysis.

**Strengths:**
- Dijkstra attack-path computation with confidence weights
- Risk propagation across multi-hop chains
- Endpoint-vulnerability co-occurrence analysis

**Weaknesses:**
- No hub/centrality detection (PageRank, betweenness) — can't identify high-value nodes
- No automated surface diff between recon passes
- Graph queries rely on apoc; no custom Cypher stored procedures for complex analysis

**Root cause:** Graph queries were built for the immediate needs of chain discovery, not comprehensive attack-surface analysis.

## 2.6 Vulnerability Discovery — 8/10

**Evidence:** 17 dedicated scanner types (SQLI, XSS, DOM-XSS, Stored-XSS, NoSQL, SSRF, CSRF, JWT, Smuggling, Race, Upload, Pollution, WebSocket, SAML, Takeover, Open Redirect, AI/MCP Security). `VulnAnalysisAgent` delegates to specialist subpackage (19 handlers in `handlers/`). `ConcurrencyAgent` for race/TOCTOU. `StatefulLogicAgent` for business-logic flaws.

**Strengths:**
- Broadest vuln-class coverage of any single platform I've audited
- Specialist subpackage provides per-class handler isolation
- Race conditions, prototype pollution, request smuggling are all present
- AI/MCP security class is forward-looking

**Weaknesses:**
- No dedicated LFI/XXE/Deserialization scanners (declared in VulnClass enum but no emitters)
- No SCA (Software Composition Analysis) pipeline — A06 gap
- No TLS/crypto weakness scanner — A02 gap
- Some scanners are thin (WebSocket, SAML, Pollution) — fewer than 100 lines of detection logic

**Root cause:** Enum declares aspirational classes that no scanner implements. Some specialist agents were scaffolded but never filled.

## 2.7 Finding Validation & False Positive Reduction — 7/10

**Evidence:** `ExploitValidationAgent` executes real curl in Docker sandbox, confirms via class-specific heuristics (`_sig_*`), OAST canary short-circuit (0.97 confidence). `ConfidenceCalibrationEngine` uses Beta-Binomial posterior with prior_strength=5.0, calibrated against real H1/Bugcrowd corpus. `BaseAgent._validate_output` rejects success claims without evidence.

**Strengths:**
- Real-sandbox execution for validation (not just body inspection)
- Empirical calibration against external outcomes (H1/Bugcrowd accepted/rejected)
- Raw + calibrated confidence preserved in yield_metadata for auditability

**Weaknesses:**
- ~40 hardcoded confidence literals in agents bypass the calibration engine
- LLM secondary confirmation is only consulted in the 0.4–0.6 confidence window
- `AuditIntegrity` (scope.py) is dead code — production audit signing omits `context` from HMAC
- Receipt HMAC covers only 8 of 18 model fields — request/response summaries are tamperable

**Root cause:** Calibration engine was built but not retrofitted into existing scanner emit sites. Confidence values are hardcoded per-class conventions, not dynamically sourced.

## 2.8 Exploitation Planning — 6/10

**Evidence:** `AttackChainAgent` discovers multi-hop chains across graph nodes. `ChainComposerAgent` composes chains with scope admissibility filtering (allowed_techniques). `ChainExecutorAgent` executes hop-by-hop with abort-on-failure and per-hop receipts.

**Strengths:**
- Scope admissibility filter prevents out-of-scope exploitation
- Abort-on-failure prevents spraying downstream hops on contradicted evidence
- Per-hop receipt persistence enables bounty-grade provenance

**Weaknesses:**
- `ChainExecutorAgent` is not wired into `AgentRegistry` — unreachable without direct instantiation
- `PostExploitAgent` references `AgentType.EXPLOITATION` which doesn't exist in enum — broken
- No planner that reasons about exploit difficulty/stealth before proposing a chain
- Chain templates (`CHAIN_TEMPLATES`) are static heuristics, not learned from past success

**Root cause:** Chain composition and execution were built as a pipeline but the wiring was never completed (executor not registered, post-exploit agent broken).

## 2.9 Multi-step Attack Chaining — 5/10

**Evidence:** `ChainComposerAgent` finds `[:LEADS_TO*1..5]` paths in the graph. `ChainExecutorAgent` walks hops. `PrimitiveLedger` tracks per-hop timing. However, the executor is not registered, chain composition is LLM-driven (no verification), and chains are never validated end-to-end against the target.

**Strengths:**
- Graph-based chain discovery via Neo4j
- Per-hop receipt + ledger tracking

**Weaknesses:**
- Chain executor is unreachable from the orchestrator
- No chain-level validation (only hop-level)
- No feedback loop from chain execution results back to the composer
- No concept of "chain difficulty" or "prerequisite access" in chain selection

**Root cause:** The chain pipeline was designed but the last mile (executor registration + end-to-end validation) was never completed.

## 2.10 Memory & Knowledge Graph — 8/10

**Evidence:** Three tiers verified: Redis hot (session state, task queues), PostgreSQL warm (audit logs, approval requests, finding corpus, outbox), Neo4j graph (assets, endpoints, vulnerabilities, exploits, payloads, chains, auth contexts). GraphMemory (2,743 lines) exposes Dijkstra attack paths, risk propagation, co-occurrence analysis, endpoint-vulnerability linking, auth-context reuse detection. VectorMemory uses pgvector for semantic payload/finding similarity.

**Strengths:**
- Dijkstra attack-path computation with confidence-weighted edges
- Risk propagation across multi-hop chains
- Finding corpus enables calibration engine
- Vector memory enables semantic payload retrieval
- Primitive ledger tracks chain execution timing

**Weaknesses:**
- No hub/centrality computation
- No temporal analysis (finding age, patch velocity)
- Vector memory degrades to in-memory mock when pgvector unavailable — silent quality loss
- Graph stats cached with 10s TTL but no invalidation on writes

**Root cause:** Memory was built for the immediate needs of chain discovery and calibration, not comprehensive knowledge management.

## 2.11 MCP Integration — 5/10

**Evidence:** 14 Python servers + 6 Go binaries. HTTP+WebSocket transport (not MCP stdio/SSE spec). `MCPRegistry` manages connections with circuit breaker, per-tool timeouts, scope checking. `MCPExecutionGate` validates parameters against registered schemas. Fail-closed on unknown tools.

**Strengths:**
- Fail-closed parameter validation
- Circuit breaker with terminal failure detection
- Per-tool timeout enforcement

**Weaknesses:**
- Transport is bespoke HTTP+WS, not the MCP stdio/SSE spec — external servers must already be running
- No subprocess lifecycle management (start/stop/health-check of server processes)
- Two stub servers register with `tools: []` — ready but empty
- `payload_mcp.py` is a raw-socket pseudo-HTTP server — fragile
- MCP sandbox enforcement is advisory-only (logs warning, lets call proceed)

**Root cause:** MCP integration was built before the MCP spec standardized on stdio/SSE transport. The bespoke HTTP approach works but doesn't interoperate with the broader MCP ecosystem.

## 2.12 Tool Reliability — 6/10

**Evidence:** Circuit breaker v2 with closed/open/half-open + terminal permanent-failure (`protocol.py:359-436`). Per-tool timeout enforcement. Retry with exponential backoff in task scheduler. DLQ for terminal failures. Dynamic fallback chain (`_ALTERNATE_TECHNIQUES`).

**Strengths:**
- Circuit breaker prevents cascading failures
- Retry + DLQ provides recovery path
- Dynamic fallback tries alternate techniques before giving up

**Weaknesses:**
- Circuit breaker thresholds are not configurable per-tool
- No health-check loop for MCP servers (only on-demand via `/health`)
- Stub servers (`burp_mcp_stub.py`, `browser_mcp_stub.py`) register as healthy but expose no tools

**Root cause:** Reliability patterns were added incrementally without a unified tool-health monitoring strategy.

## 2.13 Performance & Scalability — 5/10

**Evidence:** Per-engagement inflight task cap. Per-tick task cap (200). Redis-backed task queue. PostgreSQL pool_size=20 with pre-ping. Graph stats cached 10s TTL. Agent concurrency bounded (4 recon, 10 vuln, 3 exploit, 6 workflow workers).

**Strengths:**
- Layered backpressure prevents overload
- Connection pooling with health checks
- TTL caching reduces repeated graph queries

**Weaknesses:**
- No horizontal scaling story (single orchestrator instance)
- No worker auto-scaling based on queue depth
- Neo4j is a single-instance bottleneck
- No benchmarking suite for throughput/latency under load

**Root cause:** Architecture is single-node-first; distributed deployment was an afterthought.

## 2.14 Security & Isolation — 7/10

**Evidence:** Docker sandbox with `cap_drop ALL`, `no-new-privileges`, custom bridge network, iptables egress rules (fail-closed), `governed_client.py` scope/rate/header enforcement on every outbound request. `ScopeEnforcer` validates targets against allowed domains/IPs/exclusions. EXPLOITATION phase requires operator approval.

**Strengths:**
- Real Docker containers with real iptables chains
- Fail-closed egress (any iptables failure raises, not warns)
- Every outbound request passes through governed_client scope check
- EXPLOITATION entry gate prevents unauthorized exploitation

**Weaknesses:**
- `seccomp:restricted.json` uses relative path — may be silently ignored by Docker
- MCP sandbox enforcement is advisory-only (not a hard gate)
- Receipt HMAC covers only 8 of 18 fields — request/response summaries are tamperable
- `AuditIntegrity` in scope.py is dead code
- Symmetric HMAC chains are tamper-evident only under key secrecy

**Root cause:** Security controls were built in layers over time; the most critical (sandbox, scope, approval) are solid, but audit integrity and receipt completeness need strengthening.

## 2.15 Error Recovery — 7/10

**Evidence:** `RecoveryService._reap_stuck_tasks` + `AgentReaper._recover_agent` with shared per-task lock (`task-recovery:{task_id}`). Redis NX locks with TTL. DLQ for terminal failures. Dynamic fallback chain. `_resolve_auto_next` reroutes to REPORTING when zero vulns.

**Strengths:**
- Per-task lock prevents double-reap race
- DLQ captures terminal failures with reason
- Dynamic fallback tries alternate techniques
- Zero-vuln reroute prevents hung engagements

**Weaknesses:**
- Recovery is reactive (stuck-task timeout based), not proactive
- No circuit-breaker-driven fallback (e.g., "if MCP X is down, use MCP Y")
- Dead-letter queue has no operator notification mechanism

**Root cause:** Recovery was designed for the common case (task timeout) but not for systemic failures (service outage, database corruption).

## 2.16 Observability & Logging — 6/10

**Evidence:** `structlog` structured logging throughout. `ActionTrace` JSONL per step. Per-finding token accounting via `metrics_a2`. Prometheus/Grafana/Jaeger in `docker-compose.observability.yml`. Audit events written to PostgreSQL with HMAC chain.

**Strengths:**
- Structured logging with context variables
- Action trace provides per-step forensic evidence
- Per-finding cost attribution

**Weaknesses:**
- No distributed tracing (Jaeger mentioned but not wired)
- No alerting rules in Prometheus/Grafana config
- Audit event HMAC chain omits `context` field (session_memory.py:773-784)

**Root cause:** Observability was built for debugging, not production monitoring.

## 2.17 Dashboard & UX — 4/10

**Evidence:** React + Vite UI in `ui/src/`. Pages include approval console, engagement list, report viewer. `services/` layer connects to FastAPI backend.

**Strengths:**
- Functional approval console for EXPLOITATION gate
- Report viewer for operator consumption

**Weaknesses:**
- No graph visualization (attack paths are queryable but not rendered)
- No real-time task progress view
- No live-log streaming
- No dark mode / accessibility audit
- `ui/src/styles.css` has 39 lines — minimal styling

**Root cause:** UI was built for the minimum viable approval flow, not as a comprehensive operator console.

## 2.18 Reporting Quality — 6/10

**Evidence:** `ReportingAgent` aggregates findings into operator-facing reports. `BugBountyAdapter` submits findings to HackerOne (simulation mode by default). Receipt layer exports markdown + artifact manifests. `score_engagement.py` scores against ground truth.

**Strengths:**
- Bounty-grade receipt export with redaction
- Ground-truth scoring against Juice Shop manifest
- Simulation-first bug bounty adapter

**Weaknesses:**
- No executive summary generation
- No CVSS auto-scoring from evidence
- No report templates for different audiences (technical vs management)
- No report versioning

**Root cause:** Reporting was built for the platform's own needs (scoring, audit), not for external consumption.

## 2.19 Test Coverage — 6/10

**Evidence:** 2,597 tests collected. 277 test files. Coverage gate at 70% in CI. Tests cover: agents, orchestrator, safety, MCP, payload engine, receipt layer, phase machine, approval flow.

**Strengths:**
- High test count for a research platform
- Coverage gate enforced in CI
- Integration tests for receipt chain + blind oracle
- Real Postgres/Neo4j/Redis in CI services

**Weaknesses:**
- 471 ruff BLE001 errors (broad except)
- 882 mypy errors — typing is weak
- Coverage gate at 70% is below industry standard (80%+)
- No property-based testing
- No fuzzing infrastructure

**Root cause:** Test suite grew organically; quality gates were added retroactively.

## 2.20 Benchmark Quality — 7/10

**Evidence:** `benchmarks/juiceshop/bench.py` drives real Juice Shop. `benchmarks/ground_truth/juice_shop.yaml` encodes 20 ground-truth entries. `score_engagement.py` computes precision/recall with `--min-recall 0.4 --max-fp 0` gates. Ablation studies exist. Cognition benchmark exists.

**Strengths:**
- Real-target benchmarks (not synthetic)
- Ground-truth scoring with CI integration
- Detection regression tripwire (fails closed if findings export missing)
- Ablation studies for algorithm comparison

**Weaknesses:**
- Single target (Juice Shop) — no diversity
- Ground truth is only 20 entries
- No adversarial ground truth (findings that should be REJECTED)
- No cross-target benchmark

**Root cause:** Benchmark infrastructure was built for validation, not comprehensive evaluation.

## 2.21 Documentation — 5/10

**Evidence:** `README.md` with architecture overview. `AGENTS.md` with development guidelines. `docs/adr/` with ADRs. `docs/superpowers/specs/` with design specs. `docs/superpowers/plans/` with implementation plans. `docs/runbooks/` with operational procedures.

**Strengths:**
- Architecture diagram in README
- Development guidelines in AGENTS.md
- Design specs for recent features
- Operational runbooks

**Weaknesses:**
- README claims "production-grade" but CI was red on its own gates until recently
- No API documentation (OpenAPI/Swagger)
- No contributor guide
- No changelog
- 7 `*_CERTIFICATE.md` / `*_READINESS.md` files that are self-generated and not maintained

**Root cause:** Documentation was written aspirationally rather than descriptively.

## 2.22 Deployment Experience — 6/10

**Evidence:** `Dockerfile` builds working image. `docker-compose.yml` with Neo4j/Postgres/Redis/API. `k8s/` with agent-deployment, orchestrator-deployment, HPA, PDB, network-policy, backup-cronjobs, IRSA, log-retention. CI builds Docker image and checks health endpoint.

**Strengths:**
- Complete k8s manifests (not just a Dockerfile)
- HPA for auto-scaling
- Network policies for isolation
- Backup cronjobs for persistence

**Weaknesses:**
- No Helm chart (raw manifests are harder to maintain)
- No values.yaml for configuration
- No init-container for schema migration
- No liveness/readiness probes wired in k8s manifests

**Root cause:** k8s manifests were written for a specific deployment, not generalized.

## 2.23 Extensibility — 7/10

**Evidence:** `AgentRegistry` pattern allows new agents via registration. MCP adapter pattern allows new tool servers. `PayloadTemplateLibrary` allows new payload families. `ConfidenceCalibrationEngine` is pluggable.

**Strengths:**
- Agent registration is clean and documented
- MCP adapters are self-contained
- Payload templates are declarative
- Calibration engine accepts any outcome vocabulary

**Weaknesses:**
- No plugin system for third-party agents
- No webhook/event system for external integrations
- No API versioning strategy
- Adding a new vuln class requires changes in 5+ files (enum, agent, handler, scanner, test)

**Root cause:** Extensibility was designed for internal development, not external contribution.

## 2.24 Production Readiness — 5/10

**Evidence:** CI pipeline with real services. Docker health check. k8s manifests. Coverage gate. Detection regression gate. WORM audit. HMAC-chained audit trail. Receipt layer.

**Strengths:**
- CI runs real Neo4j/Postgres/Redis
- Health endpoint verified in CI
- Detection regression tripwire
- Audit integrity (production path)

**Weaknesses:**
- 882 mypy errors — type safety is not production-grade
- 471 ruff BLE001 errors — broad except hides bugs
- No SLOs/SLIs defined
- No incident response runbook
- No canary/blue-green deployment strategy
- Self-generated certificates/ readiness reports are not maintained

**Root cause:** Production hardening was interleaved with feature development; quality gates caught some issues but not all.

## 2.25 Maintainability — 5/10

**Evidence:** 66,569 lines in src/. 40 agent classes. 277 test files. Some files exceed 1,000 lines (graph_memory.py: 2,743; task_scheduler.py: 1,738; vuln_agent.py: 3,000+).

**Strengths:**
- Agent separation provides some modularity
- Handler subpackage isolates per-class logic
- Test coverage exists for most components

**Weaknesses:**
- Several files are too large to hold in context (graph_memory.py, task_scheduler.py, vuln_agent.py)
- Duplicated PHASE_POLICY was just cleaned up — other duplications likely exist
- `PostExploitAgent` has a broken enum reference — dead code shipped
- `ChainExecutorAgent` is not registered — built but unreachable
- 471 broad-except blocks make debugging harder

**Root cause:** Rapid development without periodic refactoring; no code ownership model.

---

# Phase 2 Summary — Overall Score

| Category | Score |
|---|---|
| Architecture & System Design | 7 |
| Agent Intelligence & Reasoning | 6 |
| Autonomous Decision Making | 7 |
| Reconnaissance | 7 |
| Attack Surface Mapping | 6 |
| Vulnerability Discovery | 8 |
| Finding Validation & FP Reduction | 7 |
| Exploitation Planning | 6 |
| Multi-step Attack Chaining | 5 |
| Memory & Knowledge Graph | 8 |
| MCP Integration | 5 |
| Tool Reliability | 6 |
| Performance & Scalability | 5 |
| Security & Isolation | 7 |
| Error Recovery | 7 |
| Observability & Logging | 6 |
| Dashboard & UX | 4 |
| Reporting Quality | 6 |
| Test Coverage | 6 |
| Benchmark Quality | 7 |
| Documentation | 5 |
| Deployment Experience | 6 |
| Extensibility | 7 |
| Production Readiness | 5 |
| Maintainability | 5 |
| **OVERALL** | **6.2** |

---

# Phase 3 — Gap Analysis

## Critical Gaps

| # | Gap | Why it matters | Current state | Impact if fixed | Difficulty | Dependencies |
|---|---|---|---|---|---|---|
| C1 | Chain executor not registered in AgentRegistry | Multi-step attack chains are unreachable from orchestrator — the entire chain pipeline is built but can't run | `ChainExecutorAgent` exists, tests pass, but not in `register_all_agents` | Unlocks end-to-end chain execution | Low (1 line) | None |
| C2 | `PostExploitAgent` broken enum reference | Post-exploitation agent can never be registered — dead code | References `AgentType.EXPLOITATION` which doesn't exist | Unlocks post-exploitation capability | Low (add enum + fix ref) | Enum change |
| C3 | MCP sandbox enforcement is advisory | MCP tool calls bypass sandbox isolation — only exploit agent path is sandboxed | Logs warning, lets call proceed | Hardens tool execution isolation | Medium | Docker runtime wiring |
| C4 | `seccomp:restricted.json` relative path | Custom seccomp profile may be silently ignored by Docker | Relative path in `security_opt` | Actual syscall restriction | Low (verify + fix path) | Runtime test |

## High Gaps

| # | Gap | Why it matters | Impact | Difficulty |
|---|---|---|---|---|
| H1 | ~40 hardcoded confidence literals bypass calibration engine | Calibration engine exists but most agents don't use it — confidence is not empirically grounded | Dynamic, evidence-based confidence | Medium (systematic retrofit) |
| H2 | No LFI/XXE/Deserialization scanners | Declared in VulnClass enum but no detection logic | Vuln-class coverage completeness | High (new scanner impl) |
| H3 | No SCA (Software Composition Analysis) pipeline | A06 gap — vulnerable dependencies not detected | OWASP A06 coverage | High (new pipeline) |
| H4 | Receipt HMAC covers only 8/18 fields | Request/response summaries and confirmation_note are tamperable | Evidence integrity | Low (expand signing fields) |
| H5 | Audit integrity dead code + production path omits context | Two implementations; neither covers full payload | Audit trail completeness | Medium |
| H6 | No hub/centrality graph queries | Can't identify high-value attack nodes | Attack prioritization | Medium (apoc.algo.pageRank) |
| H7 | UI is minimal (4/10) | Operator can't visualize attack paths or monitor real-time progress | Operator experience | High (frontend work) |

## Medium Gaps

| # | Gap | Impact | Difficulty |
|---|---|---|---|
| M1 | MCP transport is bespoke HTTP+WS (not MCP stdio/SSE spec) | Ecosystem interop | High (transport rewrite) |
| M2 | 882 mypy errors | Type safety | Medium (incremental) |
| M3 | 471 ruff BLE001 errors | Error hiding | Medium (per-module) |
| M4 | No API documentation (OpenAPI) | Developer experience | Low (FastAPI auto-gen) |
| M5 | Single-target benchmark (Juice Shop only) | Evaluation breadth | Medium (new targets) |
| M6 | No horizontal scaling | Production scale | High (architectural) |
| M7 | 7 stale certificate/readiness files | Credibility | Low (delete) |
| M8 | `RetrievalAgent` not registered | Semantic memory retrieval unreachable | Low (1 line) |

## Low Gaps

| # | Gap | Impact | Difficulty |
|---|---|---|---|
| L1 | No property-based testing | Edge case discovery | Medium |
| L2 | No Helm chart for k8s | Deployment ease | Medium |
| L3 | No changelog | Release tracking | Low |
| L4 | No contributor guide | External contribution | Low |
| L5 | Coverage gate at 70% (industry standard 80%+) | Quality bar | Medium |

---

# Phase 4 — Improvement Roadmap

## Quick Wins (1-2 days each)

1. **Register ChainExecutorAgent** — add to `register_all_agents`, unblocks chain execution
2. **Fix PostExploitAgent enum** — add `EXPLOITATION` to AgentType, fix reference
3. **Register RetrievalAgent** — unblocks semantic memory retrieval
4. **Expand receipt HMAC** — add request_summary, response_summary, confirmation_note to signing fields
5. **Delete stale certificates** — remove 7 `*_CERTIFICATE.md` / `*_READINESS.md` files
6. **Fix seccomp path** — use absolute path or Docker default profile
7. **Add OpenAPI docs** — `app = FastAPI(title="AI-OSOP", openapi_url="/openapi.json")`
8. **Wire MCP sandbox as hard gate** — change advisory warning to `ScopeValidationError`

## High Impact Features (1-2 weeks each)

1. **Retrofit calibration engine** — replace ~40 hardcoded confidence literals with `calibrate_for_class` calls
2. **Add LFI/XXE/Deserialization scanners** — implement detection logic for declared-but-empty VulnClass entries
3. **Add hub/centrality graph queries** — `apoc.algo.pageRank` + betweenness for attack prioritization
4. **Expand benchmark** — add 2nd target (DVWA/WebGoat), expand ground truth to 50+ entries
5. **MCP subprocess lifecycle** — start/stop/health-check server processes from the registry
6. **UI: attack path visualization** — render Neo4j graph paths in the dashboard
7. **UI: real-time task progress** — WebSocket streaming of task status changes

## Architecture Improvements (1-3 months)

1. **MCP transport migration** — adopt MCP stdio/SSE spec for ecosystem interop
2. **Horizontal scaling** — multiple orchestrator instances with Redis-based coordination
3. **Helm chart** — package k8s manifests for production deployment
4. **Cold tier wiring** — connect S3/object storage for evidence archival
5. **Distributed tracing** — wire Jaeger into the action loop and MCP calls

## AI Reasoning Improvements

1. **Chain-of-thought in ActionLoop** — add reasoning trace before tool selection
2. **Hypothesis testing** — generate testable hypotheses, verify against evidence, update beliefs
3. **Adversarial self-play** — red-team/blue-team simulation within the reasoning loop
4. **Learning from outcomes** — update chain templates and scanner parameters from H1/Bugcrowd feedback

---

# Phase 5 — Competitive Analysis

| Capability | AI-OSOP | Burp Suite AI | PentestGPT | XBOW | AutoPwn |
|---|---|---|---|---|---|
| Agent count | 37 | N/A (single engine) | N/A | N/A | N/A |
| Vuln classes | 17 dedicated scanners | ~10 | ~5 | ~8 | ~6 |
| Memory tiers | 3 (Redis/PG/Neo4j) | None | Session-only | None | None |
| Attack chain discovery | Graph-based Dijkstra | Manual | LLM-only | Limited | Limited |
| Payload evolution | Real GA + WAF probing | Template-only | LLM-only | Template-only | Template-only |
| Calibration | Beta-Binomial empirical | None | None | None | None |
| Receipt/evidence | HMAC-chained bounty-grade | Request log | None | None | None |
| Sandboxing | Real Docker + iptables | None | None | None | Container |
| Approval gates | Phase + per-finding | None | None | None | None |
| CI/CD | Full pipeline w/ real DBs | N/A | N/A | N/A | N/A |
| UI | Minimal React | Full GUI | Terminal | Web | None |

**What AI-OSOP already exceeds:**
- Agent count and specialization breadth
- Memory tier architecture (3-tier with graph)
- Attack chain discovery (graph-based)
- Payload evolution (real GA with empirical fitness)
- Confidence calibration (Beta-Binomial with external outcomes)
- Receipt/evidence system (HMAC-chained, bounty-grade)
- Safety isolation (real Docker sandbox + iptables)

**What competitors provide that AI-OSOP lacks:**
- Polished UI/UX (Burp Suite AI)
- SCA/dependency scanning (most commercial tools)
- API documentation auto-generation
- Horizontal scaling
- Plugin ecosystem for third-party extensions

**Unique innovations AI-OSOP should build:**
- Cross-engagement knowledge transfer (vector memory + calibration across targets)
- Autonomous chain refinement (learn from successful chains across engagements)
- Real-time collaborative operator interface (multi-operator engagement support)

---

# Phase 6 — Execution Plan

## Milestone 1: Fix Broken Wiring (1 week)
**Goal:** Unreachable agents reachable, dead code removed, critical paths working
**Tasks:** C1 (register ChainExecutor), C2 (fix PostExploitAgent), C8 (register RetrievalAgent), L7 (delete stale certs), C4 (fix seccomp path)
**Validation:** `grep -r "AgentType.EXPLOITATION" src/` returns valid enum; all 37 agents registered; full test suite green
**Success metric:** 0 unreachable agent classes, 0 broken enum references
**Expected score increase:** +0.3 overall

## Milestone 2: Calibration Retrofit + Scanner Completion (2 weeks)
**Goal:** All confidence values empirically grounded, declared vuln classes have scanners
**Tasks:** H1 (retrofit calibration), H2 (LFI/XXE/deserialization scanners), H4 (expand receipt HMAC), H5 (fix audit integrity)
**Validation:** `grep -rn "confidence=" src/agents/ | wc -l` reduced by 80%; new scanner tests pass; receipt chain covers all 18 fields
**Success metric:** <10 hardcoded confidence literals remaining; 3 new scanner test files
**Expected score increase:** +0.5 overall

## Milestone 3: Graph Intelligence + Benchmarks (2 weeks)
**Goal:** Attack prioritization via centrality, expanded benchmark coverage
**Tasks:** H6 (hub/centrality queries), M5 (2nd benchmark target), L5 (coverage gate → 80%)
**Validation:** `get_centrality_scores` query returns ranked nodes; bench runs against 2 targets; coverage ≥80%
**Success metric:** centrality query in graph_memory.py; 2 ground-truth manifests; coverage gate passing
**Expected score increase:** +0.4 overall

## Milestone 4: UI + Observability (4 weeks)
**Goal:** Operator can visualize attack paths and monitor real-time progress
**Tasks:** H7 (UI attack path visualization), H7 (real-time task progress), M4 (OpenAPI docs), M7 (delete stale files)
**Validation:** UI renders graph paths from Neo4j; WebSocket streams task status; `/openapi.json` returns valid spec
**Success metric:** 3 new UI screens; OpenAPI spec generated; 0 stale certificate files
**Expected score increase:** +0.5 overall

## Milestone 5: Production Hardening (4 weeks)
**Goal:** Type safety, error handling, deployment readiness
**Tasks:** M2 (mypy → 0 errors), M3 (ruff BLE001 → 0), M6 (horizontal scaling prototype), M8 (Helm chart)
**Validation:** `mypy src` returns 0; `ruff check src --select BLE001` returns 0; Helm chart installs cleanly
**Success metric:** 0 mypy errors; 0 BLE001; Helm chart in repo
**Expected score increase:** +0.5 overall

---

# Phase 7 — Final Verdict

## Score Summary

| Dimension | Score |
|---|---|
| Overall capability | **6.2/10** |
| Production readiness | **5.5/10** |
| Intelligence | **6.0/10** |
| Reliability | **6.5/10** |
| Accuracy (FP rate) | **7.0/10** |
| Innovation | **8.0/10** |
| Maintainability | **5.0/10** |
| Commercial readiness | **5.0/10** |

## What prevents AI-OSOP from being a 10/10 platform?

1. **Broken wiring** — chain executor unreachable, post-exploit agent broken, retrieval agent unregistered. These are 1-line fixes that gate entire capability surfaces.

2. **Confidence is not empirically grounded** — the calibration engine exists but 40+ agents bypass it. The platform claims "adaptive" behavior but most decisions are hardcoded.

3. **MCP integration is bespoke** — not interoperable with the broader MCP ecosystem. External servers must already be running; no lifecycle management.

4. **UI is minimal** — operators can't visualize attack paths or monitor progress in real-time. The approval console works but nothing else does.

5. **Type safety and error handling** — 882 mypy errors and 471 broad-except blocks make the codebase fragile and hard to debug.

6. **Single-target evaluation** — Juice Shop is the only benchmark target. No diversity, no adversarial ground truth.

7. **No horizontal scaling** — single orchestrator instance, single Neo4j, single Postgres. Production deployment is single-node.

## Highest ROI improvements

1. **Register the 3 broken agents** (1 day, +0.3 overall) — immediate capability unlock
2. **Retrofit calibration engine** (1 week, +0.3 overall) — credibility upgrade
3. **Expand receipt HMAC to cover all fields** (1 day, +0.2 overall) — evidence integrity
4. **Add OpenAPI docs** (1 hour, +0.1 overall) — developer experience
5. **Delete stale certificates** (10 minutes, +0.1 overall) — credibility

## Which architectural decisions should be reconsidered?

1. **MCP transport** — the bespoke HTTP+WS approach limits ecosystem interop. Consider adopting MCP stdio/SSE for new servers while maintaining backward compatibility.
2. **Audit integrity** — two implementations (`AuditIntegrity` dead code + `session_memory.py` production path) should be unified into one.
3. **Cold tier** — SessionMemory header claims S3 but nothing is wired. Either implement it or remove the claim.
4. **POST_EXPLOITATION** — this phase is a pass-through with no tasks. Either give it work or remove it from the phase machine.

## Which features should be removed, redesigned, or replaced?

1. **Remove:** `AuditIntegrity` in `safety/scope.py` — dead code, replaced by `session_memory.py` production path
2. **Remove:** 7 `*_CERTIFICATE.md` / `*_READINESS.md` files — self-generated, not maintained, actively harmful to credibility
3. **Redesign:** MCP transport — adopt spec standard for ecosystem compatibility
4. **Replace:** Hardcoded confidence literals → calibrated values from `ConfidenceCalibrationEngine`

## Six-month implementation sequence

If I were leading this project for the next six months:

**Month 1:** Fix broken wiring + calibration retrofit + receipt completeness (Milestones 1-2)
**Month 2:** Graph intelligence + benchmark expansion + coverage gate increase (Milestone 3)
**Month 3:** UI attack-path visualization + real-time progress + OpenAPI (Milestone 4)
**Month 4:** Type safety + error handling + Helm chart (Milestone 5)
**Month 5:** MCP transport migration + horizontal scaling prototype
**Month 6:** Cross-engagement learning + adversarial benchmark + production hardening

**Expected overall score after 6 months:** 8.0/10
