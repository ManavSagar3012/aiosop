# Feature Matrix (FEATURE_MATRIX.md)

This matrix maps out the functional components of the AI-OSOP platform, detailing their implementation state and verification criteria based on live test coverage.

| Feature Area | Component | Status | Verification Reference | Notes |
|---|---|---|---|---|
| **API Gateway** | REST Router Framework | VERIFIED | `tests/test_api_v2.py` | Complete FastAPI routes separation. |
| | Prometheus Metrics | VERIFIED | `tests/test_api_v2.py::test_metrics_endpoint` | Renders `ai_osop_active_agent_count`, request latency. |
| | WebSocket Stream | VERIFIED | `tests/test_api_v2.py::test_websocket_endpoint` | Enables real-time task update notifications. |
| **Orchestrator** | Task Scheduler | VERIFIED | `tests/test_orchestrator.py` | Assigns tasks via priorities (1-10) using Redis sets. |
| | Phase Transitions | VERIFIED | `tests/test_phase_autoadvance.py` | Strictly follows valid phase sequences. |
| | Approval Coordinator | VERIFIED | `tests/test_approval_workflow.py` | Parks tasks in `awaiting_approval` state for operator gates. |
| | Durable Recovery | VERIFIED | `tests/test_orchestrator_durable.py` | Re-queues running tasks after system restarts. |
| **Agent Swarms** | BaseAgent Worker | VERIFIED | `tests/test_agent_lifecycle.py` | Enforces heartbeat flushes and teardown loops. |
| | Recon Agent | VERIFIED | `tests/test_local_mcp_adapters.py` | Dispatches subdomains mapping over MCP. |
| | Vuln Agent | VERIFIED | `tests/test_local_mcp_adapters.py` | Identifies endpoints using templates. |
| | Exploit Agent | VERIFIED | `tests/test_exploit_agent.py` | Requires explicit operator approvals for payloads. |
| | CodeQL Agent | VERIFIED | `tests/test_codeql_agent.py` | Ingests static analysis SARIF dictionaries to attack graphs. |
| | GraphQL Agent | VERIFIED | `tests/test_graphql_agent.py` | Performs schema introspection and auth validation. |
| | JS Analyzer Agent | VERIFIED | `tests/test_js_analyzer_agent.py` | Extracts hardcoded secrets and API paths. |
| | Mobile Agent | VERIFIED | `tests/test_mobile_agent.py` | Scans deep links and intercepts mobile proxy traffic. |
| | NextJS Agent | VERIFIED | `tests/test_nextjs_agent.py` | Evaluates server actions and middleware parameters. |
| | Stateful Logic Agent | VERIFIED | `tests/test_stateful_logic_agent.py` | Detects process sequence invariant violations. |
| | Visual Agent | VERIFIED | `tests/test_visual_agent.py` | Mocks screenshot analysis via multimodal LLMs. |
| **Memory Layers** | Redis Hot Store | VERIFIED | `tests/test_reliability_startup_redis.py` | Manages fast heartbeats and list buffers. |
| | Postgres Store | VERIFIED | `tests/test_production_ops.py` | Relational database schemas and VectorMemory. |
| | Neo4j Graph Memory | VERIFIED | `tests/test_local_mcp_adapters.py` | Creates attack paths via cypher constructs. |
| **Safety & Policy** | Scope Enforcer | VERIFIED | `tests/test_scope.py` | Excludes out-of-scope targets and network domains. |
| | sandbox-runtime | VERIFIED | `tests/test_scope.py` | Isolates tool binaries using seccomp-filtered Docker subnets. |
| | eBPF Network Policies | VERIFIED | `tests/test_ebpf_filter.py` | Builds Cilium policy templates and Tetragon tracers. |
| | Prompt Injection Guard | VERIFIED | `tests/test_prompt_defense.py` | Sanitizes instructions overrides and control characters. |
| **Reliability** | Exponential Backoff | VERIFIED | `tests/test_reliability.py` | Retries connections with backoff decorators. |
| | Dead Letter Queue | VERIFIED | `tests/test_reliability.py` | Enqueues and requeues exhausted task items. |
| | Circuit Breaker | VERIFIED | `tests/test_reliability_mcp_circuit_breaker.py` | Triages failed MCP calls into fallback states. |
| **Auth & Security** | Differential Auth | VERIFIED | `tests/test_diff_auth_engine.py` | Detects IDOR vectors using anonymous logic comparisons. |
| | Session Client | VERIFIED | `tests/test_diff_auth.py` | Simulates HTTPX browser session state and cookie storage. |
| | JWT / Token verify | VERIFIED | `tests/test_api_v2.py` | Validates token bearer claims and signature checks. |
