"""AI-OSOP Prometheus metrics instrumentation.

Provides counters, histograms, and gauges for API, tasks, agents, MCPs,
graph operations, and LLM calls. Imported by api/main.py and key modules.
"""

from prometheus_client import REGISTRY, Counter, Gauge, Histogram, Info

# Clean up any previously registered metrics starting with 'ai_osop_' to allow clean reloading
for collector in list(REGISTRY._collector_to_names.keys()):
    names = REGISTRY._collector_to_names[collector]
    if any(name.startswith("ai_osop_") for name in names):
        try:
            REGISTRY.unregister(collector)
        except KeyError:
            pass
# API metrics
REQUESTS_TOTAL = Counter(
    "ai_osop_requests_total",
    "Total API requests",
    ["method", "path", "status_code"],
)
REQUEST_DURATION = Histogram(
    "ai_osop_request_duration_seconds",
    "API request latency",
    ["method", "path"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)
ERRORS_TOTAL = Counter(
    "ai_osop_errors_total",
    "Total API errors",
    ["status_code", "path"],
)

# Engagement & task metrics
ACTIVE_ENGAGEMENTS = Gauge(
    "ai_osop_active_engagements",
    "Number of active engagements",
)
PENDING_APPROVALS = Gauge(
    "ai_osop_pending_approvals",
    "Number of pending approval requests",
)
TASKS_BY_STATUS = Gauge(
    "ai_osop_tasks_by_status",
    "Tasks grouped by status",
    ["status"],
)
TASK_SCHEDULE_DURATION = Histogram(
    "ai_osop_task_schedule_duration_seconds",
    "Task scheduling latency",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
TASKS_TOTAL = Counter(
    "ai_osop_tasks_total",
    "Total tasks",
    ["status", "agent_type"],
)
TASKS_COMPLETED_TOTAL = Counter(
    "ai_osop_tasks_completed_total",
    "Total completed tasks",
    ["agent_type"],
)
TASKS_FAILED_TOTAL = Counter(
    "ai_osop_tasks_failed_total",
    "Total failed tasks",
    ["agent_type"],
)
TASK_DURATION_SECONDS = Histogram(
    "ai_osop_task_duration_seconds",
    "Task execution duration",
    ["agent_type"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0],
)
TASK_THROUGHPUT = Counter(
    "ai_osop_task_throughput_total",
    "Tasks completed per unit time",
    ["agent_type"],
)
TASK_COMPLETION_TIME = Histogram(
    "ai_osop_task_completion_time_seconds",
    "End-to-end task duration (schedule → complete)",
    ["agent_type", "task_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)
QUEUED_TASKS = Gauge(
    "ai_osop_queued_tasks",
    "Number of queued tasks",
)
RUNNING_TASKS = Gauge(
    "ai_osop_running_tasks",
    "Number of running tasks",
)
FAILED_TASKS = Gauge(
    "ai_osop_failed_tasks",
    "Number of failed tasks",
)

# Agent metrics
# AIOSOP-METRIC-001 (2026-07-02): This gauge was declared with an ["agent_type"]
# label, but every call site (api.deps.update_active_agents and
# core.observability.update_active_agents) sets a bare total via .set(count) with
# no .labels(...). A labeled Prometheus metric raises
# ValueError('gauge metric is missing label values') on any unlabeled .set(), so
# this gauge never populated and every GET /agents returned 500 (the handler calls
# update_active_agents(len(agents))). No caller differentiates by agent_type for
# this metric, so the label was dead. Unlabeled matches the total-count semantics
# its name implies and its callers actually use.
ACTIVE_AGENTS = ACTIVE_AGENT_COUNT = Gauge(
    "ai_osop_active_agent_count",
    "Number of active agents",
)
AGENT_EXECUTION_DURATION = Histogram(
    "ai_osop_agent_execution_duration_seconds",
    "Agent execution latency",
    ["agent_type"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)
AGENT_UTILIZATION = Gauge(
    "ai_osop_agent_utilization",
    "Agent utilization ratio (0.0-1.0)",
    ["agent_type"],
)
AGENT_THROUGHPUT = Counter(
    "ai_osop_agent_throughput_total",
    "Agent executions per unit time",
    ["agent_type"],
)
AGENT_SUCCESS_RATE = Gauge(
    "ai_osop_agent_success_rate",
    "Agent success ratio (completed / total)",
    ["agent_type"],
)

# MCP metrics
MCP_CALL_DURATION = Histogram(
    "ai_osop_mcp_call_duration_seconds",
    "MCP call latency",
    ["server_id", "tool_name"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)
MCP_LATENCY_SECONDS = Histogram(
    "ai_osop_mcp_latency_seconds",
    "MCP call latency (legacy alias)",
    ["server_id", "method"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)
MCP_CIRCUIT_BREAKER_STATE = Gauge(
    "ai_osop_mcp_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open)",
    ["server_id"],
)
MCP_ERRORS_TOTAL = Counter(
    "ai_osop_mcp_errors_total",
    "Total MCP errors",
    ["server_id", "error_type"],
)
MCP_SUCCESS_RATE = Gauge(
    "ai_osop_mcp_success_rate",
    "MCP success ratio (success / total)",
    ["server_id"],
)

# Graph metrics
GRAPH_QUERY_DURATION = Histogram(
    "ai_osop_graph_query_duration_seconds",
    "Neo4j query latency",
    ["query_type"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)
GRAPH_WRITE_LATENCY_SECONDS = Histogram(
    "ai_osop_graph_write_latency_seconds",
    "Neo4j write latency",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# Redis / Postgres / Session metrics
REDIS_LATENCY_SECONDS = Histogram(
    "ai_osop_redis_latency_seconds",
    "Redis operation latency",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
POSTGRES_LATENCY_SECONDS = Histogram(
    "ai_osop_postgres_latency_seconds",
    "Postgres query latency",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# LLM metrics
LLM_CALL_DURATION = Histogram(
    "ai_osop_llm_call_duration_seconds",
    "LLM call latency",
    ["model"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)
LLM_CALLS_TOTAL = Counter(
    "ai_osop_llm_calls_total",
    "Total LLM calls",
    ["model", "operation"],
)
LLM_TOKENS_TOTAL = Counter(
    "ai_osop_llm_tokens_total",
    "Total LLM tokens",
    ["model", "type"],
)
LLM_COST_USD = Counter(
    "ai_osop_llm_cost_usd",
    "Total LLM cost in USD",
    ["model"],
)

# Engagement metrics
ENGAGEMENT_COMPLETION_TIME = Histogram(
    "ai_osop_engagement_completion_time_seconds",
    "Engagement duration (create → complete)",
    buckets=[60.0, 300.0, 600.0, 1800.0, 3600.0, 7200.0, 14400.0, 28800.0, 86400.0],
)
ENGAGEMENT_COST_USD = Counter(
    "ai_osop_engagement_cost_usd",
    "Total engagement cost in USD",
    ["engagement_id"],
)
APPROVAL_WAIT_TIME = Histogram(
    "ai_osop_approval_wait_time_seconds",
    "Time from approval request to resolution",
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0],
)
APPROVALS_TOTAL = Counter(
    "ai_osop_approvals_total",
    "Total approval decisions",
    ["decision"],
)

# Browser / Sandbox metrics
BROWSER_RUNTIME_SECONDS = Histogram(
    "ai_osop_browser_runtime_seconds",
    "Browser automation runtime",
    ["task_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)
SANDBOX_RUNTIME_SECONDS = Histogram(
    "ai_osop_sandbox_runtime_seconds",
    "Sandbox execution runtime",
    ["task_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)

# Security & Operations metrics
DENIED_ACTIONS_TOTAL = Counter(
    "ai_osop_denied_actions_total",
    "Blocked actions by approval gate",
    ["action_type"],
)
RBAC_FAILURES_TOTAL = Counter(
    "ai_osop_rbac_failures_total",
    "RBAC authorization rejections",
    ["endpoint", "required_role"],
)
OWNERSHIP_VIOLATIONS_TOTAL = Counter(
    "ai_osop_ownership_violations_total",
    "Ownership check failures",
    ["resource_type"],
)
SANDBOX_BLOCKS_TOTAL = Counter(
    "ai_osop_sandbox_blocks_total",
    "Sandbox/eBPF blocks",
    ["block_type"],
)
SCOPE_VIOLATIONS_TOTAL = Counter(
    "ai_osop_scope_violations_total",
    "Out-of-scope detections",
    ["rule"],
)
RATE_LIMIT_EVENTS = Counter(
    "ai_osop_rate_limit_events",
    "Rate limiter events",
    ["type"],
)

# Dependency health (1=up, 0=down)
DEPENDENCY_UP = Gauge(
    "ai_osop_dependency_up",
    "Dependency health (1=up, 0=down)",
    ["name"],
)

# Neo4j connection pool metrics
NEO4J_POOL_IN_USE = Gauge(
    "ai_osop_neo4j_pool_in_use_connections",
    "Neo4j connection pool — connections currently in use",
)
NEO4J_POOL_TOTAL = Gauge(
    "ai_osop_neo4j_pool_total_connections",
    "Neo4j connection pool — total connections (in_use + idle)",
)
NEO4J_POOL_CLOSED = Gauge(
    "ai_osop_neo4j_pool_closed",
    "Neo4j connection pool — 1 if closed, 0 if open",
)
NEO4J_POOL_READY = Gauge(
    "ai_osop_neo4j_pool_ready",
    "Neo4j connection pool — driver initialized and connected (1=ready, 0=not_ready)",
)

# Trace export
TRACE_SPANS_EXPORTED = Counter(
    "ai_osop_trace_spans_exported_total",
    "OTel spans successfully exported",
    ["exporter"],
)
TRACE_SPANS_FAILED = Counter(
    "ai_osop_trace_spans_failed_total",
    "OTel span export failures",
    ["exporter"],
)

# Readiness metric (1=ready, 0=not_ready, 0.5=degraded)
READY_STATUS = Gauge(
    "ai_osop_ready_status",
    "Pod readiness status: 1=ready, 0=not_ready, 0.5=degraded",
)

# Build info
BUILD_INFO = Info(
    "ai_osop_build_info",
    "AI-OSOP build information",
)

# SLO / Availability metrics
SLO_AVAILABILITY = Gauge(
    "ai_osop_slo_availability_ratio",
    "Rolling availability SLO (0.0-1.0)",
    ["window"],
)
SLO_ERROR_BUDGET = Gauge(
    "ai_osop_slo_error_budget_remaining",
    "Remaining error budget (0.0-1.0, 0 = exhausted)",
    ["slo_name"],
)
SLO_LATENCY_P99 = Gauge(
    "ai_osop_slo_latency_p99_seconds",
    "p99 latency per route",
    ["path"],
)
SLO_LATENCY_P95 = Gauge(
    "ai_osop_slo_latency_p95_seconds",
    "p95 latency per route",
    ["path"],
)

from prometheus_client import Counter

AGENT_RECOVERIES_TOTAL = Counter("ai_osop_agent_recoveries_total", "Total agent recoveries")
AGENT_TIMEOUTS_TOTAL = Counter("ai_osop_agent_timeouts_total", "Total agent timeouts")
TASK_REQUEUES_TOTAL = Counter("ai_osop_task_requeues_total", "Total task requeues")
STALE_LEASES_TOTAL = Counter("ai_osop_stale_leases_total", "Total stale task leases detected")

# Per-finding decision latency: from persisted detection timestamp to when a
# criticality decision lands. Sealing the gap between finding and triage is the
# metric bug bounty teams care about most (time-to-payout).
FINDING_DECISION_SECONDS = Histogram(
    "ai_osop_finding_decision_seconds",
    "Latency from detection until triage decision (validated/rejected/manual_review)",
    ["state"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0],
)
