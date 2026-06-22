"""AI-OSOP Prometheus metrics instrumentation.

Provides counters, histograms, and gauges for API, tasks, agents, MCPs,
graph operations, and LLM calls. Imported by api/main.py and key modules.
"""

from prometheus_client import Counter, Histogram, Gauge, Info

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

# Agent metrics
ACTIVE_AGENT_COUNT = Gauge(
    "ai_osop_active_agent_count",
    "Number of active agents",
    ["agent_type"],
)
AGENT_EXECUTION_DURATION = Histogram(
    "ai_osop_agent_execution_duration_seconds",
    "Agent execution latency",
    ["agent_type"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
)

# MCP metrics
MCP_CALL_DURATION = Histogram(
    "ai_osop_mcp_call_duration_seconds",
    "MCP call latency",
    ["server_id", "tool_name"],
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

# Graph metrics
GRAPH_QUERY_DURATION = Histogram(
    "ai_osop_graph_query_duration_seconds",
    "Neo4j query latency",
    ["query_type"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)

# LLM metrics
LLM_CALL_DURATION = Histogram(
    "ai_osop_llm_call_duration_seconds",
    "LLM call latency",
    ["model"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
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

# Dependency health (1=up, 0=down)
DEPENDENCY_UP = Gauge(
    "ai_osop_dependency_up",
    "Dependency health (1=up, 0=down)",
    ["name"],
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
