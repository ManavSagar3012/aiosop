"""Prometheus observability helpers + cost tracking."""

from __future__ import annotations

from typing import Dict, Optional

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

# Task lifecycle
TASKS_TOTAL = Counter("ai_osop_tasks_total", "Total tasks observed", ["status", "agent_type"])
TASKS_COMPLETED_TOTAL = Counter("ai_osop_tasks_completed_total", "Completed tasks", ["agent_type"])
TASKS_FAILED_TOTAL = Counter("ai_osop_tasks_failed_total", "Failed tasks", ["agent_type"])
TASK_DURATION_SECONDS = Histogram(
    "ai_osop_task_duration_seconds", "Task execution duration", ["agent_type"]
)
RUNNING_TASKS = Gauge("ai_osop_running_tasks", "Currently running tasks")
QUEUED_TASKS = Gauge("ai_osop_queued_tasks", "Currently queued tasks")
FAILED_TASKS = Gauge("ai_osop_failed_tasks", "Currently failed tasks")

# Agents
ACTIVE_AGENTS = Gauge("ai_osop_active_agents", "Active registered agents")
AGENT_UTILIZATION = Gauge("ai_osop_agent_utilization", "Agent utilization ratio", ["agent_type"])

# Rate limiting
RATE_LIMIT_EVENTS = Counter("ai_osop_rate_limit_events_total", "Rate limiting events", ["type"])

# Infrastructure latency
MCP_LATENCY_SECONDS = Histogram(
    "ai_osop_mcp_latency_seconds", "MCP call latency", ["server_id", "method"]
)
GRAPH_WRITE_LATENCY_SECONDS = Histogram(
    "ai_osop_graph_write_duration_seconds", "Neo4j write latency", ["operation"]
)
REDIS_LATENCY_SECONDS = Histogram(
    "ai_osop_redis_latency_seconds", "Redis operation latency", ["operation"]
)
POSTGRES_LATENCY_SECONDS = Histogram(
    "ai_osop_postgres_latency_seconds", "Postgres query latency", ["operation"]
)

# LLM / Cost
LLM_CALLS_TOTAL = Counter("ai_osop_llm_calls_total", "LLM API calls", ["model", "operation"])
LLM_TOKENS_TOTAL = Counter("ai_osop_llm_tokens_total", "LLM tokens consumed", ["model", "type"])
LLM_COST_USD = Counter("ai_osop_llm_cost_usd_total", "Estimated LLM cost in USD", ["model"])
ENGAGEMENT_COST_USD = Counter(
    "ai_osop_engagement_cost_usd_total", "Total cost per engagement", ["engagement_id"]
)

# Browser / Sandbox
BROWSER_RUNTIME_SECONDS = Histogram(
    "ai_osop_browser_runtime_seconds", "Browser automation runtime", ["task_type"]
)
SANDBOX_RUNTIME_SECONDS = Histogram(
    "ai_osop_sandbox_runtime_seconds", "Sandbox execution runtime", ["task_type"]
)


# ============== Public API ==============

def record_task(status: str, agent_type: str, duration_seconds: float) -> None:
    """Record task completion metrics."""
    TASKS_TOTAL.labels(status=status, agent_type=agent_type).inc()
    TASK_DURATION_SECONDS.labels(agent_type=agent_type).observe(max(duration_seconds, 0.0))
    if status == "completed":
        TASKS_COMPLETED_TOTAL.labels(agent_type=agent_type).inc()
    elif status == "failed":
        TASKS_FAILED_TOTAL.labels(agent_type=agent_type).inc()


def update_task_counts(running: int, queued: int, failed: int) -> None:
    """Update task state gauges."""
    RUNNING_TASKS.set(running)
    QUEUED_TASKS.set(queued)
    FAILED_TASKS.set(failed)


def update_active_agents(count: int) -> None:
    """Set active agent count."""
    ACTIVE_AGENTS.set(count)


def update_agent_utilization(agent_type: str, utilization: float) -> None:
    """Set agent utilization ratio (0.0-1.0)."""
    AGENT_UTILIZATION.labels(agent_type=agent_type).set(max(0.0, min(1.0, utilization)))


def record_rate_limiter_metrics(metrics: Dict[str, int]) -> None:
    """Record monotonically reported rate limiter counters as gauge-like events."""
    for key, value in metrics.items():
        if key.endswith("_total") or key.endswith("_events"):
            RATE_LIMIT_EVENTS.labels(type=key).inc(max(value, 0))


def record_mcp_latency(server_id: str, method: str, latency_seconds: float) -> None:
    """Record MCP call latency."""
    MCP_LATENCY_SECONDS.labels(server_id=server_id, method=method).observe(max(latency_seconds, 0.0))


def record_graph_latency(operation: str, latency_seconds: float) -> None:
    """Record Neo4j write latency."""
    GRAPH_WRITE_LATENCY_SECONDS.labels(operation=operation).observe(max(latency_seconds, 0.0))


def record_redis_latency(operation: str, latency_seconds: float) -> None:
    """Record Redis operation latency."""
    REDIS_LATENCY_SECONDS.labels(operation=operation).observe(max(latency_seconds, 0.0))


def record_postgres_latency(operation: str, latency_seconds: float) -> None:
    """Record Postgres query latency."""
    POSTGRES_LATENCY_SECONDS.labels(operation=operation).observe(max(latency_seconds, 0.0))


def record_llm_call(model: str, operation: str, tokens_input: int = 0, tokens_output: int = 0, cost_usd: float = 0.0) -> None:
    """Record LLM usage and estimated cost."""
    LLM_CALLS_TOTAL.labels(model=model, operation=operation).inc()
    if tokens_input:
        LLM_TOKENS_TOTAL.labels(model=model, type="input").inc(tokens_input)
    if tokens_output:
        LLM_TOKENS_TOTAL.labels(model=model, type="output").inc(tokens_output)
    if cost_usd:
        LLM_COST_USD.labels(model=model).inc(cost_usd)


def record_engagement_cost(engagement_id: str, cost_usd: float) -> None:
    """Record total cost attributed to an engagement."""
    ENGAGEMENT_COST_USD.labels(engagement_id=engagement_id).inc(cost_usd)


def record_browser_runtime(task_type: str, runtime_seconds: float) -> None:
    """Record browser automation runtime."""
    BROWSER_RUNTIME_SECONDS.labels(task_type=task_type).observe(max(runtime_seconds, 0.0))


def record_sandbox_runtime(task_type: str, runtime_seconds: float) -> None:
    """Record sandbox execution runtime."""
    SANDBOX_RUNTIME_SECONDS.labels(task_type=task_type).observe(max(runtime_seconds, 0.0))


def render_prometheus() -> bytes:
    """Return Prometheus exposition bytes."""
    return generate_latest()


# ============== Cost Estimation ==============

# Approximate cost per 1K tokens (USD) — update with actual provider pricing
_COST_PER_1K: Dict[str, Dict[str, float]] = {
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
}


def estimate_cost(model: str, tokens_input: int, tokens_output: int) -> float:
    """Estimate LLM cost in USD."""
    rates = _COST_PER_1K.get(model, {"input": 0.01, "output": 0.03})
    return (tokens_input / 1000.0) * rates["input"] + (tokens_output / 1000.0) * rates["output"]
