"""Prometheus observability helpers + cost tracking."""

from __future__ import annotations

from typing import Dict, Optional

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ai_osop.core.metrics import (
    ACTIVE_AGENTS,
    ACTIVE_ENGAGEMENTS,
    AGENT_SUCCESS_RATE,
    AGENT_THROUGHPUT,
    AGENT_UTILIZATION,
    APPROVALS_TOTAL,
    APPROVAL_WAIT_TIME,
    BROWSER_RUNTIME_SECONDS,
    DENIED_ACTIONS_TOTAL,
    ENGAGEMENT_COMPLETION_TIME,
    ENGAGEMENT_COST_USD,
    FAILED_TASKS,
    GRAPH_WRITE_LATENCY_SECONDS,
    LLM_CALLS_TOTAL,
    LLM_COST_USD,
    LLM_TOKENS_TOTAL,
    MCP_ERRORS_TOTAL,
    MCP_LATENCY_SECONDS,
    MCP_SUCCESS_RATE,
    OWNERSHIP_VIOLATIONS_TOTAL,
    PENDING_APPROVALS,
    POSTGRES_LATENCY_SECONDS,
    QUEUED_TASKS,
    RBAC_FAILURES_TOTAL,
    RATE_LIMIT_EVENTS,
    REDIS_LATENCY_SECONDS,
    RUNNING_TASKS,
    SANDBOX_BLOCKS_TOTAL,
    SANDBOX_RUNTIME_SECONDS,
    SCOPE_VIOLATIONS_TOTAL,
    TASKS_BY_STATUS,
    TASKS_COMPLETED_TOTAL,
    TASKS_FAILED_TOTAL,
    TASKS_TOTAL,
    TASK_COMPLETION_TIME,
    TASK_DURATION_SECONDS,
    TASK_THROUGHPUT,
)

# ============== Public API ==============
def record_task(status: str, agent_type: str, duration_seconds: float) -> None:
    """Record task completion metrics."""
    TASKS_TOTAL.labels(status=status, agent_type=agent_type).inc()
    TASK_DURATION_SECONDS.labels(agent_type=agent_type).observe(max(duration_seconds, 0.0))
    if status == "completed":
        TASKS_COMPLETED_TOTAL.labels(agent_type=agent_type).inc()
        TASK_THROUGHPUT.labels(agent_type=agent_type).inc()
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


# Sprint 6B: New recording helpers


class _EngagementMetricsState:
    """In-memory state for engagement lifecycle metrics (not for production scale)."""

    _start_times: Dict[str, float] = {}


_engagement_state = _EngagementMetricsState()


def record_engagement_started(engagement_id: str) -> None:
    """Record engagement creation and increment active gauge."""
    import time

    ACTIVE_ENGAGEMENTS.inc()
    _engagement_state._start_times[engagement_id] = time.monotonic()


def record_engagement_completed(engagement_id: str) -> None:
    """Record engagement completion, decrement active gauge, and observe duration."""
    import time

    ACTIVE_ENGAGEMENTS.dec()
    start = _engagement_state._start_times.pop(engagement_id, None)
    if start is not None:
        ENGAGEMENT_COMPLETION_TIME.observe(time.monotonic() - start)


def record_engagement_halted(engagement_id: str) -> None:
    """Record engagement halt and decrement active gauge."""
    ACTIVE_ENGAGEMENTS.dec()
    _engagement_state._start_times.pop(engagement_id, None)


def record_approval_requested(approval_id: str) -> None:
    """Record new approval request and increment pending gauge."""
    PENDING_APPROVALS.inc()


def record_approval_resolved(decision: str, wait_seconds: Optional[float] = None) -> None:
    """Record approval resolution and decrement pending gauge."""
    PENDING_APPROVALS.dec()
    APPROVALS_TOTAL.labels(decision=decision).inc()
    if wait_seconds is not None and wait_seconds >= 0:
        APPROVAL_WAIT_TIME.observe(wait_seconds)


def record_task_status_change(status: str, delta: int = 1) -> None:
    """Record task status transition for TASKS_BY_STATUS gauge."""
    # Gauges don't support delta inc; we set based on current state if we track it,
    # but for simplicity we use a counter-like approach by recording the current status.
    TASKS_BY_STATUS.labels(status=status).set(delta)


def record_agent_execution_started(agent_type: str) -> None:
    """Record agent execution start."""
    AGENT_THROUGHPUT.labels(agent_type=agent_type).inc()


def record_mcp_call(server_id: str, method: str, latency_seconds: float, success: bool) -> None:
    """Record MCP call latency and update success rate."""
    MCP_LATENCY_SECONDS.labels(server_id=server_id, method=method).observe(max(latency_seconds, 0.0))
    if success:
        MCP_SUCCESS_RATE.labels(server_id=server_id).set(1.0)
    else:
        MCP_SUCCESS_RATE.labels(server_id=server_id).set(0.0)


def record_circuit_breaker_state(server_id: str, is_open: bool) -> None:
    """Record MCP circuit breaker state (0=closed, 1=open)."""
    from ai_osop.core.metrics import MCP_CIRCUIT_BREAKER_STATE

    MCP_CIRCUIT_BREAKER_STATE.labels(server_id=server_id).set(1.0 if is_open else 0.0)


def record_rbac_failure(endpoint: str, required_role: str) -> None:
    """Record RBAC authorization failure."""
    RBAC_FAILURES_TOTAL.labels(endpoint=endpoint, required_role=required_role).inc()


def record_ownership_violation(resource_type: str) -> None:
    """Record ownership check failure."""
    OWNERSHIP_VIOLATIONS_TOTAL.labels(resource_type=resource_type).inc()


def record_scope_violation(rule: str) -> None:
    """Record out-of-scope detection."""
    SCOPE_VIOLATIONS_TOTAL.labels(rule=rule).inc()


def record_sandbox_block(block_type: str) -> None:
    """Record sandbox/eBPF block."""
    SANDBOX_BLOCKS_TOTAL.labels(block_type=block_type).inc()


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
