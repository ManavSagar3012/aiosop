"""Prometheus observability helpers."""

from __future__ import annotations

from typing import Dict

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

TASKS_TOTAL = Counter("ai_osop_tasks_total", "Total tasks observed", ["status", "agent_type"])
TASK_DURATION_SECONDS = Histogram(
    "ai_osop_task_duration_seconds", "Task execution duration", ["agent_type"]
)
ACTIVE_AGENTS = Gauge("ai_osop_active_agents", "Active registered agents")
RATE_LIMIT_EVENTS = Counter("ai_osop_rate_limit_events_total", "Rate limiting events", ["type"])


def record_task(status: str, agent_type: str, duration_seconds: float) -> None:
    """Record task completion metrics."""
    TASKS_TOTAL.labels(status=status, agent_type=agent_type).inc()
    TASK_DURATION_SECONDS.labels(agent_type=agent_type).observe(max(duration_seconds, 0.0))


def update_active_agents(count: int) -> None:
    """Set active agent count."""
    ACTIVE_AGENTS.set(count)


def record_rate_limiter_metrics(metrics: Dict[str, int]) -> None:
    """Record monotonically reported rate limiter counters as gauge-like events."""
    for key, value in metrics.items():
        if key.endswith("_total") or key.endswith("_events"):
            RATE_LIMIT_EVENTS.labels(type=key).inc(max(value, 0))


def render_prometheus() -> tuple[bytes, str]:
    """Return Prometheus exposition bytes and content type."""
    return generate_latest(), CONTENT_TYPE_LATEST
