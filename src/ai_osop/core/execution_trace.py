"""Execution Observatory — full lifecycle tracing for every task."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional

# Forward reference for type hint (avoid circular import at module level)
# SessionMemory is passed at call time.


class ExecutionStage(str, Enum):
    """Every observable stage in a task's lifecycle."""
    TASK_CREATED = "task_created"
    TASK_PERSISTED = "task_persisted"
    TASK_QUEUED = "task_queued"
    WORKER_LEASE_REQUESTED = "worker_lease_requested"
    WORKER_LEASE_GRANTED = "worker_lease_granted"
    WORKER_ASSIGNED = "worker_assigned"
    DEPENDENCY_INJECTION_COMPLETE = "dependency_injection_complete"
    REDIS_CONNECTED = "redis_connected"
    NEO4J_CONNECTED = "neo4j_connected"
    POSTGRES_CONNECTED = "postgres_connected"
    MCP_CONNECTED = "mcp_connected"
    MCP_CONNECT_FAILED = "mcp_connect_failed"
    PLANNER_STARTED = "planner_started"
    SCANNER_STARTED = "scanner_started"
    SCANNER_SKIPPED = "scanner_skipped"
    SCANNER_TIMED_OUT = "scanner_timed_out"
    SCANNER_FAILED = "scanner_failed"
    VERIFICATION_STARTED = "verification_started"
    PERSISTENCE_COMPLETED = "persistence_completed"
    DASHBOARD_UPDATED = "dashboard_updated"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"


class FailureCategory(str, Enum):
    """Enforced failure taxonomy. Unknown is unacceptable."""
    INFRASTRUCTURE = "infrastructure"
    QUEUE = "queue"
    WORKER = "worker"
    DEPENDENCY = "dependency"
    MCP = "mcp"
    PLANNER = "planner"
    RECON = "recon"
    PARSER = "parser"
    SCANNER = "scanner"
    VERIFICATION = "verification"
    PERSISTENCE = "persistence"
    DASHBOARD = "dashboard"
    UNKNOWN = "unknown"


class StageRecord:
    """A single lifecycle stage observation."""
    __slots__ = ("stage", "timestamp", "duration_ms", "error", "metadata")

    def __init__(
        self,
        stage: str,
        timestamp: Optional[float] = None,
        duration_ms: Optional[float] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.stage = stage
        self.timestamp = timestamp or time.monotonic()
        self.duration_ms = duration_ms
        self.error = error
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"stage": self.stage, "timestamp": self.timestamp}
        if self.duration_ms is not None:
            d["duration_ms"] = round(self.duration_ms, 2)
        if self.error:
            d["error"] = self.error
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class TaskExecutionTrace:
    """Tracks a task through every lifecycle stage."""

    def __init__(self, task_id: str, engagement_id: str):
        self.task_id = task_id
        self.engagement_id = engagement_id
        self._stages: List[StageRecord] = []
        self._start_time = time.monotonic()
        self._failure: Optional[Dict[str, Any]] = None

    def record(
        self,
        stage: str,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StageRecord:
        now = time.monotonic()
        prev = self._stages[-1].timestamp if self._stages else self._start_time
        duration_ms = (now - prev) * 1000 if self._stages else None
        rec = StageRecord(stage=stage, timestamp=now, duration_ms=duration_ms, error=error, metadata=metadata)
        self._stages.append(rec)
        return rec

    def record_failure(
        self,
        category: str,
        reason: str,
        component: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        meta: Dict[str, Any] = {"category": category, "reason": reason}
        if component:
            meta["component"] = component
        if details:
            meta["details"] = details
        self._failure = meta
        self.record(ExecutionStage.TASK_FAILED, error=reason, metadata=meta)

    @property
    def elapsed_seconds(self) -> float:
        # Once terminal, freeze at the final stage's timestamp — otherwise this
        # kept counting wall-clock since start and reported a completed 37s task
        # as 900s+ minutes later (dashboards/benchmarks/SLA all wrong).
        end = self._stages[-1].timestamp if (self._stages and self.is_complete) else time.monotonic()
        return end - self._start_time

    @property
    def is_complete(self) -> bool:
        if not self._stages:
            return False
        terminal = {ExecutionStage.TASK_COMPLETED.value, ExecutionStage.TASK_FAILED.value}
        return self._stages[-1].stage in terminal

    @property
    def stages(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._stages]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "engagement_id": self.engagement_id,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "stage_count": len(self._stages),
            "is_complete": self.is_complete,
            "stages": self.stages,
            "failure": self._failure,
        }

    def summary(self) -> str:
        stages = ", ".join(s.stage for s in self._stages[-5:])
        fail = f" FAILURE={self._failure['category']}:{self._failure['reason']}" if self._failure else ""
        return f"[{self.task_id}] {self.elapsed_seconds:.1f}s | {stages}{fail}"


_TRACE_ATTR = "_execution_trace"


def attach_trace(task: Any) -> TaskExecutionTrace:
    trace = TaskExecutionTrace(task_id=task.id, engagement_id=task.engagement_id)
    setattr(task, _TRACE_ATTR, trace)
    trace.record(ExecutionStage.TASK_CREATED, metadata={"task_type": task.type, "agent_type": str(task.agent_type)})
    return trace


def get_trace(task: Any) -> Optional[TaskExecutionTrace]:
    return getattr(task, _TRACE_ATTR, None)


def record_stage(task: Any, stage: str, error: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> None:
    trace = get_trace(task)
    if trace is not None:
        trace.record(stage, error=error, metadata=metadata)


def record_failure(task: Any, category: str, reason: str, component: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
    trace = get_trace(task)
    if trace is not None:
        trace.record_failure(category=category, reason=reason, component=component, details=details)


# ── Persistence helpers (store/load traces via Redis) ────────────────────────


async def store_trace_to_redis(session_memory: Any, trace: TaskExecutionTrace, ttl: int = 86400) -> None:
    """Persist an execution trace to Redis so it survives process restarts.

    The trace is stored as JSON under the key ``trace:<task_id>`` with a default
    TTL of 24 hours. Best-effort: never raises.
    """
    try:
        await session_memory.store_hot(f"trace:{trace.task_id}", trace.to_dict(), ttl=ttl)
    except Exception:  # noqa: BLE001 - persistence is advisory
        pass


async def load_trace_from_redis(session_memory: Any, task_id: str) -> Optional[Dict[str, Any]]:
    """Load a serialised execution trace from Redis by task ID.

    Returns the trace dict (or None if not found / expired). The caller can
    reconstruct a ``TaskExecutionTrace`` from the dict if needed.
    """
    try:
        return await session_memory.retrieve_hot(f"trace:{task_id}")
    except Exception:  # noqa: BLE001 - lookup is advisory
        return None
