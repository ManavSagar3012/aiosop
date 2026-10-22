"""Safe, bounded diagnostics for an individual engagement.

Audit events carry tool arguments and results that may contain secrets or
credentials. Diagnostics deliberately expose only event provenance metadata.
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from ai_osop.core.models import AuditEvent, Task


def _utc_naive(value: datetime) -> datetime:
    """Normalize aware and naive (stored UTC) timestamps for duration math."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _iso_utc(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return _utc_naive(value).isoformat() + "Z"


def _task_view(task: Task, now: datetime) -> Dict[str, Any]:
    running = task.status == "running" and task.started_at is not None
    elapsed_seconds: Optional[int] = None
    if running and task.started_at is not None:
        elapsed_seconds = max(
            0, int((_utc_naive(now) - _utc_naive(task.started_at)).total_seconds())
        )

    # Timeouts only identify a suspected stalled task; they do not alter execution.
    overdue = bool(
        running and elapsed_seconds is not None and elapsed_seconds > task.timeout_seconds
    )
    return {
        "task_id": task.id,
        "task_type": task.type,
        "agent_type": task.agent_type.value,
        "assigned_agent_id": task.assigned_agent_id,
        "status": task.status,
        "retry_count": task.retry_count,
        "max_retries": task.max_retries,
        "created_at": _iso_utc(task.created_at),
        "started_at": _iso_utc(task.started_at),
        "completed_at": _iso_utc(task.completed_at),
        "running_seconds": elapsed_seconds,
        "overdue": overdue,
    }


def _event_view(event: AuditEvent) -> Dict[str, Any]:
    """Whitelist safe fields; action/result/context may include credentials."""
    raw_task_id = event.action.get("task_id") if isinstance(event.action, dict) else None
    task_id = (
        raw_task_id
        if isinstance(raw_task_id, str)
        and raw_task_id.startswith("task-")
        and len(raw_task_id) <= 64
        else None
    )
    return {
        "event_id": event.event_id,
        "timestamp": _iso_utc(event.timestamp),
        "event_type": event.event_type,
        "severity": event.severity,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "task_id": task_id,
        "integrity_hash": event.integrity_hash,
    }


def build_engagement_diagnostics(
    engagement_id: str,
    phase: str,
    tasks: Iterable[Task],
    events: Iterable[AuditEvent],
    event_limit: int,
    audit_available: bool = True,
    now: Optional[datetime] = None,
    task_limit: int = 100,
) -> Dict[str, Any]:
    """Combine live task snapshots with a recent, persisted audit timeline.

    The task inventory is process-local and may omit completed tasks after a
    restart. Audit events are fetched from durable storage independently.
    """
    captured_at = _utc_naive(now or datetime.utcnow())
    matching_tasks = [task for task in tasks if task.engagement_id == engagement_id]
    task_views = [_task_view(task, captured_at) for task in matching_tasks]
    counts = dict(sorted(Counter(task.status for task in matching_tasks).items()))
    task_views.sort(
        key=lambda item: (
            (
                0
                if item["overdue"]
                else 1 if item["status"] in {"running", "awaiting_approval"} else 2
            ),
            item["created_at"] or "",
        )
    )
    recent_events = sorted(
        (event for event in events if event.engagement_id == engagement_id),
        key=lambda event: (_utc_naive(event.timestamp), event.event_id),
        reverse=True,
    )
    return {
        "engagement_id": engagement_id,
        "phase": phase,
        "captured_at": _iso_utc(captured_at),
        "tasks": {
            "source": "live_memory",
            "total": len(matching_tasks),
            "status_counts": counts,
            "retried": sum(task.retry_count > 0 for task in matching_tasks),
            "overdue_running": sum(view["overdue"] for view in task_views),
            "items": task_views[:task_limit],
            "truncated": len(task_views) > task_limit,
        },
        "audit": {
            "source": "persistent_audit_log",
            "available": audit_available,
            "limit": event_limit,
            "events_returned": min(len(recent_events), event_limit),
            "events": [_event_view(event) for event in recent_events[:event_limit]],
        },
    }
