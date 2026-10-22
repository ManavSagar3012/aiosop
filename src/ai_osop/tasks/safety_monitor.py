"""Passive operational safety monitor for authorized security engagements.

The monitor inspects existing in-memory state; it never contacts a target.
Window and missing-approval violations trigger the orchestrator's existing
audited emergency-halt path. Overdue tasks remain owned by its task reaper.
"""

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

from ai_osop.core.models import AuditEvent, Task

logger = structlog.get_logger("ai_osop.tasks.safety_monitor")
_ACTIVE_STATUSES = {"running", "scheduled", "dispatching"}


def _utc_naive(value: datetime) -> datetime:
    """Normalize UTC database timestamps for comparisons with injected clocks."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


class SafetyMonitor:
    """Inspect active task state and enforce engagement boundaries."""

    def __init__(self, orchestrator: Any, check_interval: float = 15.0) -> None:
        if check_interval <= 0:
            raise ValueError("check_interval must be positive")
        self.orchestrator = orchestrator
        self.check_interval = check_interval
        self.detected_hazards: List[Dict[str, str]] = []
        self._reported: Set[Tuple[str, str, str]] = set()
        self._stop_event = asyncio.Event()
        self._runner: Optional[asyncio.Task] = None

    async def check_once(self, now: Optional[datetime] = None) -> List[Dict[str, str]]:
        """Check live tasks without exposing payloads, tokens, or target details."""
        current_time = _utc_naive(now or datetime.utcnow())
        events: List[Dict[str, str]] = []
        sessions = dict(self.orchestrator._sessions)
        tasks = list(self.orchestrator._tasks.values())
        for session_id, session in sessions.items():
            active = [
                task
                for task in tasks
                if task.engagement_id == session_id and task.status in _ACTIVE_STATUSES
            ]
            if not active:
                continue

            # A persisted halt is authoritative even if an old worker still
            # exposes stale running status in the in-memory task snapshot.
            if session.phase in {"halted", "completed"}:
                for task in active:
                    await self._report(session_id, task, "task_after_terminal_phase", events)
                continue

            # Deadline is compared without attempting a fresh network request.
            scope = session.scope
            start = _utc_naive(scope.testing_window_start) if scope.testing_window_start else None
            end = _utc_naive(scope.testing_window_end) if scope.testing_window_end else None
            window_closed = (start is not None and current_time < start) or (
                end is not None and current_time > end
            )
            if window_closed:
                try:
                    await self._report(session_id, active[0], "testing_window_closed", events)
                finally:
                    # A failure in audit storage cannot allow active execution
                    # to continue outside the engagement testing window.
                    await self.orchestrator.halt_engagement(
                        session_id, "Safety monitor: testing window closed"
                    )
                continue

            for task in active:
                if task.status == "running" and task.approval_required:
                    approval_id = task.payload.get("approval_id")
                    verified = False
                    if isinstance(approval_id, str) and approval_id:
                        try:
                            verified = await self.orchestrator.session_memory.is_task_approved(
                                task.id, session_id, approval_id
                            )
                        except Exception:
                            logger.warning("persisted_approval_check_unavailable", task_id=task.id)
                    if not verified:
                        try:
                            await self._report(
                                session_id, task, "missing_operator_approval", events
                            )
                        finally:
                            await self.orchestrator.halt_engagement(
                                session_id, "Safety monitor: active task lacks persisted approval"
                            )
                        break
                if task.status == "running" and task.started_at:
                    elapsed = (current_time - _utc_naive(task.started_at)).total_seconds()
                    if elapsed > max(task.timeout_seconds, 1):
                        await self._report(session_id, task, "task_overdue", events)
        return events

    async def _report(
        self,
        session_id: str,
        task: Task,
        code: str,
        events: List[Dict[str, str]],
    ) -> None:
        key = (session_id, task.id, code)
        if key in self._reported:
            return
        # Only register the incident after the durable audit write succeeds.
        await self.orchestrator._audit_log(
            AuditEvent(
                event_type="operational_safety_alert",
                severity="critical" if code != "task_overdue" else "warning",
                actor_type="system",
                actor_id="operational-safety-monitor",
                action={"task_id": task.id, "code": code},
                result={"detected": True},
                context={"status": task.status},
                engagement_id=session_id,
            )
        )
        self._reported.add(key)
        item = {"engagement_id": session_id, "task_id": task.id, "code": code}
        events.append(item)
        self.detected_hazards.append(item)
        logger.warning("operational_safety_alert", **item)

    async def monitor_loop(self) -> None:
        """Periodically inspect state until shutdown, surviving transient faults."""
        while not self._stop_event.is_set():
            try:
                await self.check_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("operational_safety_check_failed", error=type(exc).__name__)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.check_interval)
            except asyncio.TimeoutError:
                continue

    async def start(self) -> None:
        """Start a single monitor loop on the active application event loop."""
        if self._runner is not None and not self._runner.done():
            return
        self._stop_event.clear()
        self._runner = asyncio.create_task(self.monitor_loop())

    async def shutdown(self) -> None:
        """Stop monitor checks before the persistence connection is closed."""
        self._stop_event.set()
        if self._runner is not None:
            await asyncio.wait_for(self._runner, timeout=5.0)
            self._runner = None


async def run_safety_monitor(orchestrator: Any, check_interval: float = 15.0) -> SafetyMonitor:
    """Create and start a monitor; the caller owns its shutdown lifecycle."""
    monitor = SafetyMonitor(orchestrator, check_interval=check_interval)
    await monitor.start()
    return monitor
