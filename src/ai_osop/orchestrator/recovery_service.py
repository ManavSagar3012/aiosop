"""RecoveryService — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles stuck-task reaper, restart recovery, and DLQ integration.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict

from ai_osop.core.models import AuditEvent, Task
from ai_osop.core.tracing import trace_span
from ai_osop.core.config import AgentType

import structlog

logger = structlog.get_logger("ai_osop.orchestrator.recovery_service")


class RecoveryService:
    """Recover stuck tasks and restore state after restarts."""

    REAPER_INTERVAL_SECONDS = 30

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def _reaper_loop(self) -> None:
        """Background reaper: periodically recover/fail tasks stuck past their timeout."""
        while self._orch._running:
            try:
                await asyncio.sleep(self.REAPER_INTERVAL_SECONDS)
                await self._reap_stuck_tasks()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("reaper_loop_error", error=str(e))

    async def _reap_stuck_tasks(self) -> int:
        """Detect pending/running tasks older than their timeout and recover or fail them."""
        now = datetime.utcnow()
        reaped = 0
        for task in list(self._orch._tasks.values()):
            if task.status not in ("pending", "running"):
                continue
            ref = task.started_at if (task.status == "running" and task.started_at) else task.created_at
            if not ref:
                continue
            age = (now - ref).total_seconds()
            timeout = task.timeout_seconds or 300
            if age <= timeout:
                continue
            if task.status == "running" and task.retry_count < task.max_retries:
                await self._orch._audit_log(self._reaper_audit(task, age, "recovering"))
                reaped += 1
                await self._orch.task_scheduler._maybe_retry(
                    task, {"error": f"reaper: stuck {int(age)}s > {timeout}s timeout"}
                )
                continue
            task.status = "failed"
            task.completed_at = now
            task.result = {"status": "failed", "error": f"reaper timeout after {int(age)}s"}
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"reaped": True, "age_seconds": int(age)}
            )
            await self._orch._audit_log(self._reaper_audit(task, age, "failed"))
            reaped += 1
        if reaped:
            logger.info("reaper_reaped_stuck_tasks", count=reaped)
        return reaped

    @staticmethod
    def _reaper_audit(task: Task, age: float, action: str) -> AuditEvent:
        return AuditEvent(
            event_type="task_reaped",
            severity="warning",
            actor_type="system",
            actor_id="orchestrator-reaper",
            action={
                "task_id": task.id,
                "task_type": task.type,
                "prior_status": task.status,
                "age_seconds": int(age),
                "timeout_seconds": task.timeout_seconds,
                "outcome": action,
            },
            result={"reaped": True},
            context={"engagement_id": task.engagement_id},
            engagement_id=task.engagement_id,
        )

    async def recover_state(self) -> Dict[str, Any]:
        """Restart recovery: restore in-memory state from durable stores."""
        recovered = {"engagements": 0, "tasks": 0, "agents": 0}
        try:
            sessions = await self._orch.session_memory.list_all_sessions()
            for session in sessions:
                self._orch._sessions[session.session_id] = session
                recovered["engagements"] += 1
            tasks = await self._orch.session_memory.list_all_tasks()
            for task in tasks:
                if task.status in ("pending", "running"):
                    task.assigned_agent_id = None
                    task.status = "pending"
                self._orch._tasks[task.id] = task
                recovered["tasks"] += 1
                await self._orch.session_memory.push_task_queue(
                    f"tasks:{task.engagement_id}", task.model_dump()
                )
        except Exception as e:
            logger.warning("orchestrator_startup_recovery_failed", error=str(e))
        return recovered
