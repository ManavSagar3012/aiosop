"""RecoveryService — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles stuck-task reaper, restart recovery, and DLQ integration.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict

import structlog

from ai_osop.core.config import AgentType
from ai_osop.core.models import AuditEvent, Task
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.orchestrator.recovery_service")


class RecoveryService:
    """Recover stuck tasks and restore state after restarts."""

    REAPER_INTERVAL_SECONDS = 30

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator
        # Task ids whose TERMINAL status has been reconciled to the graph. Several
        # execution paths (agent.execute_task, _execute_task_durable) advance the
        # in-memory task to 'completed'/'failed' WITHOUT persisting that terminal
        # state to Neo4j — the node stays 'running' (agent=None, updated_at frozen at
        # assignment) forever. Neo4j is the ground truth for the reaper, restart
        # recovery, dedupe, and reporting, so an unsynced terminal task is invisible
        # as "done" — the true "0 tasks ever completed in the graph" disease. The
        # reaper reconciles each such task ONCE (below) and records it here so it is
        # not re-written every 30s pass.
        self._graph_terminal_synced: set = set()

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
        """Recover executions that exceed their runtime budget.

        A ``pending`` task has not begun execution, so its age is queue wait time,
        not scanner runtime. Reaping it with ``timeout_seconds`` turns ordinary
        worker backpressure into false failures and can exhaust retries before the
        task ever receives an agent. Queue availability is handled by the scheduler;
        this reaper owns only tasks that were actually started.
        """
        now = datetime.utcnow()
        reaped = 0
        _TERMINAL = ("completed", "failed", "cancelled", "timeout", "error")
        for task in list(self._orch._tasks.values()):
            if task.status not in ("pending", "running"):
                # Durable-state reconciliation: the in-memory task is TERMINAL but the
                # graph may still say 'running' (some executors never persist the
                # terminal transition). Sync it ONCE so Neo4j — the ground truth for
                # reaper/recovery/dedupe/reporting — reflects that the task is done.
                if task.status in _TERMINAL and task.id not in self._graph_terminal_synced:
                    try:
                        await self._orch.graph_memory.upsert_task(
                            task,
                            result_summary=task.result if isinstance(task.result, dict) else None,
                        )
                        self._graph_terminal_synced.add(task.id)
                    except Exception as e:  # noqa: BLE001 - never let resync break the reaper
                        logger.warning(
                            "reaper_terminal_resync_failed", task_id=task.id, error=str(e)
                        )
                continue
            if task.status == "pending":
                continue
            ref = task.started_at
            if not ref:
                continue
            age = (now - ref).total_seconds()
            timeout = task.timeout_seconds or 300
            if age <= timeout:
                continue
            if task.status == "running" and task.retry_count < task.max_retries:
                # A retry must replace the execution that timed out.  Re-queueing
                # without cancelling its handle leaves the original coroutine alive
                # and allows duplicate scans to accumulate against the same target.
                handles = getattr(self._orch, "_task_handles", None)
                handle = handles.pop(task.id, None) if handles is not None else None
                if handle is not None and not handle.done():
                    handle.cancel()
                    try:
                        await asyncio.wait_for(handle, timeout=5.0)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        pass
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
            await self._orch.session_memory.store_task(task)
            await self._orch._audit_log(self._reaper_audit(task, age, "failed"))
            reaped += 1
        if reaped:
            logger.info("reaper_reaped_stuck_tasks", count=reaped)
        # DIAG (2026-07-05, temporary): expose what the reaper actually iterates so we
        # can confirm in-memory-terminal tasks are visible for graph reconciliation.
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

    # GAP-4-5: cap how many times a task may be resurrected across restarts so a
    # poison task that crashes the orchestrator cannot be recovered forever.
    MAX_RECOVERY_ATTEMPTS = 3
    _EXPLOIT_TASK_TYPES = ("validate_exploit", "exploit_validation")

    async def recover_state(self) -> Dict[str, Any]:
        """Restart recovery: restore ALL in-memory state from durable stores.

        This is the SINGLE recovery authority (GAP-6-2). It restores sessions,
        pending approvals (with their timeout watchers), and active tasks. Recovered
        tasks are re-gated for approval (GAP-2-3) and bounded by a recovery-attempt
        cap (GAP-4-5)."""
        recovered = {"engagements": 0, "tasks": 0, "approvals": 0, "exhausted": 0}
        try:
            # 1) Sessions. list_all_sessions() returns raw Redis keys ("session:<id>");
            #    hydrate each into a real SessionState before storing it in memory.
            session_keys = await self._orch.session_memory.list_all_sessions()
            for key in session_keys:
                session_id = key.split("session:", 1)[-1] if "session:" in key else key
                session = await self._orch.session_memory.get_session_state(session_id)
                if session is None:
                    continue
                self._orch._sessions[session.session_id] = session
                recovered["engagements"] += 1

            # 2) Pending approvals — restore them AND re-spawn their timeout watchers
            #    so a denial/timeout still fails the parked task after a restart.
            try:
                pending_approvals = await self._orch.session_memory.list_pending_approvals()
                for apr in pending_approvals:
                    await self._orch.approval_coordinator._register_approval(apr)
                    asyncio.create_task(
                        self._orch.approval_coordinator._await_approval_outcome(apr.id)
                    )
                    recovered["approvals"] += 1
            except Exception as e:
                logger.warning("recover_pending_approvals_failed", error=str(e))

            # 3) Active tasks. load_all_active_tasks() returns Task objects already
            #    filtered to non-terminal status.
            tasks = await self._orch.session_memory.load_all_active_tasks()
            for task in tasks:
                # GAP-2-3: NEVER replay a persisted/forced approval grant. Exploit-class
                # tasks must re-enter the operator approval gate after any restart, and
                # the agent-trusted token is stripped so the gate re-fires.
                if task.type in self._EXPLOIT_TASK_TYPES:
                    task.approval_required = True
                if task.approval_required:
                    self._orch.task_scheduler._sanitize_external_payload(task)

                if task.status in ("pending", "running"):
                    # GAP-4-5: bound resurrection. Count this recovery; over the cap the
                    # task is failed + dead-lettered instead of re-queued.
                    if not isinstance(task.payload, dict):
                        task.payload = {}
                    attempts = int(task.payload.get("_recovery_attempts", 0)) + 1
                    task.payload["_recovery_attempts"] = attempts
                    if attempts > self.MAX_RECOVERY_ATTEMPTS:
                        task.status = "failed"
                        task.completed_at = datetime.utcnow()
                        task.result = {
                            "status": "failed",
                            "error": f"recovery attempts exhausted ({attempts})",
                        }
                        await self._orch.graph_memory.upsert_task(
                            task, result_summary={"recovery_exhausted": True}
                        )
                        try:
                            await self._orch.dlq.enqueue(
                                task,
                                reason="recovery_exhausted",
                                final_error="max recovery attempts exceeded",
                            )
                        except Exception as e:
                            logger.error("recovery_dlq_failed", task_id=task.id, error=str(e))
                        self._orch._tasks[task.id] = task
                        recovered["exhausted"] += 1
                        continue
                    task.assigned_agent_id = None
                    task.status = "pending"
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)

                self._orch._tasks[task.id] = task
                recovered["tasks"] += 1
                await self._orch.session_memory.push_task_queue(
                    f"tasks:{task.engagement_id}", task.model_dump()
                )
        except Exception as e:
            logger.warning("orchestrator_startup_recovery_failed", error=str(e))
        return recovered
