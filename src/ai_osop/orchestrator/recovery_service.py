"""RecoveryService — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles stuck-task reaper, restart recovery, and DLQ integration.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from ai_osop.core.models import AuditEvent, Task
from ai_osop.core.tracing import trace_span
from ai_osop.core.config import AgentType
from ai_osop.safety.scope import ScopeEnforcer

import structlog

logger = structlog.get_logger("ai_osop.orchestrator.recovery_service")


class RecoveryService:
    """Recover stuck tasks and restore state after restarts."""

    REAPER_INTERVAL_SECONDS = 30

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator
        self._flagged_tasks: set[str] = set()

    async def _queue_current_signed_task(self, task: Task) -> bool:
        """Publish a restart hint under current, locked PostgreSQL authority.

        The startup list and Redis payload can both be stale. The real
        scheduler's one-shot claim remains the execution authority; this
        prequeue fence prevents publishing a snapshot which no longer matches
        its signed Task, ROE, Flow, dependency or pinned human decision.
        Holding the rows until Redis acknowledges the hint closes the recovery
        read/publish gap. A failed/ambiguous publish leaves the Task untouched.
        """
        from sqlalchemy import select

        from ai_osop.memory.authorization_store import guard_sql
        from ai_osop.memory.session_memory import (
            ApprovalRequestORM,
            ExecutionFlowORM,
            ExecutionSubtaskORM,
            SessionMemory,
            TaskORM,
        )
        from ai_osop.memory.supervision_store import SupervisionStore
        from ai_osop.safety.approval_binding import matches_pinned_payload

        sm = self._orch.session_memory
        if not isinstance(sm, SessionMemory) or not callable(getattr(sm, "_async_session", None)):
            return False
        payload = task.payload
        version = payload.get("_authorization_version") if isinstance(payload, dict) else None
        if type(version) is not int or version < 1:
            return False
        async with sm._async_session() as db:
            async with db.begin():
                # Lock in the same order as SessionMemory's signed dispatch:
                # engagement/ROE, then Task, Flow, step and dependencies.
                await SupervisionStore._guard(db, task.engagement_id, require_window=True)
                signed = await guard_sql(db, task.engagement_id, expected_version=version)
                if signed.version != version:
                    return False
                row = (await db.execute(select(TaskORM).where(
                    TaskORM.id == task.id,
                    TaskORM.engagement_id == task.engagement_id,
                ).with_for_update(read=True))).scalar_one_or_none()
                if row is None or row.status not in {"pending", "awaiting_approval"}:
                    return False
                from ai_osop.safety.approval_binding import task_payload_sha256

                # Compare the full durable scheduling identity. The signed
                # approval digest excludes grant fields, so additionally bind
                # the complete payload including those fields by equality.
                if (
                    row.id != task.id
                    or row.engagement_id != task.engagement_id
                    or row.status != task.status
                    or row.type != task.type
                    or row.agent_type != task.agent_type.value
                    or row.flow_id != task.flow_id
                    or row.subtask_id != task.subtask_id
                    or row.parent_task_id != task.parent_task_id
                    or row.dependencies != task.dependencies
                    or row.approval_required != task.approval_required
                    or row.priority != task.priority
                    or row.retry_count != task.retry_count
                    or row.scope_check != task.scope_check
                    or row.max_retries != task.max_retries
                    or row.timeout_seconds != task.timeout_seconds
                    or row.created_at != task.created_at
                    or not isinstance(row.payload, dict)
                    or task_payload_sha256(row.payload) != task_payload_sha256(payload)
                    or row.payload != payload
                ):
                    return False
                if task.flow_id:
                    flow = (await db.execute(select(ExecutionFlowORM).where(
                        ExecutionFlowORM.id == task.flow_id,
                        ExecutionFlowORM.engagement_id == task.engagement_id,
                    ).with_for_update(read=True))).scalar_one_or_none()
                    if (
                        flow is None or flow.status not in {"pending", "running"}
                        or ("_flow_revision" in payload
                            and (type(payload["_flow_revision"]) is not int
                                 or payload["_flow_revision"] != flow.revision))
                    ):
                        return False
                    if task.subtask_id:
                        step = (await db.execute(select(ExecutionSubtaskORM).where(
                            ExecutionSubtaskORM.id == task.subtask_id,
                            ExecutionSubtaskORM.engagement_id == task.engagement_id,
                            ExecutionSubtaskORM.flow_id == task.flow_id,
                        ).with_for_update(read=True))).scalar_one_or_none()
                        if (
                            step is None or step.execution_task_id != task.id
                            or step.task_id != task.parent_task_id
                            or step.status not in {"dispatched", "running"}
                            or step.task_type != task.type
                            or step.approval_required and not task.approval_required
                        ):
                            return False
                elif task.subtask_id:
                    return False
                if task.dependencies:
                    if (
                        not isinstance(task.dependencies, list)
                        or len(set(task.dependencies)) != len(task.dependencies)
                        or any(not isinstance(dep, str) or not dep for dep in task.dependencies)
                    ):
                        return False
                    parents = (await db.execute(select(TaskORM.id, TaskORM.status).where(
                        TaskORM.id.in_(task.dependencies),
                        TaskORM.engagement_id == task.engagement_id,
                    ).with_for_update(read=True))).all()
                    if {parent_id for parent_id, state in parents if state == "completed"} != set(task.dependencies):
                        return False
                if task.approval_required:
                    grant = payload.get("approval_id")
                    if task.status == "awaiting_approval":
                        if not isinstance(grant, str) or payload.get("operator_approved") is not True:
                            return False
                        approval = (await db.execute(select(ApprovalRequestORM).where(
                            ApprovalRequestORM.id == grant,
                            ApprovalRequestORM.task_id == task.id,
                            ApprovalRequestORM.engagement_id == task.engagement_id,
                            ApprovalRequestORM.status == "approved",
                        ).with_for_update(read=True))).scalar_one_or_none()
                        if (
                            approval is None or not approval.operator_id
                            or approval.responded_at is None
                            or not matches_pinned_payload(approval.evidence, row.payload)
                        ):
                            return False
                    elif grant is not None or payload.get("operator_approved") is True:
                        return False
                elif (
                    task.status == "awaiting_approval"
                    or payload.get("operator_approved") is True
                    or payload.get("approval_id") is not None
                ):
                    return False
                await sm.push_task_queue(f"tasks:{task.engagement_id}", task.model_dump())
                return True

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
            ref = (
                task.started_at
                if (task.status == "running" and task.started_at)
                else task.created_at
            )
            if task.status == "pending" and task.dependencies:
                # A dependency-blocked task has NOT exhausted its execution
                # window simply because it was created long ago. The timeout
                # starts only after all same-engagement predecessors actually
                # became terminal-successful. Consult PostgreSQL, not cached
                # in-memory/Redis parents which may have been revoked/changed.
                from ai_osop.memory.session_memory import SessionMemory

                memory = self._orch.session_memory
                read_parent = (
                    getattr(memory, "load_task_authoritative", None)
                    if isinstance(memory, SessionMemory)
                    else getattr(memory, "load_task", None)
                )
                if not callable(read_parent):
                    continue
                ready_at = []
                try:
                    for dependency in task.dependencies:
                        parent = await read_parent(dependency)
                        if (
                            parent is None
                            or parent.engagement_id != task.engagement_id
                            or parent.status != "completed"
                            or parent.completed_at is None
                        ):
                            ready_at = []
                            break
                        ready_at.append(parent.completed_at)
                except Exception:
                    # Database outage is not evidence the task became
                    # runnable; do not expire it from a stale cache.
                    continue
                if len(ready_at) != len(task.dependencies):
                    continue

                def utc_naive(value: datetime) -> datetime:
                    return (
                        value.astimezone(timezone.utc).replace(tzinfo=None)
                        if value.tzinfo is not None
                        else value
                    )

                ref = (
                    max([utc_naive(ref), *(utc_naive(instant) for instant in ready_at)])
                    if ref is not None
                    else max(utc_naive(instant) for instant in ready_at)
                )
            if not ref:
                continue
            age = (now - ref).total_seconds()
            timeout = task.timeout_seconds or 300
            if age <= timeout:
                continue
            if task.status == "running":
                # A local timeout is not a remote execution cancellation receipt.
                # Check distributed lease in Redis
                sm = getattr(self._orch, "session_memory", None)
                has_lease = False
                if sm is not None and hasattr(sm, "has_task_lease"):
                    try:
                        has_lease = await sm.has_task_lease(task.id)
                    except Exception:
                        has_lease = True

                if not has_lease:
                    engagement = self._orch._sessions.get(task.engagement_id)
                    is_exploit = (
                        (engagement and getattr(engagement, "phase", None) == "exploitation")
                        or task.approval_required
                        or task.agent_type == AgentType.EXPLOIT_VALIDATION
                        or "exploit" in task.type.lower()
                    )
                    if is_exploit:
                        task.status = "quarantined_unknown"
                        task.result = {
                            "status": "quarantined_unknown",
                            "reason": f"Worker crashed or lost lease during invasive exploit execution after {int(age)}s; quarantined.",
                        }
                        if sm is not None:
                            await sm.store_task(task)
                        await self._orch.graph_memory.upsert_task(task)
                        await self._orch._audit_log(
                            AuditEvent(
                                event_type="task_quarantined",
                                severity="critical",
                                actor_type="system",
                                actor_id="reaper_service",
                                action={"task_id": task.id, "task_type": task.type, "reason": "lease_expired_exploit_quarantine"},
                                result={"status": "quarantined_unknown"},
                                context={"engagement_id": task.engagement_id},
                                engagement_id=task.engagement_id,
                            )
                        )
                        reaped += 1
                        continue

                if task.id not in self._flagged_tasks:
                    self._flagged_tasks.add(task.id)
                    await self._orch._audit_log(
                        self._reaper_audit(task, age, "external_outcome_unknown")
                    )
                continue
            from ai_osop.memory.session_memory import SessionMemory

            durable_expiry = isinstance(self._orch.session_memory, SessionMemory)
            if durable_expiry:
                # The cache may still say pending while another replica has
                # committed a running/external claim. A reaper must NEVER
                # overwrite that claim based on an obsolete local timestamp.
                try:
                    expired = await self._orch.session_memory.expire_pending_task_atomic(
                        task.id,
                        task.engagement_id,
                        created_before=now - timedelta(seconds=timeout),
                    )
                except Exception as exc:
                    logger.warning(
                        "pending_task_timeout_unverified",
                        task_id=task.id,
                        error_type=type(exc).__name__,
                    )
                    continue
                if not expired:
                    fresh = await self._orch.session_memory.load_task_authoritative(task.id)
                    if fresh is not None:
                        self._orch._tasks[task.id] = fresh
                    continue
            task.status = "failed"
            task.completed_at = now
            task.result = (
                {"status": "failed", "reason": "pending_task_timeout"}
                if durable_expiry
                else {"status": "failed", "error": f"reaper timeout after {int(age)}s"}
            )
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"reaped": True, "age_seconds": int(age)}
            )
            if durable_expiry:
                try:
                    await self._orch.session_memory.store_hot(
                        f"task:{task.id}",
                        task.model_dump(),
                        ttl=86400 * 7,
                    )
                except Exception:
                    logger.warning("reaper_hot_cache_unavailable", task_id=task.id)
            else:
                await self._orch.session_memory.store_task(task)
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
        """Restore authoritative sessions before pending tasks are scheduled.

        The warm store exposes point reads for older deployments, so select
        session IDs directly if a dedicated list_all_sessions API is absent.
        """
        recovered = {"engagements": 0, "tasks": 0, "agents": 0, "unresolved": 0, "skipped": 0}
        sm = self._orch.session_memory
        try:
            if hasattr(sm, "list_all_sessions"):
                sessions = await sm.list_all_sessions()
            else:
                from sqlalchemy import select
                from ai_osop.memory.session_memory import SessionStateORM

                async with sm._async_session() as db:
                    result = await db.execute(select(SessionStateORM.session_id))
                    session_ids = result.scalars().all()
                sessions = []
                for session_id in session_ids:
                    session = await sm.load_session_state(session_id)
                    if session:
                        sessions.append(session)
            for session in sessions:
                self._orch._sessions[session.session_id] = session
                recovered["engagements"] += 1
                # This is a read-only hydration, not a fresh policy update.
                # Upserting the snapshot could restore an outdated ROE if
                # another operator replica changed the engagement meanwhile.

            if hasattr(sm, "list_all_tasks"):
                tasks = await sm.list_all_tasks()
            else:
                tasks = await sm.load_all_active_tasks()
            for task in tasks:
                # Completed and failed records are historical, not queue entries.
                if task.status in ("completed", "failed", "cancelled"):
                    self._orch._tasks[task.id] = task
                    continue
                self._orch._tasks[task.id] = task
                if task.status in {"running", "scheduled", "dispatching", "dispatch_unknown"}:
                    # No execution receipt/worker lease proves the previous
                    # remote action stopped. Never automatically resubmit it.
                    engagement = self._orch._sessions.get(task.engagement_id)
                    is_exploit = (
                        (engagement and getattr(engagement, "phase", None) == "exploitation")
                        or task.approval_required
                        or task.agent_type == AgentType.EXPLOIT_VALIDATION
                        or "exploit" in task.type.lower()
                    )
                    if is_exploit:
                        task.status = "quarantined_unknown"
                        task.result = {
                            "status": "quarantined_unknown",
                            "reason": "Process restarted while invasive exploit task was active; quarantined to prevent duplicate exploitation side-effects.",
                        }
                        await sm.store_task(task)
                        await self._orch.graph_memory.upsert_task(task)
                        await self._orch._audit_log(
                            AuditEvent(
                                event_type="task_quarantined",
                                severity="critical",
                                actor_type="system",
                                actor_id="recovery_service",
                                action={
                                    "task_id": task.id,
                                    "task_type": task.type,
                                    "reason": "crash_recovery_quarantine",
                                },
                                result={"status": "quarantined_unknown"},
                                context={"engagement_id": task.engagement_id},
                                engagement_id=task.engagement_id,
                            )
                        )
                        recovered["quarantined"] = recovered.get("quarantined", 0) + 1
                    recovered["unresolved"] += 1
                    continue
                if task.status not in {"pending", "awaiting_approval"}:
                    recovered["skipped"] += 1
                    continue
                if task.status == "awaiting_approval":
                    # A senior may have committed the signed approval and its
                    # TaskORM grant atomically immediately before this
                    # replica/process died, but before its in-memory
                    # scheduler launched. The durable Task deliberately
                    # remains awaiting_approval until one-shot execution
                    # admission. Recover ONLY the already-approved exact
                    # pinned grant, never a pending human decision.
                    from ai_osop.memory.session_memory import SessionMemory

                    grant = (
                        task.payload.get("approval_id")
                        if isinstance(task.payload, dict) else None
                    )
                    if (
                        not isinstance(sm, SessionMemory)
                        or not task.approval_required
                        or not isinstance(grant, str)
                        or not grant
                        or task.payload.get("operator_approved") is not True
                    ):
                        recovered["skipped"] += 1
                        continue
                    try:
                        if not await sm.is_task_approved(
                            task.id, task.engagement_id, grant
                        ):
                            recovered["skipped"] += 1
                            continue
                    except Exception:
                        recovered["skipped"] += 1
                        continue
                engagement = self._orch._sessions.get(task.engagement_id)
                if (
                    engagement is None
                    or engagement.phase in {"halted", "completed"}
                    or not engagement.scope.authorization_ref
                    or not (engagement.scope.domains or engagement.scope.ips)
                ):
                    recovered["skipped"] += 1
                    continue
                try:
                    ScopeEnforcer(engagement.scope).validate_time_window()
                except Exception:
                    recovered["skipped"] += 1
                    continue
                # Startup Redis hydration is NOT an authorization source.
                # A pending task from a retired signer, revoked/expired ROE,
                # or older policy version must never be requeued after a
                # worker restart even if the cached scope still looks valid.
                from ai_osop.memory.session_memory import SessionMemory

                if isinstance(sm, SessionMemory):
                    version = (
                        task.payload.get("_authorization_version")
                        if isinstance(task.payload, dict)
                        else None
                    )
                    if type(version) is not int or version < 1:
                        recovered["skipped"] += 1
                        continue
                    try:
                        await sm.assert_signed_authorization(
                            task.engagement_id, expected_version=version
                        )
                    except Exception:
                        recovered["skipped"] += 1
                        continue
                if task.flow_id:
                    try:
                        flow = await sm.load_flow(task.flow_id)
                    except Exception:
                        # A single missing/unavailable Flow record must not
                        # abort recovery of unrelated owner-scoped tasks.
                        recovered["skipped"] += 1
                        logger.warning("recovery_flow_unavailable", task_id=task.id)
                        continue
                    if (
                        flow is None
                        or flow.engagement_id != task.engagement_id
                        or flow.status not in {"pending", "running"}
                    ):
                        recovered["skipped"] += 1
                        continue
                try:
                    if isinstance(sm, SessionMemory) and (
                        callable(getattr(sm, "_async_session", None))
                        or hasattr(sm, "_pg_engine")
                    ):
                        admitted = await self._queue_current_signed_task(task)
                        if not admitted:
                            recovered["skipped"] += 1
                            continue
                    else:
                        # Legacy adapter/test memory has no PostgreSQL session.
                        # The actual signed SessionMemory always uses the
                        # transaction above; final execution claim is separate.
                        await sm.push_task_queue(f"tasks:{task.engagement_id}", task.model_dump())
                except Exception:
                    # Redis is only a delivery tier. Leave the PG-authorized
                    # PENDING record untouched for a future recovery pass.
                    # Never interpret an ambiguous publish as permission to
                    # create an additional task or claim external execution.
                    recovered["skipped"] += 1
                    logger.warning("recovery_redis_delivery_unavailable", task_id=task.id)
                    continue
                recovered["tasks"] += 1
        except Exception as e:
            logger.warning("orchestrator_startup_recovery_failed", error=str(e))
        return recovered
