"""TaskScheduler — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all task scheduling, assignment, execution, retry, and lifecycle management.
The Orchestrator retains ownership of shared state (agents, tasks, busy_agents)
and passes itself as context so the scheduler can access it.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, Optional

import structlog

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ApprovalRequest, AuditEvent, Task
from ai_osop.core.observability import record_task, update_task_counts
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.orchestrator.task_scheduler")


class TaskScheduler:
    """Schedule, assign, execute, and retry tasks."""

    # Terminal failure statuses that should not trigger retry success path
    _FAILURE_STATUSES = {"failed", "error", "timeout", "cancelled", "unsupported", "not_executed"}

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator
        # In-process serialization covers concurrent queue, approval and
        # downstream-dispatch callbacks for the same deterministic Temporal ID.
        self._temporal_dispatch_locks: Dict[str, asyncio.Lock] = {}

    async def _assert_signed_schedule_persisted(self, task: Task) -> None:
        """Reject phantom queue/bus entries after a denied TaskORM CAS.

        SessionMemory.store_task intentionally ignores conflicting stale
        snapshots, so returning from that writer alone is not proof the
        *candidate* exists in the authoritative store. This read is an
        advisory prequeue check: the final agent/Temporal claim still locks
        and revalidates signed authorization, scope, owner, and approvals.
        Legacy unsigned/manual queue behavior is unchanged.
        """
        from ai_osop.memory.session_memory import SessionMemory
        from ai_osop.safety.approval_binding import task_payload_sha256

        memory = self._orch.session_memory
        if not isinstance(memory, SessionMemory):
            return
        version = (
            task.payload.get("_authorization_version") if isinstance(task.payload, dict) else None
        )
        if type(version) is not int or version < 1:
            raise WorkflowException("Signed task admission has no authorization version")
        try:
            actual = await memory.load_task_authoritative(task.id)
            if (
                actual is None
                or actual.engagement_id != task.engagement_id
                or actual.status != task.status
                or actual.status not in {"pending", "planned"}
                or actual.type != task.type
                or actual.agent_type != task.agent_type
                or actual.flow_id != task.flow_id
                or actual.subtask_id != task.subtask_id
                or actual.parent_task_id != task.parent_task_id
                or actual.approval_required != task.approval_required
                or actual.dependencies != task.dependencies
                or actual.retry_count != task.retry_count
                or actual.priority != task.priority
                or actual.max_retries != task.max_retries
                or actual.timeout_seconds != task.timeout_seconds
                or actual.scope_check != task.scope_check
                or actual.created_at != task.created_at
                or task_payload_sha256(actual.payload) != task_payload_sha256(task.payload)
            ):
                raise WorkflowException("Authoritative signed task snapshot was not admitted")
            await memory.assert_signed_authorization(task.engagement_id, expected_version=version)
        except WorkflowException:
            raise
        except Exception as exc:
            raise WorkflowException("Authoritative signed task admission unavailable") from exc

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution."""
        from ai_osop.core.telemetry import inject_trace_context
        from ai_osop.safety.scope import action_requires_approval

        await self._orch._bind_task_authorization(task)
        session = self._orch._sessions.get(task.engagement_id)
        if session is not None and action_requires_approval(task.type, session.scope):
            task.approval_required = True
        if task.agent_type == AgentType.EXPLOIT_VALIDATION:
            task.approval_required = True

        if self._orch.temporal_enabled:
            self._orch._validate_temporal_task_scope(task)

        if not task.trace_context:
            inject_trace_context(task.trace_context)
        RequestContext.bind(
            task_id=task.id,
            engagement_id=task.engagement_id,
            flow_id=task.flow_id or "",
            subtask_id=task.subtask_id or "",
            trace_id=(
                task.trace_context.get("traceparent", "").split("-")[1]
                if task.trace_context.get("traceparent")
                else ""
            ),
        )

        with trace_span(
            "orchestrator.schedule_task",
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_type": task.agent_type.value,
                "engagement_id": task.engagement_id,
                "approval_required": task.approval_required,
            },
        ):
            # Force approval for exploit-class tasks
            if (
                task.type in ("validate_exploit", "exploit_validation")
                and not task.approval_required
            ):
                task.approval_required = True
            if task.approval_required:
                task.payload.pop("operator_approved", None)
                task.payload.pop("approval_id", None)

            await self._orch.session_memory.store_task(task)
            await self._assert_signed_schedule_persisted(task)
            self._orch._tasks[task.id] = task
            # Graph/bus are derived observations, never stronger admission
            # authorities than PostgreSQL. An observer outage cannot discard
            # an already persisted, authorized task before dispatch.
            from ai_osop.memory.session_memory import SessionMemory

            durable = isinstance(self._orch.session_memory, SessionMemory)
            try:
                await self._orch.graph_memory.upsert_task(task)
            except Exception:
                if not durable:
                    raise
                logger.warning("scheduled_task_graph_projection_delayed", task_id=task.id)
            try:
                await self._orch.coordination_bus.publish(
                    "task.scheduled",
                    {
                        "task_id": task.id,
                        "task_type": task.type,
                        "agent_type": task.agent_type.value,
                    },
                    "orchestrator",
                )
            except Exception:
                if not durable:
                    raise
                logger.warning("scheduled_task_bus_notification_delayed", task_id=task.id)
            try:
                await self._orch.session_memory.push_task_queue(
                    f"tasks:{task.engagement_id}", task.model_dump()
                )
            except Exception:
                if not durable:
                    raise
                # PG is the admission authority. The best-effort hot queue
                # cannot prevent a currently live scheduler from attempting
                # its separate one-shot signed claim. A dependent task stays
                # pending until durable recovery redelivery is available.
                logger.warning("signed_task_redis_queue_delayed", task_id=task.id)

            if self._orch.temporal_enabled:
                await self._dispatch_temporal_task(task)
                return task

            if not task.dependencies:
                await self._assign_task(task)

            return task

    async def _dependencies_complete(self, task: Task) -> bool:
        """Resolve completed parents from persistence after a worker restart."""
        for dep_id in task.dependencies:
            parent = self._orch._tasks.get(dep_id)
            if parent is None:
                # load_all_active_tasks intentionally omits completed tasks.
                # Child dispatch must still work after a process restart.
                parent = await self._orch.session_memory.load_task(dep_id)
                if parent is not None and parent.engagement_id == task.engagement_id:
                    self._orch._tasks[dep_id] = parent
            if (
                parent is None
                or parent.engagement_id != task.engagement_id
                or parent.status != "completed"
            ):
                return False
        return True

    async def _dispatch_temporal_task(self, task: Task) -> None:
        """Gate Temporal startup on verified approval, scope and dependencies.

        Approval resolution, the scheduler loop and downstream task completion
        all pass through this method, so only one start call runs per task.
        """
        if not self._orch.temporal_enabled or self._orch.temporal_scheduler is None:
            raise WorkflowException("Temporal scheduler is unavailable")

        lock = self._temporal_dispatch_locks.setdefault(task.id, asyncio.Lock())
        async with lock:
            if task.status in {
                "scheduled",
                "dispatching",
                "dispatch_unknown",
                "running",
                "completed",
                "failed",
                "cancelled",
            }:
                return
            if not await self._dependencies_complete(task):
                if task.status != "pending":
                    task.status = "pending"
                    await self._orch.session_memory.store_task(task)
                return

            # Revalidate scope at actual dispatch time: it may have changed
            # while the task waited for an operator or parent task.
            self._orch._validate_temporal_task_scope(task)

            if task.approval_required:
                approval_id = task.payload.get("approval_id")
                persisted = (
                    await self._orch.session_memory.load_approval_request(approval_id)
                    if isinstance(approval_id, str) and approval_id
                    else None
                )
                authorized = (
                    persisted is not None
                    and persisted.status == "approved"
                    and bool(persisted.operator_id)
                    and persisted.responded_at is not None
                    and persisted.task_id == task.id
                    and persisted.engagement_id == task.engagement_id
                    and task.payload.get("operator_approved") is True
                )
                if not authorized:
                    self._strip_stale_approval(task)
                    pending_request = next(
                        (
                            request
                            for request in self._orch._approval_requests.values()
                            if request.task_id == task.id
                            and request.engagement_id == task.engagement_id
                            and request.status == "pending"
                        ),
                        None,
                    )
                    if task.status != "awaiting_approval":
                        task.status = "awaiting_approval"
                        await self._orch.graph_memory.upsert_task(task)
                        await self._orch.session_memory.store_task(task)
                    if pending_request is None:
                        request = ApprovalRequest(
                            task_id=task.id,
                            agent_id="",
                            action_type=task.type,
                            target=str(
                                task.payload.get("url")
                                or task.payload.get("target")
                                or task.payload.get("domain")
                                or "unknown"
                            ),
                            payload_summary=str(task.payload),
                            risk_assessment="high",
                            engagement_id=task.engagement_id,
                        )
                        from ai_osop.core.observability import record_approval_requested

                        record_approval_requested(request.id)
                        await self._orch.approval_coordinator._raise_approval(request)
                    return

            # A process-local lock is not sufficient across API replicas.
            # Production takes a PostgreSQL-authoritative one-shot claim,
            # including the currently signed policy, Flow, full payload and
            # operator approval, BEFORE any Temporal network call. If the
            # call outcome is ambiguous, recovery must never blindly replay.
            from ai_osop.memory.session_memory import SessionMemory

            durable_claim = isinstance(self._orch.session_memory, SessionMemory)
            claim_id = None
            if durable_claim:
                claim_id = await self._orch.session_memory.claim_temporal_dispatch(task)
                task.status = "dispatching"
            from ai_osop.core.telemetry import RequestContext

            RequestContext.bind(
                task_id=task.id,
                engagement_id=task.engagement_id,
                flow_id=task.flow_id or "",
                subtask_id=task.subtask_id or "",
            )
            try:
                workflow_id = await self._orch.temporal_scheduler.start_task_workflow(
                    task.model_dump()
                )
            except BaseException:
                if durable_claim:
                    # A disconnect/cancel after submission proves neither
                    # remote execution nor termination. Persist UNKNOWN and
                    # do not reissue this claimed task automatically.
                    task.status = "dispatch_unknown"
                    task.result = {"status": "unknown", "reason": "temporal_start_unverified"}
                    try:
                        await self._orch.session_memory.settle_temporal_dispatch(
                            task.id,
                            task.engagement_id,
                            claim_id,
                            "dispatch_unknown",
                        )
                    except Exception:
                        logger.warning(
                            "temporal_start_receipt_persistence_unavailable", task_id=task.id
                        )
                raise
            task.status = "scheduled"
            task.result = {"workflow_id": workflow_id, "durable": True}
            try:
                if durable_claim:
                    await self._orch.session_memory.settle_temporal_dispatch(
                        task.id,
                        task.engagement_id,
                        claim_id,
                        "scheduled",
                        workflow_id=workflow_id,
                    )
                else:
                    await self._orch.session_memory.store_task(task)
            except Exception as exc:
                if durable_claim:
                    task.status = "dispatch_unknown"
                    task.result = {"status": "unknown", "reason": "temporal_receipt_unavailable"}
                raise WorkflowException("Temporal dispatch receipt was not persisted") from exc

    async def reconcile_temporal_dispatch(
        self,
        task_id: str,
        engagement_id: str,
    ) -> Dict[str, Any]:
        """Observe an uncertain Temporal start; never replay or settle it.

        Only the PostgreSQL task is authoritative. Redis queue snapshots and
        caller-provided Task objects cannot authorize even a provider lookup.
        This method is for internal supervision callers that have already
        checked operator ownership; it grants no API authorization itself.
        Provider workflow completion is not a receipt for external effects.
        PostgreSQL status and approval remain unchanged pending a separate,
        owner-fenced reconciliation transaction.
        """
        from ai_osop.memory.session_memory import SessionMemory

        if not self._orch.temporal_enabled or self._orch.temporal_scheduler is None:
            raise WorkflowException("Temporal scheduler is unavailable")
        if (
            not isinstance(task_id, str)
            or not task_id
            or not isinstance(engagement_id, str)
            or not engagement_id
        ):
            raise PermissionError("Temporal reconciliation task unavailable")

        memory = self._orch.session_memory
        if not isinstance(memory, SessionMemory):
            raise WorkflowException("Authoritative Temporal task store unavailable")
        try:
            task = await memory.load_task_authoritative(task_id)
            if task is None or task.engagement_id != engagement_id:
                raise PermissionError("Temporal reconciliation task unavailable")
            if task.status not in {"dispatching", "dispatch_unknown"}:
                return {
                    "task_id": task_id,
                    "engagement_id": engagement_id,
                    "task_status": task.status,
                    "observation": "not_applicable",
                    "verified": False,
                    "safe_to_retry": False,
                    "durable_status_changed": False,
                }

            # Fresh signed PostgreSQL policy remains the source of authority
            # for an uncertain task. Never use cached engagement/ROE fields.
            version = task.payload.get("_authorization_version")
            if type(version) is not int or version < 1:
                raise PermissionError("Temporal reconciliation authorization unavailable")
            await memory.assert_signed_authorization(
                engagement_id,
                expected_version=version,
            )
        except PermissionError:
            raise
        except Exception as exc:
            raise WorkflowException("Temporal reconciliation store unavailable") from exc

        receipt = await self._orch.temporal_scheduler.observe_task_workflow(task_id)
        return {
            "task_id": task_id,
            "engagement_id": engagement_id,
            "task_status": task.status,
            **receipt,
            # No read-only Temporal observation commits a workflow receipt,
            # marks task completion, revokes approval, or permits a retry.
            "durable_status_changed": False,
            "safe_to_retry": False,
        }

    async def _execute_task_durable(self, task: Task) -> Dict[str, Any]:
        """Keep Temporal/alternate callers on the canonical execution path."""
        return await self._orch._execute_task_durable(task)

    async def _assign_task(self, task: Task) -> None:
        """Assign task to appropriate agent."""
        session = self._orch._sessions.get(task.engagement_id)
        if task.status == "cancelled" or (
            session is not None and session.phase in {"halted", "completed"}
        ):
            return
        if self._orch.temporal_enabled:
            await self._dispatch_temporal_task(task)
            return
        if any(
            self._orch._tasks.get(dep_id) is None or self._orch._tasks[dep_id].status != "completed"
            for dep_id in task.dependencies
        ):
            if task.status != "awaiting_approval":
                task.status = "pending"
            return
        with trace_span(
            "orchestrator._assign_task",
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_type": task.agent_type.value,
                "engagement_id": task.engagement_id,
                "approval_required": task.approval_required,
            },
        ):
            if hasattr(self._orch, "rate_limiter") and self._orch.rate_limiter:
                await self._orch.rate_limiter.acquire(tool="orchestrator")

            # Approval gate FIRST
            if task.approval_required and not task.payload.get("operator_approved"):
                from ai_osop.memory.session_memory import SessionMemory

                if isinstance(self._orch.session_memory, SessionMemory):
                    request = ApprovalRequest(
                        id=self._orch.session_memory.deterministic_task_approval_id(
                            task.engagement_id,
                            task.id,
                        ),
                        task_id=task.id,
                        agent_id="",
                        action_type=task.type,
                        target=str(task.payload.get("url", task.payload.get("target", "unknown"))),
                        payload_summary=str(task.payload)[:1024],
                        risk_assessment="high",
                        engagement_id=task.engagement_id,
                    )
                    try:
                        created = await self._orch.session_memory.park_task_for_approval_atomic(
                            task,
                            request,
                        )
                    except Exception as exc:
                        logger.warning(
                            "approval_parking_unavailable",
                            task_id=task.id,
                            error_type=type(exc).__name__,
                        )
                        return
                    if not created:
                        fresh = await self._orch.session_memory.load_task_authoritative(task.id)
                        if fresh is not None:
                            self._orch._tasks[task.id] = fresh
                        return
                    task.status = "awaiting_approval"
                    self._orch._tasks[task.id] = task
                    from ai_osop.core.observability import record_approval_requested

                    record_approval_requested(request.id)
                    await self._orch.approval_coordinator._raise_approval(request)
                    return
                if task.status != "awaiting_approval":
                    task.status = "awaiting_approval"
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)
                    request = ApprovalRequest(
                        task_id=task.id,
                        agent_id="",
                        action_type=task.type,
                        target=str(task.payload.get("url", task.payload.get("target", "unknown"))),
                        payload_summary=str(task.payload),
                        risk_assessment="high",
                        engagement_id=task.engagement_id,
                    )
                    from ai_osop.core.observability import record_approval_requested

                    record_approval_requested(request.id)
                    await self._orch.approval_coordinator._raise_approval(request)
                    return

            # Find + atomically claim an available agent
            agent = await self._find_available_agent(task.agent_type, task.type)
            if agent:
                from ai_osop.memory.session_memory import SessionMemory

                durable_claim = isinstance(self._orch.session_memory, SessionMemory)
                if durable_claim:
                    # This is the final cross-replica admission immediately
                    # before spawning a local agent. The PostgreSQL claim
                    # verifies current signed ROE, approval, Flow, dependencies
                    # and Task snapshot atomically; a queue message alone
                    # cannot confer execution authority.
                    try:
                        admitted = await self._orch.session_memory.claim_local_agent_start(
                            task,
                            agent.ctx.agent_id,
                        )
                    except Exception as exc:
                        logger.warning(
                            "local_agent_claim_denied",
                            task_id=task.id,
                            error_type=type(exc).__name__,
                        )
                        admitted = False
                    if not admitted:
                        self._release_agent(agent.ctx.agent_id)
                        return
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                if durable_claim:
                    # The durable transaction already set running/agent owner.
                    # After that one-shot commit, no fallible awaited graph,
                    # Redis or bus operation may stand between admission and
                    # launching the in-process worker. A failed observer could
                    # otherwise strand the task in PostgreSQL RUNNING forever
                    # without any attempt having started. The worker executes
                    # only after its supervision claim and current ROE checks.
                    try:
                        self._orch._spawn_agent_execution(agent, task, self._execute_via_agent)
                    except BaseException:
                        # There is no safe generic way to roll back a signed
                        # one-shot admission: a replacement process cannot
                        # prove whether the coroutine was launched.
                        self._release_agent(agent.ctx.agent_id)
                        raise
                    try:
                        await self._orch.session_memory.store_hot(
                            f"task:{task.id}",
                            task.model_dump(),
                            ttl=86400 * 7,
                        )
                    except Exception:
                        logger.warning("local_agent_hot_cache_unavailable", task_id=task.id)
                    try:
                        await self._orch.graph_memory.upsert_task(task)
                    except Exception:
                        logger.warning("local_agent_graph_projection_delayed", task_id=task.id)
                    try:
                        await self._orch.coordination_bus.publish(
                            "task.assigned",
                            {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                            "orchestrator",
                        )
                    except Exception:
                        logger.warning(
                            "local_agent_assignment_notification_delayed", task_id=task.id
                        )
                else:
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)
                    await self._orch.coordination_bus.publish(
                        "task.assigned",
                        {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                        "orchestrator",
                    )
                    self._orch._spawn_agent_execution(agent, task, self._execute_via_agent)
            else:
                if task.status != "awaiting_approval":
                    task.status = "pending"
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)

    async def _find_available_agent(
        self, agent_type: AgentType, task_type: str = ""
    ) -> Optional[Any]:
        """Use the canonical distributed agent claim implementation."""
        return await self._orch._find_available_agent(agent_type, task_type)

    def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release the same local and distributed ownership that was claimed."""
        self._orch._release_agent(agent_id)

    @staticmethod
    def _strip_stale_approval(task: Task) -> None:
        """Drop persisted approval grant so gate re-fires."""
        if task.approval_required and isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)

    def _signed_claim_may_have_external_effects(self, task: Task) -> bool:
        """Claimed signed executions cannot be retried on local failure alone."""
        from ai_osop.memory.session_memory import SessionMemory

        return (
            isinstance(self._orch.session_memory, SessionMemory)
            and isinstance(task.payload, dict)
            and type(task.payload.get("_authorization_version")) is int
            and task.payload["_authorization_version"] > 0
            # Agent adapters may mutate their Task snapshot on error. The
            # immutable assigned owner/ROE version, not that mutable status,
            # identifies an already-claimed execution.
            and bool(task.assigned_agent_id)
        )

    async def _maybe_retry(self, task: Task, result: Dict[str, Any]) -> bool:
        """Requeue a failed task if retry budget remains."""
        if task.retry_count >= task.max_retries:
            try:
                await self._orch.dlq.enqueue(
                    task,
                    reason="retry_budget_exhausted",
                    final_error=str(result.get("error") or result.get("status") or ""),
                )
            except Exception as e:
                logger.error("dlq_enqueue_failed", task_id=task.id, error=str(e))
            return False

        task.retry_count += 1
        backoff = min(2**task.retry_count, 30)
        await self._orch._audit_log(
            AuditEvent(
                event_type="task_retry",
                severity="warning",
                actor_type="system",
                actor_id="orchestrator",
                action={
                    "task_id": task.id,
                    "task_type": task.type,
                    "attempt": task.retry_count,
                    "max_retries": task.max_retries,
                    "backoff_seconds": backoff,
                    "error": str(result.get("error") or result.get("status") or "")[:300],
                },
                result={"requeued": True},
                context={"engagement_id": task.engagement_id},
                engagement_id=task.engagement_id,
            )
        )
        logger.info(
            "retrying_task",
            task_id=task.id,
            task_type=task.type,
            attempt=task.retry_count,
            max_retries=task.max_retries,
            backoff=backoff,
        )

        task.status = "pending"
        task.assigned_agent_id = None
        self._strip_stale_approval(task)
        await self._orch.graph_memory.upsert_task(
            task, result_summary={"retry_attempt": task.retry_count}
        )
        await self._retry_sleep(backoff)
        await self._assign_task(task)
        return True

    async def _retry_sleep(self, seconds: float) -> None:
        """Sleep for retry backoff with short wake-ups for responsiveness."""
        await asyncio.sleep(seconds)

    async def _execute_via_agent(self, agent: Any, task: Task) -> None:
        """Execute task through assigned agent."""
        from ai_osop.core.telemetry import extract_trace_context
        from ai_osop.core.tracing import trace_span_with_parent

        parent_span_context = extract_trace_context(task.trace_context)

        with trace_span_with_parent(
            "orchestrator._execute_via_agent",
            parent_span_context=parent_span_context if parent_span_context.is_valid else None,
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_id": agent.ctx.agent_id,
                "agent_type": agent.ctx.agent_type.value,
                "engagement_id": task.engagement_id,
            },
        ):
            sm = getattr(self._orch, "session_memory", None)
            worker_id = f"worker:{agent.ctx.agent_id}"
            lease_acquired = False
            heartbeat_task = None
            if sm is not None and hasattr(sm, "acquire_task_lease"):
                try:
                    lease_acquired = await sm.acquire_task_lease(task.id, worker_id, ttl_seconds=60)
                except Exception:
                    pass

            async def _heartbeat_loop():
                try:
                    while True:
                        await asyncio.sleep(20)
                        if hasattr(sm, "renew_task_lease"):
                            await sm.renew_task_lease(task.id, worker_id, ttl_seconds=60)
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass

            if lease_acquired:
                heartbeat_task = asyncio.create_task(_heartbeat_loop())

            try:
                result = await self._orch._execute_supervised_agent(agent, task)
                status = result.get("status") if isinstance(result, dict) else None
                if status == "terminal_committed":
                    # The durable callback worker, not this agent worker,
                    # is responsible for the already committed completion.
                    # Do not turn a later callback failure into task retry.
                    task.status = "completed"
                    return
                if status == "execution_unknown":
                    await self._orch._quarantine_unknown_execution(task)
                    return
                if status in self._FAILURE_STATUSES:
                    normalized = result if isinstance(result, dict) else {"status": "failed"}
                    if self._signed_claim_may_have_external_effects(task):
                        # A failed tool/agent response does not prove that an
                        # authenticated target-side request was never accepted.
                        # Leave the persisted one-shot claim UNKNOWN until
                        # independently reconciled, without resetting approval
                        # or consuming a second retry slot.
                        await self._orch._quarantine_unknown_execution(task)
                    elif not await self._maybe_retry(task, normalized):
                        await self._on_task_failure(task, normalized)
                else:
                    normalized = (
                        result if isinstance(result, dict) else {"status": "success", "raw": result}
                    )
                    await self._on_task_success(task, normalized)

            except asyncio.CancelledError:
                # A cancelled local coroutine cannot prove an already
                # dispatched tool has stopped. Preserve emergency-halt final
                # status; otherwise quarantine without a retry or false fail.
                if task.status not in {"cancelled", "halted"}:
                    await self._orch._quarantine_unknown_execution(task)
                raise
            except Exception as e:
                err = {"error": str(e)}
                if self._signed_claim_may_have_external_effects(task):
                    await self._orch._quarantine_unknown_execution(task)
                elif not await self._maybe_retry(task, err):
                    await self._on_task_failure(task, err)
            finally:
                if heartbeat_task is not None:
                    heartbeat_task.cancel()
                if lease_acquired and sm is not None and hasattr(sm, "release_task_lease"):
                    try:
                        await sm.release_task_lease(task.id, worker_id)
                    except Exception:
                        pass
                self._release_agent(agent.ctx.agent_id)

    async def _on_task_success(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle task completion."""
        with trace_span(
            "orchestrator._on_task_success",
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_id": task.assigned_agent_id,
                "engagement_id": task.engagement_id,
            },
        ):
            from ai_osop.memory.session_memory import SessionMemory

            durable = isinstance(self._orch.session_memory, SessionMemory)
            if durable and not await self._orch.session_memory.settle_local_task_terminal_atomic(
                task,
                "completed",
                result,
            ):
                logger.warning("stale_local_success_callback_ignored", task_id=task.id)
                return
            task.result = result
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            await self._orch.graph_memory.upsert_task(task, result_summary=result)
            if not durable:
                await self._orch.session_memory.store_task(task)
            await self._orch.coordination_bus.publish(
                "task.completed",
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    # Bus notifications are shared across subscribers and
                    # may be logged. Persisted evidence remains in its
                    # engagement-controlled store, not broadcast verbatim.
                    "status": "completed",
                },
                "orchestrator",
            )
            if hasattr(self._orch, "_sync_subtask_result"):
                await self._orch._sync_subtask_result(task, "completed", result)
            if hasattr(self._orch, "_refine_completed_flow_subtask"):
                await self._orch._refine_completed_flow_subtask(task, result)
            record_task(
                "completed",
                task.agent_type.value,
                (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.completed_at and task.started_at
                    else 0.0
                ),
            )
            # Trigger downstream
            await self._trigger_downstream_tasks(task)
            await self._chain_authenticated_surface(task)
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"downstream_triggered": True}
            )
            if not durable:
                await self._orch.session_memory.store_task(task)
            if hasattr(self._orch, "adaptive_planner"):
                try:
                    await self._orch.adaptive_planner.on_task_completed(task)
                except Exception as exc:
                    logger.warning(
                        "adaptive_planning_after_task_failed", task_id=task.id, error=str(exc)
                    )

    async def _on_task_failure(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle task failure."""
        with trace_span(
            "orchestrator._on_task_failure",
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_id": task.assigned_agent_id,
                "engagement_id": task.engagement_id,
                "error": str(result.get("error", ""))[:120],
            },
        ):
            from ai_osop.memory.session_memory import SessionMemory

            durable = isinstance(self._orch.session_memory, SessionMemory)
            if durable and not await self._orch.session_memory.settle_local_task_terminal_atomic(
                task,
                "failed",
                result,
            ):
                logger.warning("stale_local_failure_callback_ignored", task_id=task.id)
                return
            task.result = result
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"error": str(result.get("error", ""))[:300]}
            )
            if not durable:
                await self._orch.session_memory.store_task(task)
            await self._orch.coordination_bus.publish(
                "task.failed",
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    "status": "failed",
                },
                "orchestrator",
            )
            if hasattr(self._orch, "_sync_subtask_result"):
                await self._orch._sync_subtask_result(task, "failed", result)
            if task.retry_count >= task.max_retries:
                try:
                    await self._orch.dlq.enqueue(
                        task,
                        reason="terminal_failure",
                        final_error=str(result.get("error") or result.get("status") or ""),
                    )
                except Exception as e:
                    logger.error("dlq_enqueue_fallback_failed", task_id=task.id, error=str(e))

    async def _trigger_downstream_tasks(self, parent: Task) -> None:
        """Dispatch only children whose declared parent tasks all succeeded."""
        # Graph-backed lineage is useful for audit/recovery; the canonical
        # dependency list for execution resides on the persisted Task itself.
        for child in list(self._orch._tasks.values()):
            if parent.id not in child.dependencies or child.status != "pending":
                continue
            if all(
                self._orch._tasks.get(dep_id) is not None
                and self._orch._tasks[dep_id].status == "completed"
                for dep_id in child.dependencies
            ):
                await self._assign_task(child)

    async def _chain_authenticated_surface(self, task: Task) -> None:
        """If the just-completed task was auth_diff, auto-discover the authenticated surface."""
        if task.type != "auth_diff":
            return
        engagement_id = task.engagement_id
        from ai_osop.memory.session_memory import SessionMemory

        if isinstance(self._orch.session_memory, SessionMemory):
            # In signed deployments, the manager verifies the completed source
            # TaskORM and calls the canonical PG-first discovery admission.
            # Graph session flags, availability hints and vanished legacy
            # scheduling entrypoints must not gate/recreate this child.
            await self._orch.engagement_manager.claim_auto_discovery(engagement_id, "", task.id)
            return
        if not await self._orch.engagement_manager._engagement_is_authenticated(engagement_id):
            return

        # Find an available recon agent and dispatch it as an autonomous task
        recon_agent = await self._find_available_agent(AgentType.RECON)
        if not recon_agent:
            logger.info("no_recon_agent_for_chained_surface", engagement_id=engagement_id)
            return

        auth_user_label = await self._orch.engagement_manager._pick_auth_user_label(engagement_id)
        if not auth_user_label:
            logger.info("no_auth_user_label_for_chained_surface", engagement_id=engagement_id)
            return

        await self._orch.engagement_manager.claim_auto_discovery(
            engagement_id, auth_user_label, task.id
        )

    async def _persist_task_dependency(self, parent: Task, child: Task) -> None:
        """Persist a parent→child dependency in the graph."""
        await self._orch.graph_memory.link_task_dependency(parent.id, child.id)
