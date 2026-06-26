"""TaskScheduler — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all task scheduling, assignment, execution, retry, and lifecycle management.
The Orchestrator retains ownership of shared state (agents, tasks, busy_agents)
and passes itself as context so the scheduler can access it.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timedelta
from typing import Any, Dict, Optional

import structlog

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.exceptions import WorkflowException
from ai_osop.orchestrator.state_machine import EngagementStateMachine
from ai_osop.core.models import ApprovalRequest, AuditEvent, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span
from ai_osop.core.observability import record_task, update_task_counts

logger = structlog.get_logger("ai_osop.orchestrator.task_scheduler")


class TaskScheduler:
    """Schedule, assign, execute, and retry tasks."""

    # Terminal failure statuses that should not trigger retry success path
    _FAILURE_STATUSES = {"failed", "error", "timeout", "cancelled"}
    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator
        self.state_machine = EngagementStateMachine(self._orch.session_memory)

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution."""
        from ai_osop.core.telemetry import inject_trace_context

        if not task.trace_context:
            inject_trace_context(task.trace_context)
        RequestContext.bind(
            task_id=task.id,
            engagement_id=task.engagement_id,
            trace_id=task.trace_context.get("traceparent", "").split("-")[1]
            if task.trace_context.get("traceparent")
            else "",
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
            # REL-006: exploit-class tasks ALWAYS require approval and may never
            # carry a caller-supplied approval token. Only resolve_approval (after a
            # real operator decision) re-adds the token. Sanitizing here closes the
            # GAP-2-1 self-authorization vector for anything entering via schedule_task.
            if task.agent_type == AgentType.EXPLOIT_VALIDATION or task.type in (
                "validate_exploit",
                "exploit_validation",
            ):
                task.approval_required = True
            self._sanitize_external_payload(task)
            self._orch._tasks[task.id] = task
            await self._orch.graph_memory.upsert_task(task)
            await self._orch.session_memory.store_task(task)
            await self._orch.coordination_bus.publish(
                "task.scheduled",
                {"task_id": task.id, "task_type": task.type, "agent_type": task.agent_type.value},
                "orchestrator",
            )
            await self._orch.session_memory.push_task_queue(
                f"tasks:{task.engagement_id}", task.model_dump()
            )

            if self._orch.temporal_enabled and self._orch.temporal_scheduler:
                workflow_id = await self._orch.temporal_scheduler.start_task_workflow(task.model_dump())
                task.status = "scheduled"
                task.result = {"workflow_id": workflow_id, "durable": True}
                return task

            if not task.dependencies:
                await self._assign_task(task)

            return task

    async def _execute_task_durable(self, task: Task) -> Dict[str, Any]:
        """Execute task durably, waiting for an available agent if necessary, with timeout."""
        self._orch._tasks[task.id] = task
        start_time = asyncio.get_event_loop().time()
        timeout = task.timeout_seconds or 300

        while True:
            agent = await self._find_available_agent(task.agent_type, task.type)
            if agent:
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                try:
                    result = await agent.execute_task(task)
                    status = result.get("status") if isinstance(result, dict) else None
                    if status in self._FAILURE_STATUSES:
                        task.status = "failed"
                        task.result = result
                    else:
                        task.status = "completed"
                        task.result = (
                            result if isinstance(result, dict) else {"status": "success", "raw": result}
                        )
                    await self._orch.session_memory.store_task(task)
                    return task.result
                except Exception as e:
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                    await self._orch.session_memory.store_task(task)
                    return task.result
                finally:
                    await self._release_agent(agent.ctx.agent_id)

            if asyncio.get_event_loop().time() - start_time > timeout:
                task.status = "failed"
                task.result = {"status": "failed", "error": "Timeout waiting for agent"}
                await self._orch.session_memory.store_task(task)
                return task.result

            await asyncio.sleep(0.5)

    async def _assign_task(self, task: Task) -> None:
        """Assign task to appropriate agent."""
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

            # GAP-3-1: phase/task contract. If we know the engagement's current phase,
            # refuse to dispatch a task that is not permitted in it (e.g. an exploit
            # validation while still in reconnaissance). Defense-in-depth on top of the
            # approval gate. Skipped only when the phase is unknown (no in-memory
            # session), where the approval gate still protects exploit-class tasks.
            session = self._orch._sessions.get(task.engagement_id)
            if session is not None:
                try:
                    self.state_machine.assert_task_allowed(
                        task, EngagementPhase(session.phase)
                    )
                except WorkflowException as e:
                    logger.warning(
                        "task_phase_violation", task_id=task.id, error=str(e)
                    )
                    await self._on_task_failure(
                        task, {"error": str(e), "error_type": "PhaseViolation"}
                    )
                    return

            # GAP-2-4: tamper detection for exploit-class tasks. If the engagement's
            # scope carries a signature that no longer verifies, the manifest was
            # altered after creation — refuse to run the exploit and audit it. (Legacy
            # unsigned scopes are allowed through; signing happens at creation now.)
            if task.agent_type == AgentType.EXPLOIT_VALIDATION or task.type in (
                "validate_exploit",
                "exploit_validation",
            ):
                _sess = self._orch._sessions.get(task.engagement_id)
                _scope = getattr(_sess, "scope", None) if _sess is not None else None
                if _scope is not None and getattr(_scope, "signature", None):
                    from ai_osop.core.config import scope_signing_key

                    if not _scope.verify_signature(scope_signing_key()):
                        logger.error("scope_signature_invalid", task_id=task.id)
                        await self._on_task_failure(
                            task,
                            {"error": "scope signature invalid", "error_type": "ScopeTamper"},
                        )
                        return

            # Approval gate FIRST. Authority is the operator-resolved ApprovalRequest
            # record (is_task_approved), NEVER task.payload.operator_approved — that
            # field is agent-writable/persisted and trusting it is the GAP-2-2 bypass.
            logger.info("assign_task_attempt", task_id=task.id)
            if task.approval_required and not self._orch.approval_coordinator.is_task_approved(
                task.id
            ):
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
            logger.info("find_agent_result", agent=agent)
            if not agent:
                logger.info("no_agent_found", task_id=task.id)
            if agent:
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                await self._orch.graph_memory.upsert_task(task)
                await self._orch.session_memory.store_task(task)
                await self._orch.coordination_bus.publish(
                    "task.assigned",
                    {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                    "orchestrator",
                )
                # GAP-2-6: retain the handle so halt_engagement can cancel it.
                handle = asyncio.create_task(self._execute_via_agent(agent, task))
                handles = getattr(self._orch, "_task_handles", None)
                if handles is not None:
                    handles[task.id] = handle
            else:
                task.status = "pending"
                await self._orch.graph_memory.upsert_task(task)
                await self._orch.session_memory.store_task(task)

    async def _find_available_agent(
        self, agent_type: AgentType, task_type: str = ""
    ) -> Optional[Any]:
        """Find and atomically claim an idle agent."""
        for agent in self._orch._agents.values():
            logger.info("matching_debug", agent_id=agent.ctx.agent_id, type_match=(str(agent.ctx.agent_type) == str(agent_type)), agent_type=str(agent.ctx.agent_type), target_type=str(agent_type), status=agent.ctx.status, status_match=(agent.ctx.status == "idle"))
            if str(agent.ctx.agent_type) == str(agent_type) and agent.ctx.status == "idle":
                if task_type and hasattr(agent, "supports_task_type"):
                    if not agent.supports_task_type(task_type):
                        continue
                
                # Acquire distributed lock to prevent multi-orchestrator collisions
                lock_key = f"lock:agent:{agent.ctx.agent_id}"
                success = await self._orch.session_memory.acquire_lock(lock_key, "locked")
                if not success:
                    continue
                
                await self._orch.session_memory.add_busy_agent(agent.ctx.agent_id)
                return agent
        return None

    async def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release an agent claim."""
        if agent_id:
            await self._orch.session_memory.remove_busy_agent(agent_id)
            lock_key = f"lock:agent:{agent_id}"
            await self._orch.session_memory.release_lock(lock_key, "locked")
    @staticmethod
    def _sanitize_external_payload(task: Task) -> None:
        """Strip operator-approval tokens injected by any non-orchestrator producer
        (agents, queue producers, recovered/persisted records).

        Approval authority is the operator-resolved ApprovalRequest record. The only
        place the payload token is (re)added is resolve_approval, after a real human
        decision. Every other ingress must be stripped so a caller cannot self-grant
        approval (GAP-2-1) or replay a persisted grant (GAP-2-3)."""
        if isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)

    async def ingest_queued_task(self, task: Task) -> None:
        """Assign a task that arrived from the Redis work queue.

        Queue producers include agents (e.g. AttackChainAgent), so this is an
        UNTRUSTED boundary: re-apply REL-006 and strip any self-granted approval
        token before assignment. Without this, an agent could push a pre-approved
        exploit_validation task straight to the queue and bypass the gate."""
        if task.agent_type == AgentType.EXPLOIT_VALIDATION or task.type in (
            "validate_exploit",
            "exploit_validation",
        ):
            task.approval_required = True
        self._sanitize_external_payload(task)
        await self._assign_task(task)

    @staticmethod
    def _strip_stale_approval(task: Task) -> None:
        """Drop persisted approval grant so gate re-fires."""
        if task.approval_required and isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)

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
        await self._orch._retry_sleep(backoff)
        await self._orch._assign_task(task)
        return True

    async def _retry_sleep(self, seconds: float) -> None:
        """Sleep for retry backoff with short wake-ups for responsiveness."""
        await asyncio.sleep(seconds)

    async def _execute_via_agent(self, agent: Any, task: Task) -> None:
        """Execute task through assigned agent."""
        from ai_osop.core.telemetry import extract_trace_context
        from ai_osop.core.tracing import trace_span_with_parent

        parent_span_context = extract_trace_context(task.trace_context)
        
        if parent_span_context.is_valid:
            span_ctx = trace_span_with_parent(
                "orchestrator._execute_via_agent",
                parent_span_context=parent_span_context,
                attributes={
                    "task_id": task.id,
                    "task_type": task.type,
                    "agent_id": agent.ctx.agent_id,
                    "agent_type": agent.ctx.agent_type.value,
                    "engagement_id": task.engagement_id,
                },
            )
        else:
            span_ctx = trace_span(
                "orchestrator._execute_via_agent",
                attributes={
                    "task_id": task.id,
                    "task_type": task.type,
                    "agent_id": agent.ctx.agent_id,
                    "agent_type": agent.ctx.agent_type.value,
                    "engagement_id": task.engagement_id,
                },
            )

        with span_ctx:
            try:
                result = await agent.execute_task(task)
                status = result.get("status") if isinstance(result, dict) else None
                if status in self._FAILURE_STATUSES:
                    normalized = result if isinstance(result, dict) else {"status": "failed"}
                    if not await self._maybe_retry(task, normalized):
                        await self._on_task_failure(task, normalized)
                else:
                    normalized = (
                        result if isinstance(result, dict) else {"status": "success", "raw": result}
                    )
                    await self._on_task_success(task, normalized)

            except asyncio.CancelledError:
                await self._on_task_failure(
                    task, {"error": "execution cancelled", "error_type": "CancelledError"}
                )
                raise
            except Exception as e:
                err = {"error": str(e)}
                if not await self._maybe_retry(task, err):
                    await self._on_task_failure(task, err)
            finally:
                await self._release_agent(agent.ctx.agent_id)
                handles = getattr(self._orch, "_task_handles", None)
                if handles is not None:
                    handles.pop(task.id, None)

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
            task.result = result
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            await self._orch.graph_memory.upsert_task(task, result_summary=result)
            await self._orch.session_memory.store_task(task)
            await self._orch.coordination_bus.publish(
                "task.completed",
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    "result": result,
                },
                "orchestrator",
            )
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
            await self._orch.session_memory.store_task(task)

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
            task.result = result
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"error": str(result.get("error", ""))[:300]}
            )
            await self._orch.session_memory.store_task(task)
            await self._orch.coordination_bus.publish(
                "task.failed",
                {"task_id": task.id, "agent_id": task.assigned_agent_id, "result": result},
                "orchestrator",
            )
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
        """Launch child tasks that depend on parent completion."""
        # Use Neo4j as the ground-truth dependency graph so restart recovery and
        # concurrent scheduling have the same source of truth. We need the parent's
        # DEPENDENTS (tasks that list parent.id as a dependency), not the parent's
        # own dependencies — the prior call used get_task_dependencies, which (a) did
        # not exist on GraphMemory and (b) is the wrong direction.
        try:
            child_ids = await self._orch.graph_memory.get_task_dependents(parent.id)
        except Exception as e:
            logger.error("graph_lookup_failed", parent_id=parent.id, error=str(e))
            return
        for child_id in child_ids:
            child = self._orch._tasks.get(child_id)
            if child and child.status == "pending":
                all_deps = await self._orch.graph_memory.get_task_dependencies(child.id)
                if all(
                    self._orch._tasks.get(dep_id, Task(id=dep_id, type="", agent_type=AgentType.RECON, engagement_id="")).status
                    in ("completed", "failed")
                    for dep_id in all_deps
                ):
                    await self._assign_task(child)

    async def _chain_authenticated_surface(
        self, task: Task, result: Optional[Dict[str, Any]] = None
    ) -> None:
        """Chain authenticated surface discovery tasks automatically."""
        if not result:
            result = {}

        eid = task.engagement_id

        # 1. auth_diff -> autonomous discovery
        if task.type == "auth_diff":
            if not await self._orch._engagement_is_authenticated(eid):
                return

            recon_agent = await self._find_available_agent(AgentType.RECON)
            if not recon_agent:
                logger.info("no_recon_agent_for_chained_surface", engagement_id=eid)
                return

            auth_user_label = await self._orch._pick_auth_user_label(eid)
            if not auth_user_label:
                logger.info("no_auth_user_label_for_chained_surface", engagement_id=eid)
                return

            await self._orch.claim_auto_discovery(
                eid, auth_user_label, task.id
            )
            return

        # 2. map_workflow -> capture_authenticated_surface
        elif task.type == "map_workflow":
            if not await self._orch._engagement_is_authenticated(eid):
                return
            workflow_id = result.get("workflow_id")
            if not workflow_id:
                return

            child = Task(
                type="capture_authenticated_surface",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "url": task.payload.get("url", ""),
                    "user_label": task.payload.get("user_label", "guest"),
                    "workflow_id": workflow_id,
                },
                dependencies=[task.id],
                engagement_id=eid,
            )

        # 3. capture_authenticated_surface -> extract_har_api_inventory
        elif task.type == "capture_authenticated_surface":
            har_path = result.get("har_path")
            if not har_path:
                return

            child = Task(
                type="extract_har_api_inventory",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "har_path": har_path,
                    "user_label": task.payload.get("user_label", "guest"),
                    "workflow_id": task.payload.get("workflow_id", ""),
                },
                dependencies=[task.id],
                engagement_id=eid,
            )

        # 4. extract_har_api_inventory -> replay_for_diff_auth
        elif task.type == "extract_har_api_inventory":
            workflow_id = task.payload.get("workflow_id")
            if not workflow_id:
                return

            child = Task(
                type="replay_for_diff_auth",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "workflow_id": workflow_id,
                },
                dependencies=[task.id],
                engagement_id=eid,
            )
        else:
            return

        # Deduplicate using graph_memory.task_has_spawned
        if await self._orch.graph_memory.task_has_spawned(task.id):
            return

        # Persist spawned edge in Neo4j
        async with self._orch.graph_memory._driver.session() as g_session:
            await g_session.run(
                "MATCH (p:Task {id: $parent_id}), (c:Task {id: $child_id}) MERGE (p)-[:SPAWNED]->(c)",
                {"parent_id": task.id, "child_id": child.id}
            )

        # Audit log event
        await self._orch._audit_log(
            AuditEvent(
                event_type="auto_task_chain",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={
                    "trigger_task_id": task.id,
                    "created_type": child.type,
                },
                result={"success": True},
                context={"engagement_id": eid},
                engagement_id=eid,
            )
        )

        # Schedule the child task
        await self._orch.schedule_task(child)
    async def _persist_task_dependency(self, parent: Task, child: Task) -> None:
        """Persist a parent→child dependency in the graph."""
        await self._orch.graph_memory.link_task_dependency(parent.id, child.id)
