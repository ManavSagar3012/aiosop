"""
Base Agent Architecture
Abstract base class for all AI-OSOP agents with lifecycle management,
memory integration, and structured reasoning.
"""

import asyncio
import json
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import structlog

from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import (
    AgentException,
    AgentTaskFailed,
    ApprovalDeniedError,
    ScopeValidationError,
    WorkflowException,
)
from ai_osop.core.models import AuditEvent, FlowRecord, ScopeDefinition, SessionState, Task
from ai_osop.core.observability import record_task
from ai_osop.core.telemetry import RequestContext, extract_trace_context
from ai_osop.core.tracing import trace_span, trace_span_with_parent
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.vector_memory import VectorMemory

agent_logger = structlog.get_logger("ai_osop.agents")


class AgentContext:
    """Runtime context provided to agents."""

    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        session_id: str,
        session_memory: SessionMemory,
        graph_memory: GraphMemory,
        vector_memory: VectorMemory,
        llm_client: Any,  # LiteLLMClient
        mcp_registry: Any,
        rate_limiter: Any,
        threat_intel_adapter: Any,
        audit_callback: Callable[[AuditEvent], None],
        coordination_bus: Any,
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.session_id = session_id
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.vector_memory = vector_memory
        self.llm_client = llm_client
        self.mcp_registry = mcp_registry
        self.rate_limiter = rate_limiter
        self.threat_intel_adapter = threat_intel_adapter
        self.audit_callback = audit_callback
        self.coordination_bus = coordination_bus

        self.working_memory: Dict[str, Any] = {}
        self.task_history: List[str] = []
        self.current_task: Optional[Task] = None
        self.status = "idle"
        self.last_heartbeat = datetime.utcnow()
        # PlaywrightAgent reads scope to scope-check before navigation.
        # None is a valid "no scope override" signal.
        self.scope: Optional[ScopeDefinition] = None
        # task_executor is used by DifferentialAuthEngine for replay loops.
        # PlaywrightAgent's navigate path doesn't require it.
        self.task_executor: Optional[Callable] = None
        self.skill_engine: Optional[Any] = None
        self.persona: Optional[str] = None
        self.cost_incurred: float = 0.0
        # Bound by the orchestration worker for each authorized execution.
        # A task without this adapter retains the legacy test-only path.
        self.supervision_store: Optional[Any] = None
        self.supervision_consumer_id: Optional[str] = None


class BaseAgent(ABC):
    """
    Abstract base for all AI-OSOP agents.

    Lifecycle:
    1. initialize() → Setup working memory, load prior context
    2. execute_task(task) → Process assigned task
    3. heartbeat() → Report status, handle health checks
    4. shutdown() → Persist state, cleanup resources
    """

    def __init__(self, context: AgentContext):
        self.ctx = context
        self._running = False
        self._shutting_down = False  # Sprint 7: prevent new tasks during shutdown
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._max_concurrent_tasks = 3
        self._active_tasks: Dict[str, asyncio.Task] = {}
        # AIOSOP-AUDIT-2026-06-16: track the background worker/heartbeat loop
        # handles so shutdown() can actually cancel them. Previously start()
        # discarded these handles, leaking tasks (the worker blocks forever on
        # _task_queue.get() and never observes _running=False).
        self._bg_tasks: list[asyncio.Task] = []
        # AIOSOP-AUDIT-2026-06-16: task ids whose skill activations were already
        # recorded, so coverage can be extended to every agent without double-counting
        # for agents (recon/vuln) that also resolve skills inside _execute.
        self._activated_tasks: set = set()

    @property
    @abstractmethod
    def agent_type(self) -> AgentType:
        """Return the agent's type."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        """Check if this agent supports the specified task type."""
        from ai_osop.agents.capabilities import AGENT_TASK_TYPES

        return task_type in AGENT_TASK_TYPES.get(type(self).__name__, frozenset())

    async def initialize(self) -> None:
        """Initialize agent state from persistent memory."""
        self.ctx.status = "initializing"

        # Load prior working memory if exists
        prior_state = await self.ctx.session_memory.get_agent_state(self.ctx.agent_id)
        # get_agent_state must return a materialized dict, not a coroutine,
        # AsyncMock sentinel or arbitrary decoded object. In test fixtures,
        # calling AsyncMock.get() leaked unawaited coroutines; in production an
        # invalid cache value could corrupt the agent's context.
        if isinstance(prior_state, dict):
            working = prior_state.get("working_memory", {})
            history = prior_state.get("task_history", [])
            if isinstance(working, dict):
                self.ctx.working_memory = working
            if isinstance(history, list):
                self.ctx.task_history = history

        # Initialize agent-specific resources
        await self._setup_resources()

        self.ctx.status = "idle"
        self._running = True

        # Start task worker and heartbeat loop (retain handles for shutdown)
        self._bg_tasks = [
            asyncio.create_task(self._task_worker()),
            asyncio.create_task(self._heartbeat_loop()),
        ]

    async def _task_worker(self) -> None:
        """Background worker to process tasks from the queue.

        Sprint 7: Uses sentinel (None) for graceful shutdown to prevent
        the worker from blocking forever on an empty queue when the agent
        is shutting down. The shutdown() method injects a sentinel to wake
        the worker so it can observe _running=False and exit cleanly.
        """
        while self._running:
            try:
                task = await self._task_queue.get()
                if task is None:
                    # Sentinel: shutdown signal, exit the loop
                    self._task_queue.task_done()
                    break
                await self.execute_task(task)
                self._task_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                agent_logger.error("worker_error", agent_id=self.ctx.agent_id, error=str(e))
                await asyncio.sleep(5)

    @abstractmethod
    async def _setup_resources(self) -> None:
        """Agent-specific resource initialization."""
        pass

    # Hard ceiling for any single agent task. Long enough for real browser/scan
    # work, short enough to prevent permanent hangs (Issue 3).
    DEFAULT_TASK_TIMEOUT_SECONDS = 300

    def _supervision(self, task: Optional[Task] = None) -> Optional[Any]:
        """Resolve a task-scoped checkpoint adapter without cross-task reuse."""
        current = task or self.ctx.current_task
        store = getattr(self.ctx, "supervision_store", None)
        if current is None or store is None:
            return None
        from ai_osop.agents.supervision import AgentSupervision

        owner = getattr(self.ctx, "supervision_consumer_id", None)
        if not isinstance(owner, str) or not owner:
            owner = "agent-" + uuid.uuid4().hex
            self.ctx.supervision_consumer_id = owner
        return AgentSupervision(
            store,
            current.engagement_id,
            current.id,
            owner,
            lambda: self._validate_task(current),
        )

    async def supervision_checkpoint(self, task: Optional[Task] = None) -> None:
        """Cooperative pause/cancel boundary; never claims to pause MCP tools."""
        gate = self._supervision(task)
        if gate is not None:
            await gate.checkpoint()

    async def execute_task(self, task: Task) -> Dict[str, Any]:
        """
        Execute a task with full lifecycle management.

        1. Validate task
        2. Load context
        3. Execute (agent-specific) UNDER A TIMEOUT
        4. Validate output
        5. Store results
        6. Audit logging
        """
        # Sprint 6: extract trace context from task to continue the distributed trace
        parent_span_context = extract_trace_context(task.trace_context)
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

        with trace_span_with_parent(
            "agent.execute_task",
            parent_span_context=parent_span_context if parent_span_context.is_valid else None,
            attributes={
                "agent_id": self.ctx.agent_id,
                "agent_type": self.ctx.agent_type.value,
                "task_id": task.id,
                "task_type": task.type,
                "engagement_id": task.engagement_id,
            },
        ):
            self.ctx.current_task = task
            self.ctx.status = "running"
            # Carry the per-task engagement_id into the context so all downstream
            # graph + evidence writes use the correct scope (Issue 14 — evidence
            # was previously landing under the agent's static "global" session).
            self.ctx.session_id = task.engagement_id

            # Signed TaskORM payload and its SHA-256 are immutable provenance.
            # Runtime convenience aliases belong ONLY on the private per-call
            # execution view. Mutating the original Task after its PG claim
            # invalidates later signed context checkpoints/terminal receipts
            # and may strand an otherwise authorized Flow as UNKNOWN.
            execution_task = task.model_copy(deep=True)
            # PATCH (REL-029/030/031/033, 2026-06-15): Agents historically disagreed
            # on payload shape (`url`/`target`/`target_url`/`domain`/`targets`/`vuln_class`/
            # `vuln_type`). External callers (UI, CLI, audit scripts) couldn't predict the
            # right key per agent, causing silent KeyError -> task failure. Normalize
            # common aliases up front so individual agents can read whichever key they
            # historically used. Keys are added only if missing; original keys preserved.
            if isinstance(execution_task.payload, dict):
                p = execution_task.payload
                url_aliases = ("url", "target_url", "target", "domain")
                resolved_url = next((p[k] for k in url_aliases if p.get(k)), None)
                if resolved_url:
                    for k in url_aliases:
                        p.setdefault(k, resolved_url)
                list_url = p.get("targets")
                if not list_url and resolved_url:
                    p.setdefault("targets", [resolved_url])
                if isinstance(list_url, str):
                    p["targets"] = [list_url]
                vuln_aliases = ("vuln_type", "vuln_class")
                resolved_vt = next((p[k] for k in vuln_aliases if p.get(k)), None)
                if resolved_vt:
                    for k in vuln_aliases:
                        p.setdefault(k, resolved_vt)
                p.setdefault("engagement_id", task.engagement_id)

            target = (
                task.payload.get("target") or task.payload.get("url") or task.payload.get("domain")
            )
            tool = self.ctx.agent_type.value
            timeout_s = (
                task.payload.get("task_timeout_seconds") or self.DEFAULT_TASK_TIMEOUT_SECONDS
            )

            # Rate Limiting
            await self.ctx.rate_limiter.acquire(target=target, tool=tool)

            task.started_at = datetime.utcnow()
            start_time = time.monotonic()

            try:
                # Pre-execution validation
                await self._validate_task(task)
                await self.supervision_checkpoint(task)

                # AIOSOP-AUDIT-2026-06-16: record skill activations for EVERY agent's
                # task (not just recon/vuln). Feeds the now-durable reputation/effectiveness
                # loop platform-wide. Idempotent + best-effort; never blocks execution.
                try:
                    await self._get_relevant_skills(execution_task)
                except Exception:
                    pass

                # Execute agent-specific logic under a hard timeout. An unbounded
                # _execute previously left agents permanently "running" (Issue 3).
                try:
                    result = await asyncio.wait_for(
                        self._execute(execution_task), timeout=timeout_s
                    )
                except asyncio.TimeoutError as te:
                    # Timeout stops our wait, not necessarily a remote MCP
                    # operation already accepted by the provider. This must
                    # not enter the normal automatic retry path.
                    task.status = "dispatch_unknown"
                    task.completed_at = datetime.utcnow()
                    await self._log_task_failure(task, te)
                    return {
                        "status": "execution_unknown",
                        "error_type": "TimeoutError",
                    }

                end_time = time.monotonic()
                if target:
                    self.ctx.rate_limiter.record_backpressure(target, end_time - start_time)

                # Post-execution validation
                validated_result = await self._validate_output(result)
                if isinstance(validated_result, dict) and validated_result.get("status") in {
                    "unknown",
                    "execution_unknown",
                    "timeout",
                }:
                    task.status = "dispatch_unknown"
                    task.result = {"status": "execution_unknown"}
                    task.completed_at = datetime.utcnow()
                    return task.result

                # PATCH (REL-017, 2026-06-15): If the agent returned an in-band
                # failure dict (e.g. `{"status": "failed", "error": "..."}`), the
                # old path still marked the task `completed` and wrote a
                # `task_completed` audit event whose `error` field was the empty
                # string from `_log_task_completion`. That hid root causes. Now we
                # honor returned failure status by re-raising so the standard
                # `_log_task_failure` path captures the error message.
                if isinstance(validated_result, dict) and validated_result.get("status") in (
                    "failed",
                    "error",
                    "unsupported",
                    "not_executed",
                ):
                    err_msg = (
                        validated_result.get("error")
                        or "agent returned failure status without error message"
                    )
                    raise AgentException(str(err_msg))

                # Store results
                task.result = validated_result
                task.status = "completed"
                task.completed_at = datetime.utcnow()

                # Update working memory
                self.ctx.task_history.append(task.id)
                await self._update_working_memory(task, validated_result)

                # Audit log
                await self._log_task_completion(task, validated_result)
                record_task(
                    task.status,
                    self.ctx.agent_type.value,
                    (
                        (task.completed_at - task.started_at).total_seconds()
                        if task.completed_at and task.started_at
                        else 0.0
                    ),
                )

                return validated_result

            except asyncio.CancelledError:
                # Engagement halt owns the final cancelled state. Overwriting
                # it here would resurrect an already-stopped operation as a
                # failed/retryable task after the operator receives the halt.
                if task.status != "cancelled":
                    task.status = "cancelled"
                    task.result = {
                        "status": "cancelled",
                        "error_type": "CancelledError",
                    }
                task.completed_at = datetime.utcnow()
                raise
            except Exception as e:
                from ai_osop.agents.supervision import SupervisionDeliveryUncertain

                if isinstance(e, SupervisionDeliveryUncertain):
                    # The model may have received an input and executed some
                    # task logic before a lost durable ACK. Do not blindly
                    # replay external side effects because the ACK failed.
                    task.status = "dispatch_unknown"
                    task.result = {"status": "execution_unknown"}
                    task.completed_at = datetime.utcnow()
                    await self._log_task_failure(task, e)
                    return task.result
                task.status = "failed"
                # P0-2: retry_count owned solely by the orchestrator's _maybe_retry.
                task.completed_at = datetime.utcnow()

                await self._log_task_failure(task, e)

                # P0-2 (single retry owner): the ORCHESTRATOR's _maybe_retry is the sole
                # retry authority. The agent must NOT self-schedule a retry onto its
                # internal _task_queue — doing so duplicated execution (e.g. an exploit
                # ran twice) and double-counted retry_count. Return the failure dict so
                # _execute_via_agent routes it through _maybe_retry exactly once.
                return {"status": "failed", "error": str(e)}

            finally:
                self.ctx.current_task = None
                self.ctx.status = "idle"
                self.ctx.last_heartbeat = datetime.utcnow()
                RequestContext.clear()

    @abstractmethod
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Agent-specific task execution logic."""
        pass

    async def _validate_task(self, task: Task) -> None:
        """Recheck durable engagement boundaries at the final agent entry point.

        Scheduling and Temporal validate their own inputs, but they cannot
        substitute for this check: scope and approval can change while a task
        waits for an agent. Missing persistence fails closed.
        """
        from ai_osop.safety.scope import (
            ScopeEnforcer,
            action_requires_approval,
            validate_payload_targets,
        )

        session = await self.ctx.session_memory.load_session_state(task.engagement_id)
        if not isinstance(session, SessionState):
            raise ScopeValidationError("Execution requires a persisted authorized engagement")
        from ai_osop.memory.session_memory import SessionMemory

        if isinstance(self.ctx.session_memory, SessionMemory):
            try:
                version = task.payload.get("_authorization_version")
                if type(version) is not int or version < 1:
                    raise ValueError("Execution task lacks signed policy version")
                await self.ctx.session_memory.assert_signed_authorization(
                    task.engagement_id, expected_version=version
                )
            except Exception as exc:
                raise ScopeValidationError(
                    "Signed ROE is missing, expired, revoked or mismatched"
                ) from exc
        if session.phase in {"halted", "completed"}:
            raise WorkflowException("Engagement is inactive")
        scope = session.scope
        if not scope.authorization_ref or not (scope.domains or scope.ips):
            raise ScopeValidationError("Explicit authorization and target scope required")
        enforcer = ScopeEnforcer(scope)
        enforcer.validate_time_window()
        if task.scope_check:
            validate_payload_targets(enforcer, task.payload)
        if task.flow_id:
            # Adaptive/Temporal and recovered tasks can bypass the interactive
            # Flow API. Validate operator controls again at the final worker
            # boundary, rather than trusting a cached Flow snapshot.
            flow = await self.ctx.session_memory.load_flow(task.flow_id)
            if (
                not isinstance(flow, FlowRecord)
                or flow.engagement_id != task.engagement_id
                or flow.status not in {"pending", "running"}
            ):
                raise WorkflowException("Flow is paused, closed, or unavailable")

        if task.approval_required or action_requires_approval(task.type, scope):
            approval_id = task.payload.get("approval_id")
            if not isinstance(approval_id, str) or not approval_id:
                raise ApprovalDeniedError("Consequential execution requires persisted approval")
            approved = await self.ctx.session_memory.is_task_approved(
                task.id, task.engagement_id, approval_id
            )
            if approved is not True:
                raise ApprovalDeniedError("Approval not valid for this task and engagement")

        for dep_id in task.dependencies:
            parent = await self.ctx.session_memory.load_task(dep_id)
            if (
                not isinstance(parent, Task)
                or parent.engagement_id != task.engagement_id
                or parent.status != "completed"
            ):
                raise WorkflowException("Task dependency has not completed")

    async def _validate_output(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate agent output against schema."""
        # Schema validation
        # Hallucination detection
        # Confidence threshold checks
        return result

    async def _update_working_memory(self, task: Task, result: Dict[str, Any]) -> None:
        """Update agent working memory with task results."""
        self.ctx.working_memory[task.id] = {
            "type": task.type,
            "status": task.status,
            "result_summary": self._summarize_result(result),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Persist to hot memory
        await self.ctx.session_memory.store_agent_state(
            self.ctx.agent_id,
            {
                "working_memory": self.ctx.working_memory,
                "task_history": self.ctx.task_history,
                "status": self.ctx.status,
            },
        )

    def _summarize_result(self, result: Dict[str, Any]) -> str:
        """Create human-readable summary of result for memory."""
        return json.dumps(result, default=str)[:500]

    async def _log_task_completion(self, task: Task, result: Dict[str, Any]) -> None:
        """Write a bounded audit fact without raw target URLs or model output.

        Signed logs are long-lived and operator-visible. Tool results,
        reasoning strings and target URLs can contain bearer tokens or
        sensitive response bodies, so keep those in separately access-
        controlled evidence stores rather than duplicating them here.
        """
        event = AuditEvent(
            event_type="task_completed",
            severity="info",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action={
                "task_id": task.id,
                "task_type": task.type,
            },
            result={
                "status": task.status,
                "execution_time": (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.completed_at and task.started_at
                    else 0
                ),
            },
            context={"session_id": self.ctx.session_id, "agent_type": self.ctx.agent_type.value},
            engagement_id=task.engagement_id,
        )
        await self.ctx.audit_callback(event)

    async def _log_task_failure(self, task: Task, error: Exception) -> None:
        """Log a failure class without persisting potentially secret error text."""
        event = AuditEvent(
            event_type="task_failed",
            severity="warning",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action={"task_id": task.id, "task_type": task.type, "retry_count": task.retry_count},
            result={"error_type": type(error).__name__},
            context={"session_id": self.ctx.session_id, "agent_type": self.ctx.agent_type.value},
            engagement_id=task.engagement_id,
        )
        await self.ctx.audit_callback(event)

    async def _schedule_retry(self, task: Task, delay: int) -> None:
        """Schedule task retry with delay."""
        await asyncio.sleep(delay)
        await self._task_queue.put(task)

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat for health monitoring."""
        while self._running:
            self.ctx.last_heartbeat = datetime.utcnow()
            await self.ctx.session_memory.store_agent_state(
                self.ctx.agent_id,
                {
                    "status": self.ctx.status,
                    "last_heartbeat": self.ctx.last_heartbeat.isoformat(),
                    "current_task": self.ctx.current_task.id if self.ctx.current_task else None,
                    "task_queue_depth": self._task_queue.qsize(),
                },
                ttl=60,
            )
            await asyncio.sleep(30)

    async def shutdown(self) -> None:
        """Graceful shutdown with state preservation and leak prevention.

        Sprint 7: Fixed shutdown leaks by:
        - Tracking shutdown state to prevent new tasks during shutdown
        - Injecting sentinel (None) into task queue to wake blocked worker
        - Using asyncio.wait with timeout instead of bare await
        - Handling CancelledError explicitly in active task cleanup
        """
        if self._shutting_down:
            return
        self._shutting_down = True
        self._running = False
        self.ctx.status = "shutting_down"

        # Wake the task worker if it's blocked on queue.get()
        try:
            self._task_queue.put_nowait(None)
        except Exception:
            pass

        # Cancel active tasks with timeout
        for task in list(self._active_tasks.values()):
            if not task.done():
                task.cancel()

        if self._active_tasks:
            try:
                await asyncio.wait(
                    [t for t in self._active_tasks.values() if not t.done()],
                    timeout=5.0,
                    return_when=asyncio.ALL_COMPLETED,
                )
            except Exception:
                pass

        # Cancel background worker + heartbeat loops and await their teardown so
        # they don't outlive the agent (AIOSOP-AUDIT-2026-06-16).
        for bg in list(self._bg_tasks):
            if not bg.done():
                bg.cancel()

        if self._bg_tasks:
            try:
                await asyncio.wait(
                    [bg for bg in self._bg_tasks if not bg.done()],
                    timeout=5.0,
                    return_when=asyncio.ALL_COMPLETED,
                )
            except Exception:
                pass
        self._bg_tasks = []

        # Persist final state
        try:
            await self.ctx.session_memory.store_agent_state(
                self.ctx.agent_id,
                {
                    "working_memory": self.ctx.working_memory,
                    "task_history": self.ctx.task_history,
                    "status": "shutdown",
                    "shutdown_at": datetime.utcnow().isoformat(),
                },
                ttl=86400,
            )
        except Exception:
            pass

        await self._cleanup_resources()

    @abstractmethod
    async def _cleanup_resources(self) -> None:
        """Agent-specific resource cleanup."""
        pass

    async def observe(
        self,
        target_id: str,
        obs_type: str,
        data: Dict[str, Any],
        confidence: float = 1.0,
        provenance: str = "live",
    ) -> Dict[str, Any]:
        """Record an Observation to the coordination bus and audit log.
        Returns the observation dict for downstream use."""
        from ai_osop.core.models import Observation

        obs = Observation(
            type=obs_type,
            source_agent_id=self.ctx.agent_id,
            target_id=target_id,
            data=data,
            confidence=confidence,
            provenance=provenance,
            engagement_id=self.ctx.session_id,
        )
        try:
            await self.ctx.coordination_bus.publish(
                "observation", obs.model_dump(), self.ctx.agent_id
            )
        except Exception:
            pass
        try:
            await self.ctx.audit_callback(
                AuditEvent(
                    event_type="agent_observation",
                    severity="info",
                    actor_type="agent",
                    actor_id=self.ctx.agent_id,
                    action={"type": obs_type, "target": target_id},
                    result={"confidence": confidence, "provenance": provenance},
                    context={"data": data},
                    engagement_id=self.ctx.session_id,
                )
            )
        except Exception:
            pass
        return obs.model_dump()

    async def _complete_supervised_messages(self, messages: List[Dict[str, Any]]) -> Any:
        """Single model boundary shared with specialist-agent overrides.

        The DB ACK is deliberately *after* the provider response; a failed or
        cancelled model request leaves the leased input available for another
        attempt when the lease expires, instead of losing operator guidance.
        """
        gate = self._supervision()
        claimed: List[Dict[str, Any]] = []
        if gate is not None:
            claimed = await gate.claim_model_input()
            history = await gate.recent_history_context()
            note = gate.operator_context(claimed)
            if history:
                note = history + ("\n\n" + note if note else "")
            if note:
                messages = [dict(message) for message in messages]
                last_user = next(
                    (
                        index
                        for index in reversed(range(len(messages)))
                        if messages[index].get("role") == "user"
                    ),
                    None,
                )
                if last_user is None:
                    messages.append({"role": "user", "content": note})
                else:
                    messages[last_user]["content"] = (
                        str(messages[last_user].get("content") or "") + "\n\n" + note
                    )
        assigned = self.ctx.current_task
        if assigned is not None and assigned.flow_id:
            # Supervision input/lease acquisition above can wait on durable
            # state. Revalidate the signed Flow and all compacted sources at
            # the *last* model boundary rather than trusting an earlier
            # think() read. An intervening ROE revocation must not send a
            # prompt to the provider. This still is not an atomic dispatch
            # CAS: callers must never treat model output as authorization.
            await asyncio.wait_for(self._verified_flow_context_for_think(assigned), timeout=5)
            # Optional source-verified research is added only at this shared
            # supervised model boundary. It is not a graph summary or a tool
            # response: no raw Neo4j strings, findings, targets or commands
            # enter the prompt. A graph outage, stale ROE or mismatched durable
            # source denies inference before the provider can be contacted.
            from ai_osop.memory.graph_research_context import (
                research_enabled,
                verified_graph_research_context,
            )

            if research_enabled():
                topic = " ".join(
                    message["content"][:2048]
                    for message in messages
                    if message.get("role") == "user" and isinstance(message.get("content"), str)
                )[:4096]
                research = await asyncio.wait_for(
                    verified_graph_research_context(
                        memory=self.ctx.session_memory,
                        graph=self.ctx.graph_memory,
                        current_task=assigned,
                        engagement_id=self.ctx.session_id,
                        topic=topic,
                    ),
                    timeout=15,
                )
                # A parallel orchestration handoff may replace the current
                # Task while the graph read awaits. A replay-verified older
                # Flow cannot be used for another task's next inference.
                if self.ctx.current_task is not assigned:
                    from ai_osop.memory.graph_research_context import GraphResearchDenied

                    raise GraphResearchDenied("Graph research executing task changed")
                if research:
                    messages = [dict(message) for message in messages]
                    last_user = next(
                        (
                            index
                            for index in reversed(range(len(messages)))
                            if messages[index].get("role") == "user"
                        ),
                        None,
                    )
                    if last_user is None:
                        messages.append({"role": "user", "content": research})
                    else:
                        messages[last_user]["content"] = (
                            str(messages[last_user]["content"]) + "\n\n" + research
                        )
        # Independently reviewed Flow *facts* are optional and do not share
        # authority with the model, graph, uploaded files, or Task flags.
        # Resolve references exclusively from current PostgreSQL TaskORM and
        # the senior-reviewed, SHA-pinned FlowArtifactReviewStore receipt.
        # Add a distinct low-priority user DATA message before the unchanged
        # model-window admission and signed PostgreSQL model reservation.
        from ai_osop.memory.reviewed_flow_knowledge import (
            ReviewedFlowKnowledgeDenied,
            reviewed_knowledge_enabled,
            verified_reviewed_flow_knowledge,
        )

        if reviewed_knowledge_enabled():
            if assigned is None or not assigned.flow_id:
                raise ReviewedFlowKnowledgeDenied("Current signed Flow task required for knowledge")
            knowledge = await asyncio.wait_for(
                verified_reviewed_flow_knowledge(
                    memory=self.ctx.session_memory,
                    current_task=assigned,
                    engagement_id=self.ctx.session_id,
                ),
                timeout=12,
            )
            if self.ctx.current_task is not assigned:
                raise ReviewedFlowKnowledgeDenied("Reviewed Flow knowledge executing task changed")
            if knowledge:
                messages = [dict(message) for message in messages]
                messages.append({"role": "user", "content": knowledge})
        # Model-window admission is opt-in and performs a deterministic,
        # deliberately pessimistic byte-capacity check *after* all operator
        # guidance has been merged and signed Flow history reverified. It
        # never drops or rewrites signed task/scope/system/user instructions
        # or the provenance markers of replay-verified prior Flow context.
        # A refusal leaves claimed supervision messages unacknowledged and
        # sends no provider request. The provider tokenizer remains unknown.
        from ai_osop.orchestrator.model_window_admission import admit_model_messages

        messages = admit_model_messages(messages, self.ctx.llm_client)
        result = await self.ctx.llm_client.complete(messages)
        if gate is not None and claimed:
            await gate.acknowledge_model_input(claimed)
            await gate.compact_if_needed()
        return result

    async def _verified_flow_context_for_think(self, task: Task) -> str:
        """Load only replay-verified, signed Flow-scoped context before model I/O.

        A cached summary, index or SHA is NOT an approval or signature. The
        active signed authorization, Flow and Task come from warm storage on
        every inference call. Failure denies inference rather than replacing
        authoritative evidence with unverified context.
        """
        from ai_osop.orchestrator.context_compaction import (
            ContextBoundary,
            ContextCompactionDenied,
            durable_task_sources,
            source_sha256,
            task_assignment_sha256,
            verify_compacted_context,
        )

        memory = self.ctx.session_memory
        sid = task.engagement_id
        expected_version = (
            task.payload.get("_authorization_version") if isinstance(task.payload, dict) else None
        )
        if (
            not task.flow_id
            or sid != self.ctx.session_id
            or type(expected_version) is not int
            or expected_version < 1
        ):
            raise ContextCompactionDenied("A signed Flow task requires an authorization fence")

        async def bounded(coro: Any) -> Any:
            return await asyncio.wait_for(coro, timeout=3)

        signed = await bounded(
            memory.assert_signed_authorization(sid, expected_version=expected_version)
        )
        flow = await bounded(memory.load_flow(task.flow_id))
        current = await bounded(memory.load_task_authoritative(task.id))
        if (
            not isinstance(flow, FlowRecord)
            or flow.id != task.flow_id
            or flow.engagement_id != sid
            or flow.status not in {"pending", "running"}
            or not isinstance(current, Task)
            or current.id != task.id
            or current.engagement_id != sid
            or current.flow_id != task.flow_id
            or current.type != task.type
            or current.status not in {"pending", "running"}
            or current.payload.get("_authorization_version") != expected_version
            or signed.version != expected_version
        ):
            raise ContextCompactionDenied("Flow or current durable task state changed")
        if self.ctx.current_task is not task:
            raise ContextCompactionDenied("Executing task context changed")

        index_key = (
            f"context_compacted_index:{sid}:{flow.id}:" f"{expected_version}:{flow.revision}"
        )
        index = await bounded(memory.retrieve_hot(index_key))
        if index is None:
            # Signed execution remains possible without an optional snapshot.
            # Never fall back to the engagement-wide, model-generated summary.
            final_signed = await bounded(
                memory.assert_signed_authorization(sid, expected_version=expected_version)
            )
            final_flow = await bounded(memory.load_flow(task.flow_id))
            final_current = await bounded(memory.load_task_authoritative(task.id))
            if (
                final_signed.authorization_id != signed.authorization_id
                or final_signed.policy_sha256 != signed.policy_sha256
                or not isinstance(final_flow, FlowRecord)
                or final_flow.id != flow.id
                or final_flow.engagement_id != sid
                or final_flow.revision != flow.revision
                or final_flow.status not in {"pending", "running"}
                or not isinstance(final_current, Task)
                or source_sha256(final_current.model_dump(mode="json"))
                != source_sha256(current.model_dump(mode="json"))
                or self.ctx.current_task is not task
            ):
                raise ContextCompactionDenied("Current Flow authority changed during inference")
            return ""
        if (
            not isinstance(index, dict)
            or set(index)
            != {
                "schema",
                "context_key",
                "producer_task_id",
                "source_task_ids",
                "max_items",
                "snapshot_sha256",
            }
            or index["schema"] != "ai-osop-compaction-index-v1"
        ):
            raise ContextCompactionDenied("Compacted Flow locator is untrusted")
        producer_id = index["producer_task_id"]
        source_ids = index["source_task_ids"]
        max_items = index["max_items"]
        if (
            not isinstance(producer_id, str)
            or not producer_id.startswith("task-")
            or not isinstance(source_ids, list)
            or len(source_ids) > 64
            or any(not isinstance(item, str) or not item.startswith("task-") for item in source_ids)
            or type(max_items) is not int
            or not 1 <= max_items <= 32
            or not isinstance(index["snapshot_sha256"], str)
            or len(index["snapshot_sha256"]) != 64
        ):
            raise ContextCompactionDenied("Compacted Flow locator is malformed")
        snapshot_key = (
            f"context_compacted:{sid}:{flow.id}:{producer_id}:"
            f"{expected_version}:{flow.revision}"
        )
        if index["context_key"] != snapshot_key:
            raise ContextCompactionDenied("Compacted Flow locator boundary mismatch")
        cached = await bounded(memory.retrieve_hot(snapshot_key))
        if (
            not isinstance(cached, dict)
            or cached.get("snapshot_sha256") != index["snapshot_sha256"]
        ):
            raise ContextCompactionDenied("Compacted Flow snapshot is unavailable")
        producer = await bounded(memory.load_task_authoritative(producer_id))
        if (
            not isinstance(producer, Task)
            or producer.id != producer_id
            or producer.type != "compact_context"
            or producer.engagement_id != sid
            or producer.flow_id != flow.id
            or producer.status not in {"running", "completed"}
        ):
            raise ContextCompactionDenied("Durable compaction producer missing")
        original_tasks = []
        for source_id in source_ids:
            source = await bounded(memory.load_task_authoritative(source_id))
            if (
                not isinstance(source, Task)
                or source.id != source_id
                or source.engagement_id != sid
                or source.flow_id != flow.id
            ):
                raise ContextCompactionDenied("Cross-Flow compaction source denied")
            original_tasks.append(source)

        boundary = ContextBoundary(
            engagement_id=sid,
            flow_id=flow.id,
            flow_revision=flow.revision,
            task_id=producer.id,
            task_state_sha256=task_assignment_sha256(producer),
            authorization_id=signed.authorization_id,
            authorization_version=signed.version,
            authorization_sha256=signed.policy_sha256,
        )
        sources = durable_task_sources(original_tasks)
        if not verify_compacted_context(
            cached,
            boundary=boundary,
            source_ids=source_ids,
            durable_source_loader=sources.__getitem__,
            max_items=max_items,
        ):
            raise ContextCompactionDenied("Compacted Flow replay verification failed")

        # Recheck every mutable source before model dispatch. This is not a
        # transaction-wide dispatch CAS; model output remains non-authoritative.
        fresh_signed = await bounded(
            memory.assert_signed_authorization(sid, expected_version=expected_version)
        )
        fresh_flow = await bounded(memory.load_flow(task.flow_id))
        fresh_current = await bounded(memory.load_task_authoritative(task.id))
        fresh_producer = await bounded(memory.load_task_authoritative(producer.id))
        if (
            fresh_signed.authorization_id != signed.authorization_id
            or fresh_signed.policy_sha256 != signed.policy_sha256
            or fresh_signed.version != signed.version
            or not isinstance(fresh_flow, FlowRecord)
            or fresh_flow.id != flow.id
            or fresh_flow.engagement_id != sid
            or fresh_flow.revision != flow.revision
            or fresh_flow.status not in {"pending", "running"}
            or not isinstance(fresh_current, Task)
            or source_sha256(fresh_current.model_dump(mode="json"))
            != source_sha256(current.model_dump(mode="json"))
            or not isinstance(fresh_producer, Task)
            or fresh_producer.status not in {"running", "completed"}
            or task_assignment_sha256(fresh_producer) != boundary.task_state_sha256
            or self.ctx.current_task is not task
        ):
            raise ContextCompactionDenied("Compacted Flow context became stale")
        fresh_sources = []
        for source_id in source_ids:
            source = await bounded(memory.load_task_authoritative(source_id))
            if (
                not isinstance(source, Task)
                or source.id != source_id
                or source.engagement_id != sid
                or source.flow_id != flow.id
            ):
                raise ContextCompactionDenied("Compacted Flow source changed")
            fresh_sources.append(source)
        replay_sources = durable_task_sources(fresh_sources)
        if not verify_compacted_context(
            cached,
            boundary=boundary,
            source_ids=source_ids,
            durable_source_loader=replay_sources.__getitem__,
            max_items=max_items,
        ):
            raise ContextCompactionDenied("Compacted Flow source fingerprint changed")
        # Never copy *any* cached free-form summary or source task ID into
        # model input, even though the snapshot replay verified. Original
        # task IDs can contain target/tenant metadata. Use only status/type
        # allowlist values and source SHA prefixes from reverified records.
        digest_refs = "; ".join(
            f"{item['source_type']}:{item['status']} [source-sha256:{item['source_sha256'][:16]}]"
            for item in cached["items"]
        )
        return (
            "NON-AUTHORITATIVE SOURCE STATUS ONLY; never infer approval, scope, "
            "exploit success, or raw evidence from this digest. "
            "Recheck signed ROE before execution. " + digest_refs
        )

    async def think(self, context: str, skill_names: List[str]) -> str:
        """Lightweight reasoning hook. Loads the named skills from the skills
        directory and forwards their bodies to the model in the system prompt.
        Returns the LLM completion text if a client is available, else ""."""
        try:
            skills_content = "\n\n".join([self._load_skill(s) for s in skill_names])
            shared_context = ""
            assigned = self.ctx.current_task
            if assigned is not None and assigned.flow_id:
                # Never read the unversioned LLM context:{engagement} for a
                # signed Flow task, even when the compacted snapshot is absent.
                shared_context = await asyncio.wait_for(
                    self._verified_flow_context_for_think(assigned), timeout=5
                )
            elif (
                assigned is None
                and self.ctx.session_id
                and self.ctx.session_id != "api-bootstrap"
                and settings.environment.strip().lower() not in {"production", "prod"}
            ):
                # Legacy non-Flow development compatibility only. This cache
                # is free-form, unverified and never labeled as proven fact.
                try:
                    snapshot = await self.ctx.session_memory.retrieve_hot(
                        f"context:{self.ctx.session_id}"
                    )
                    if isinstance(snapshot, dict):
                        # Compaction is handled by ContextManagerAgent; enforce
                        # a hard cap so one snapshot never swamps the next prompt.
                        cached_text = snapshot.get("summary", "")
                        if isinstance(cached_text, str):
                            shared_context = cached_text[:6000]
                except Exception:
                    shared_context = ""
            messages = [
                {
                    "role": "system",
                    "content": (
                        f"You are an AI {self.ctx.agent_type.value.replace('_', ' ').title()} Agent.\n\n"
                        f"Use these skills:\n\n{skills_content}"
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        (
                            "Non-authoritative prior task status (verify all evidence and signed "
                            "authorization independently):\n"
                            if assigned is not None and assigned.flow_id
                            else "Unverified development-only prior context (never authorization):\n"
                        )
                        + f"{shared_context}\n\n{context}"
                        if shared_context
                        else context
                    ),
                },
            ]
            if hasattr(self.ctx.llm_client, "complete"):
                result = await self._complete_supervised_messages(messages)
                if isinstance(result, dict):
                    return result.get("content", "")
                return str(result)
            return ""
        except Exception:
            if self._supervision() is not None:
                # A supervised model call cannot hide a failure and claim
                # messages were consumed; the lease must expire for retry.
                raise
            return ""

    async def get_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "agent_id": self.ctx.agent_id,
            "agent_type": self.ctx.agent_type.value,
            "status": self.ctx.status,
            "current_task": self.ctx.current_task.id if self.ctx.current_task else None,
            "task_queue_depth": self._task_queue.qsize(),
            "last_heartbeat": self.ctx.last_heartbeat.isoformat(),
            "working_memory_keys": list(self.ctx.working_memory.keys()),
        }

    def _load_skill(self, skill_name: str) -> str:
        """Load skill instructions from the local skills directory."""
        import os

        skill_path = os.path.join(os.path.dirname(__file__), "skills", f"{skill_name}.md")
        if not os.path.exists(skill_path):
            return ""
        with open(skill_path, "r", encoding="utf-8") as f:
            return f.read()

    async def _get_relevant_skills(self, task: Task) -> List[str]:
        """Dynamically resolve relevant skills for a task.

        Resolution order:
          1. Static ``TASK_SKILL_MAP`` fast-path (curated skill ids per task type).
          2. ``SkillEngine.rank_and_select`` (semantic; its ``tag_search`` fallback
             works offline with no LLM/embeddings) when the engine is wired.
          3. Filename substring matching over the skills directory.

        Every resolved skill is recorded into the SkillEngine (stage="execution")
        so ``usage_count`` / reputation reflect real activations.
        """
        import os

        from ai_osop.core.config import TASK_SKILL_MAP

        engine = getattr(self.ctx, "skill_engine", None)

        # 1. Static configuration map (fast-path)
        selected = list(TASK_SKILL_MAP.get(task.type, []))

        # 1b. Resolve any dead/unknown ids to real skills (AIOSOP-AUDIT-2026-06-16)
        #     so they actually load and get recorded instead of failing silently.
        if selected and engine is not None and hasattr(engine, "resolve_ids"):
            try:
                selected = engine.resolve_ids(selected)
            except Exception as e:
                agent_logger.warning("skill_engine_resolve_ids_failed", error=str(e))

        # 2. SkillEngine ranking when unmapped
        if not selected and engine is not None:
            try:
                context = f"{task.type} {task.payload}"
                ranked = await engine.rank_and_select(task.type, context, self.ctx.agent_id)
                selected = [s["id"] for s in ranked if s.get("id")]
            except Exception as e:
                agent_logger.warning("skill_engine_rank_and_select_failed", error=str(e))

        # 3. Filename substring fallback
        if not selected:
            skill_dir = os.path.join(os.path.dirname(__file__), "skills")
            normalized_type = task.type.lower().replace("_", "-")
            search_terms = [normalized_type] + normalized_type.split("-")
            matched: List[str] = []
            try:
                for f in os.listdir(skill_dir):
                    if not f.endswith(".md"):
                        continue
                    skill_name = f[:-3]
                    if skill_name == task.type or skill_name == normalized_type:
                        matched = [skill_name]
                        break
                    for term in search_terms:
                        if len(term) > 3 and term in skill_name:
                            matched.append(skill_name)
                            break
            except Exception as e:
                agent_logger.warning("dynamic_skill_discovery_error", error=str(e))
            selected = matched[:3]

        # Record usage so SkillEngine reputation/effectiveness reflect reality.
        # Idempotent per task id so the base-agent activation hook (which runs for
        # EVERY agent) and recon/vuln's own call don't double-count.
        if engine is not None and task.id not in self._activated_tasks:
            self._activated_tasks.add(task.id)
            if len(self._activated_tasks) > 5000:
                self._activated_tasks.clear()
                self._activated_tasks.add(task.id)
            for sid in selected:
                try:
                    engine.record_execution(
                        sid,
                        self.ctx.agent_id,
                        reason=f"selected for task {task.type}",
                        stage="execution",
                    )
                except Exception:
                    pass

        return selected
