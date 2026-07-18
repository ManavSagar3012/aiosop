"""
Base Agent Architecture
Abstract base class for all AI-OSOP agents with lifecycle management,
memory integration, and structured reasoning.
"""

import asyncio
import json
import os
import socket
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

import structlog

from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import AgentException
from ai_osop.core.execution_trace import (
    ExecutionStage,
    FailureCategory,
    record_failure,
    record_stage,
)
from ai_osop.core.models import AuditEvent, ScopeDefinition, Task
from ai_osop.core.observability import record_task
from ai_osop.core.telemetry import (
    RequestContext,
    extract_trace_context,
    reset_mcp_latency,
)
from ai_osop.core.tracing import trace_span_with_parent
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
        self.logger = structlog.get_logger(f"ai_osop.agents.{self.__class__.__name__}")
        self.findings: Dict[str, Any] = {}
        self._running = False
        self._shutting_down = False  # Sprint 7: prevent new tasks during shutdown
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._max_concurrent_tasks = 3
        self._active_tasks: Dict[str, asyncio.Task] = {}
        # Track agent start time for uptime calculation in heartbeats
        self._started_at = datetime.utcnow()
        # AIOSOP-AUDIT-2026-06-16: track the background worker/heartbeat loop
        # handles so shutdown() can actually cancel them. Previously start()
        # discarded these handles, leaking tasks (the worker blocks forever on
        # _task_queue.get() and never observes _running=False).
        self._bg_tasks: list[asyncio.Task] = []
        # AIOSOP-AUDIT-2026-06-16: task ids whose skill activations were already
        # recorded, so coverage can be extended to every agent without double-counting
        # for agents (recon/vuln) that also resolve skills inside _execute.
        self._activated_tasks: set = set()
    def safe_path(self, path: str) -> str:
        """Enforce file access within the agent's sandbox directory."""
        # Agent workspace directory
        sandbox_dir = os.path.abspath(f"/tmp/agent-{self.ctx.agent_id}")
        os.makedirs(sandbox_dir, exist_ok=True)
        
        # Join and check if the resulting path is still inside the sandbox
        # Use abspath to normalize and prevent traversal
        safe_path = os.path.abspath(os.path.join(sandbox_dir, path))
        if not safe_path.startswith(sandbox_dir):
            raise AgentException(f"Path traversal attempted: {path}")
        return safe_path

    def safe_open(self, path: str, *args, **kwargs):
        """Open a file safely within the sandbox."""
        resolved = self.safe_path(path)
        mode = args[0] if args else kwargs.get("mode", "r")
        if "w" in mode or "a" in mode or "x" in mode:
            os.makedirs(os.path.dirname(resolved), exist_ok=True)
        return open(resolved, *args, **kwargs)

    @property
    @abstractmethod
    def agent_type(self) -> AgentType:
        """Return the agent's type."""
        pass

    def supports_task_type(self, task_type: str) -> bool:
        """Check if this agent supports the specified task type."""
        return True

    async def recall_prior_findings(
        self, query: Any, *, limit: int = 5, min_score: float = 0.0
    ) -> List[Any]:
        """Recall semantically-similar findings from past engagements (P2 learning
        brain). Any agent can call this to inform its reasoning with prior results.

        Reads the findings knowledge base wired onto graph memory. Returns an empty
        list (never raises) when the KB is unavailable, so callers can use it
        unconditionally. ``query`` may be a string or a finding/dict.
        """
        kb = getattr(getattr(self.ctx, "graph_memory", None), "findings_knowledge", None)
        if kb is None:
            return []
        try:
            return await kb.recall_similar(query, limit=limit, min_score=min_score)
        except Exception as e:  # noqa: BLE001 - recall is advisory, never fatal
            agent_logger.warning("recall_prior_findings_failed", error=str(e))
            return []

    async def initialize(self) -> None:
        """Initialize agent state from persistent memory."""
        self.ctx.status = "initializing"

        # Load prior working memory if exists
        prior_state = await self.ctx.session_memory.get_agent_state(self.ctx.agent_id)
        if prior_state:
            self.ctx.working_memory = prior_state.get("working_memory", {})
            self.ctx.task_history = prior_state.get("task_history", [])

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
            except GeneratorExit:
                break
            except RuntimeError as e:
                # AIOSOP-LIFECYCLE-001 (2026-07-03): during interpreter / event-loop
                # teardown (e.g. an agent started in a unit test that never called
                # shutdown(), or a shutdown race) the queue/loop can already be gone.
                # That is expected teardown, not a worker fault — exit quietly instead
                # of logging a misleading ERROR and retrying.
                if "Event loop is closed" in str(e) or "no running event loop" in str(e):
                    break
                agent_logger.error("worker_error", agent_id=self.ctx.agent_id, error=str(e))
                try:
                    await asyncio.sleep(5)
                except (RuntimeError, asyncio.CancelledError):
                    break
            except Exception as e:
                agent_logger.error("worker_error", agent_id=self.ctx.agent_id, error=str(e))
                try:
                    await asyncio.sleep(5)
                except (RuntimeError, asyncio.CancelledError):
                    break

    @abstractmethod
    async def _setup_resources(self) -> None:
        """Agent-specific resource initialization."""
        pass

    # Hard ceiling for any single agent task. Long enough for real browser/scan
    # work, short enough to prevent permanent hangs (Issue 3).
    DEFAULT_TASK_TIMEOUT_SECONDS = 300

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
            # Agents are long-lived workers. Preserve their bootstrap/previous
            # session so a completed task cannot make a later engagement halt
            # permanently shut down this shared worker.
            _previous_session_id = self.ctx.session_id
            self.ctx.current_task = task
            self.ctx.status = "running"

            # Process-level profiling instrumentation (Sprint 9)
            reset_mcp_latency()
            import psutil

            _proc = psutil.Process()
            _start_cpu = _proc.cpu_times().user + _proc.cpu_times().system

            # Record database connectivity validation
            if (
                self.ctx.session_memory
                and getattr(self.ctx.session_memory, "_redis", None) is not None
            ):
                record_stage(task, ExecutionStage.REDIS_CONNECTED)
            if (
                self.ctx.session_memory
                and getattr(self.ctx.session_memory, "_pg_engine", None) is not None
            ):
                record_stage(task, ExecutionStage.POSTGRES_CONNECTED)
            if (
                self.ctx.graph_memory
                and getattr(self.ctx.graph_memory, "_driver", None) is not None
            ):
                record_stage(task, ExecutionStage.NEO4J_CONNECTED)

            # Record MCP server connectivity validation
            if self.ctx.mcp_registry:
                if len(self.ctx.mcp_registry._servers) > 0:
                    record_stage(
                        task,
                        ExecutionStage.MCP_CONNECTED,
                        metadata={
                            "active_mcp_servers": list(self.ctx.mcp_registry._servers.keys())
                        },
                    )
                else:
                    record_stage(
                        task,
                        ExecutionStage.MCP_CONNECT_FAILED,
                        error="No active MCP servers in registry",
                    )

            # Record trace stage for agent-side execution start
            record_stage(
                task, ExecutionStage.PLANNER_STARTED, metadata={"agent_id": self.ctx.agent_id}
            )
            # Carry the per-task engagement_id into the context so all downstream
            # graph + evidence writes use the correct scope (Issue 14 — evidence
            # was previously landing under the agent's static "global" session).
            self.ctx.session_id = task.engagement_id

            # PATCH (REL-029/030/031/033, 2026-06-15): Agents historically disagreed
            # on payload shape (`url`/`target`/`target_url`/`domain`/`targets`/`vuln_class`/
            # `vuln_type`). External callers (UI, CLI, audit scripts) couldn't predict the
            # right key per agent, causing silent KeyError -> task failure. Normalize
            # common aliases up front so individual agents can read whichever key they
            # historically used. Keys are added only if missing; original keys preserved.
            if isinstance(task.payload, dict):
                p = task.payload
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
                task.timeout_seconds
                or task.payload.get("task_timeout_seconds")
                or self.DEFAULT_TASK_TIMEOUT_SECONDS
            )

            # Rate Limiting
            await self.ctx.rate_limiter.acquire(target=target, tool=tool)

            task.started_at = datetime.utcnow()
            start_time = time.monotonic()

            try:
                # Pre-execution validation
                await self._validate_task(task)

                # AIOSOP-AUDIT-2026-06-16: record skill activations for EVERY agent's
                # task (not just recon/vuln). Feeds the now-durable reputation/effectiveness
                # loop platform-wide. Idempotent + best-effort; never blocks execution.
                try:
                    await self._get_relevant_skills(task)
                except Exception:
                    pass

                # Execute agent-specific logic under a hard timeout. An unbounded
                # _execute previously left agents permanently "running" (Issue 3).
                #
                # AIOSOP-DOUBLE-TIMEOUT-FIX: intentionally use (timeout_s - 5) here so the
                # INNER timeout always fires 5 seconds BEFORE the outer timeout in
                # _execute_via_agent (task_scheduler.py). When both timeouts fire at the
                # same value (both default to 300s), asyncio.wait_for races — the outer's
                # CancelledError can propagate INTO execute_task before the inner's
                # TimeoutError handler runs, preventing the failure result from being
                # returned and stranding the task in "running" forever. A 5s buffer
                # guarantees the inner fires first and returns cleanly.
                try:
                    record_stage(
                        task,
                        ExecutionStage.SCANNER_STARTED,
                        metadata={"scanner": self.ctx.agent_type.value, "task_type": task.type},
                    )
                    # max(1, ...) keeps the inner timeout positive for tiny timeout_s
                    _inner_timeout = max(1, timeout_s - 5)
                    result = await asyncio.wait_for(self._execute(task), timeout=_inner_timeout)
                    record_stage(
                        task,
                        ExecutionStage.VERIFICATION_STARTED,
                        metadata={"scanner": self.ctx.agent_type.value},
                    )
                except asyncio.TimeoutError as te:
                    record_stage(
                        task,
                        ExecutionStage.SCANNER_TIMED_OUT,
                        error=f"timed out after {_inner_timeout}s",
                        metadata={"timeout": _inner_timeout},
                    )
                    record_failure(
                        task,
                        FailureCategory.SCANNER,
                        f"task timed out after {_inner_timeout}s",
                        component=self.ctx.agent_id,
                    )
                    task.status = "failed"
                    task.completed_at = datetime.utcnow()
                    elapsed = (
                        (task.completed_at - task.started_at).total_seconds()
                        if task.started_at
                        else 0.0
                    )
                    task.result = {
                        "status": "failed",
                        "failure_type": "ScannerTimeout",
                        "component": self.ctx.agent_id,
                        "phase": task.status,
                        "reason": f"task timed out after {_inner_timeout}s",
                        "elapsed": elapsed,
                        "retryable": True,
                    }
                    task.result = self._inject_telemetry(task, task.result, _start_cpu, _proc)
                    await self._log_task_failure(task, te)
                    return task.result
                end_time = time.monotonic()
                if target:
                    self.ctx.rate_limiter.record_backpressure(
                        target, 
                        status_code=result.get("status_code"), 
                        response_time=end_time - start_time
                    )

                # Post-execution validation
                validated_result = await self._validate_output(result)

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
                ):
                    err_msg = (
                        validated_result.get("error")
                        or validated_result.get("message")
                        or "agent returned failure status without error message"
                    )
                    raise AgentException(str(err_msg))

                # Store results
                task.completed_at = datetime.utcnow()
                validated_result = self._inject_telemetry(task, validated_result, _start_cpu, _proc)
                task.result = validated_result
                task.status = "completed"
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
                task.status = "failed"
                elapsed = (
                    (datetime.utcnow() - task.started_at).total_seconds()
                    if task.started_at
                    else 0.0
                )
                task.result = {
                    "status": "failed",
                    "failure_type": "TaskCancelled",
                    "component": self.ctx.agent_id,
                    "phase": task.status,
                    "reason": "task cancelled by the orchestrator",
                    "elapsed": elapsed,
                    "retryable": False,
                }
                task.result = self._inject_telemetry(task, task.result, _start_cpu, _proc)
                raise
            except Exception as e:
                record_failure(
                    task,
                    FailureCategory.SCANNER,
                    str(e),
                    component=self.ctx.agent_id,
                    details={"error_type": type(e).__name__},
                )
                task.status = "failed"
                task.completed_at = datetime.utcnow()
                elapsed = (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.started_at
                    else 0.0
                )
                task.result = {
                    "status": "failed",
                    "failure_type": "UncaughtException",
                    "component": self.ctx.agent_id,
                    "phase": "execution",
                    "reason": str(e),
                    "error_type": type(e).__name__,
                    "elapsed": elapsed,
                    "retryable": True,
                }
                task.result = self._inject_telemetry(task, task.result, _start_cpu, _proc)
                await self._log_task_failure(task, e)
                return task.result

            finally:
                # LIFECYCLE ROOT-CAUSE FIX (2026-07-05): persist the task's TERMINAL
                # status to the graph. The live executor is the agent _task_worker loop
                # calling execute_task (the orchestrator's _execute_via_agent path is
                # not exercised here — proven by task.assigned=0 in a real autonomous
                # run). But execute_task only wrote terminal status to the audit log +
                # Postgres hot state — NEVER to Neo4j via upsert_task. The Task node was
                # set 'running' at schedule time and never advanced, so EVERY task showed
                # 'running' forever in the graph, which is the ground truth for the
                # stuck-task reaper, restart recovery, and dedupe. That is the true
                # "0/372 ever completed" disease. upsert_task is an idempotent MERGE and
                # this is best-effort so graph persistence can never break execution.
                _gm = getattr(self.ctx, "graph_memory", None)
                if _gm is not None and getattr(task, "status", None) in (
                    "completed",
                    "failed",
                    "error",
                    "timeout",
                    "cancelled",
                ):
                    try:
                        _rs = (
                            task.result if isinstance(getattr(task, "result", None), dict) else None
                        )
                        await _gm.upsert_task(task, result_summary=_rs)
                    except Exception as _persist_err:  # noqa: BLE001 - never break the task
                        agent_logger.warning(
                            "graph_terminal_persist_failed",
                            task_id=getattr(task, "id", "?"),
                            status=getattr(task, "status", "?"),
                            error=str(_persist_err),
                        )
                self.ctx.current_task = None
                self.ctx.status = "idle"
                self.ctx.last_heartbeat = datetime.utcnow()
                self.ctx.session_id = _previous_session_id
                RequestContext.clear()

    @abstractmethod
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Agent-specific task execution logic."""
        pass

    async def _validate_task(self, task: Task) -> None:
        """Validate task before execution."""
        # Check scope if required
        if task.scope_check:
            # Scope validation logic here
            pass

        # Check dependencies
        for dep_id in task.dependencies:
            # Verify dependency completed
            pass

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
        """Write audit log for task completion."""
        target = (
            task.payload.get("target")
            or task.payload.get("domain")
            or task.payload.get("url")
            or "unknown"
        )
        event = AuditEvent(
            event_type="task_completed",
            severity="info",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action={
                "task_id": task.id,
                "task_type": task.type,
                "target": target,
            },
            result={
                "status": task.status,
                "execution_time": (
                    (task.completed_at - task.started_at).total_seconds()
                    if task.completed_at and task.started_at
                    else 0
                ),
                "reasoning": result.get("reasoning", ""),
            },
            context={"session_id": self.ctx.session_id, "agent_type": self.ctx.agent_type.value},
            engagement_id=task.engagement_id,
        )
        await self.ctx.audit_callback(event)

    async def _log_task_failure(self, task: Task, error: Exception) -> None:
        """Write audit log for task failure."""
        event = AuditEvent(
            event_type="task_failed",
            severity="warning",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action={"task_id": task.id, "task_type": task.type, "retry_count": task.retry_count},
            result={"error": str(error), "error_type": type(error).__name__},
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
        _consecutive_failures = 0
        _MAX_BACKOFF = 60  # Cap at 60s to avoid silent disappearance
        while self._running:
            try:
                self.ctx.last_heartbeat = datetime.utcnow()

                if self.ctx.current_task:
                    self.ctx.current_task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                    await self.ctx.session_memory.store_task(self.ctx.current_task)

                # Enrich heartbeat with worker telemetry (mission: Worker Telemetry)
                _queue_wait = 0.0
                if self.ctx.current_task and self.ctx.current_task.created_at:
                    _queue_wait = (
                        datetime.utcnow() - self.ctx.current_task.created_at
                    ).total_seconds()

                await self.ctx.session_memory.update_agent_heartbeat(
                    self.ctx.agent_id,
                    {
                        "agent_id": self.ctx.agent_id,
                        "agent_type": str(self.ctx.agent_type),
                        "status": self.ctx.status,
                        "task_id": self.ctx.current_task.id if self.ctx.current_task else None,
                        "task_type": self.ctx.current_task.type if self.ctx.current_task else None,
                        "engagement_id": self.ctx.session_id,
                        "version": "8.1",
                        "pid": os.getpid(),
                        "hostname": socket.gethostname(),
                        "uptime_seconds": (datetime.utcnow() - self._started_at).total_seconds(),
                        "queue_wait_seconds": round(_queue_wait, 2),
                        "task_queue_depth": self._task_queue.qsize(),
                    },
                )
                _consecutive_failures = 0  # Reset on success
            except (asyncio.CancelledError, GeneratorExit):
                break
            except RuntimeError as e:
                # AIOSOP-LIFECYCLE-001: expected during interpreter/event-loop teardown
                if "Event loop is closed" in str(e) or "no running event loop" in str(e):
                    break
                _consecutive_failures += 1
                if _consecutive_failures <= 3:
                    agent_logger.warning(
                        "heartbeat_loop_error", agent_id=self.ctx.agent_id, error=str(e)
                    )
                elif _consecutive_failures == 4:
                    agent_logger.warning(
                        "heartbeat_loop_backoff",
                        agent_id=self.ctx.agent_id,
                        error=str(e),
                        msg="suppressing further heartbeat errors until recovery",
                    )
            except Exception as e:
                _consecutive_failures += 1
                if _consecutive_failures <= 3:
                    agent_logger.warning(
                        "heartbeat_loop_error", agent_id=self.ctx.agent_id, error=str(e)
                    )
                elif _consecutive_failures == 4:
                    agent_logger.warning(
                        "heartbeat_loop_backoff",
                        agent_id=self.ctx.agent_id,
                        error=str(e),
                        msg="suppressing further heartbeat errors until recovery",
                    )
            # Exponential backoff: 5s → 10s → 20s → 40s → 60s cap
            _sleep = min(5 * (2 ** _consecutive_failures), _MAX_BACKOFF) if _consecutive_failures else 5
            try:
                await asyncio.sleep(_sleep)
            except (asyncio.CancelledError, RuntimeError):
                break

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


        try:
            await asyncio.wait_for(
                self._cleanup_resources(),
                timeout=settings.agent_cleanup_timeout_seconds,
            )
        except asyncio.TimeoutError:
            agent_logger.warning(
                "agent_cleanup_timed_out",
                agent_id=self.ctx.agent_id,
                timeout_seconds=settings.agent_cleanup_timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            agent_logger.warning(
                "cleanup_resources_error", agent_id=self.ctx.agent_id, error=str(e)
            )

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

    async def think(self, context: str, skill_names: List[str]) -> str:
        """Lightweight reasoning hook. Loads the named skills from the skills
        directory and forwards their bodies to the model in the system prompt.
        Returns the LLM completion text if a client is available, else ""."""
        try:
            skills_content = "\n\n".join([self._load_skill(s) for s in skill_names])
            messages = [
                {
                    "role": "system",
                    "content": (
                        f"You are an AI {self.ctx.agent_type.value.replace('_', ' ').title()} Agent.\n\n"
                        f"Use these skills:\n\n{skills_content}"
                    ),
                },
                {"role": "user", "content": context},
            ]
            if hasattr(self.ctx.llm_client, "complete"):
                # AIOSOP-LLM-WARM-001: cap advisory reasoning tokens (see recon_agent).
                from ai_osop.core.config import settings as _settings

                result = await self.ctx.llm_client.complete(
                    messages, max_tokens=_settings.llm_reasoning_max_tokens
                )
                if isinstance(result, dict):
                    return result.get("content", "")
                return str(result)
            return ""
        except Exception:
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

    def _inject_telemetry(
        self, task: Task, result: Dict[str, Any], start_cpu: float, proc: Any
    ) -> Dict[str, Any]:
        """Compute and inject task execution telemetry metrics (Sprint 9)."""
        try:
            from datetime import datetime

            from ai_osop.core.telemetry import get_mcp_latency

            end_cpu = proc.cpu_times().user + proc.cpu_times().system
            cpu_seconds = max(0.0, end_cpu - start_cpu)
            memory_rss_bytes = proc.memory_info().rss
            mcp_latency_ms = get_mcp_latency()

            completed_at = task.completed_at or datetime.utcnow()
            execution_time = (
                (completed_at - task.started_at).total_seconds() if task.started_at else 0.0
            )
            network_wait = max(0.0, execution_time - cpu_seconds)

            # Populate telemetry dictionary
            result["telemetry"] = {
                "queue_wait_time_s": (
                    (task.started_at - task.created_at).total_seconds()
                    if task.started_at and task.created_at
                    else 0.0
                ),
                "worker_assignment_latency_s": (
                    (task.started_at - task.created_at).total_seconds()
                    if task.started_at and task.created_at
                    else 0.0
                ),
                "execution_time_s": execution_time,
                "cpu_user_system_seconds": round(cpu_seconds, 4),
                "memory_rss_bytes": memory_rss_bytes,
                "network_wait_s": round(network_wait, 4),
                "mcp_latency_ms": round(mcp_latency_ms, 2),
                "retry_count": task.retry_count,
            }
        except Exception as e:
            self.logger.warning("failed_to_inject_telemetry", error=str(e))
        return result
