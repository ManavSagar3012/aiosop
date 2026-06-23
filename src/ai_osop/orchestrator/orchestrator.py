"""
Central Orchestrator
Task scheduling, state management, agent coordination, and workflow enforcement.
"""

import asyncio
import json
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import structlog

from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import ScopeException, WorkflowException, WorkflowTransitionError
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.core.metrics import (
    ACTIVE_ENGAGEMENTS,
    ACTIVE_AGENT_COUNT,
    PENDING_APPROVALS,
    TASKS_BY_STATUS,
    TASK_SCHEDULE_DURATION,
    AGENT_EXECUTION_DURATION,
    MCP_CALL_DURATION,
    MCP_CIRCUIT_BREAKER_STATE,
    MCP_ERRORS_TOTAL,
    GRAPH_QUERY_DURATION,
    LLM_CALL_DURATION,
)
from ai_osop.core.telemetry import RequestContext, inject_trace_context
from ai_osop.core.tracing import trace_span, trace_span_with_parent
from ai_osop.core.observability import (
    record_engagement_started,
    record_engagement_halted,
    record_engagement_completed,
    record_approval_requested,
    record_approval_resolved,
    update_task_counts,
    update_active_agents,
)
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus
from ai_osop.orchestrator.temporal_worker import (
    TemporalTaskScheduler,
    TemporalUnavailableError,
    temporal_available,
)
from ai_osop.safety.rate_limiter import RateLimiter

logger = structlog.get_logger("ai_osop.orchestrator")


class EngagementPhase(str, Enum):
    INITIALIZED = "initialized"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    HALTED = "halted"


class Orchestrator:
    """
    Central Orchestrator (CO)

    Responsibilities:
    - Engagement lifecycle management
    - Task decomposition and scheduling
    - Agent assignment and monitoring
    - Workflow state machine enforcement
    - Human approval coordination
    - Conflict resolution
    """

    VALID_TRANSITIONS = {
        EngagementPhase.INITIALIZED: [EngagementPhase.RECONNAISSANCE, EngagementPhase.HALTED],
        EngagementPhase.RECONNAISSANCE: [
            EngagementPhase.VULNERABILITY_DISCOVERY,
            EngagementPhase.HALTED,
        ],
        EngagementPhase.VULNERABILITY_DISCOVERY: [
            EngagementPhase.EXPLOITATION,
            EngagementPhase.REPORTING,
            EngagementPhase.HALTED,
        ],
        EngagementPhase.EXPLOITATION: [
            EngagementPhase.POST_EXPLOITATION,
            EngagementPhase.REPORTING,
            EngagementPhase.HALTED,
        ],
        EngagementPhase.POST_EXPLOITATION: [EngagementPhase.REPORTING, EngagementPhase.HALTED],
        EngagementPhase.REPORTING: [EngagementPhase.COMPLETED, EngagementPhase.HALTED],
        EngagementPhase.COMPLETED: [],
        EngagementPhase.HALTED: [],
    }

    # Transition policy: Phase -> (RequiresManualApproval, AutomaticNextPhase)
    PHASE_POLICY = {
        EngagementPhase.INITIALIZED: {
            "manual_approval": False,
            "auto_next": EngagementPhase.RECONNAISSANCE,
        },
        EngagementPhase.RECONNAISSANCE: {
            "manual_approval": False,
            "auto_next": EngagementPhase.VULNERABILITY_DISCOVERY,
        },
        EngagementPhase.VULNERABILITY_DISCOVERY: {
            "manual_approval": False,
            "auto_next": EngagementPhase.EXPLOITATION,
        },
        EngagementPhase.EXPLOITATION: {
            "manual_approval": False,
            "auto_next": EngagementPhase.POST_EXPLOITATION,
        },
        EngagementPhase.POST_EXPLOITATION: {
            "manual_approval": False,
            "auto_next": EngagementPhase.REPORTING,
        },
        EngagementPhase.REPORTING: {
            "manual_approval": False,
            "auto_next": EngagementPhase.COMPLETED,
        },
    }

    def __init__(
        self,
        session_memory: SessionMemory,
        graph_memory: GraphMemory,
        mcp_registry: MCPRegistry,
        llm_client: Any,
        temporal_scheduler: Optional[TemporalTaskScheduler] = None,
        coordination_bus: Optional[AgentCoordinationBus] = None,
    ):
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.mcp_registry = mcp_registry
        self.llm_client = llm_client
        self.rate_limiter = RateLimiter()
        self.temporal_scheduler = temporal_scheduler
        self.temporal_enabled = settings.temporal_enabled
        self.coordination_bus = coordination_bus or AgentCoordinationBus()
        # Phase 1 Bug Bounty Upgrade: user-session store so the orchestrator can tell
        # whether an engagement is authenticated (has imported user sessions) and
        # should run the capture_authenticated_surface -> extract_har_api_inventory chain.
        self.session_store = SessionStore(session_memory)
        # Idempotency for autonomous discovery is now Neo4j-backed (Reliability sprint):
        #  - chain dedupe: the (:Task)-[:SPAWNED]->(:Task) edge (graph_memory.task_has_spawned)
        #  - map-dispatch dedupe: an atomic (:AutoDiscoveryClaim) MERGE (claim_auto_discovery)
        # Both survive process restart, replacing the former in-memory sets.

        self._agents: Dict[str, Any] = {}  # agent_id -> agent instance
        self._tasks: Dict[str, Task] = {}  # task_id -> Task
        self._sessions: Dict[str, SessionState] = {}  # session_id -> SessionState
        self._approval_requests: Dict[str, ApprovalRequest] = {}
        # P0-1 (concurrency): orchestrator-side atomic claim set keyed by agent_id.
        # An agent is claimed SYNCHRONOUSLY the moment it is selected for a task
        # (no await between find and claim), released in _execute_via_agent's finally.
        # This closes the window where a fire-and-forget dispatch hadn't yet flipped
        # the agent's status to "running" and the same idle agent got selected twice,
        # driving two coroutines through one agent and clobbering shared self.ctx.
        self._busy_agents: set[str] = set()

        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._reaper_task: Optional[asyncio.Task] = None
        self._phase_monitor_task: Optional[asyncio.Task] = None
        self._approval_callbacks: List[Callable[[ApprovalRequest], None]] = []
        # Auto-transition backoff state (keyed by session_id): failed attempts so a
        # repeatedly-failing transition (e.g. an engagement with no vulnerabilities)
        # stops log-spamming every monitor tick. Cleared when the phase changes.
        self._auto_transition_failures: Dict[str, Dict[str, Any]] = {}

        # Start phase monitor if an event loop is running (avoids test errors)
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                self._phase_monitor_task = loop.create_task(self._phase_monitor())
        except RuntimeError:
            pass

    async def initialize(self) -> None:
        """Initialize orchestrator and start scheduler."""
        await self.session_memory.connect()
        await self.graph_memory.connect()
        if self.temporal_enabled:
            if not temporal_available() and self.temporal_scheduler is None:
                raise TemporalUnavailableError(
                    "Temporal is enabled but temporalio is not installed"
                )
            self.temporal_scheduler = self.temporal_scheduler or TemporalTaskScheduler()
            await self.temporal_scheduler.connect()

        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        # Reliability sprint: background stuck-task reaper.
        self._reaper_task = asyncio.create_task(self._reaper_loop())
        # Retention service: automated cleanup of old data
        from ai_osop.memory.retention_service import RetentionService

        self._retention_service = RetentionService(self.graph_memory, self.session_memory)
        await self._retention_service.start()
        # Phase monitor drives auto-transitions. __init__ only starts it when a loop
        # is already running at construction; start it here (idempotently) so the
        # canonical construct-then-initialize path can never leave it dead.
        if self._phase_monitor_task is None or self._phase_monitor_task.done():
            self._phase_monitor_task = asyncio.create_task(self._phase_monitor())

        # P0: Recovery sprint — restore in-flight state from warm tier so restarts
        # don't lose pending approvals or active tasks.
        try:
            pending_approvals = await self.session_memory.list_pending_approvals()
            for apr in pending_approvals:
                self._approval_requests[apr.id] = apr
                # Re-spawn timeout watcher so stale approvals still fail correctly
                asyncio.create_task(self._await_approval_outcome(apr.id))
            active_tasks = await self.session_memory.load_all_active_tasks()
            for task in active_tasks:
                self._tasks[task.id] = task
                # If the task was running when we crashed, reset to pending so the
                # scheduler can re-assign it (the agent is certainly gone).
                if task.status == "running":
                    task.status = "pending"
                    task.assigned_agent_id = None
                await self.session_memory.push_task_queue(
                    f"tasks:{task.engagement_id}", task.model_dump()
                )
        except Exception as e:
            # Log but don't block startup — the orchestrator can still function
            # with empty in-memory state (new engagements will work fine).
            import structlog

            logger = structlog.get_logger()
            logger.warning("orchestrator_startup_recovery_failed", error=str(e))

    async def create_engagement(
        self, scope: ScopeDefinition, roe: Dict[str, Any], created_by: Optional[str] = None
    ) -> SessionState:
        """Create new engagement session."""
        with trace_span(
            "orchestrator.create_engagement",
            attributes={
                "engagement_id": scope.engagement_id,
                "created_by": created_by or "system",
            },
        ):
            session = SessionState(
                session_id=f"eng-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{scope.engagement_id}",
                scope=scope,
                roe=roe,
                phase=EngagementPhase.INITIALIZED.value,
                agents={},
                checkpoint_id=None,
                audit_log_position="0",
                created_by=created_by,
            )

            # Persist session
            await self.session_memory.store_session_state(session)
            await self.session_memory.persist_session_state(session)

            self._sessions[session.session_id] = session

            # Sprint 6B: Record engagement metrics
            record_engagement_started(session.session_id)

            # Audit log
            await self._audit_log(
                AuditEvent(
                    event_type="engagement_created",
                    severity="info",
                    actor_type="system",
                    actor_id="orchestrator",
                    action={"scope": scope.model_dump(), "roe": roe},
                    result={"session_id": session.session_id},
                    context={"phase": session.phase},
                    engagement_id=scope.engagement_id,
                )
            )

            return session

    async def transition_phase(self, session_id: str, new_phase: EngagementPhase) -> SessionState:
        """Transition engagement to new phase with validation."""
        session = self._sessions.get(session_id)
        if not session:
            raise WorkflowException(f"Session {session_id} not found")

        current = EngagementPhase(session.phase)

        if new_phase not in self.VALID_TRANSITIONS.get(current, []):
            raise WorkflowTransitionError(
                f"Invalid transition: {current.value} -> {new_phase.value}"
            )

        # Phase-specific validation
        if new_phase == EngagementPhase.EXPLOITATION:
            # Check if findings exist
            stats = await self.graph_memory.get_graph_stats(session_id)
            if stats.get("vulnerabilities", 0) == 0:
                raise WorkflowException("Cannot transition to exploitation without vulnerabilities")

        session.phase = new_phase.value
        session.updated_at = datetime.utcnow()

        await self.session_memory.store_session_state(session)
        await self.session_memory.persist_session_state(session)

        # Trigger phase-specific tasks
        await self._on_phase_enter(session, new_phase)

        await self._audit_log(
            AuditEvent(
                event_type="phase_transition",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={"from_phase": current.value, "to_phase": new_phase.value},
                result={"success": True},
                context={"session_id": session_id},
                engagement_id=session.scope.engagement_id,
            )
        )

        return session

    async def _on_phase_enter(self, session: SessionState, phase: EngagementPhase) -> None:
        """Trigger automatic tasks when entering a phase."""
        if phase == EngagementPhase.RECONNAISSANCE:
            # Auto-create recon tasks for all scope domains
            for domain in session.scope.domains:
                task = Task(
                    type="full_recon",
                    priority=5,
                    agent_type=AgentType.RECON,
                    payload={"domain": domain, "scope": session.scope.model_dump()},
                    engagement_id=session.session_id,
                )
                await self.schedule_task(task)

            # Auto-dispatch hook 1 (phase-entry): if the engagement already has an
            # imported session by the time we reach RECON, kick off authenticated
            # discovery (map_workflow -> capture -> extract). Idempotent with the
            # session-import hook so exactly one map_workflow is created.
            url_hint = f"https://{session.scope.domains[0]}/" if session.scope.domains else None
            await self.ensure_authenticated_discovery(session.session_id, url_hint=url_hint)

        elif phase == EngagementPhase.VULNERABILITY_DISCOVERY:
            # Auto-create scan tasks for discovered assets
            cypher = "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain"
            async with self.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"sid": session.session_id})
                async for record in result:
                    domain = record["domain"]

                    # Schedule Burp Scan
                    burp_task = Task(
                        type="burp_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={"url": f"https://{domain}"},
                        engagement_id=session.session_id,
                    )
                    await self.schedule_task(burp_task)

                    # Schedule Nuclei Scan
                    nuclei_task = Task(
                        type="nuclei_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={"targets": [f"https://{domain}"]},
                        engagement_id=session.session_id,
                    )
                    await self.schedule_task(nuclei_task)

        elif phase == EngagementPhase.EXPLOITATION:
            # Auto-create validation tasks for confirmed vulns
            cypher = "MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.id as vuln_id"
            vuln_ids = []
            async with self.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"sid": session.session_id})
                async for record in result:
                    vuln_ids.append(record["vuln_id"])

            logger.info(
                "exhaustive_mode",
                session_id=session.session_id,
                vuln_count=len(vuln_ids),
                task_count=len(vuln_ids),
            )
            for vid in vuln_ids:
                # Fetch endpoint URL for vulnerability (Issue 13)
                endpoint_url = await self.graph_memory.get_endpoint_url_for_vulnerability(vid)

                task = Task(
                    type="exploit_validation",
                    priority=9,
                    agent_type=AgentType.EXPLOIT_VALIDATION,
                    approval_required=True,
                    payload={
                        "target": endpoint_url,
                        "vulnerability_id": vid,
                        "operator_approved": False,
                        "approval_id": f"auto-{vid}",
                    },
                    engagement_id=session.session_id,
                )
                await self.schedule_task(task)

        elif phase == EngagementPhase.REPORTING:
            # Auto-create final report task
            task = Task(
                type="generate_report",
                priority=10,
                agent_type=AgentType.REPORTING,
                payload={"format": "markdown", "detail_level": "high"},
                engagement_id=session.session_id,
            )
            await self.schedule_task(task)

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution."""
        # Sprint 6: propagate trace context into the task so the agent can continue the trace
        if not task.trace_context:
            inject_trace_context(task.trace_context)
        # Also bind the task IDs into RequestContext for downstream logging
        RequestContext.bind(
            task_id=task.id,
            engagement_id=task.engagement_id,
            trace_id=task.trace_context.get("traceparent", "").split("-")[1] if task.trace_context.get("traceparent") else "",
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
            # PATCH (REL-006, 2026-06-15): Exploit-class tasks unconditionally
            # require operator approval at the agent layer
            # (exploit_agent._execute_validation raises if approval_id is missing).
            # If the caller forgot to flag `approval_required=true`, the scheduler
            # would skip _assign_task's approval gate and the task would loop
            # forever on retries. Force the flag so the gate triggers + the
            # operator gets a /approvals/pending entry to act on.
            if (
                task.type in ("validate_exploit", "exploit_validation")
                and not task.approval_required
            ):
                task.approval_required = True

            self._tasks[task.id] = task
            # Durable task state (Reliability sprint): persist so the reaper, restart
            # recovery, and graph-backed dedupe have ground truth beyond process memory.
            await self.graph_memory.upsert_task(task)
            await self.session_memory.store_task(task)
            await self.coordination_bus.publish(
                "task.scheduled",
                {"task_id": task.id, "task_type": task.type, "agent_type": task.agent_type.value},
                "orchestrator",
            )

            # Store in hot memory
            await self.session_memory.push_task_queue(f"tasks:{task.engagement_id}", task.model_dump())

            if self.temporal_enabled and self.temporal_scheduler:
                workflow_id = await self.temporal_scheduler.start_task_workflow(task.model_dump())
                task.status = "scheduled"
                task.result = {"workflow_id": workflow_id, "durable": True}
                return task

            # If no dependencies and agent available, assign immediately
            if not task.dependencies:
                await self._assign_task(task)

            return task

    async def _execute_task_durable(self, task: Task) -> Dict[str, Any]:
        """Execute task durably, waiting for an available agent if necessary, with timeout."""
        self._tasks[task.id] = task
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
                            result
                            if isinstance(result, dict)
                            else {"status": "success", "raw": result}
                        )
                    # P0: Persist final state before returning.
                    await self.session_memory.store_task(task)
                    return task.result
                except Exception as e:
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                    await self.session_memory.store_task(task)
                    return task.result
                finally:
                    # P0-1: release the claim taken by _find_available_agent.
                    self._release_agent(agent.ctx.agent_id)

            if asyncio.get_event_loop().time() - start_time > timeout:
                task.status = "failed"
                task.result = {"status": "failed", "error": "Timeout waiting for agent"}
                await self.session_memory.store_task(task)
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
            if hasattr(self, "rate_limiter") and self.rate_limiter:
                await self.rate_limiter.acquire(tool="orchestrator")

            # Approval gate FIRST — decided before (and independent of) agent selection so
            # the scheduler never blocks and we never hold an agent claim while pending.
            if task.approval_required and not task.payload.get("operator_approved"):
                # Don't re-raise a request for a task already parked awaiting approval.
                if task.status != "awaiting_approval":
                    task.status = "awaiting_approval"
                    await self.graph_memory.upsert_task(task)
                    # P0: Persist awaiting_approval so recovery knows the task is parked.
                    await self.session_memory.store_task(task)
                    request = ApprovalRequest(
                        task_id=task.id,
                        agent_id="",
                        action_type=task.type,
                        target=str(task.payload.get("url", task.payload.get("target", "unknown"))),
                        payload_summary=str(task.payload),
                        risk_assessment="high",
                        engagement_id=task.engagement_id,
                    )
                    # Sprint 6B: Record approval metrics
            record_approval_requested(request.id)

            await self._raise_approval(request)
                return

            # Find + atomically claim an available agent (single sync critical section).
            agent = await self._find_available_agent(task.agent_type, task.type)

            if agent:
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                await self.graph_memory.upsert_task(task)
                # P0: Persist running task so recovery can re-assign after restart.
                await self.session_memory.store_task(task)
                await self.coordination_bus.publish(
                    "task.assigned",
                    {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                    "orchestrator",
                )

                # Execute via agent (claim released in _execute_via_agent's finally).
                asyncio.create_task(self._execute_via_agent(agent, task))
            else:
                # Queue for later assignment
                task.status = "pending"
                await self.graph_memory.upsert_task(task)
                # P0: Persist pending so recovery knows it needs assignment.
                await self.session_memory.store_task(task)

    async def _find_available_agent(
        self, agent_type: AgentType, task_type: str = ""
    ) -> Optional[Any]:
        """Find an idle, unclaimed agent of the specified type that supports the task type,
        and atomically CLAIM it (P0-1).

        The find+claim is a single synchronous critical section: this method awaits
        nothing between selecting an agent and marking it busy, so two concurrent
        _assign_task coroutines can never both receive the same agent. Callers that
        obtain an agent here OWN the claim and MUST release it via _release_agent
        (done in _execute_via_agent's finally). Callers that decide not to dispatch
        (e.g. an approval gate) must release it themselves before returning.
        """
        for agent in self._agents.values():
            if agent.ctx.agent_id in self._busy_agents:
                continue
            if agent.ctx.agent_type == agent_type and agent.ctx.status == "idle":
                if task_type and hasattr(agent, "supports_task_type"):
                    if not agent.supports_task_type(task_type):
                        continue
                # Synchronous claim — no await before this point in the loop body.
                self._busy_agents.add(agent.ctx.agent_id)
                return agent
        return None

    def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release an agent claim made by _find_available_agent (P0-1)."""
        if agent_id:
            self._busy_agents.discard(agent_id)

    @staticmethod
    def _strip_stale_approval(task: Task) -> None:
        """P1-2 (approval bypass on recovery/retry): drop any persisted approval grant
        from an approval_required task so _assign_task's gate re-fires and a FRESH human
        decision is demanded. Without this, a previously-approved (or payload-tampered)
        exploit task re-runs autonomously on restart recovery / retry with no new
        operator decision — safety-critical."""
        if task.approval_required and isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)

    _FAILURE_STATUSES = {"failed", "error", "timeout", "cancelled"}

    async def _maybe_retry(self, task: Task, result: Dict[str, Any]) -> bool:
        """Requeue a failed task if it still has retry budget (Phase 2 reliability).

        Respects Task.max_retries / retry_count, records each attempt in audit
        history, and re-assigns with exponential backoff (capped). Returns True if
        the task was requeued (caller must NOT then mark it failed), False when the
        retry budget is exhausted and the failure is terminal.
        """
        if task.retry_count >= task.max_retries:
            return False

        task.retry_count += 1
        backoff = min(2**task.retry_count, 30)
        await self._audit_log(
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

        # Reset for re-dispatch, then requeue after backoff.
        task.status = "pending"
        task.assigned_agent_id = None
        # P1-2: a retried approval-required task must get a FRESH human decision —
        # strip any prior approval so _assign_task's gate re-fires.
        self._strip_stale_approval(task)
        await self.graph_memory.upsert_task(
            task, result_summary={"retry_attempt": task.retry_count}
        )
        await self._retry_sleep(backoff)
        await self._assign_task(task)
        return True

    async def _retry_sleep(self, seconds: float) -> None:
        """Backoff sleep for retries — isolated so tests can stub it without
        patching the global asyncio.sleep (which the phase monitor also uses)."""
        await asyncio.sleep(seconds)

    async def _execute_via_agent(self, agent: Any, task: Task) -> None:
        """Execute task through assigned agent."""
        # Sprint 6: extract trace context from task to continue the trace
        from ai_osop.core.telemetry import extract_trace_context

        parent_span_context = extract_trace_context(task.trace_context)

        with trace_span_with_parent(
            "orchestrator._execute_via_agent",
            parent_span_context=parent_span_context,
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_id": agent.ctx.agent_id,
                "agent_type": agent.ctx.agent_type.value,
                "engagement_id": task.engagement_id,
            },
        ):
            try:
                result = await agent.execute_task(task)

                # Agents return varied success markers ("success", "authenticated",
                # "workflow_recorded", ...). Treat only the explicit failure set as
                # failure; everything else (including a missing status) as success.
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
                # Don't leak "running" tasks when dispatch is cancelled (Issue 4).
                # Cancellation is intentional shutdown — never retry it.
                await self._on_task_failure(
                    task, {"error": "execution cancelled", "error_type": "CancelledError"}
                )
                raise
            except Exception as e:
                err = {"error": str(e)}
                if not await self._maybe_retry(task, err):
                    await self._on_task_failure(task, err)
            finally:
                # P0-1: release the agent claim regardless of outcome (success/failure/
                # cancel/retry) so the agent becomes selectable again. _maybe_retry
                # re-dispatches on a fresh selection that re-claims as needed.
                self._release_agent(agent.ctx.agent_id)

    async def validate_workflow_completion(self, task: Task, result: Dict[str, Any]) -> bool:
        """Verify workflow node, steps, and evidence exist in Neo4j."""
        if task.agent_type != AgentType.WORKFLOW or task.type != "map_workflow":
            return True

        workflow_id = result.get("workflow_id")
        if not workflow_id:
            logger.error("validate_workflow_completion_missing_workflow_id", task_id=task.id)
            return False

        cypher = """
        MATCH (w:Workflow {id: $workflow_id})
        OPTIONAL MATCH (w)-[:HAS_STEP]->(s:Step)
        OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(ev:Evidence)
        RETURN count(w) > 0 as workflow_exists, count(s) as step_count, count(ev) as evidence_count
        """
        try:
            async with self.graph_memory._driver.session() as session:
                res = await session.run(cypher, {"workflow_id": workflow_id})
                record = await res.single()
                if not record:
                    return False

                exists = record["workflow_exists"]
                step_count = record["step_count"]
                evidence_count = record["evidence_count"]

                logger.debug(
                    "validate_workflow_completion",
                    workflow_id=workflow_id,
                    exists=exists,
                    steps=step_count,
                    evidence=evidence_count,
                )
                return bool(exists and step_count > 0 and evidence_count > 0)
        except Exception as e:
            logger.error("validate_workflow_completion_cypher_error", task_id=task.id, error=str(e))
            return False

    async def _engagement_is_authenticated(self, engagement_id: str) -> bool:
        """True if the engagement has at least one imported (non-expired) user session.

        Only authenticated engagements get the capture_authenticated_surface chain —
        there's nothing to capture as an authenticated user otherwise.
        """
        try:
            sessions = await self.session_store.list_sessions(engagement_id)
        except Exception as e:
            logger.debug("engagement_is_authenticated_lookup_failed", error=str(e))
            return False
        return any(not s.is_expired() for s in sessions)

    async def _pick_auth_user_label(self, engagement_id: str) -> Optional[str]:
        """Return the label of the first non-expired imported session, if any."""
        try:
            sessions = await self.session_store.list_sessions(engagement_id)
        except Exception:
            return None
        for s in sessions:
            if not s.is_expired():
                return s.user_label
        return None

    async def _has_existing_map_workflow(self, engagement_id: str) -> bool:
        """Restart-safe check: is there already a map_workflow for this engagement,
        either in memory (_tasks) or persisted in Neo4j (survives a process restart,
        since _tasks is in-memory only)?"""
        for t in self._tasks.values():
            if t.engagement_id == engagement_id and t.type == "map_workflow":
                return True
        cypher = "MATCH (t:Task {engagement_id: $eid, type: 'map_workflow'}) RETURN count(t) AS c"
        try:
            async with self.graph_memory._driver.session() as g:
                res = await g.run(cypher, {"eid": engagement_id})
                rec = await res.single()
                return bool(rec and rec["c"] > 0)
        except Exception as e:
            logger.debug("has_existing_map_workflow_check_failed", error=str(e))
            return False

    async def ensure_authenticated_discovery(
        self, engagement_id: str, url_hint: Optional[str] = None
    ) -> Optional[Task]:
        """Auto-dispatch a single map_workflow for an authenticated engagement.

        Entry point for autonomous discovery — called from BOTH the RECONNAISSANCE
        phase-entry hook and the session-import API endpoints. Idempotent: at most
        one map_workflow is ever created per engagement. Returns the created Task,
        or None when skipped (not authenticated / already dispatched).
        """
        # Authentication gate first (safe to repeat; doesn't claim the slot).
        if not await self._engagement_is_authenticated(engagement_id):
            return None

        # Atomic, restart-safe claim via Neo4j MERGE (replaces the in-memory set).
        # Only the first caller wins; concurrent hooks and restarted processes lose.
        if not await self.graph_memory.claim_auto_discovery(engagement_id):
            return None

        # Secondary guard: a map_workflow may already exist from a prior run.
        if await self._has_existing_map_workflow(engagement_id):
            return None

        user_label = await self._pick_auth_user_label(engagement_id) or "guest"
        url = url_hint or ""
        if not url:
            session = self._sessions.get(engagement_id)
            if session and session.scope.domains:
                url = f"https://{session.scope.domains[0]}/"

        task = Task(
            type="map_workflow",
            priority=7,
            agent_type=AgentType.WORKFLOW,
            payload={"url": url, "user_label": user_label, "name": "Auto Authenticated Journey"},
            engagement_id=engagement_id,
        )
        await self._audit_log(
            AuditEvent(
                event_type="auto_map_dispatch",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={"created_task_id": task.id, "user_label": user_label, "url": url},
                result={"success": True},
                context={"engagement_id": engagement_id},
                engagement_id=engagement_id,
            )
        )
        await self.schedule_task(task)
        logger.info("auto_map_dispatched", task_id=task.id, engagement_id=engagement_id, url=url)
        return task

    async def _persist_task_dependency(self, parent: Task, child: Task) -> None:
        """Record (:Task)-[:SPAWNED]->(:Task) in Neo4j so the automation chain is
        auditable in the graph alongside the Workflow/APIEndpoint nodes it produces."""
        cypher = """
        MERGE (p:Task {id: $parent_id})
          SET p.type = $parent_type, p.engagement_id = $eid
        MERGE (c:Task {id: $child_id})
          SET c.type = $child_type, c.engagement_id = $eid,
              c.status = $child_status, c.created_at = $created_at
        MERGE (p)-[:SPAWNED]->(c)
        RETURN c.id AS id
        """
        try:
            async with self.graph_memory._driver.session() as g:
                await g.run(
                    cypher,
                    {
                        "parent_id": parent.id,
                        "parent_type": parent.type,
                        "child_id": child.id,
                        "child_type": child.type,
                        "eid": child.engagement_id,
                        "child_status": child.status,
                        "created_at": child.created_at.isoformat(),
                    },
                )
        except Exception as e:
            logger.debug("persist_task_dependency_failed", error=str(e))

    async def _chain_authenticated_surface(self, task: Task, result: Dict[str, Any]) -> None:
        """Auto-create the next link in the authenticated-surface automation chain.

        Idempotent + restart-safe: the durable (:Task)-[:SPAWNED]->(:Task) edge is the
        dedupe marker. If this task already has a SPAWNED child (in Neo4j), a re-delivered
        or post-restart completion never creates the child twice.
        """
        # Duplicate-completion protection (graph-backed; survives process restart).
        if await self.graph_memory.task_has_spawned(task.id):
            return

        next_task: Optional[Task] = None

        if task.type == "map_workflow":
            # Only chain for authenticated engagements.
            if not await self._engagement_is_authenticated(task.engagement_id):
                return
            user_label = (
                task.payload.get("user_label")
                or await self._pick_auth_user_label(task.engagement_id)
                or "guest"
            )
            workflow_id = result.get("workflow_id", "")
            url = task.payload.get("url") or task.payload.get("target_url") or ""
            next_task = Task(
                type="capture_authenticated_surface",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "url": url,
                    "user_label": user_label,
                    "workflow_id": workflow_id,
                    "engagement_id": task.engagement_id,
                },
                dependencies=[task.id],
                engagement_id=task.engagement_id,
            )

        elif task.type == "capture_authenticated_surface":
            har_path = result.get("har_path", "")
            if not har_path:
                logger.debug("capture_authenticated_surface_no_har_path", task_id=task.id)
                return
            next_task = Task(
                type="extract_har_api_inventory",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "har_path": har_path,
                    "user_label": task.payload.get("user_label", "guest"),
                    "workflow_id": task.payload.get("workflow_id", ""),
                    "engagement_id": task.engagement_id,
                },
                dependencies=[task.id],
                engagement_id=task.engagement_id,
            )

        elif task.type == "extract_har_api_inventory":
            # Final link: run differential-authorization (BOLA/IDOR) analysis over the
            # inventoried API surface. Without this the autonomous pipeline builds an API
            # map and stops one step short of the findings it exists to produce.
            workflow_id = task.payload.get("workflow_id") or result.get("workflow_id") or ""
            if not workflow_id:
                logger.debug("extract_har_api_inventory_no_workflow_id", task_id=task.id)
                return
            next_task = Task(
                type="replay_for_diff_auth",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "workflow_id": workflow_id,
                    "engagement_id": task.engagement_id,
                },
                dependencies=[task.id],
                engagement_id=task.engagement_id,
            )

        if next_task is None:
            return

        # The SPAWNED edge written by _persist_task_dependency (below, before the child
        # is scheduled) is the durable dedupe marker checked at the top of this method.
        # Persist dependency in Neo4j + record an engagement-history (audit) entry,
        # then schedule. dependencies=[task.id] is already satisfied (task just
        # completed) so schedule_task assigns it as soon as a WORKFLOW agent is free.
        await self._persist_task_dependency(task, next_task)
        await self._audit_log(
            AuditEvent(
                event_type="auto_task_chain",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={
                    "trigger_task_id": task.id,
                    "trigger_type": task.type,
                    "created_task_id": next_task.id,
                    "created_type": next_task.type,
                },
                result={"success": True},
                context={"engagement_id": task.engagement_id},
                engagement_id=task.engagement_id,
            )
        )
        await self.schedule_task(next_task)
        logger.info(
            "auto_chained",
            parent_task_type=task.type,
            parent_task_id=task.id,
            child_task_type=next_task.type,
            child_task_id=next_task.id,
        )

    async def _on_task_success(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle successful task completion."""
        with trace_span(
            "orchestrator._on_task_success",
            attributes={
                "task_id": task.id,
                "task_type": task.type,
                "agent_id": task.assigned_agent_id,
                "engagement_id": task.engagement_id,
                "workflow_id": result.get("workflow_id", ""),
            },
        ):
            if not await self.validate_workflow_completion(task, result):
                await self._on_task_failure(
                    task,
                    {
                        "error": "Workflow invariant validation failed (missing nodes or evidence in Neo4j)",
                        "result": result,
                    },
                )
                return

            task.result = result
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            # Persist completion BEFORE chaining so restart recovery + dedupe see ground truth.
            # result_summary carries what recovery needs to resume the next chain link.
            await self.graph_memory.upsert_task(
                task,
                result_summary={
                    "workflow_id": result.get("workflow_id", ""),
                    "har_path": result.get("har_path", ""),
                    "user_label": task.payload.get("user_label", ""),
                    "url": task.payload.get("url", ""),
                },
            )
            # P0: Persist completed task to warm tier so recovery knows it's done.
            await self.session_memory.store_task(task)
            await self.coordination_bus.publish(
                "task.completed",
                {"task_id": task.id, "agent_id": task.assigned_agent_id},
                "orchestrator",
            )

            # Trigger path discovery if relevant
            if task.type in ["burp_scan", "nuclei_scan", "exploit_validation"]:
                path_task = Task(
                    type="discover_paths",
                    priority=6,
                    agent_type=AgentType.ATTACK_CHAIN,
                    payload={"engagement_id": task.engagement_id},
                    engagement_id=task.engagement_id,
                )
                await self.schedule_task(path_task)

            # Phase 1 Bug Bounty Upgrade: authenticated-surface automation chain.
            #   map_workflow ─▶ capture_authenticated_surface ─▶ extract_har_api_inventory
            # Each link is created only when its predecessor succeeds, carries the
            # predecessor's id as a dependency, and is persisted to Neo4j + audit history.
            await self._chain_authenticated_surface(task, result)

            # Check for downstream tasks
            await self._trigger_downstream_tasks(task)

            # Update session state
            session = self._sessions.get(task.engagement_id)
            if session:
                session.agents[task.assigned_agent_id] = {
                    "last_task": task.id,
                    "last_result": "success",
                    "timestamp": datetime.utcnow().isoformat(),
                }

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
            await self.graph_memory.upsert_task(
                task, result_summary={"error": str(result.get("error", ""))[:300]}
            )
            # P0: Persist task state so failure is recorded across restarts.
            await self.session_memory.store_task(task)
            await self.coordination_bus.publish(
                "task.failed",
                {"task_id": task.id, "agent_id": task.assigned_agent_id, "result": result},
                "orchestrator",
            )

            # Retry logic handled by agent
            # Orchestrator may escalate if critical
            if task.approval_required:
                # Notify operator
                pass

    async def _trigger_downstream_tasks(self, completed_task: Task) -> None:
        """Trigger tasks that depend on completed task."""
        for task in self._tasks.values():
            if completed_task.id in task.dependencies:
                # Check if all dependencies satisfied
                all_deps_complete = all(
                    self._tasks[dep_id].status == "completed" for dep_id in task.dependencies
                )
                if all_deps_complete:
                    await self._assign_task(task)

    async def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        """Submit approval request and BLOCK until the operator decides (or timeout).

        Direct callers (API/CLI) use this blocking form. The scheduler must NOT
        block on approval (P0-3) — it uses _raise_approval instead.
        """
        await self._register_approval(request)

        # Wait for operator response (with timeout)
        try:
            await asyncio.wait_for(
                self._wait_for_approval(request.id), timeout=settings.approval_timeout_seconds
            )
        except asyncio.TimeoutError:
            request.status = "timeout"
            request.operator_notes = "Auto-rejected due to timeout"

        return request

    async def _register_approval(self, request: ApprovalRequest) -> None:
        """Register an approval request and fan it out to operator-notification
        callbacks (UI, email, ...). Does NOT wait for a decision."""
        self._approval_requests[request.id] = request
        # P0: Persist approval so it survives restarts.
        await self.session_memory.store_approval_request(request)
        for callback in self._approval_callbacks:
            try:
                await callback(request)
            except Exception:
                pass

    async def _raise_approval(self, request: ApprovalRequest) -> None:
        """Non-blocking approval used by the scheduler (P0-3). Registers + notifies,
        then spawns a background watcher so a denial/timeout fails the parked task
        WITHOUT stalling the scheduler. Approval is re-driven by resolve_approval."""
        await self._register_approval(request)
        asyncio.create_task(self._await_approval_outcome(request.id))

    async def _await_approval_outcome(self, request_id: str) -> None:
        """Background: wait out the approval timeout; on timeout/denial fail the parked
        task so it isn't left in awaiting_approval forever. Approval is handled by
        resolve_approval (which re-assigns); we only act on the non-approval outcome."""
        try:
            await asyncio.wait_for(
                self._wait_for_approval(request_id), timeout=settings.approval_timeout_seconds
            )
        except asyncio.TimeoutError:
            request = self._approval_requests.get(request_id)
            if request and request.status not in ("approved", "rejected", "modified"):
                request.status = "timeout"
                request.operator_notes = "Auto-rejected due to timeout"
                # P0: Persist timeout so restart recovery sees it.
                await self.session_memory.store_approval_request(request)
        request = self._approval_requests.get(request_id)
        if not request or request.status == "approved":
            return
        # Denied / timed out -> fail the parked task (only if still awaiting).
        task = self._tasks.get(request.task_id)
        if task and task.status == "awaiting_approval":
            await self._on_task_failure(task, {"error": f"Approval denied: {request.status}"})

    async def _wait_for_approval(self, request_id: str) -> None:
        """Wait for approval request to be resolved."""
        while True:
            request = self._approval_requests.get(request_id)
            if request and request.status in ["approved", "rejected", "modified"]:
                return
            await asyncio.sleep(1)

    async def resolve_approval(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Resolve an approval request with operator decision."""
        with trace_span(
            "orchestrator.resolve_approval",
            attributes={
                "request_id": request_id,
                "decision": decision,
                "operator_id": operator_id,
            },
        ):
            request = self._approval_requests.get(request_id)
            if not request:
                raise WorkflowException(f"Approval request {request_id} not found")

            request.status = decision
            request.operator_id = operator_id
            request.operator_notes = notes
            request.responded_at = datetime.utcnow()

            # Sprint 6B: Record approval resolution metrics
            wait_seconds = None
            if request.requested_at:
                wait_seconds = (request.responded_at - request.requested_at).total_seconds()
            record_approval_resolved(decision, wait_seconds)

            # P0: Persist approval resolution so state survives restarts.
            await self.session_memory.store_approval_request(request)

            # Update task payload if approved
            if decision == "approved":
                task = self._tasks.get(request.task_id)
                if task:
                    task.payload["operator_approved"] = True
                    task.payload["approval_id"] = request.id
                    # Now that it's approved, we can assign it
                    await self._assign_task(task)
                    # Persist task so the approval metadata survives.
                    await self.session_memory.store_task(task)

            # Audit log
            await self._audit_log(
                AuditEvent(
                    event_type="approval_resolved",
                    severity="info" if decision == "approved" else "warning",
                    actor_type="operator",
                    actor_id=operator_id,
                    action={
                        "request_id": request_id,
                        "task_id": request.task_id,
                        "decision": decision,
                    },
                    result={"status": decision, "notes": notes},
                    context={"engagement_id": request.engagement_id},
                    engagement_id=request.engagement_id,
                )
            )

            return request

    async def halt_engagement(self, session_id: str, reason: str) -> None:
        """Emergency halt of engagement."""
        with trace_span(
            "orchestrator.halt_engagement",
            attributes={
                "session_id": session_id,
                "reason": reason,
            },
        ):
            session = self._sessions.get(session_id)
            if not session:
                return

            session.phase = EngagementPhase.HALTED.value
            await self.session_memory.store_session_state(session)

            # Sprint 6B: Record engagement halt metrics
            record_engagement_halted(session_id)

            # Cancel all pending tasks
            for task in self._tasks.values():
                if task.engagement_id == session_id and task.status in ["pending", "running"]:
                    task.status = "cancelled"

            # Halt all agents
            for agent in self._agents.values():
                if agent.ctx.session_id == session_id:
                    await agent.shutdown()

            await self._audit_log(
                AuditEvent(
                    event_type="engagement_halted",
                    severity="critical",
                    actor_type="system",
                    actor_id="orchestrator",
                    action={"reason": reason},
                    result={"session_id": session_id, "phase": "halted"},
                    context={"session_id": session_id},
                    engagement_id=session.scope.engagement_id,
                )
            )

    # ---- Reliability sprint: stuck-task reaper + restart recovery ----

    REAPER_INTERVAL_SECONDS = 30

    async def _reaper_loop(self) -> None:
        """Background reaper: periodically recover/fail tasks stuck past their timeout."""
        while self._running:
            try:
                await asyncio.sleep(self.REAPER_INTERVAL_SECONDS)
                await self._reap_stuck_tasks()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("reaper_loop_error", error=str(e))

    async def _reap_stuck_tasks(self) -> int:
        """Detect pending/running tasks older than their timeout and recover or fail them.

        running + retry budget  -> requeue via _maybe_retry (recover)
        otherwise               -> mark failed (timeout) + task_reaped audit
        Returns the number of tasks reaped.
        """
        now = datetime.utcnow()
        reaped = 0
        for task in list(self._tasks.values()):
            if task.status not in ("pending", "running"):
                continue
            ref = (
                task.started_at
                if (task.status == "running" and task.started_at)
                else task.created_at
            )
            if not ref:
                continue
            age = (now - ref).total_seconds()
            timeout = task.timeout_seconds or 300
            if age <= timeout:
                continue

            # Recover a stuck running task if it still has retry budget.
            if task.status == "running" and task.retry_count < task.max_retries:
                await self._audit_log(self._reaper_audit(task, age, "recovering"))
                reaped += 1
                await self._maybe_retry(
                    task, {"error": f"reaper: stuck {int(age)}s > {timeout}s timeout"}
                )
                continue

            # Otherwise fail it terminally.
            task.status = "failed"
            task.completed_at = now
            task.result = {"status": "failed", "error": f"reaper timeout after {int(age)}s"}
            await self.graph_memory.upsert_task(
                task, result_summary={"reaped": True, "age_seconds": int(age)}
            )
            await self._audit_log(self._reaper_audit(task, age, "failed"))
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
        """Restart recovery (Reliability sprint), called once at startup.

        1. Reset tasks left 'running' by a dead process to 'interrupted'.
        2. Resume incomplete autonomous-discovery chains: a completed parent missing its
           next SPAWNED child gets that child re-created from the persisted result_summary.
        Re-dispatch flows through the same Neo4j dedupe, so nothing is duplicated.
        """
        summary = {
            "interrupted_reset": 0,
            "redispatched": 0,
            "failed_over_cap": 0,
            "chains_resumed": 0,
            "resumed": [],
        }
        try:
            interrupted = await self.graph_memory.reset_interrupted_tasks()
            summary["interrupted_reset"] = len(interrupted)
            for t in interrupted:
                await self._audit_log(
                    AuditEvent(
                        event_type="task_recovered",
                        severity="warning",
                        actor_type="system",
                        actor_id="orchestrator-recovery",
                        action={
                            "task_id": t.get("id"),
                            "task_type": t.get("type"),
                            "from": "running",
                            "to": "interrupted",
                        },
                        result={"recovered": True},
                        context={"engagement_id": t.get("engagement_id")},
                        engagement_id=t.get("engagement_id") or "system",
                    )
                )
                # AIOSOP-AUDIT-2026-06-16: actually RE-DISPATCH the interrupted task so
                # the engagement does not stall. Capped to avoid crash-loops: a task that
                # has already been recovered MAX_RECOVERY_ATTEMPTS times is failed instead.
                redispatched = await self._redispatch_interrupted_task(t)
                if redispatched is True:
                    summary["redispatched"] += 1
                elif redispatched is False:
                    summary["failed_over_cap"] += 1

            for parent in await self.graph_memory.find_incomplete_chains():
                child = await self._resume_chain_link(parent)
                if child:
                    summary["chains_resumed"] += 1
                    summary["resumed"].append(
                        {"parent": parent.get("id"), "child_type": child.type}
                    )
        except Exception as e:
            logger.error("recover_state_error", error=str(e))
        logger.info("recovery_complete", summary=summary)
        return summary

    # Max times restart-recovery will re-dispatch the same interrupted task before
    # giving up and failing it (prevents a poison task from crash-looping the system).
    MAX_RECOVERY_ATTEMPTS = 3

    async def _redispatch_interrupted_task(self, rec: Dict[str, Any]) -> Optional[bool]:
        """Reconstruct an interrupted Task from its persisted Neo4j props and re-schedule
        it. Returns True if re-dispatched, False if failed over the attempt cap, None if
        it could not be reconstructed (AIOSOP-AUDIT-2026-06-16)."""
        import json as _json

        task_id = rec.get("id")
        attempts = int(rec.get("recovery_attempts") or 0)
        if attempts > self.MAX_RECOVERY_ATTEMPTS:
            await self.graph_memory.mark_task_status(task_id, "failed")
            await self._audit_log(
                AuditEvent(
                    event_type="task_recovery_exhausted",
                    severity="error",
                    actor_type="system",
                    actor_id="orchestrator-recovery",
                    action={"task_id": task_id, "task_type": rec.get("type"), "attempts": attempts},
                    result={"failed": True},
                    context={"engagement_id": rec.get("engagement_id")},
                    engagement_id=rec.get("engagement_id") or "system",
                )
            )
            return False

        try:
            payload = rec.get("payload")
            payload = (
                _json.loads(payload) if isinstance(payload, str) and payload else (payload or {})
            )
            agent_type = rec.get("agent_type")
            task = Task(
                id=task_id,
                type=rec.get("type"),
                priority=int(rec.get("priority") or 5),
                agent_type=(
                    AgentType(agent_type) if not isinstance(agent_type, AgentType) else agent_type
                ),
                payload=payload if isinstance(payload, dict) else {},
                max_retries=int(rec.get("max_retries") or 3),
                timeout_seconds=int(rec.get("timeout_seconds") or 300),
                status="pending",
                engagement_id=rec.get("engagement_id") or "",
            )
        except Exception as e:
            logger.debug("could_not_reconstruct_interrupted_task", task_id=task_id, error=str(e))
            return None

        # P1-2: on recovery, force a fresh approval for approval_required tasks — the
        # persisted payload may carry a stale operator_approved=True (or be tampered),
        # which would otherwise let a destructive exploit re-run with no human in loop.
        if task.type in ("validate_exploit", "exploit_validation"):
            task.approval_required = True
        self._strip_stale_approval(task)

        # schedule_task re-persists (same id -> MERGE, no dup) and re-applies the
        # exploit approval gate, then _assign_task routes it to the right agent.
        await self.schedule_task(task)
        await self._assign_task(task)
        return True

    async def _resume_chain_link(self, parent: Dict[str, Any]) -> Optional[Task]:
        """Recreate the missing next chain link for a completed parent task."""
        import json as _json

        rs = parent.get("result_summary") or "{}"
        try:
            rs = _json.loads(rs) if isinstance(rs, str) else rs
        except Exception:
            rs = {}
        ptype = parent.get("type")
        eid = parent.get("engagement_id")
        # Guard: only resume if no SPAWNED child exists (find_incomplete_chains already filters,
        # but re-check defends against a concurrent resume).
        if await self.graph_memory.task_has_spawned(parent["id"]):
            return None

        if ptype == "capture_authenticated_surface" and rs.get("har_path"):
            child = Task(
                type="extract_har_api_inventory",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "har_path": rs.get("har_path", ""),
                    "user_label": rs.get("user_label", "guest"),
                    "workflow_id": rs.get("workflow_id", ""),
                    "engagement_id": eid,
                },
                dependencies=[parent["id"]],
                engagement_id=eid,
            )
        elif ptype == "map_workflow" and await self._engagement_is_authenticated(eid):
            child = Task(
                type="capture_authenticated_surface",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "url": rs.get("url", ""),
                    "user_label": rs.get("user_label", "guest"),
                    "workflow_id": rs.get("workflow_id", ""),
                    "engagement_id": eid,
                },
                dependencies=[parent["id"]],
                engagement_id=eid,
            )
        else:
            return None

        # Build the parent stub for the SPAWNED edge, persist the dependency, audit, schedule.
        parent_stub = Task(
            id=parent["id"],
            type=ptype,
            agent_type=AgentType.WORKFLOW,
            payload={},
            engagement_id=eid,
            status="completed",
        )
        await self._persist_task_dependency(parent_stub, child)
        await self._audit_log(
            AuditEvent(
                event_type="chain_resumed",
                severity="info",
                actor_type="system",
                actor_id="orchestrator-recovery",
                action={
                    "parent_task_id": parent["id"],
                    "parent_type": ptype,
                    "created_task_id": child.id,
                    "created_type": child.type,
                },
                result={"resumed": True},
                context={"engagement_id": eid},
                engagement_id=eid or "system",
            )
        )
        await self.schedule_task(child)
        logger.info(
            "chain_resume",
            parent_type=ptype,
            parent_id=parent["id"][:12],
            child_type=child.type,
            child_id=child.id[:12],
        )
        return child

    async def _scheduler_loop(self) -> None:
        """Background task scheduler."""
        while self._running:
            try:
                # 1. Process pending tasks already in memory (Issue 15: task leakage)
                for task in list(self._tasks.values()):
                    if task.status == "pending":
                        # Check dependencies
                        if not task.dependencies:
                            await self._assign_task(task)
                        else:
                            all_deps_complete = all(
                                self._tasks.get(dep_id)
                                and self._tasks[dep_id].status == "completed"
                                for dep_id in task.dependencies
                            )
                            if all_deps_complete:
                                await self._assign_task(task)

                # 2. Process new tasks from queues
                for session_id, session in self._sessions.items():
                    if session.phase == EngagementPhase.HALTED.value:
                        continue

                    task_data = await self.session_memory.pop_task_queue(
                        f"tasks:{session.session_id}"
                    )
                    if task_data:
                        task = Task(**task_data)
                        if task.id in self._tasks:
                            existing = self._tasks[task.id]
                            if existing.status in ["running", "completed", "failed"]:
                                continue

                        self._tasks[task.id] = task
                        await self._assign_task(task)

                # 3. Health check agents
                for agent_id, agent in list(self._agents.items()):
                    status = await agent.get_status()
                    if status["status"] == "shutdown":
                        del self._agents[agent_id]

                await asyncio.sleep(5)

            except Exception as e:
                # Log but don't crash scheduler
                logger.error("scheduler_error", error=str(e))
                await asyncio.sleep(10)

    async def _audit_log(self, event: AuditEvent) -> None:
        """Write audit event."""
        await self.session_memory.write_audit_event(event)

    async def register_agent(self, agent: Any) -> None:
        """Register an agent with the orchestrator."""
        self._agents[agent.ctx.agent_id] = agent
        await agent.initialize()

    # Auto-transition backoff: after this many consecutive failures we stop logging
    # the failure at warning volume and only emit one quiet line, retrying on an
    # ever-growing (capped) tick interval until the phase changes and resets state.
    AUTO_TRANSITION_MAX_ATTEMPTS = 5
    AUTO_TRANSITION_MAX_BACKOFF_TICKS = 30

    async def _phase_monitor(self) -> None:
        """Monitor engagement phases and trigger auto-transitions."""
        tick = 0
        while self._running:
            try:
                await asyncio.sleep(10)
                tick += 1
                for session_id, session in list(self._sessions.items()):
                    phase = EngagementPhase(session.phase)
                    policy = self.PHASE_POLICY.get(phase)

                    if policy and policy["auto_next"]:
                        # Check if all tasks for current phase are complete
                        if await self._is_phase_complete(session_id, phase):
                            next_phase = await self._resolve_auto_next(
                                session_id, phase, policy["auto_next"]
                            )
                            if next_phase is None:
                                continue
                            if not self._auto_transition_ready(session_id, phase, tick):
                                continue
                            try:
                                await self.transition_phase(session_id, next_phase)
                                logger.info(
                                    "auto_transition", session_id=session_id, phase=next_phase.value
                                )
                                self._auto_transition_failures.pop(session_id, None)
                            except Exception as e:
                                self._record_auto_transition_failure(session_id, phase, tick, e)
            except Exception as loop_err:
                logger.error("phase_monitor_loop_error", error=str(loop_err))

    def _auto_transition_ready(self, session_id: str, phase: "EngagementPhase", tick: int) -> bool:
        """Backoff gate: skip an auto-transition attempt while a prior failure for this
        session is still in its backoff window, or once the attempt cap is exhausted."""
        state = self._auto_transition_failures.get(session_id)
        if not state:
            return True
        # Phase changed since the last failure -> stale counter, reset and allow.
        if state.get("phase") != phase.value:
            self._auto_transition_failures.pop(session_id, None)
            return True
        if state["count"] >= self.AUTO_TRANSITION_MAX_ATTEMPTS:
            return False
        return tick >= state["next_tick"]

    def _record_auto_transition_failure(
        self, session_id: str, phase: "EngagementPhase", tick: int, err: Exception
    ) -> None:
        """Track a failed auto-transition with exponential backoff (mirrors _maybe_retry)."""
        state = self._auto_transition_failures.get(session_id)
        if not state or state.get("phase") != phase.value:
            state = {"phase": phase.value, "count": 0, "next_tick": tick}
        state["count"] += 1
        backoff = min(2 ** state["count"], self.AUTO_TRANSITION_MAX_BACKOFF_TICKS)
        state["next_tick"] = tick + backoff
        self._auto_transition_failures[session_id] = state
        if state["count"] >= self.AUTO_TRANSITION_MAX_ATTEMPTS:
            logger.warning(
                "auto_transition_giving_up",
                session_id=session_id,
                attempts=state["count"],
                error=str(err),
            )
        elif state["count"] < self.AUTO_TRANSITION_MAX_ATTEMPTS:
            logger.warning(
                "auto_transition_failed",
                session_id=session_id,
                attempt=state["count"],
                next_retry=backoff,
                error=str(err),
            )

    async def _resolve_auto_next(
        self,
        session_id: str,
        phase: "EngagementPhase",
        desired_next: "EngagementPhase",
    ) -> Optional["EngagementPhase"]:
        """Pick the auto-transition target, rerouting around guard conditions that
        would otherwise make the pipeline hang.

        Concretely: VULNERABILITY_DISCOVERY normally auto-advances to EXPLOITATION,
        but transition_phase() refuses that hop when no Vulnerability nodes exist
        (a real outcome when scans find nothing). Without rerouting, the monitor
        would retry the impossible transition every 10s forever and the engagement
        would never reach REPORTING. VALID_TRANSITIONS already allows
        VULNERABILITY_DISCOVERY -> REPORTING, so fall back to it and let the mission
        terminate cleanly at COMPLETED. (AIOSOP-AUTO-2026-06-16)
        """
        if desired_next == EngagementPhase.EXPLOITATION:
            try:
                stats = await self.graph_memory.get_graph_stats(session_id)
            except Exception as e:
                logger.error(
                    "resolve_auto_next_graph_stats_failed", session_id=session_id, error=str(e)
                )
                stats = {}
            if stats.get("vulnerabilities", 0) == 0:
                fallback = EngagementPhase.REPORTING
                if fallback in self.VALID_TRANSITIONS.get(phase, []):
                    logger.info(
                        "auto_reroute_no_vulnerabilities",
                        session_id=session_id,
                        from_phase=phase.value,
                        to_phase="reporting",
                    )
                    return fallback
        return desired_next

    async def _is_phase_complete(self, session_id: str, phase: EngagementPhase) -> bool:
        """Check if all tasks for the current phase are finished."""
        if phase == EngagementPhase.INITIALIZED:
            return True

        # Map phase to corresponding AgentTypes
        phase_agent_mapping = {
            EngagementPhase.RECONNAISSANCE: {AgentType.RECON},
            EngagementPhase.VULNERABILITY_DISCOVERY: {AgentType.VULN_ANALYSIS},
            EngagementPhase.EXPLOITATION: {AgentType.EXPLOIT_VALIDATION, AgentType.ATTACK_CHAIN},
            EngagementPhase.POST_EXPLOITATION: {AgentType.WORKFLOW},
            EngagementPhase.REPORTING: {AgentType.REPORTING},
        }

        # Pass-through phases: _on_phase_enter() schedules NO work of its own for
        # these, so "no tasks" must mean "nothing to wait on" — otherwise the
        # monitor hangs here forever (POST_EXPLOITATION never schedules a WORKFLOW
        # task, so it would never be considered complete). For these phases, treat
        # absence of in-flight tasks as complete. (AIOSOP-AUTO-2026-06-16)
        PASS_THROUGH_PHASES = {EngagementPhase.POST_EXPLOITATION}

        allowed_agents = phase_agent_mapping.get(phase, set())
        session_tasks = [t for t in self._tasks.values() if t.engagement_id == session_id]
        phase_tasks = [t for t in session_tasks if t.agent_type in allowed_agents]

        # If no tasks exist yet for this phase: pass-through phases are complete;
        # work-scheduling phases are not (we must wait for their tasks to appear).
        if not phase_tasks:
            return phase in PASS_THROUGH_PHASES

        # Complete only if none of the phase tasks are pending or running
        return all(t.status not in ["pending", "running"] for t in phase_tasks)

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        self._running = False

        for bg in (self._scheduler_task, self._reaper_task, self._phase_monitor_task):
            if bg:
                bg.cancel()
                try:
                    await bg
                except asyncio.CancelledError:
                    pass

        # Shutdown retention service
        if hasattr(self, "_retention_service") and self._retention_service:
            await self._retention_service.stop()

        # Shutdown all agents
        for agent in self._agents.values():
            await agent.shutdown()

        await self.session_memory.close()
        await self.graph_memory.close()
