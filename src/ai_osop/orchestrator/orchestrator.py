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
from ai_osop.reliability.dlq import DeadLetterQueue
from ai_osop.orchestrator.task_scheduler import TaskScheduler
from ai_osop.orchestrator.approval_coordinator import ApprovalCoordinator
from ai_osop.orchestrator.phase_monitor import PhaseMonitor
from ai_osop.orchestrator.engagement_manager import EngagementManager
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.reliability.agent_reaper import AgentReaper
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


from ai_osop.core.config import AgentType, EngagementPhase


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
        # Sprint 7: Dead Letter Queue for tasks that exhaust their retry budget
        self.dlq = DeadLetterQueue(session_memory)
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

        # Sprint 9: Extracted sub-components for Architecture Excellence
        self.task_scheduler = TaskScheduler(self)
        self.approval_coordinator = ApprovalCoordinator(self)
        self.phase_monitor = PhaseMonitor(self)
        self.engagement_manager = EngagementManager(self)
        self.recovery_service = RecoveryService(self)
        self.agent_reaper = AgentReaper(self)

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
                self._phase_monitor_task = loop.create_task(self.phase_monitor._phase_monitor())
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

        # Sprint 6B: Restore in-flight engagement state
        await self.recover_state()

        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        # Reliability sprint: background stuck-task reaper.
        self._agent_reaper_task = asyncio.create_task(self.agent_reaper.run())
        self._reaper_task = asyncio.create_task(self._reaper_loop())
        # Retention service: automated cleanup of old data
        from ai_osop.memory.retention_service import RetentionService

        self._retention_service = RetentionService(self.graph_memory, self.session_memory)
        await self._retention_service.start()
        # Phase monitor drives auto-transitions. __init__ only starts it when a loop
        # is already running at construction; start it here (idempotently) so the
        # canonical construct-then-initialize path can never leave it dead.
        if self._phase_monitor_task is None or self._phase_monitor_task.done():
            self._phase_monitor_task = asyncio.create_task(self.phase_monitor._phase_monitor())

        # P0: Recovery sprint — restore in-flight state from warm tier so restarts
        # don't lose pending approvals or active tasks.
        try:
            pending_approvals = await self.session_memory.list_pending_approvals()
            for apr in pending_approvals:
                self._approval_requests[apr.id] = apr
                # Re-spawn timeout watcher so stale approvals still fail correctly
                asyncio.create_task(self.approval_coordinator._await_approval_outcome(apr.id))
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
        """Create new engagement session. Delegated to EngagementManager."""
        return await self.engagement_manager.create_engagement(scope, roe, created_by)

    async def transition_phase(self, session_id: str, new_phase: EngagementPhase) -> SessionState:
        """Transition engagement to new phase with validation. Delegated to EngagementManager."""
        return await self.engagement_manager.transition_phase(session_id, new_phase)
        # The previous lines were corrupted and lacked context for the AuditEvent
        # Removed them as create_engagement is now delegated to EngagementManager.

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
            # Sprint 15A/15B — value-ordered, batched endpoint scanning.
            #
            # Previously this scanned host ASSETS (one nuclei + one burp per asset),
            # which (a) ignored the rich discovered ENDPOINT surface entirely and
            # (b) fanned out one task per asset. Now we scan the discovered endpoints,
            # ranked by the Attack Surface Value Engine and chunked into a BOUNDED
            # number of batches so 1,000 endpoints become ~10 high-value scan jobs
            # rather than 1,000 tasks. Falls back to per-asset scanning when no
            # endpoints were discovered (e.g. WAF-fronted target).
            from ai_osop.core.value_engine import batch_endpoints_for_scan

            # 1) Per-asset Burp scan of the host(s) — Burp crawls from the root.
            assets: List[str] = []
            async with self.graph_memory._driver.session() as g_session:
                result = await g_session.run(
                    "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain",
                    {"sid": session.session_id},
                )
                async for record in result:
                    assets.append(record["domain"])

            for domain in assets:
                burp_task = Task(
                    type="burp_scan",
                    priority=7,
                    agent_type=AgentType.VULN_ANALYSIS,
                    payload={"url": f"https://{domain}"},
                    engagement_id=session.session_id,
                    timeout_seconds=600,
                )
                await self.schedule_task(burp_task)

            # 2) Endpoint-aware Nuclei scans, value-ordered + batched.
            endpoints: List[Dict[str, Any]] = []
            async with self.graph_memory._driver.session() as g_session:
                result = await g_session.run(
                    """MATCH (e:Endpoint {engagement_id: $sid})
                       RETURN e.url AS url, e.method AS method,
                              e.status_code AS status_code, e.technologies AS technologies""",
                    {"sid": session.session_id},
                )
                async for r in result:
                    if r["url"]:
                        endpoints.append({
                            "url": r["url"],
                            "method": r["method"] or "GET",
                            "status_code": r["status_code"],
                            "technologies": r["technologies"] or [],
                        })

            batches = batch_endpoints_for_scan(endpoints, batch_size=20, max_targets=200)

            if batches:
                logger.info(
                    "value_batched_scan",
                    session_id=session.session_id,
                    endpoints=len(endpoints),
                    batches=len(batches),
                )
                for i, batch in enumerate(batches):
                    nuclei_task = Task(
                        type="nuclei_scan",
                        # Earlier (higher-value) batches scan first.
                        priority=9 if i == 0 else 7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={
                            "targets": batch,
                            "severity": "critical,high,medium",
                            "batch_index": i,
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=settings.nuclei_mcp_timeout + 120,
                    )
                    await self.schedule_task(nuclei_task)
            else:
                # Fallback: no endpoints discovered → scan the host assets directly
                # (timeout-aligned + severity-scoped, per the nuclei self-heal).
                for domain in assets:
                    nuclei_task = Task(
                        type="nuclei_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={
                            "targets": [f"https://{domain}"],
                            "severity": "critical,high,medium",
                        },
                        engagement_id=session.session_id,
                        timeout_seconds=settings.nuclei_mcp_timeout + 120,
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
        """Schedule a task for execution. Delegated to TaskScheduler."""
        return await self.task_scheduler.schedule_task(task)
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
        """Assign task to appropriate agent. Delegated to TaskScheduler."""
        return await self.task_scheduler._assign_task(task)

    async def _find_available_agent(self, agent_type: AgentType, task_type: str = "") -> Optional[Any]:
        """Find and atomically claim an idle agent. Delegated to TaskScheduler."""
        return await self.task_scheduler._find_available_agent(agent_type, task_type)

    def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release an agent claim. Delegated to TaskScheduler."""
        return self.task_scheduler._release_agent(agent_id)

    @staticmethod
    def _strip_stale_approval(task: Task) -> None:
        """Drop persisted approval grant so gate re-fires. Delegated to ApprovalCoordinator."""
        return ApprovalCoordinator._strip_stale_approval(task)

    async def _maybe_retry(self, task: Task, result: Dict[str, Any]) -> bool:
        """Requeue a failed task if retry budget remains. Delegated to TaskScheduler."""
        return await self.task_scheduler._maybe_retry(task, result)

    async def _execute_via_agent(self, agent: Any, task: Task) -> None:
        """Execute task through assigned agent. Delegated to TaskScheduler."""
        return await self.task_scheduler._execute_via_agent(agent, task)

    async def _on_task_success(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle task completion. Delegated to TaskScheduler."""
        return await self.task_scheduler._on_task_success(task, result)

    async def _on_task_failure(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle task failure. Delegated to TaskScheduler."""
        return await self.task_scheduler._on_task_failure(task, result)

    async def _trigger_downstream_tasks(self, completed_task: Task) -> None:
        """Trigger tasks that depend on completed task. Delegated to TaskScheduler."""
        return await self.task_scheduler._trigger_downstream_tasks(completed_task)

    async def _chain_authenticated_surface(self, task: Task, result: Optional[Dict[str, Any]] = None) -> None:
        """Chain authenticated surface discovery. Delegated to TaskScheduler."""
        return await self.task_scheduler._chain_authenticated_surface(task, result)

    async def _persist_task_dependency(self, parent: Task, child: Task) -> None:
        """Persist a parent→child dependency. Delegated to TaskScheduler."""
        return await self.task_scheduler._persist_task_dependency(parent, child)

    async def _execute_task_durable(self, task: Task) -> Dict[str, Any]:
        """Execute task durably. Delegated to TaskScheduler."""
        return await self.task_scheduler._execute_task_durable(task)

    async def _retry_sleep(self, seconds: float) -> None:
        """Sleep for retry backoff. Delegated to TaskScheduler."""
        return await self.task_scheduler._retry_sleep(seconds)
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

    async def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        """Submit approval request and BLOCK until operator decides. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator.request_approval(request)

    async def _register_approval(self, request: ApprovalRequest) -> None:
        """Register approval request. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator._register_approval(request)

    async def _raise_approval(self, request: ApprovalRequest) -> None:
        """Non-blocking approval. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator._raise_approval(request)

    async def _await_approval_outcome(self, request_id: str) -> None:
        """Background approval timeout watcher. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator._await_approval_outcome(request_id)

    async def _wait_for_approval(self, request_id: str) -> None:
        """Wait for approval request to be resolved. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator._wait_for_approval(request_id)

    async def resolve_approval(self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None) -> ApprovalRequest:
        """Resolve an approval request. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator.resolve_approval(request_id, decision, operator_id, notes)
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

    async def halt_engagement(self, session_id: str, reason: str) -> None:
        """Emergency halt of engagement. Delegated to EngagementManager."""
        return await self.engagement_manager.halt_engagement(session_id, reason)

    async def claim_auto_discovery(self, engagement_id: str, auth_user_label: str, source_task_id: str) -> None:
        """Claim autonomous discovery. Delegated to EngagementManager."""
        return await self.engagement_manager.claim_auto_discovery(engagement_id, auth_user_label, source_task_id)


    async def _on_phase_enter(self, session: SessionState, phase: EngagementPhase) -> None:
        """Trigger automatic tasks when entering a phase. Delegated to PhaseMonitor."""
        return await self.phase_monitor._on_phase_enter(session, phase)

    async def _phase_monitor(self) -> None:
        """Background phase monitor. Delegated to PhaseMonitor."""
        return await self.phase_monitor._phase_monitor()

    async def _reaper_loop(self) -> None:
        """Background reaper for stuck tasks. Delegated to RecoveryService."""
        return await self.recovery_service._reaper_loop()

    async def _reap_stuck_tasks(self) -> int:
        """Detect and recover stuck tasks. Delegated to RecoveryService."""
        return await self.recovery_service._reap_stuck_tasks()

    async def recover_state(self) -> Dict[str, Any]:
        """Restart recovery. Delegated to RecoveryService."""
        return await self.recovery_service.recover_state()
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
                logger.info("scheduler_debug", tasks_count=len(self._tasks), sessions_count=len(self._sessions))
                # 1. Process pending tasks already in memory (Issue 15: task leakage)
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
