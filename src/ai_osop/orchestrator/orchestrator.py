"""
Central Orchestrator
Task scheduling, state management, agent coordination, and workflow enforcement.
"""

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from ai_osop.core.config import AgentType, settings
from ai_osop.core.exceptions import ScopeException, WorkflowException, WorkflowTransitionError
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition, SessionState, Task
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
        EngagementPhase.INITIALIZED: {"manual_approval": False, "auto_next": EngagementPhase.RECONNAISSANCE},
        EngagementPhase.RECONNAISSANCE: {"manual_approval": False, "auto_next": EngagementPhase.VULNERABILITY_DISCOVERY},
        EngagementPhase.VULNERABILITY_DISCOVERY: {"manual_approval": False, "auto_next": EngagementPhase.EXPLOITATION},
        EngagementPhase.EXPLOITATION: {"manual_approval": False, "auto_next": EngagementPhase.REPORTING},
        EngagementPhase.REPORTING: {"manual_approval": False, "auto_next": EngagementPhase.COMPLETED},
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

        self._agents: Dict[str, Any] = {}  # agent_id -> agent instance
        self._tasks: Dict[str, Task] = {}  # task_id -> Task
        self._sessions: Dict[str, SessionState] = {}  # session_id -> SessionState
        self._approval_requests: Dict[str, ApprovalRequest] = {}

        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._approval_callbacks: List[Callable[[ApprovalRequest], None]] = []

        # Start phase monitor if an event loop is running (avoids test errors)
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                loop.create_task(self._phase_monitor())
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

    async def create_engagement(self, scope: ScopeDefinition, roe: Dict[str, Any]) -> SessionState:
        """Create new engagement session."""
        session = SessionState(
            session_id=f"eng-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{scope.engagement_id}",
            scope=scope,
            roe=roe,
            phase=EngagementPhase.INITIALIZED.value,
            agents={},
            checkpoint_id=None,
            audit_log_position="0",
        )

        # Persist session
        await self.session_memory.store_session_state(session)
        await self.session_memory.persist_session_state(session)

        self._sessions[session.session_id] = session

        # Audit log
        await self._audit_log(
            AuditEvent(
                event_type="engagement_created",
                severity="info",
                actor_type="system",
                actor_id="orchestrator",
                action={"scope": scope.dict(), "roe": roe},
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
                    payload={"domain": domain, "scope": session.scope.dict()},
                    engagement_id=session.session_id,
                )
                await self.schedule_task(task)

        elif phase == EngagementPhase.VULNERABILITY_DISCOVERY:
            # Auto-create scan tasks for discovered assets
            cypher = "MATCH (a:Asset {engagement_id: $sid}) RETURN a.value as domain"
            async with self.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"sid": session.session_id})
                async for record in result:
                    domain = record["domain"]
                    task = Task(
                        type="burp_scan",
                        priority=7,
                        agent_type=AgentType.VULN_ANALYSIS,
                        payload={"url": f"https://{domain}"},
                        engagement_id=session.session_id,
                    )
                    await self.schedule_task(task)

        elif phase == EngagementPhase.EXPLOITATION:
            # Auto-create validation tasks for confirmed vulns
            cypher = "MATCH (v:Vulnerability {engagement_id: $sid}) RETURN v.id as vuln_id"
            vuln_ids = []
            async with self.graph_memory._driver.session() as g_session:
                result = await g_session.run(cypher, {"sid": session.session_id})
                async for record in result:
                    vuln_ids.append(record["vuln_id"])
            
            print(f"EXHAUSTIVE_MODE: Generating {len(vuln_ids)} exploit tasks for session {session.session_id}")
            for vid in vuln_ids:
                task = Task(
                    type="exploit_validation",
                    priority=9,
                    agent_type=AgentType.EXPLOIT_VALIDATION,
                    approval_required=True,
                    payload={
                        "vuln_id": vid,
                        "operator_approved": False,
                        "approval_id": f"auto-{vid}"
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
        self._tasks[task.id] = task
        await self.coordination_bus.publish(
            "task.scheduled",
            {"task_id": task.id, "task_type": task.type, "agent_type": task.agent_type.value},
            "orchestrator",
        )

        # Store in hot memory
        await self.session_memory.push_task_queue(f"tasks:{task.engagement_id}", task.dict())

        if self.temporal_enabled and self.temporal_scheduler:
            workflow_id = await self.temporal_scheduler.start_task_workflow(task.dict())
            task.status = "scheduled"
            task.result = {"workflow_id": workflow_id, "durable": True}
            return task

        # If no dependencies and agent available, assign immediately
        if not task.dependencies:
            await self._assign_task(task)

        return task

    async def _assign_task(self, task: Task) -> None:
        """Assign task to appropriate agent."""
        if hasattr(self, "rate_limiter") and self.rate_limiter:
            await self.rate_limiter.acquire(tool="orchestrator")

        # Find available agent of required type
        agent = await self._find_available_agent(task.agent_type)

        if agent:
            # Approval Gatekeeping
            if task.approval_required:
                request = ApprovalRequest(
                    task_id=task.id,
                    agent_id=agent.ctx.agent_id,
                    action_type=task.type,
                    target=str(task.payload.get("url", task.payload.get("target", "unknown"))),
                    payload_summary=str(task.payload),
                    risk_assessment="high",
                    engagement_id=task.engagement_id
                )
                await self.request_approval(request)
                if request.status != "approved":
                    task.status = "failed"
                    task.result = {"error": f"Approval denied: {request.status}"}
                    return

            task.assigned_agent_id = agent.ctx.agent_id
            task.status = "running"
            await self.coordination_bus.publish(
                "task.assigned",
                {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                "orchestrator",
            )

            # Execute via agent
            asyncio.create_task(self._execute_via_agent(agent, task))
        else:
            # Queue for later assignment
            task.status = "pending"

    async def _find_available_agent(self, agent_type: AgentType) -> Optional[Any]:
        """Find an idle agent of the specified type."""
        for agent in self._agents.values():
            if agent.ctx.agent_type == agent_type and agent.ctx.status == "idle":
                return agent
        return None

    async def _execute_via_agent(self, agent: Any, task: Task) -> None:
        """Execute task through assigned agent."""
        try:
            result = await agent.execute_task(task)

            # Handle result
            if result.get("status") == "success":
                await self._on_task_success(task, result)
            else:
                await self._on_task_failure(task, result)

        except Exception as e:
            await self._on_task_failure(task, {"error": str(e)})

    async def _on_task_success(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle successful task completion."""
        task.result = result
        task.status = "completed"
        task.completed_at = datetime.utcnow()
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
        task.result = result
        task.status = "failed"
        task.completed_at = datetime.utcnow()
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
        """Submit approval request and wait for operator decision."""
        self._approval_requests[request.id] = request

        # Notify all registered callbacks (UI, email, etc.)
        for callback in self._approval_callbacks:
            try:
                await callback(request)
            except Exception:
                pass

        # Wait for operator response (with timeout)
        try:
            await asyncio.wait_for(
                self._wait_for_approval(request.id), timeout=settings.approval_timeout_seconds
            )
        except asyncio.TimeoutError:
            request.status = "timeout"
            request.operator_notes = "Auto-rejected due to timeout"

        return request

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
        request = self._approval_requests.get(request_id)
        if not request:
            raise WorkflowException(f"Approval request {request_id} not found")

        request.status = decision
        request.operator_id = operator_id
        request.operator_notes = notes
        request.responded_at = datetime.utcnow()

        # Update task payload if approved
        if decision == "approved":
            task = self._tasks.get(request.task_id)
            if task:
                task.payload["operator_approved"] = True
                task.payload["approval_id"] = request.id
                # Now that it's approved, we can assign it
                await self._assign_task(task)

        # Audit log
        await self._audit_log(
            AuditEvent(
                event_type="approval_resolved",
                severity="info" if decision == "approved" else "warning",
                actor_type="operator",
                actor_id=operator_id,
                action={"request_id": request_id, "task_id": request.task_id, "decision": decision},
                result={"status": decision, "notes": notes},
                context={"engagement_id": request.engagement_id},
                engagement_id=request.engagement_id,
            )
        )

        return request

    async def halt_engagement(self, session_id: str, reason: str) -> None:
        """Emergency halt of engagement."""
        session = self._sessions.get(session_id)
        if not session:
            return

        session.phase = EngagementPhase.HALTED.value
        await self.session_memory.store_session_state(session)

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

    async def _scheduler_loop(self) -> None:
        """Background task scheduler."""
        while self._running:
            try:
                # Process task queues
                for session_id, session in self._sessions.items():
                    if session.phase == EngagementPhase.HALTED.value:
                        continue

                    # Poll for pending tasks
                    task_data = await self.session_memory.pop_task_queue(
                        f"tasks:{session.scope.engagement_id}"
                    )
                    if task_data:
                        task = Task(**task_data)
                        if task.status == "pending":
                            await self._assign_task(task)

                # Health check agents
                for agent_id, agent in list(self._agents.items()):
                    status = await agent.get_status()
                    if status["status"] == "shutdown":
                        del self._agents[agent_id]

                await asyncio.sleep(5)

            except Exception as e:
                # Log but don't crash scheduler
                print(f"Scheduler error: {e}")
                await asyncio.sleep(10)

    async def _audit_log(self, event: AuditEvent) -> None:
        """Write audit event."""
        await self.session_memory.write_audit_event(event)

    async def register_agent(self, agent: Any) -> None:
        """Register an agent with the orchestrator."""
        self._agents[agent.ctx.agent_id] = agent
        await agent.initialize()

    async def _phase_monitor(self) -> None:
        """Monitor engagement phases and trigger auto-transitions."""
        while True:
            await asyncio.sleep(10)
            for session_id, session in self._sessions.items():
                phase = EngagementPhase(session.phase)
                policy = self.PHASE_POLICY.get(phase)

                if policy and policy["auto_next"]:
                    # Check if all tasks for current phase are complete
                    if await self._is_phase_complete(session_id, phase):
                        try:
                            await self.transition_phase(session_id, policy["auto_next"])
                            print(f"AUTO-TRANSITION: {session_id} to {policy['auto_next']}")
                        except Exception as e:
                            print(f"AUTO-TRANSITION FAILED for {session_id}: {e}")

    async def _is_phase_complete(self, session_id: str, phase: EngagementPhase) -> bool:
        """Check if all tasks for the current phase are finished."""
        phase_tasks = [
            t for t in self._tasks.values() 
            if t.engagement_id == session_id and t.status in ["pending", "running"]
        ]
        return len(phase_tasks) == 0

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        self._running = False

        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass

        # Shutdown all agents
        for agent in self._agents.values():
            await agent.shutdown()

        await self.session_memory.close()
        await self.graph_memory.close()
