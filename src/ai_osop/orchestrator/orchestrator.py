"""
Central Orchestrator
Task scheduling, state management, agent coordination, and workflow enforcement.
"""

import asyncio
import inspect
import re
import uuid
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

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
from ai_osop.orchestrator.approval_coordinator import (
    ApprovalCoordinator, remaining_durable_approval_seconds,
)
from ai_osop.orchestrator.phase_monitor import PhaseMonitor
from ai_osop.orchestrator.engagement_manager import EngagementManager
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.orchestrator.engagement_controller import GoalOrientedEngagementController
from ai_osop.orchestrator.flow_refinement import BoundedFlowRefiner
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
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus
from ai_osop.orchestrator.temporal_worker import (
    TemporalTaskScheduler,
    TemporalUnavailableError,
    temporal_available,
)
from ai_osop.safety.rate_limiter import RateLimiter
from ai_osop.safety.scope import ScopeEnforcer

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
        # Shared by the legacy orchestrator and extracted coordinator routes.
        # Serializes local decisions; the durable cross-replica CAS remains a
        # separate release gate and is not implied by this process-local lock.
        self._approval_decision_locks: Dict[str, asyncio.Lock] = {}
        # P0-1 (concurrency): orchestrator-side atomic claim set keyed by agent_id.
        # An agent is claimed SYNCHRONOUSLY the moment it is selected for a task
        # (no await between find and claim), released in _execute_via_agent's finally.
        # This closes the window where a fire-and-forget dispatch hadn't yet flipped
        # the agent's status to "running" and the same idle agent got selected twice,
        # driving two coroutines through one agent and clobbering shared self.ctx.
        self._busy_agents: set[str] = set()
        # Retain handles for in-process dispatch. Emergency halt must cancel
        # the actual coroutine, not only persist a cancelled task status.
        self._inflight_tasks: Dict[str, asyncio.Task] = {}
        # Backed by PostgreSQL, not by a process-local event buffer. Created
        # lazily so older test doubles do not require a database connection.
        self._supervision_store = None
        self._terminal_store = None
        self._terminal_dispatcher = None
        self._supervision_active = False
        self._supervision_outbox = None

        # Sprint 9: Extracted sub-components for Architecture Excellence
        self.task_scheduler = TaskScheduler(self)
        self.approval_coordinator = ApprovalCoordinator(self)
        self.phase_monitor = PhaseMonitor(self)
        self.engagement_manager = EngagementManager(self)
        self.recovery_service = RecoveryService(self)
        self.adaptive_planner = GoalOrientedEngagementController(self)
        self.flow_refiner = BoundedFlowRefiner(self)

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
        # A real warm-tier transaction is required before a worker may write
        # durable execution attempts; test doubles continue to exercise their
        # explicitly mocked scheduler paths.
        self._supervision_active = (
            isinstance(self.session_memory, SessionMemory)
            and self.session_memory._async_session is not None
        )
        if self._supervision_active and callable(
            getattr(self.mcp_registry, "set_execution_event_callback", None)
        ):
            async def persist_mcp_execution_event(
                engagement_id: str, task_id: str, kind: str, metadata: Dict[str, Any]
            ) -> bool:
                remote_request_id = metadata.get("request_id")
                if not isinstance(remote_request_id, str) or not remote_request_id:
                    return False
                server_id = metadata.get("server_id")
                if not isinstance(server_id, str) or not server_id:
                    return False
                if kind == "dispatch_accepted":
                    # A previous replica can have accepted this request and
                    # disappeared before an HTTP response. Never replay it.
                    return await self.supervision_store.claim_mcp_dispatch(
                        engagement_id, task_id, server_id,
                        remote_request_id, metadata.get("tool_name", ""),
                    )
                return await self.supervision_store.record_mcp_dispatch_event(
                    engagement_id, task_id, server_id, remote_request_id,
                    kind, metadata.get("status", "unknown"),
                    attested_receipt=metadata.get("attested_receipt"),
                )

            self.mcp_registry.set_execution_event_callback(
                persist_mcp_execution_event
            )
        await self.graph_memory.connect()
        if self.temporal_enabled:
            if not temporal_available() and self.temporal_scheduler is None:
                raise TemporalUnavailableError(
                    "Temporal is enabled but temporalio is not installed"
                )
            self.temporal_scheduler = self.temporal_scheduler or TemporalTaskScheduler()
            await self.temporal_scheduler.connect()

        # Restore engagement ownership/scope and pending tasks before consumers
        # are allowed to dispatch work on this process.
        await self.recovery_service.recover_state()
        # Recover pending approval watchers and interrupted discovery chains.
        # Warm-tier tasks have already been restored by RecoveryService.
        try:
            pending_approvals = await self.session_memory.list_pending_approvals()
            for apr in pending_approvals:
                self._approval_requests[apr.id] = apr
                # Re-spawn timeout watcher so stale approvals still fail correctly
                asyncio.create_task(self.approval_coordinator._await_approval_outcome(apr.id))
            await self.recover_state()
        except Exception as e:
            # Log but don't block startup — the orchestrator can still function
            # with empty in-memory state (new engagements will work fine).
            logger.warning("orchestrator_startup_recovery_failed", error=str(e))

        self._running = True
        if self._supervision_active:
            from ai_osop.orchestrator.supervision_outbox import SupervisionOutboxDispatcher
            from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher

            self._supervision_outbox = SupervisionOutboxDispatcher(
                self.supervision_store,
                self.coordination_bus,
                enqueue_registered_task=self.reconcile_flow_dispatch_intent,
                enqueue_signed_replay_pair=self.reconcile_signed_replay_pair_intent,
            )
            self._supervision_outbox.start()
            self._terminal_dispatcher = TerminalCallbackDispatcher(self)
            self._terminal_dispatcher.start()
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        self._reaper_task = asyncio.create_task(self._reaper_loop())
        from ai_osop.memory.retention_service import RetentionService

        self._retention_service = RetentionService(self.graph_memory, self.session_memory)
        await self._retention_service.start()
        if self._phase_monitor_task is None or self._phase_monitor_task.done():
            self._phase_monitor_task = asyncio.create_task(self._phase_monitor())

    async def create_engagement(
        self,
        scope: ScopeDefinition,
        roe: Dict[str, Any],
        created_by: Optional[str] = None,
        *,
        signed_roe: Optional[Dict[str, Any]] = None,
    ) -> SessionState:
        """Admit an engagement only from a real signed policy and PG record.

        Previously arbitrary operator-supplied authorization_ref strings and
        an UPSERT could forge a scope or overwrite an existing engagement.
        External/CLI/direct callers share this fail-closed production gate.
        """
        from ai_osop.safety.signed_roe import verify_signed_roe
        from ai_osop.memory.authorization_store import AuthorizationDenied, AuthorizationStore

        if not isinstance(signed_roe, dict) or not created_by:
            raise WorkflowException("Signed ROE and accountable owner required")
        verified = verify_signed_roe(
            signed_roe,
            expected_engagement_id=scope.engagement_id,
            expected_owner=created_by,
            expected_scope=scope,
            expected_roe=roe,
            now=datetime.now(timezone.utc),
        )
        if scope.engagement_id != verified.engagement_id:
            raise WorkflowException("Signed engagement identity mismatch")
        with trace_span(
            "orchestrator.create_engagement",
            attributes={
                "engagement_id": scope.engagement_id,
                "created_by": created_by or "system",
            },
        ):
            session = SessionState(
                session_id=verified.engagement_id,
                scope=scope,
                roe=roe,
                phase=EngagementPhase.INITIALIZED.value,
                agents={},
                checkpoint_id=None,
                audit_log_position="0",
                created_by=created_by,
            )

            # Commit the session and authorization binding atomically. A
            # failed/duplicate signature, retired version or database outage
            # must not create a runnable engagement in Redis or memory.
            authority = AuthorizationStore(self.session_memory)
            try:
                await authority.create_authorized_session(session, verified, created_by)
            except AuthorizationDenied:
                # A proxy or client can lose the *response* after PostgreSQL
                # committed session+signature+outbox. A retry of the identical
                # still-active signed policy is an idempotent read, never a
                # second creation or widening of the authorized scope.
                await authority.assert_active(
                    verified.engagement_id,
                    expected_version=verified.version,
                    expected_digest=verified.policy_digest,
                )
                persisted = await self.session_memory.load_session_state(
                    verified.engagement_id
                )
                if (
                    not isinstance(persisted, SessionState)
                    or persisted.created_by != created_by
                    or persisted.scope.model_dump(mode="json")
                    != session.scope.model_dump(mode="json")
                    or persisted.roe != roe
                ):
                    raise WorkflowException("Existing signed engagement differs")
                self._sessions[persisted.session_id] = persisted
                return persisted
            self._sessions[session.session_id] = session
            # Post-commit cache is secondary to the authoritative PG ledger.
            try:
                await self.session_memory.store_session_state(session)
            except Exception as exc:
                logger.warning(
                    "signed_engagement_cache_unavailable",
                    engagement_id=session.session_id,
                    error_class=type(exc).__name__,
                )

            # Sprint 6B: Record engagement metrics
            record_engagement_started(session.session_id)

            # Audit log
            try:
                await self._audit_log(
                    AuditEvent(
                    event_type="engagement_created",
                    severity="info",
                    actor_type="system",
                    actor_id="orchestrator",
                    action={
                        "authorization_id": verified.authorization_id,
                        "policy_digest": verified.policy_digest,
                        "policy_version": verified.version,
                    },
                    result={"session_id": session.session_id},
                    context={"phase": session.phase},
                    engagement_id=scope.engagement_id,
                    )
                )
            except Exception as exc:
                # The transactional authorization event/outbox is already
                # committed. Never incorrectly return creation failure after
                # those durable effects because a duplicate retry could
                # report a ghost session.
                logger.warning(
                    "signed_engagement_secondary_audit_unavailable",
                    engagement_id=session.session_id,
                    error_class=type(exc).__name__,
                )

            return session

    async def checkpoint_engagement(
        self, session_id: str, metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Store a recoverable session checkpoint and persist its reference."""
        session = self._sessions.get(session_id)
        if session is None:
            raise WorkflowException(f"Session {session_id} not found")
        await self.session_memory.store_session_state(session)
        checkpoint_id = await self.session_memory.create_checkpoint(session_id, metadata or {})
        session.checkpoint_id = checkpoint_id
        await self.session_memory.persist_session_state(session)
        return checkpoint_id

    async def restore_engagement_checkpoint(self, checkpoint_id: str) -> SessionState:
        """Restore a snapshot explicitly, without triggering task dispatch."""
        snapshot = await self.session_memory.retrieve_hot(f"checkpoint:{checkpoint_id}")
        if not snapshot or not snapshot.get("session_id"):
            raise WorkflowException("Checkpoint not found or expired")
        session_id = snapshot["session_id"]
        if session_id not in self._sessions:
            raise WorkflowException("Cannot restore checkpoint for an unknown engagement")
        active_states = {"running", "scheduled", "dispatching", "dispatch_unknown"}
        if any(
            task.engagement_id == session_id and task.status in active_states
            for task in self._tasks.values()
        ):
            raise WorkflowException("Cannot restore checkpoint while tasks are running or unresolved")
        session = await self.session_memory.restore_checkpoint(checkpoint_id)
        self._sessions[session.session_id] = session
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

    async def _bind_task_authorization(self, task: Task) -> None:
        """Fence task dispatch against later ROE replacement and revocation."""
        if not isinstance(self.session_memory, SessionMemory):
            return  # Isolated fake-memory unit harnesses have no PG backing.
        try:
            receipt = await self.session_memory.assert_signed_authorization(
                task.engagement_id
            )
        except Exception as exc:
            raise WorkflowException("Task lacks active signed authorization") from exc
        previous = task.payload.get("_authorization_version")
        if previous is not None and (
            type(previous) is not int or previous != receipt.version
        ):
            raise WorkflowException("Task carries a stale authorization revision")
        task.payload["_authorization_version"] = receipt.version

    async def enqueue_registered_task(self, task_id: str) -> Task:
        """Deliver an already-committed Flow execution intent to the queue.

        Unlike schedule_task, this never inserts/upserts a Task, grants an
        approval, or invokes a tool/agent/Temporal workflow. A crash before
        Redis delivery leaves the PostgreSQL pending Task recoverable. A queue
        copy is not authority; dispatchers must recheck the durable claim.
        """
        from ai_osop.safety.scope import action_requires_approval, validate_payload_targets

        if not isinstance(self.session_memory, SessionMemory):
            raise WorkflowException("Durable Flow enqueue requires PostgreSQL")
        sm = self.session_memory
        task = await sm.load_task_authoritative(task_id)
        if (
            task is None or task.status != "pending"
            or not task.flow_id or not task.subtask_id or not task.parent_task_id
            or not isinstance(task.payload, dict)
            or any(key in task.payload for key in ("operator_approved", "approval_id"))
        ):
            raise WorkflowException("Durable Flow execution intent is missing or already claimed")
        version = task.payload.get("_authorization_version")
        if type(version) is not int or version < 1:
            raise WorkflowException("Durable Flow intent lacks signed policy binding")
        try:
            await sm.assert_signed_authorization(task.engagement_id, expected_version=version)
            # Session state reads already use PostgreSQL, not Redis.
            engagement = await sm.load_session_state(task.engagement_id)
            flow = await sm.load_flow(task.flow_id)
            steps = await sm.list_subtasks(task.flow_id)
            matching = [step for step in steps if step.id == task.subtask_id]
            step = matching[0] if len(matching) == 1 else None
            if (
                engagement is None or engagement.phase in {"halted", "completed"}
                or flow is None or flow.engagement_id != task.engagement_id
                or flow.status not in {"pending", "running"}
                or step is None or step.engagement_id != task.engagement_id
                or step.status != "dispatched"
                or step.execution_task_id != task.id
                or step.task_id != task.parent_task_id
                or step.task_type != task.type
                or step.agent_type != task.agent_type
                or step.approval_required and not task.approval_required
                or (action_requires_approval(task.type, engagement.scope)
                    or task.agent_type == AgentType.EXPLOIT_VALIDATION)
                and not task.approval_required
            ):
                raise WorkflowException("Flow execution lineage changed before queue admission")
            enforcer = ScopeEnforcer(engagement.scope)
            enforcer.validate_time_window()
            validate_payload_targets(
                enforcer, task.payload,
                require_target=task.agent_type in {AgentType.RECON, AgentType.VULN_ANALYSIS},
            )
        except Exception as exc:
            raise WorkflowException("Durable Flow intent is no longer authorized") from exc
        # This is a delivery hint, not an execution admission. If Redis fails,
        # the Task/outbox remain authoritative for restart reconciliation.
        await sm.push_task_queue(f"tasks:{task.engagement_id}", task.model_dump())
        return task

    async def reconcile_flow_dispatch_intent(self, task_id: str) -> None:
        """Retry only safe queue *delivery*, never an unknown remote action.

        The supervision outbox already leases records across replicas. A
        pending immutable Task may be queued again because PostgreSQL
        execution admission is one-shot; an already parked/claimed/completed
        Task MUST NOT be re-enqueued. A missing task or unavailable signed
        authority leaves the outbox unacknowledged for investigation.
        """
        if not isinstance(self.session_memory, SessionMemory):
            raise WorkflowException("Flow intent reconciliation needs the durable store")
        task = await self.session_memory.load_task_authoritative(task_id)
        if task is None or not task.flow_id or not task.subtask_id:
            raise WorkflowException("Flow intent has no immutable execution Task")
        if task.status == "pending":
            await self.enqueue_registered_task(task_id)
            return
        if task.status in {
            "awaiting_approval", "dispatching", "dispatch_unknown",
            "scheduled", "running", "completed", "failed", "cancelled", "halted",
        }:
            # A durable downstream state is evidence that queue delivery is
            # no longer needed. It is NOT evidence of remote termination.
            return
        raise WorkflowException("Unknown Flow intent state needs reconciliation")

    async def reconcile_signed_replay_pair_intent(
        self, source_task_id: str, target_task_id: str
    ) -> bool:
        """Redeliver only pending committed observation hints from the PG outbox.

        This has no browser/MCP/Temporal side effects. We revalidate the
        original approved source/parent, both exact immutable TaskORMs and
        current signed policy in one SQL transaction before any Redis hint.
        A lost acknowledgement may redeliver a queue copy, never permission
        to restart a claimed/UNKNOWN physical action.
        """
        if (
            not isinstance(self.session_memory, SessionMemory)
            or not isinstance(source_task_id, str)
            or not isinstance(target_task_id, str)
            or source_task_id == target_task_id
        ):
            raise WorkflowException("Durable replay pair reconciliation unavailable")
        sm = self.session_memory
        source = await sm.load_task_authoritative(source_task_id)
        target = await sm.load_task_authoritative(target_task_id)
        if (
            source is None
            or target is None
            or not isinstance(source.payload, dict)
            or not isinstance(target.payload, dict)
            or source.payload.get("_comparison_role") != "source"
            or target.payload.get("_comparison_role") != "target"
            or source.parent_task_id is None
            or source.parent_task_id != target.parent_task_id
            or source.engagement_id != target.engagement_id
            or source.flow_id != target.flow_id
        ):
            raise WorkflowException("Signed replay pair is missing original lineage")
        parent = await sm.load_task_authoritative(source.parent_task_id)
        if parent is None:
            raise WorkflowException("Signed replay parent is unavailable")

        def without_execution_state(task: Task) -> Task:
            payload = {
                key: value
                for key, value in task.payload.items()
                if key not in {"approval_id", "operator_approved"}
            }
            return task.model_copy(
                update={
                    "payload": payload,
                    "status": "pending",
                    "result": None,
                    "assigned_agent_id": None,
                    "retry_count": 0,
                    "started_at": None,
                    "completed_at": None,
                }
            )

        try:
            await sm.admit_signed_replay_observation_pair(
                parent,
                [without_execution_state(source), without_execution_state(target)],
                existing_only=True,
            )
        except Exception as exc:
            raise WorkflowException("Signed replay pair outbox authorization is stale") from exc
        for task in (source, target):
            if task.status == "pending":
                # Redis is solely a delivery hint; real admission is always
                # PostgreSQL CAS + independently approved execution claim.
                await sm.push_task_queue(f"tasks:{task.engagement_id}", task.model_dump())
            elif task.status not in {
                "awaiting_approval",
                "scheduled",
                "dispatching",
                "dispatch_unknown",
                "running",
                "completed",
                "failed",
                "cancelled",
                "halted",
            }:
                raise WorkflowException("Unknown replay observation outcome requires review")
        return True

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution."""
        from ai_osop.safety.scope import action_requires_approval

        await self._bind_task_authorization(task)
        session = self._sessions.get(task.engagement_id)
        if session is not None and action_requires_approval(task.type, session.scope):
            task.approval_required = True
        if task.agent_type == AgentType.EXPLOIT_VALIDATION:
            task.approval_required = True
        if self.temporal_enabled:
            self._validate_temporal_task_scope(task)
        # Sprint 6: propagate trace context into the task so the agent can continue the trace
        if not task.trace_context:
            inject_trace_context(task.trace_context)
        # Also bind the task IDs into RequestContext for downstream logging
        RequestContext.bind(
            task_id=task.id,
            engagement_id=task.engagement_id,
            flow_id=task.flow_id or "",
            subtask_id=task.subtask_id or "",
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
            if task.approval_required:
                # New tasks cannot assert their own approval through caller
                # supplied payload flags. Only approval resolution may set it.
                task.payload.pop("operator_approved", None)
                task.payload.pop("approval_id", None)

            # Persist first: an unsuccessful signed TaskORM CAS must never
            # publish a graph assertion, bus event or Redis queue entry that
            # appears to represent an admitted execution.
            await self.session_memory.store_task(task)
            await self.task_scheduler._assert_signed_schedule_persisted(task)
            self._tasks[task.id] = task
            durable = isinstance(self.session_memory, SessionMemory)
            try:
                await self.graph_memory.upsert_task(task)
            except Exception:
                if not durable:
                    raise
                logger.warning("task_graph_projection_delayed", task_id=task.id)
            try:
                await self.coordination_bus.publish(
                    "task.scheduled",
                    {"task_id": task.id, "task_type": task.type, "agent_type": task.agent_type.value},
                    "orchestrator",
                )
            except Exception:
                if not durable:
                    raise
                logger.warning("task_schedule_notification_delayed", task_id=task.id)

            # Store in hot memory
            try:
                await self.session_memory.push_task_queue(
                    f"tasks:{task.engagement_id}", task.model_dump()
                )
            except Exception:
                if not durable:
                    raise
                logger.warning("signed_task_redis_queue_delayed", task_id=task.id)

            if self.temporal_enabled:
                await self.task_scheduler._dispatch_temporal_task(task)
                return task

            # If no dependencies and agent available, assign immediately
            if not task.dependencies:
                await self._assign_task(task)

            return task

    def _validate_temporal_task_scope(self, task: Task) -> None:
        """Apply ROE scope checks before handing work to an external worker."""
        session = self._sessions.get(task.engagement_id)
        if session is None:
            raise WorkflowException("Temporal task requires a loaded engagement")
        if session.phase in {EngagementPhase.HALTED.value, EngagementPhase.COMPLETED.value}:
            raise WorkflowException("Cannot schedule work on an inactive engagement")
        enforcer = ScopeEnforcer(session.scope)
        enforcer.validate_time_window()
        if not session.scope.authorization_ref or not (
            session.scope.domains or session.scope.ips
        ):
            raise ScopeException("Temporal dispatch requires explicit authorization and scope")
        if not task.scope_check:
            return
        from ai_osop.safety.scope import validate_payload_targets

        validate_payload_targets(enforcer, task.payload)

    async def _execute_task_durable(
        self, task: Task, *, persist_terminal: bool = True
    ) -> Dict[str, Any]:
        """Execute task durably, waiting for an available agent if necessary, with timeout."""
        RequestContext.bind(
            task_id=task.id,
            engagement_id=task.engagement_id,
            flow_id=task.flow_id or "",
            subtask_id=task.subtask_id or "",
        )
        self._tasks[task.id] = task
        start_time = asyncio.get_event_loop().time()
        timeout = task.timeout_seconds or 300

        while True:
            agent = await self._find_available_agent(task.agent_type, task.type)
            if agent:
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                # Temporal has already claimed the durable attempt in its
                # activity. Bind the same safe checkpoint/message adapter,
                # without claiming a second execution attempt here.
                if self._supervision_active:
                    agent.ctx.supervision_store = self.supervision_store
                    agent.ctx.supervision_consumer_id = "temporal-" + uuid.uuid4().hex
                try:
                    result = await agent.execute_task(task)
                    status = result.get("status") if isinstance(result, dict) else None
                    if status in {"unknown", "execution_unknown", "timeout"}:
                        task.status = "dispatch_unknown"
                        task.result = {"status": "execution_unknown"}
                        if persist_terminal:
                            await self.session_memory.store_task(task)
                        return task.result
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
                    if persist_terminal:
                        await self.session_memory.store_task(task)
                    return task.result
                except Exception as e:
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                    if persist_terminal:
                        await self.session_memory.store_task(task)
                    return task.result
                finally:
                    if self._supervision_active:
                        agent.ctx.supervision_store = None
                        agent.ctx.supervision_consumer_id = None
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
        session = self._sessions.get(task.engagement_id)
        if task.status == "cancelled" or (
            session is not None and session.phase in {"halted", "completed"}
        ):
            return
        if self.temporal_enabled:
            await self.task_scheduler._dispatch_temporal_task(task)
            return
        if any(
            self._tasks.get(dep_id) is None
            or self._tasks[dep_id].status != "completed"
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
            if hasattr(self, "rate_limiter") and self.rate_limiter:
                await self.rate_limiter.acquire(tool="orchestrator")

            # Approval gate FIRST — decided before (and independent of) agent selection so
            # the scheduler never blocks and we never hold an agent claim while pending.
            if task.approval_required and not task.payload.get("operator_approved"):
                if isinstance(self.session_memory, SessionMemory):
                    # Task parking and its unique human review request must
                    # commit together. Two replicas can never generate two
                    # independent approvals; a crash cannot leave a new task
                    # parked without the corresponding durable request.
                    request = ApprovalRequest(
                        id=self.session_memory.deterministic_task_approval_id(
                            task.engagement_id, task.id,
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
                        created = await self.session_memory.park_task_for_approval_atomic(
                            task, request,
                        )
                    except Exception as exc:
                        logger.warning(
                            "approval_parking_unavailable", task_id=task.id,
                            error_type=type(exc).__name__,
                        )
                        return
                    if not created:
                        fresh = await self.session_memory.load_task_authoritative(task.id)
                        if fresh is not None:
                            self._tasks[task.id] = fresh
                        return
                    task.status = "awaiting_approval"
                    self._tasks[task.id] = task
                    record_approval_requested(request.id)
                    # Registration below is idempotent; the pending request
                    # and outbox already committed before any notification.
                    await self._raise_approval(request)
                    return
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
                durable_claim = isinstance(self.session_memory, SessionMemory)
                if durable_claim:
                    try:
                        admitted = await self.session_memory.claim_local_agent_start(
                            task, agent.ctx.agent_id,
                        )
                    except Exception as exc:
                        logger.warning(
                            "local_agent_claim_denied", task_id=task.id,
                            error_type=type(exc).__name__,
                        )
                        admitted = False
                    if not admitted:
                        # Release Redis + local agent ownership on denial; a
                        # stale queue snapshot cannot start an external action.
                        self._release_agent(agent.ctx.agent_id)
                        return
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                if durable_claim:
                    # Spawn BEFORE any awaited cache/graph/bus projection.
                    # Those are derived observers, not evidence the approved
                    # task was launched. A failed observer must not strand
                    # an irrevocably claimed signed TaskORM in RUNNING
                    # without a coroutine or supervision attempt.
                    try:
                        self._spawn_agent_execution(
                            agent, task, self._execute_via_agent
                        )
                    except BaseException:
                        self._release_agent(agent.ctx.agent_id)
                        raise
                    try:
                        await self.session_memory.store_hot(
                            f"task:{task.id}", task.model_dump(), ttl=86400 * 7,
                        )
                    except Exception:
                        logger.warning("local_agent_hot_cache_unavailable", task_id=task.id)
                    try:
                        await self.graph_memory.upsert_task(task)
                    except Exception:
                        logger.warning("local_agent_graph_projection_delayed", task_id=task.id)
                    try:
                        await self.coordination_bus.publish(
                            "task.assigned",
                            {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                            "orchestrator",
                        )
                    except Exception:
                        logger.warning("local_agent_assignment_notification_delayed", task_id=task.id)
                else:
                    await self.graph_memory.upsert_task(task)
                    await self.session_memory.store_task(task)
                    await self.coordination_bus.publish(
                        "task.assigned",
                        {"task_id": task.id, "agent_id": agent.ctx.agent_id},
                        "orchestrator",
                    )
                    self._spawn_agent_execution(agent, task, self._execute_via_agent)
            else:
                # Queue for later assignment
                if task.status != "awaiting_approval":
                    task.status = "pending"
                    await self.graph_memory.upsert_task(task)
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
                    supported = agent.supports_task_type(task_type)
                    if inspect.isawaitable(supported):
                        # Production agents implement this synchronously;
                        # async adapters/test doubles must still be awaited.
                        # Relying on coroutine truthiness silently accepted
                        # unsupported tasks and leaked AsyncMock coroutines.
                        supported = await supported
                    if supported is False:
                        continue

                # Sprint 6A: Distributed Lock — acquire lock in Redis
                lock_key = f"lock:agent:{agent.ctx.agent_id}"
                lock_value = f"orch-{id(self)}"
                acquired = await self.session_memory.acquire_lock(lock_key, lock_value, ttl_seconds=60)
                if not acquired:
                    continue  # Locked by another replica

                # Synchronous claim
                self._busy_agents.add(agent.ctx.agent_id)
                agent._current_lock_value = lock_value
                return agent
        return None

    def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release an agent claim made by _find_available_agent (P0-1)."""
        if agent_id:
            self._busy_agents.discard(agent_id)
            agent = self._agents.get(agent_id)
            if agent and hasattr(agent, "_current_lock_value"):
                lock_value = agent._current_lock_value
                asyncio.create_task(
                    self.session_memory.release_lock(f"lock:agent:{agent_id}", lock_value)
                )

    def _spawn_agent_execution(self, agent: Any, task: Task, execute: Any) -> asyncio.Task:
        """Retain a cancellable handle for the exact task being dispatched."""
        existing = self._inflight_tasks.get(task.id)
        if existing is not None and not existing.done():
            return existing
        handle = asyncio.create_task(execute(agent, task))
        self._inflight_tasks[task.id] = handle

        def forget(finished: asyncio.Task) -> None:
            if self._inflight_tasks.get(task.id) is finished:
                self._inflight_tasks.pop(task.id, None)

        handle.add_done_callback(forget)
        return handle

    @property
    def supervision_store(self):
        """Operator history/control persistence shared with the API and agents."""
        if self._supervision_store is None:
            from ai_osop.memory.supervision_store import SupervisionStore

            self._supervision_store = SupervisionStore(self.session_memory)
        return self._supervision_store

    @property
    def terminal_store(self):
        """Transactional terminal state is separate from legacy hot task cache."""
        if self._terminal_store is None:
            from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore

            self._terminal_store = TerminalLifecycleStore(self.session_memory)
        return self._terminal_store

    async def _execute_supervised_agent(self, agent: Any, task: Task) -> Any:
        """Create a durable idempotency claim BEFORE any agent/tool invocation.

        A repeated attempt (including after worker crash) is never blindly
        replayed. Completed attempts are persisted without raw LLM replies
        or tool output; transport exceptions are conservatively UNKNOWN.
        """
        if not self._supervision_active:
            return await agent.execute_task(task)
        try:
            record = await self.supervision_store.start_attempt(
                task.engagement_id,
                task.id,
                task.retry_count + 1,
                status="running",
            )
        except Exception:
            return {
                "status": "execution_unknown",
                "reason": "supervision_start_unavailable_no_execution",
            }
        if record.get("created") is not True:
            return {
                "status": "execution_unknown",
                "reason": "duplicate_or_unreconciled_attempt",
            }
        try:
            await self.supervision_store.append_event(
                task.engagement_id,
                task.id,
                "agent.execution_started",
                actor_id="orchestrator",
                payload={"attempt": task.retry_count + 1},
                idempotency_key="start:" + record["id"],
            )
        except Exception:
            # Persisted attempt exists; do not dispatch without the event.
            return {"status": "execution_unknown", "reason": "supervision_event_unavailable"}
        agent_ctx = getattr(agent, "ctx", None)
        if agent_ctx is not None:
            agent_ctx.supervision_store = self.supervision_store
            agent_ctx.supervision_consumer_id = "agent-" + uuid.uuid4().hex
        try:
            result = await agent.execute_task(task)
        except asyncio.CancelledError:
            await self.supervision_store.update_attempt(
                record["id"], record["revision"], "unknown",
                receipt={"reason": "local_coroutine_cancelled_remote_unverified"},
            )
            raise
        except Exception:
            await self.supervision_store.update_attempt(
                record["id"], record["revision"], "unknown",
                receipt={"reason": "unhandled_agent_exception_remote_unverified"},
            )
            return {"status": "execution_unknown", "reason": "agent_exception"}
        finally:
            if agent_ctx is not None:
                agent_ctx.supervision_store = None
                agent_ctx.supervision_consumer_id = None
        status = result.get("status") if isinstance(result, dict) else None
        if status in {"unknown", "execution_unknown", "timeout"}:
            try:
                await self.supervision_store.update_attempt(
                    record["id"], record["revision"], "unknown",
                    receipt={"result_code": "remote_outcome_unverified"},
                )
            except Exception:
                pass
            return {"status": "execution_unknown", "reason": "remote_outcome_unverified"}
        if status in self._FAILURE_STATUSES:
            # No provider receipt proves side effects stopped. Do not turn an
            # arbitrary agent failure into an automatically replayable task.
            try:
                await self.terminal_store.commit_terminal(
                    task.engagement_id, task.id, record["id"], record["revision"],
                    "unknown", receipt_code="unverified_agent_failure",
                )
            except Exception:
                pass
            return {"status": "execution_unknown", "reason": "failure_outcome_unverified"}
        try:
            if not await self.validate_workflow_completion(task, result if isinstance(result, dict) else {}):
                return {"status": "execution_unknown", "reason": "workflow_result_not_verified"}
            persisted = await self.terminal_store.commit_terminal(
                task.engagement_id, task.id, record["id"], record["revision"],
                "succeeded", receipt_code="agent_completed",
                continuation=result if isinstance(result, dict) else None,
            )
        except Exception:
            return {"status": "execution_unknown", "reason": "terminal_commit_unavailable"}
        if persisted is None:
            return {"status": "execution_unknown", "reason": "attempt_revision_conflict"}
        return {"status": "terminal_committed", "task_id": task.id}

    async def _quarantine_unknown_execution(self, task: Task) -> None:
        """Preserve unknown remote outcomes without success or unsafe retries."""
        if self._supervision_active and isinstance(self.session_memory, SessionMemory):
            from sqlalchemy import select
            from ai_osop.memory.session_memory import SessionStateORM, TaskORM

            # Never use store_task's unguarded UPSERT here. A network timeout
            # after a successful terminal COMMIT is not permission to replace
            # a persisted completed task with dispatch_unknown.
            async with self.session_memory._async_session() as db:
                async with db.begin():
                    engagement = (
                        await db.execute(
                            select(SessionStateORM)
                            .where(SessionStateORM.session_id == task.engagement_id)
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if engagement is None:
                        raise WorkflowException("Cannot quarantine without persisted engagement")
                    current = (
                        await db.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.id == task.id,
                                TaskORM.engagement_id == task.engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if current is None:
                        raise WorkflowException("Cannot quarantine without persisted task")
                    if current.status in {"completed", "failed", "cancelled", "halted"}:
                        task.status = current.status
                        return
                    current.status = "dispatch_unknown"
                    current.result = {"status": "execution_unknown"}
                    task.status = "dispatch_unknown"
                    task.result = {"status": "execution_unknown"}
        else:
            task.status = "dispatch_unknown"
            task.result = {"status": "execution_unknown"}
            await self.session_memory.store_task(task)
        if self._supervision_active:
            await self.supervision_store.append_event(
                task.engagement_id,
                task.id,
                "agent.execution_outcome_unknown",
                actor_id="orchestrator",
                payload={"status": "dispatch_unknown"},
            )

    async def request_task_control(
        self, engagement_id: str, task_id: str, action: str, request_id: str
    ) -> Dict[str, Any]:
        """Attempt an already-persisted operator control, reporting actual receipts.

        The authenticated API must commit request_control before calling this.
        Cancelling a Python coroutine or requesting Temporal cancellation is
        not evidence that a remote MCP command has stopped. No action is
        silently replayed or called confirmed unless its provider says so.
        """
        if action not in {"cancel", "pause", "resume"}:
            raise ValueError("Unsupported task control")
        session = await self.session_memory.load_session_state(engagement_id)
        durable_task_reader = (
            getattr(self.session_memory, "load_task_authoritative", None)
            if isinstance(self.session_memory, SessionMemory)
            else None
        )
        task = await (
            durable_task_reader(task_id)
            if callable(durable_task_reader)
            else self.session_memory.load_task(task_id)
        )
        if session is None or task is None or task.engagement_id != engagement_id:
            raise WorkflowException("Task supervision requires persisted engagement ownership")
        if action in {"pause", "resume"}:
            # Pausing only the in-memory task object is a lie: another worker
            # can continue executing an already accepted remote action.
            outcome = {
                "status": "unknown",
                "reason": "distributed_suspend_resume_not_supported",
                "execution_stopped": False,
            }
            await self.supervision_store.resolve_control(request_id, "unknown", outcome)
            return outcome

        receipts: Dict[str, Any] = {}
        handle = self._inflight_tasks.get(task_id)
        if handle is not None and not handle.done():
            handle.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(handle), timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            receipts["local_coroutine"] = (
                "cancelled" if handle.done() else "cancel_pending"
            )
        else:
            receipts["local_coroutine"] = "not_present_on_this_replica"

        # Temporal's handle.cancel only confirms the request was accepted,
        # not that the activity or a separately delegated MCP tool stopped.
        if self.temporal_enabled and self.temporal_scheduler is not None:
            try:
                receipts["temporal"] = await asyncio.wait_for(
                    self.temporal_scheduler.cancel_task_workflow(task_id), timeout=5.0
                )
            except (Exception, asyncio.TimeoutError):
                receipts["temporal"] = {"status": "unknown"}

        if self.mcp_registry is not None and callable(
            getattr(self.mcp_registry, "cancel_task_execution", None)
        ):
            try:
                receipts["mcp"] = await asyncio.wait_for(
                    self.mcp_registry.cancel_task_execution(
                        task_id, engagement_id, request_id
                    ),
                    timeout=5.0,
                )
            except (Exception, asyncio.TimeoutError):
                receipts["mcp"] = {"status": "unknown"}
        else:
            receipts["mcp"] = {"status": "not_supported"}

        # Unknown external acceptance remains unresolved even when all known
        # in-process handles have stopped. The UI must not show STOPPED.
        outcome = {
            "status": "unknown",
            "execution_stopped": False,
            "receipts": receipts,
        }
        await self.supervision_store.resolve_control(request_id, "unknown", outcome)
        return outcome

    async def reconcile_mcp_dispatch(
        self, engagement_id: str, task_id: str, server_id: str, request_id: str
    ) -> Dict[str, Any]:
        """Reconcile a persisted remote execution without replaying its tool.

        A restarted worker lacks the old in-memory remote execution map but
        must still prove the exact original dispatch from PostgreSQL.
        """
        claim = await self.supervision_store.get_mcp_dispatch(
            engagement_id, task_id, server_id, request_id
        )
        if claim is None:
            return {"status": "unknown", "reason": "original_dispatch_not_found"}
        if (
            not isinstance(claim, dict)
            or claim.get("engagement_id") != engagement_id
            or claim.get("task_id") != task_id
            or claim.get("server_id") != server_id
            or claim.get("request_id") != request_id
            or type(claim.get("authorization_version")) is not int
            or claim["authorization_version"] < 1
            or claim.get("status") not in {
                "accepted_unconfirmed", "started_unknown", "outcome_unknown",
                "provider_returned", "cancel_requested", "provider_running",
                "confirmed_stopped", "confirmed_finished",
            }
        ):
            return {"status": "unknown", "reason": "original_dispatch_unverified"}
        connection = (
            self.mcp_registry.get_server(server_id)
            if self.mcp_registry is not None and
            callable(getattr(self.mcp_registry, "get_server", None))
            else None
        )
        if connection is None:
            return {"status": "not_supported", "reason": "provider_not_connected"}
        # Pure observation with the original immutable request tuple only.
        # Reissuing /mcp/execute of the consequential tool is forbidden.
        try:
            receipt = await connection.reconcile_persisted_status(dict(claim))
        except Exception:
            return {"status": "unknown", "reason": "remote_observation_unavailable"}
        # An HTTP provider response alone cannot confirm external termination.
        # Reload the exact committed receipt after the event/outbox transaction.
        persisted = await self.supervision_store.get_mcp_dispatch(
            engagement_id, task_id, server_id, request_id
        )
        if (
            not isinstance(persisted, dict)
            or any(persisted.get(key) != claim.get(key) for key in (
                "engagement_id", "task_id", "server_id", "request_id",
                "tool_name", "authorization_version",
            ))
        ):
            return {"status": "unknown", "reason": "receipt_not_persisted"}
        if not isinstance(receipt, dict):
            return {"status": "unknown", "reason": "invalid_remote_observation"}
        status = receipt.get("status")
        if (
            receipt.get("server_id") not in (None, server_id)
            or receipt.get("request_id") not in (None, request_id)
        ):
            return {"status": "unknown", "reason": "remote_observation_identity_mismatch"}
        if status in {"confirmed_stopped", "confirmed_finished"} and persisted["status"] != status:
            return {"status": "unknown", "reason": "receipt_not_persisted"}
        # Never display an uncommitted/untrusted RUNNING assertion as proven
        # remote status. A later provider status could race a different
        # confirmed result; the actual PostgreSQL row is authoritative.
        if status == "running" and persisted["status"] != "provider_running":
            return {"status": "unknown", "reason": "running_receipt_not_persisted"}
        if status not in {
            "unknown", "running", "confirmed_stopped", "confirmed_finished",
            "not_supported", "denied",
        }:
            return {"status": "unknown", "reason": "unverified_provider_receipt"}
        return {
            "status": status,
            "persisted_status": persisted["status"],
            "request_id": request_id,
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }

    async def cancel_persisted_mcp_dispatch(
        self, engagement_id: str, task_id: str, server_id: str,
        request_id: str, *, actor_id: str, reason: str,
        expected_authorization_version: int,
    ) -> Dict[str, Any]:
        """Single global PostgreSQL-admitted stop for a remote surviving restart.

        The request is only issued after the immutable original dispatch is
        loaded and a one-shot cancellation intent is transactionally committed.
        Failure after intent commit stays UNKNOWN forever until separately
        reconciled with provider status. Never retry this provider stop blindly.
        """
        claim = await self.supervision_store.get_mcp_dispatch(
            engagement_id, task_id, server_id, request_id,
        )
        if (
            not isinstance(claim, dict)
            or any(claim.get(key) != expected for key, expected in (
                ("engagement_id", engagement_id), ("task_id", task_id),
                ("server_id", server_id), ("request_id", request_id),
                ("authorization_version", expected_authorization_version),
            ))
        ):
            return {"status": "denied", "persisted_status": "unknown",
                    "safe_to_retry": False, "remote_stopped": False}
        connection = (
            self.mcp_registry.get_server(server_id)
            if self.mcp_registry is not None
            and callable(getattr(self.mcp_registry, "get_server", None))
            else None
        )
        if connection is None or not callable(
            getattr(connection, "cancel_persisted_execution", None)
        ):
            return {"status": "not_supported", "persisted_status": claim["status"],
                    "safe_to_retry": False, "remote_stopped": False}
        # A registry may lazily configure a connection only on first execute.
        # A process restarted solely to stop old jobs must attach the current
        # authoritative PG budget/ROE verifier and event writer *before*
        # touching a remote provider; never inherit stale connection callbacks.
        registry_budget = getattr(self.mcp_registry, "_budget_callback", None)
        registry_events = getattr(self.mcp_registry, "_execution_event_callback", None)
        if (
            registry_budget is not None
            and callable(getattr(connection, "set_budget_callback", None))
        ):
            connection.set_budget_callback(registry_budget)
        if (
            registry_events is not None
            and callable(getattr(connection, "set_execution_event_callback", None))
        ):
            connection.set_execution_event_callback(registry_events)
        try:
            admitted = await self.supervision_store.claim_mcp_cancellation_once(
                engagement_id, task_id, server_id, request_id,
                actor_id=actor_id, reason=reason,
                expected_authorization_version=expected_authorization_version,
            )
        except Exception:
            return {"status": "denied", "persisted_status": "unknown",
                    "safe_to_retry": False, "remote_stopped": False}
        if admitted is not True:
            return {"status": "unknown", "persisted_status": claim["status"],
                    "safe_to_retry": False, "remote_stopped": False}
        # Fresh durable exact identity after atomic admission; a completed
        # provider action/terminal callback may have raced the requested stop.
        current = await self.supervision_store.get_mcp_dispatch(
            engagement_id, task_id, server_id, request_id,
        )
        if (
            not isinstance(current, dict)
            or current.get("status") != "cancel_requested"
            or any(current.get(key) != claim.get(key) for key in (
                "engagement_id", "task_id", "server_id", "request_id",
                "tool_name", "authorization_version",
            ))
        ):
            return {"status": "unknown", "persisted_status": "unknown",
                    "safe_to_retry": False, "remote_stopped": False}
        try:
            receipt = await connection.cancel_persisted_execution(current)
        except Exception:
            receipt = None
        verified = await self.supervision_store.get_mcp_dispatch(
            engagement_id, task_id, server_id, request_id,
        )
        committed = (
            isinstance(receipt, dict)
            and receipt.get("status") == "confirmed_stopped"
            and receipt.get("server_id") == server_id
            and receipt.get("request_id") == request_id
            and isinstance(verified, dict)
            and verified.get("status") == "confirmed_stopped"
            and all(verified.get(key) == claim.get(key) for key in (
                "engagement_id", "task_id", "server_id", "request_id",
                "tool_name", "authorization_version",
            ))
        )
        return {
            "status": "confirmed_stopped" if committed else "unknown",
            "persisted_status": verified.get("status", "unknown")
            if isinstance(verified, dict) else "unknown",
            # Provider-signed STOP is a provider's statement, not independent
            # proof that a real target-side external effect has ceased.
            "remote_stopped": False,
            "provider_reported_stop": committed,
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }

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
        session = self._sessions.get(task.engagement_id)
        if task.status == "cancelled" or (
            session is not None and session.phase in {"halted", "completed"}
        ):
            return False
        if task.retry_count >= task.max_retries:
            # Sprint 7: Send to Dead Letter Queue for operator review
            try:
                await self.dlq.enqueue(
                    task,
                    reason="retry_budget_exhausted",
                    final_error=str(result.get("error") or result.get("status") or ""),
                )
            except Exception as e:
                logger.error("dlq_enqueue_failed", task_id=task.id, error=str(e))
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
                result = await self._execute_supervised_agent(agent, task)

                # Agents return varied success markers ("success", "authenticated",
                # "workflow_recorded", ...). Treat only the explicit failure set as
                # failure; everything else (including a missing status) as success.
                status = result.get("status") if isinstance(result, dict) else None
                if status == "terminal_committed":
                    # Terminal TaskORM, attempt and callback intent already
                    # committed as one PostgreSQL transaction. A separate
                    # leased consumer can finish after a process crash.
                    # Never process it inline: callback I/O failure after a
                    # committed execution must not enter this execution
                    # worker's broad exception/retry handler.
                    task.status = "completed"
                    return
                if status == "execution_unknown":
                    await self._quarantine_unknown_execution(task)
                    return
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
                # Keep the externally unknown outcome instead of converting
                # an interrupted Python coroutine into a confirmed failure.
                if task.status not in {"cancelled", "halted"}:
                    await self._quarantine_unknown_execution(task)
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

        workflow_id = result.get("workflow_id") if isinstance(result, dict) else None
        if not isinstance(workflow_id, str) or not re.fullmatch(
            r"wf-[A-Za-z0-9._-]{1,80}", workflow_id
        ) or not task.engagement_id:
            logger.error("validate_workflow_completion_missing_workflow_id", task_id=task.id)
            return False

        cypher = """
        MATCH (w:Workflow {id: $workflow_id, engagement_id: $eid})
        OPTIONAL MATCH (w)-[:HAS_STEP]->(s:Step {engagement_id: $eid, workflow_id: $workflow_id})
        OPTIONAL MATCH (s)-[:HAS_EVIDENCE]->(ev:Evidence {engagement_id: $eid, workflow_id: $workflow_id})
        RETURN count(DISTINCT w) > 0 as workflow_exists,
               count(DISTINCT s) as step_count, count(DISTINCT ev) as evidence_count
        """
        try:
            async with self.graph_memory._driver.session() as session:
                res = await session.run(
                    cypher, {"workflow_id": workflow_id, "eid": task.engagement_id}
                )
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

    async def _authenticated_user_label_is_active(
        self, engagement_id: str, user_label: str
    ) -> bool:
        """Prove one pinned imported user is still active in PostgreSQL.

        This is stricter than 'at least one session': another user's import
        cannot authorize an original user-label-bound autonomous child, and
        a stale Redis storage state cannot resurrect a revoked credential.
        """
        if (
            not isinstance(user_label, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user_label)
        ):
            return False
        try:
            record = await self.session_store.get_session_authoritative(
                engagement_id, user_label
            )
            return bool(
                record is not None
                and record.engagement_id == engagement_id
                and record.user_label == user_label
                and not record.is_expired(skew_seconds=0)
                and (record.cookies or record.local_storage)
            )
        except Exception:
            return False

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

        if isinstance(self.session_memory, SessionMemory):
            # Neo4j's old claim was committed before TaskORM insertion. A
            # crash after the claim made this first autonomous task disappear
            # permanently. Signed deployments use a deterministic PostgreSQL
            # task identity as the one-shot admission instead; graph claims
            # are never execution authority.
            import hashlib

            from ai_osop.safety.scope import validate_payload_targets

            state = await self.session_memory.load_session_state(engagement_id)
            if (
                state is None
                or state.phase in {"completed", "halted"}
                or not state.scope.authorization_ref
                or not (state.scope.domains or state.scope.ips)
            ):
                return None
            try:
                receipt = await self.session_memory.assert_signed_authorization(engagement_id)
                ScopeEnforcer(state.scope).validate_time_window()
                url = url_hint or (
                    f"https://{state.scope.domains[0]}/" if state.scope.domains else ""
                )
                if not isinstance(url, str) or not 1 <= len(url) <= 1024:
                    return None
                validate_payload_targets(
                    ScopeEnforcer(state.scope), {"url": url}, require_target=True
                )
            except (ScopeException, WorkflowException, ValueError, PermissionError):
                return None
            task_id = "task-" + hashlib.sha256(
                f"{engagement_id}:auto_authenticated_map_workflow".encode("utf-8")
            ).hexdigest()[:32]
            existing = await self.session_memory.load_task_authoritative(task_id)
            if existing is not None:
                if existing.engagement_id != engagement_id or existing.type != "map_workflow":
                    raise WorkflowException("Authenticated discovery task identity conflict")
                # Existing task may be running/UNKNOWN/terminal; nothing is
                # automatically replayed or rewritten, even if graph is down.
                return None
            user_label = await self._pick_auth_user_label(engagement_id)
            if (
                not isinstance(user_label, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", user_label)
                or not await self._authenticated_user_label_is_active(
                    engagement_id, user_label
                )
            ):
                return None
            task = Task(
                id=task_id,
                type="map_workflow",
                priority=7,
                agent_type=AgentType.WORKFLOW,
                # An imported session and signed ROE are NOT the operator's
                # approval for a new authenticated browser traversal. The
                # deterministic TaskORM must park for its own execution gate.
                approval_required=True,
                payload={
                    "url": url,
                    "user_label": user_label,
                    "name": "Auto Authenticated Journey",
                    "_authorization_version": receipt.version,
                },
                engagement_id=engagement_id,
            )
            # The existing SQL INSERT/UPSERT CAS and signed scheduler
            # assertion arbitrate concurrent replicas; a failed admission
            # cannot create a preemptive, permanent Neo4j slot claim.
            await self.schedule_task(task)
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
            return task

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
        # Graph is a derived projection, not ownership authority. Never let a
        # child in a different engagement overwrite an existing Task node's
        # tenant through MERGE keyed on ID alone.
        if (
            not parent.engagement_id
            or parent.engagement_id != child.engagement_id
            or parent.id == child.id
        ):
            logger.warning("cross_tenant_task_dependency_denied", parent_id=parent.id)
            return
        cypher = """
        MERGE (p:Task {id: $parent_id, engagement_id: $eid})
          SET p.type = $parent_type
        MERGE (c:Task {id: $child_id, engagement_id: $eid})
          SET c.type = $child_type,
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
        if isinstance(self.session_memory, SessionMemory):
            # Terminal callbacks run AFTER the signed parent commits. Never
            # admit a child from an in-memory completion/result or a Neo4j
            # SPAWNED marker: those can be stale, forged or written before a
            # previous PostgreSQL child admission. This is also the live
            # callback path, not just the restart recovery path.
            canonical = await self.session_memory.load_task_authoritative(task.id)
            if (
                canonical is None
                or canonical.id != task.id
                or canonical.engagement_id != task.engagement_id
                or canonical.type != task.type
                or canonical.status != "completed"
                or not isinstance(canonical.payload, dict)
            ):
                return
            version = canonical.payload.get("_authorization_version")
            if type(version) is not int or version < 1:
                return
            session = await self.session_memory.load_session_state(task.engagement_id)
            if (
                session is None
                or session.phase in {"halted", "completed"}
                or not session.scope.authorization_ref
                or not (session.scope.domains or session.scope.ips)
            ):
                return
            from ai_osop.memory.terminal_lifecycle import _continuation_metadata
            from ai_osop.safety.scope import validate_payload_targets

            try:
                ScopeEnforcer(session.scope).validate_time_window()
                await self.session_memory.assert_signed_authorization(
                    task.engagement_id, expected_version=version
                )
                metadata = _continuation_metadata(canonical.type, canonical.result)
                if task.type == "map_workflow":
                    url = canonical.payload.get("url")
                    if not isinstance(url, str) or not 1 <= len(url) <= 1024:
                        return
                    validate_payload_targets(
                        ScopeEnforcer(session.scope), {"url": url}, require_target=True
                    )
                    metadata["url"] = url
                elif task.type == "capture_authenticated_surface":
                    path = metadata.get("har_path")
                    if (
                        not isinstance(path, str)
                        or not path
                        or path.startswith(("/", "\\"))
                        or ":" in path
                        or any(
                            part in {"", ".", ".."}
                            for part in path.replace("\\", "/").split("/")
                        )
                    ):
                        return
                elif task.type != "extract_har_api_inventory":
                    return
                label = canonical.payload.get("user_label")
                if isinstance(label, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label):
                    metadata["user_label"] = label
                # Only the original admitted payload may name a captured
                # workflow; model/graph summaries cannot select it later.
                if task.type in {"capture_authenticated_surface", "extract_har_api_inventory"}:
                    workflow_id = canonical.payload.get("workflow_id")
                    if (
                        isinstance(workflow_id, str)
                        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", workflow_id)
                    ):
                        metadata["workflow_id"] = workflow_id
                if task.type == "extract_har_api_inventory":
                    replay_user = canonical.payload.get("target_user_label")
                    if (
                        isinstance(replay_user, str)
                        and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", replay_user)
                    ):
                        metadata["target_user_label"] = replay_user
                await self._resume_chain_link(
                    {
                        "id": canonical.id,
                        "engagement_id": canonical.engagement_id,
                        "type": canonical.type,
                        "authorization_version": version,
                        "result_summary": metadata,
                    }
                )
            except (ScopeException, WorkflowException, ValueError, PermissionError):
                logger.warning("signed_chain_parent_not_authorized", task_id=task.id)
            return

        # Duplicate-completion protection (graph-backed; survives process restart).
        if await self.graph_memory.task_has_spawned(task.id, task.engagement_id):
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
        session = self._sessions.get(task.engagement_id)
        if task.status == "cancelled" or (session is not None and session.phase == "halted"):
            return
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
            if task.status == "cancelled":
                return

            if isinstance(self.session_memory, SessionMemory):
                admitted = await self.session_memory.settle_local_task_terminal_atomic(
                    task, "completed", result,
                )
                if not admitted:
                    logger.warning("stale_local_success_callback_ignored", task_id=task.id)
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
            if not isinstance(self.session_memory, SessionMemory):
                await self.session_memory.store_task(task)
            await self.coordination_bus.publish(
                "task.completed",
                {"task_id": task.id, "agent_id": task.assigned_agent_id},
                "orchestrator",
            )
            await self._sync_subtask_result(task, "completed", result)
            await self._refine_completed_flow_subtask(task, result)

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
            # Failure to plan must never turn a validated, completed task into
            # a failed task or trigger a retry of completed side effects.
            try:
                await self.adaptive_planner.on_task_completed(task)
            except Exception as exc:
                logger.warning("adaptive_planning_after_task_failed", task_id=task.id, error=str(exc))

    async def _on_task_failure(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle task failure."""
        if task.status == "cancelled":
            return
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
            if isinstance(self.session_memory, SessionMemory):
                admitted = await self.session_memory.settle_local_task_terminal_atomic(
                    task, "failed", result,
                )
                if not admitted:
                    logger.warning("stale_local_failure_callback_ignored", task_id=task.id)
                    return
            task.result = result
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            await self.graph_memory.upsert_task(
                task, result_summary={"error": str(result.get("error", ""))[:300]}
            )
            # P0: Persist task state so failure is recorded across restarts.
            if not isinstance(self.session_memory, SessionMemory):
                await self.session_memory.store_task(task)
            await self.coordination_bus.publish(
                "task.failed",
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    "status": "failed",
                },
                "orchestrator",
            )
            await self._sync_subtask_result(task, "failed", result)

            # Sprint 7: Safety fallback — send to DLQ if retries exhausted and not already sent
            if task.retry_count >= task.max_retries:
                try:
                    await self.dlq.enqueue(
                        task,
                        reason="terminal_failure",
                        final_error=str(result.get("error") or result.get("status") or ""),
                    )
                except Exception as e:
                    logger.error("dlq_enqueue_fallback_failed", task_id=task.id, error=str(e))

            # Retry logic handled by agent
            # Orchestrator may escalate if critical
            if task.approval_required:
                # Notify operator
                pass

    async def _sync_subtask_result(
        self, task: Task, status: str, result: Dict[str, Any]
    ) -> None:
        """Mirror worker terminal results into persistent execution subtasks."""
        if not task.flow_id or not task.subtask_id:
            return
        if not hasattr(self.session_memory, "list_subtasks"):
            return
        try:
            subtasks = await self.session_memory.list_subtasks(task.flow_id)
            for subtask in subtasks:
                if subtask.id != task.subtask_id:
                    continue
                if subtask.engagement_id != task.engagement_id:
                    logger.error("subtask_ownership_mismatch", task_id=task.id)
                    return
                subtask.status = status
                subtask.execution_task_id = task.id
                if (
                    task.type == "navigate"
                    and isinstance(task.payload, dict)
                    and task.payload.get("_comparison_role") in {"source", "target"}
                ):
                    # This shared Flow projection must never contain raw
                    # cross-account bodies, URLs, headers, cookies or a
                    # model/provider response. Comparison is a separate
                    # owner-scoped signed evidence read.
                    subtask.result_summary = json.dumps({
                        "status": status,
                        "comparison_role": task.payload["_comparison_role"],
                        "verification_status": "provider_testimony_only",
                        "target_effect_verified": False,
                        "authorization_violation_verified": False,
                    }, separators=(",", ":"))
                else:
                    subtask.result_summary = json.dumps(result, default=str)[:4000]
                subtask.updated_at = datetime.utcnow()
                await self.session_memory.store_subtask(subtask)
                break
        except Exception as exc:
            logger.warning("subtask_result_sync_failed", task_id=task.id, error=str(exc))

    async def generate_flow_subtasks(self, flow_id: str, task_id: str) -> Dict[str, Any]:
        """Operator-facing generator entry point; records steps without execution.

        External callers must authorize the operator for flow_id before calling.
        """
        return await self.flow_refiner.generate(flow_id, task_id)

    async def refine_flow_subtask(
        self, flow_id: str, subtask_id: str
    ) -> Dict[str, Any]:
        """Explicit operator revision of a completed source (up to three passes)."""
        return await self.flow_refiner.refine(
            flow_id, subtask_id, operator_initiated=True
        )

    async def _refine_completed_flow_subtask(
        self, task: Task, result: Dict[str, Any]
    ) -> None:
        """Best-effort follow-up after task and subtask completion are durable."""
        if (
            task.flow_id
            and task.subtask_id
            and task.status == "completed"
            and not (
                task.type == "navigate"
                and isinstance(task.payload, dict)
                and task.payload.get("_comparison_role") in {"source", "target"}
            )
        ):
            try:
                await self.flow_refiner.on_subtask_completed(task, result)
            except (ModelBudgetExceeded, ModelOutcomeUncertain):
                # The durable callback dispatcher must quarantine uncertain
                # provider activity; downstream dispatch cannot follow it.
                raise
            except Exception as exc:
                # Planning failure cannot change a confirmed execution result.
                logger.warning(
                    "flow_refinement_after_success_failed",
                    task_id=task.id,
                    error_class=type(exc).__name__,
                )

    async def _trigger_downstream_tasks(self, completed_task: Task) -> None:
        """Trigger tasks that depend on completed task."""
        for task in list(self._tasks.values()):
            if task.status == "pending" and completed_task.id in task.dependencies:
                # Check if all dependencies satisfied
                all_deps_complete = all(
                    self._tasks.get(dep_id) is not None
                    and self._tasks[dep_id].status == "completed"
                    for dep_id in task.dependencies
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
            request, _ = await self._expire_pending_approval(request.id)

        return request

    async def _expire_pending_approval(
        self, request_id: str,
    ) -> tuple[Optional[ApprovalRequest], bool]:
        """Resolve a timer race against the *durable* operator decision.

        Production always returns the winning PostgreSQL record. The second
        value indicates only whether the legacy mock path should fail a local
        parked task; a real database already commits its task failure/outbox.
        """
        async with self._approval_decision_locks.setdefault(request_id, asyncio.Lock()):
            request = self._approval_requests.get(request_id)
            if isinstance(self.session_memory, SessionMemory):
                current = await self.session_memory.load_approval_request(request_id)
                if current is None:
                    raise WorkflowException("Approval timeout request unavailable")
                persisted, _ = await self.session_memory.expire_approval_atomic(
                    request_id, current.engagement_id, current.task_id,
                )
                self._approval_requests[request_id] = persisted
                task = self._tasks.get(persisted.task_id)
                if persisted.status == "timeout" and task and task.status == "awaiting_approval":
                    # Mirror the committed state only; never re-save a stale
                    # task snapshot over another replica's durable result.
                    task.status = "failed"
                    task.result = {"status": "failed", "reason": "approval_timeout"}
                return persisted, False
            if request is None or request.status != "pending":
                return request, False
            expired = request.model_copy(update={
                "status": "timeout", "operator_notes": "Auto-rejected due to timeout",
                "responded_at": datetime.utcnow(),
            })
            await self.session_memory.store_approval_request(expired)
            request.status = expired.status
            request.operator_notes = expired.operator_notes
            request.responded_at = expired.responded_at
            return request, True

    async def _register_approval(self, request: ApprovalRequest) -> None:
        """Register an approval request and fan it out to operator-notification
        callbacks (UI, email, ...). Does NOT wait for a decision."""
        # A pending local request must not appear before durable registration.
        await self.session_memory.store_approval_request(request)
        self._approval_requests[request.id] = request
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
            request = self._approval_requests.get(request_id)
            remaining = remaining_durable_approval_seconds(
                request, settings.approval_timeout_seconds,
            )
            await asyncio.wait_for(
                self._wait_for_approval(request_id), timeout=remaining
            )
        except asyncio.TimeoutError:
            try:
                await self._expire_pending_approval(request_id)
            except Exception as exc:
                logger.warning("approval_timeout_persistence_unavailable", error_type=type(exc).__name__)
                return  # Never falsely fail a task after an uncommitted timeout.
        request = self._approval_requests.get(request_id)
        if not request or request.status == "approved":
            return
        if isinstance(self.session_memory, SessionMemory):
            # Rejection and timeout have already atomically settled TaskORM.
            # Never send a second, unfenced terminal update from local cache.
            return
        # Denied / timed out -> fail the parked task (only if still awaiting).
        task = self._tasks.get(request.task_id)
        if task and task.status == "awaiting_approval":
            await self._on_task_failure(task, {"error": f"Approval denied: {request.status}"})

    async def _wait_for_approval(self, request_id: str) -> None:
        """Wait for approval request to be resolved."""
        while True:
            request = self._approval_requests.get(request_id)
            if request and request.status in ["approved", "rejected", "modified", "timeout"]:
                return
            await asyncio.sleep(1)

    async def resolve_approval(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Serialize local decisions even across the two legacy entry points."""
        async with self._approval_decision_locks.setdefault(request_id, asyncio.Lock()):
            return await self._resolve_approval_locked(request_id, decision, operator_id, notes)

    async def _resolve_approval_locked(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Record a decision durably before exposing an in-memory approval."""
        if isinstance(self.session_memory, SessionMemory):
            # Real application requests are resolved by one signed,
            # transactionally fenced PostgreSQL decision rather than by a
            # process-local dict + a separately persisted task payload.
            durable = await self.session_memory.load_approval_request(request_id)
            if durable is None:
                raise WorkflowException("Approval request does not exist")
            resolved, first_decision = await self.session_memory.resolve_approval_atomic(
                request_id, durable.engagement_id, durable.task_id, decision,
                operator_id, notes,
            )
            self._approval_requests[request_id] = resolved
            local_task = self._tasks.get(resolved.task_id)
            if first_decision and local_task is not None:
                if resolved.status == "approved":
                    # The durable task/approval/outbox was already committed.
                    # Never repeat a broad store_task that could overwrite a
                    # concurrent halt/revocation with this local snapshot.
                    local_task.payload["approval_id"] = resolved.id
                    local_task.payload["operator_approved"] = True
                    await self._assign_task(local_task)
                elif local_task.status == "awaiting_approval":
                    local_task.status = "failed"
                    local_task.result = {
                        "status": "failed", "reason": "operator_rejected"
                    }
            # The transactional outbox is the durable audit source. A local
            # audit fan-out failure cannot undo a committed human decision.
            return resolved
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
            if request.status != "pending":
                # Already resolved: repeated operator/API requests must not
                # dispatch a second Temporal workflow.
                return request

            task = self._tasks.get(request.task_id)
            if task and task.engagement_id != request.engagement_id:
                raise WorkflowException("Approval and task engagement do not match")
            # A stale approval must never resurrect an engagement halted while
            # an operator had this request open in another browser tab.
            session = self._sessions.get(request.engagement_id)
            if session is None or session.phase in {"halted", "completed"}:
                raise WorkflowException("Approval engagement is inactive")
            if task is None or task.status in {"completed", "failed", "cancelled"}:
                raise WorkflowException("Approval task is no longer actionable")
            if decision not in {"approved", "rejected"}:
                raise WorkflowException("Invalid approval decision")
            if decision == "approved" and task.status != "awaiting_approval":
                raise WorkflowException("Approval task is not awaiting a decision")
            if task.type == "planner_inference":
                # Paid internal planner identities are claimed by the planner
                # admission ledger, never executed by an external agent.
                raise WorkflowException("Internal planner approval cannot dispatch an agent task")

            resolved = request.model_copy(update={
                "status": decision, "operator_id": operator_id,
                "operator_notes": notes, "responded_at": datetime.utcnow(),
            })

            # Persist first. A failed write must NOT cause waiters, other
            # coroutines or dispatcher guards to observe a phantom grant.
            await self.session_memory.store_approval_request(resolved)
            request.status = resolved.status
            request.operator_id = resolved.operator_id
            request.operator_notes = resolved.operator_notes
            request.responded_at = resolved.responded_at

            # Sprint 6B: Record approval resolution metrics
            wait_seconds = None
            if request.requested_at:
                wait_seconds = (request.responded_at - request.requested_at).total_seconds()
            record_approval_resolved(decision, wait_seconds)

            # P0: Persist approval resolution so state survives restarts.
            # Update task payload if approved
            if decision == "approved":
                if task:
                    task.payload["operator_approved"] = True
                    task.payload["approval_id"] = request.id
                    # Commit approval metadata before an external worker can
                    # observe the task; the shared dispatcher rechecks the
                    # persisted approval and all parent dependencies.
                    await self.session_memory.store_task(task)
                    await self._assign_task(task)
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
            # The warm tier is consulted by restarted workers; a Redis-only
            # halt would permit old Temporal tasks to resume after eviction.
            await self.session_memory.persist_session_state(session)

            for approval in self._approval_requests.values():
                if approval.engagement_id == session_id and approval.status == "pending":
                    approval.status = "rejected"
                    approval.operator_notes = "Engagement halted"
                    approval.responded_at = datetime.utcnow()
                    await self.session_memory.store_approval_request(approval)

            # Sprint 6B: Record engagement halt metrics
            record_engagement_halted(session_id)

            # Persist stopped tasks, including Temporal's scheduled and
            # approval-waiting states, before returning to the operator.
            for task in self._tasks.values():
                if task.engagement_id == session_id and task.status in {
                    "pending", "running", "scheduled", "dispatching", "awaiting_approval",
                }:
                    previously_running_temporal = (
                        self.temporal_enabled and task.status in {"scheduled", "running"}
                    )
                    task.status = "cancelled"
                    await self.session_memory.store_task(task)
                    if previously_running_temporal and self.temporal_scheduler:
                        try:
                            await asyncio.wait_for(
                                self.temporal_scheduler.cancel_task_workflow(task.id),
                                timeout=5.0,
                            )
                        except Exception:
                            logger.warning(
                                "temporal_workflow_cancel_request_failed",
                                task_id=task.id,
                            )

            # Agent instances serve multiple engagements. Cancel their
            # engagement-specific dispatch handles, leaving the shared agent
            # fleet available to other authorized engagements.
            active_handles = [
                handle
                for task_id, handle in list(self._inflight_tasks.items())
                if self._tasks.get(task_id) is not None
                and self._tasks[task_id].engagement_id == session_id
                and not handle.done()
            ]
            for handle in active_handles:
                handle.cancel()
            if active_handles:
                done, pending = await asyncio.wait(active_handles, timeout=5.0)
                if pending:
                    logger.error(
                        "engagement_halt_inflight_cancel_timeout",
                        session_id=session_id,
                        pending=len(pending),
                    )

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
        """Use the single safety-aware reaper implementation."""
        return await self.recovery_service._reap_stuck_tasks()

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
        """Recover completed chains without invalidating another live replica.

        A bare Graph Task status of 'running' contains no worker lease or
        heartbeat proof. Resetting ALL such nodes on process startup would
        interrupt healthy concurrent replicas and could trigger unsafe replay.
        PostgreSQL recovery retains unresolved execution for receipt review.
        """
        summary = {
            "interrupted_reset": 0,
            "redispatched": 0,
            "failed_over_cap": 0,
            "reconcile_required": 0,
            "chains_resumed": 0,
            "resumed": [],
        }
        try:
            # Do not invoke graph_memory.reset_interrupted_tasks here. That
            # legacy operation has no owner/lease guard and modifies every
            # running Task node, including another replica's active work.
            from ai_osop.memory.session_memory import SessionMemory

            durable = isinstance(self.session_memory, SessionMemory)
            # PostgreSQL is the source even when the graph parent projection
            # was NEVER written. Graph hints are useful for repairing older
            # SPAWNED edges, but can neither hide an SQL parent nor authorize
            # a new task. Both sources are bounded and repeated IDs deduped.
            try:
                graph_parents = await self.graph_memory.find_incomplete_chains(
                    include_spawned=durable
                )
            except Exception as exc:
                # Losing a Neo4j projection cannot conceal a completed
                # PostgreSQL parent. SQL and signed receipts remain the only
                # execution authority for the durable branch.
                if not durable:
                    raise
                logger.warning(
                    "graph_chain_hints_unavailable",
                    error_class=type(exc).__name__,
                )
                graph_parents = []

            async def recovery_candidates() -> AsyncIterator[Dict[str, Any]]:
                if durable:
                    # Reconcile ALL authoritative missing-child parents using
                    # bounded SQL keyset pages, rather than repeatedly reading
                    # only the oldest 500 hints and starving newer chains.
                    cursor: Optional[str] = None
                    while True:
                        kwargs = {} if cursor is None else {"after_id": cursor}
                        batch = await self.session_memory.list_recoverable_signed_chain_parents(
                            **kwargs
                        )
                        if not batch:
                            break
                        ids = [row.get("id") for row in batch]
                        if (
                            any(not isinstance(task_id, str) for task_id in ids)
                            or (len(batch) == 500 and ids != sorted(set(ids)))
                            or (cursor is not None and ids[0] <= cursor)
                        ):
                            raise WorkflowException("Signed chain recovery cursor did not advance")
                        for row in batch:
                            yield row
                        cursor = ids[-1]
                        if len(batch) < 500:
                            break
                for parent in graph_parents:
                    yield parent

            seen_parents: set[str] = set()
            async for parent in recovery_candidates():
                # Graph lineage can lag SQL. Only a persisted, completed,
                # engagement-owned parent is eligible for a new chain link.
                parent_id = parent.get("id") if isinstance(parent, dict) else None
                if not isinstance(parent_id, str) or not parent_id or parent_id in seen_parents:
                    continue
                seen_parents.add(parent_id)
                canonical = (
                    await (
                        self.session_memory.load_task_authoritative(parent_id)
                        if durable
                        else self.session_memory.load_task(parent_id)
                    )
                    if isinstance(parent_id, str) and parent_id else None
                )
                if (
                    canonical is None
                    or canonical.status != "completed"
                    or canonical.engagement_id != parent.get("engagement_id")
                    or canonical.type != parent.get("type")
                ):
                    continue
                live_session = await self.session_memory.load_session_state(
                    canonical.engagement_id
                )
                if (
                    live_session is None
                    or live_session.phase in {"halted", "completed"}
                    or not live_session.scope.authorization_ref
                    or not (live_session.scope.domains or live_session.scope.ips)
                ):
                    continue
                try:
                    ScopeEnforcer(live_session.scope).validate_time_window()
                except Exception:
                    continue
                safe_parent = parent
                if durable:
                    # Graph data is a *discovery hint*, never the authority to
                    # choose a target, HAR path or resumed authenticated action.
                    # The original signed TaskORM and current verified ROE
                    # must agree; even a validated Neo4j Task can be stale or
                    # attacker-controlled after the original owner crashed.
                    from ai_osop.memory.terminal_lifecycle import (
                        _continuation_metadata,
                    )
                    from ai_osop.safety.scope import validate_payload_targets

                    version = (
                        canonical.payload.get("_authorization_version")
                        if isinstance(canonical.payload, dict) else None
                    )
                    if type(version) is not int or version < 1:
                        continue
                    try:
                        await self.session_memory.assert_signed_authorization(
                            canonical.engagement_id, expected_version=version,
                        )
                        metadata = _continuation_metadata(
                            canonical.type, canonical.result
                        )
                        if canonical.type == "map_workflow":
                            url = canonical.payload.get("url")
                            if not isinstance(url, str) or not 1 <= len(url) <= 1024:
                                continue
                            validate_payload_targets(
                                ScopeEnforcer(live_session.scope),
                                {"url": url},
                                require_target=True,
                            )
                            metadata["url"] = url
                        elif canonical.type == "capture_authenticated_surface":
                            # A raw Neo4j har_path can otherwise be replaced
                            # with a host filesystem path and fed to a parser.
                            # Missing or unsafe original receipt is UNKNOWN.
                            path = metadata.get("har_path")
                            if (
                                not isinstance(path, str)
                                or not path
                                or path.startswith(("/", "\\"))
                                or ":" in path
                                or any(
                                    segment in {"", ".", ".."}
                                    for segment in path.replace("\\", "/").split("/")
                                )
                            ):
                                continue
                        elif canonical.type != "extract_har_api_inventory":
                            continue
                        if canonical.type in {"capture_authenticated_surface", "extract_har_api_inventory"}:
                            workflow_id = canonical.payload.get("workflow_id")
                            if (
                                isinstance(workflow_id, str)
                                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", workflow_id)
                            ):
                                metadata["workflow_id"] = workflow_id
                        if canonical.type == "extract_har_api_inventory":
                            replay_user = canonical.payload.get("target_user_label")
                            if (
                                isinstance(replay_user, str)
                                and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", replay_user)
                            ):
                                metadata["target_user_label"] = replay_user
                        label = canonical.payload.get("user_label")
                        if (
                            isinstance(label, str)
                            and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label)
                        ):
                            metadata["user_label"] = label
                        safe_parent = {
                            "id": canonical.id,
                            "engagement_id": canonical.engagement_id,
                            "type": canonical.type,
                            "authorization_version": version,
                            "result_summary": metadata,
                        }
                    except Exception:
                        # No requeue from a stale signer, unknown target or
                        # unverified original signed continuation receipt.
                        continue
                try:
                    child = await self._resume_chain_link(safe_parent)
                except Exception as exc:
                    # A contested TaskORM insertion or unknown graph receipt
                    # must never be presented as successful. Continue scanning
                    # unrelated parents rather than starving the whole batch.
                    # Deterministic identity makes the next startup a safe
                    # revalidation, not an automatic remote-effect replay.
                    summary["reconcile_required"] += 1
                    logger.warning(
                        "authenticated_chain_reconcile_required",
                        error_class=type(exc).__name__,
                    )
                    continue
                if child:
                    summary["chains_resumed"] += 1
                    summary["resumed"].append(
                        {"parent": parent.get("id"), "child_type": child.type}
                    )
        except Exception as e:
            # A failed SQL scan is not evidence that all children are present.
            # Preserve operator-visible reconciliation debt instead of
            # reporting a clean no-op recovery on an unavailable warm store.
            summary["reconcile_required"] += 1
            logger.error("recover_state_error", error_class=type(e).__name__)
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
        import hashlib
        import json as _json

        rs = parent.get("result_summary") or "{}"
        try:
            rs = _json.loads(rs) if isinstance(rs, str) else rs
        except Exception:
            rs = {}
        ptype = parent.get("type")
        eid = parent.get("engagement_id")
        from ai_osop.memory.session_memory import SessionMemory

        durable = isinstance(self.session_memory, SessionMemory)
        # Only unsigned legacy tasks may treat a Neo4j edge as dedupe.
        # Signed recoveries must examine TaskORM even if the graph claims a
        # child exists: older code wrote SPAWNED before PostgreSQL admission.
        if not durable and await self.graph_memory.task_has_spawned(parent["id"], eid):
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
        elif (
            ptype == "map_workflow"
            and await self._engagement_is_authenticated(eid)
            and (
                not durable or await self._authenticated_user_label_is_active(
                    eid, rs.get("user_label")
                )
            )
        ):
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
        elif (
            ptype == "extract_har_api_inventory"
            and rs.get("workflow_id")
            and (
                not durable
                or (
                    isinstance(rs.get("target_user_label"), str)
                    and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", rs["target_user_label"])
                )
            )
        ):
            child = Task(
                type="replay_for_diff_auth",
                priority=6,
                agent_type=AgentType.WORKFLOW,
                payload={
                    "workflow_id": rs["workflow_id"],
                    "engagement_id": eid,
                    **({"target_user_label": rs["target_user_label"]} if durable else {}),
                },
                dependencies=[parent["id"]],
                engagement_id=eid,
                # Authentication replay is consequential: the child always
                # requires a distinct operator grant, regardless of the
                # parent inventory approval or signed policy defaults.
                approval_required=durable,
            )
        else:
            return None

        # The previous recovery path persisted Neo4j SPAWNED BEFORE creating
        # the authoritative TaskORM. A crash after that graph edge made future
        # recovery suppress the child forever; a crash after TaskORM creation
        # but before SPAWNED could invent a second random task on the next
        # replica. Production now uses a deterministic, parent-bound child ID
        # and orders TaskORM admission before this derived graph edge.
        if durable:
            original_version = parent.get("authorization_version")
            if type(original_version) is not int or original_version < 1:
                raise WorkflowException(
                    "Authenticated recovery requires original signed policy version"
                )
            await self.session_memory.assert_signed_authorization(
                eid, expected_version=original_version,
            )
            child.id = "task-" + hashlib.sha256(
                f"{eid}:{parent['id']}:{child.type}".encode("utf-8")
            ).hexdigest()[:32]
            child.parent_task_id = parent["id"]
        parent_stub = Task(
            id=parent["id"],
            type=ptype,
            agent_type=AgentType.WORKFLOW,
            payload={},
            engagement_id=eid,
            status="completed",
        )
        if durable:
            prior = await self.session_memory.load_task_authoritative(child.id)
            if prior is not None:
                if (
                    prior.id != child.id
                    or prior.engagement_id != eid
                    or prior.parent_task_id != parent["id"]
                    or prior.type != child.type
                    or prior.agent_type != child.agent_type
                    or prior.dependencies != [parent["id"]]
                    or not isinstance(prior.payload, dict)
                    or prior.payload.get("_authorization_version") != original_version
                    or (
                        set(prior.payload) - set(child.payload)
                        - {"_authorization_version"}
                        - ({"approval_id", "operator_approved"} if prior.approval_required else set())
                    )
                    or any(
                        prior.payload.get(key) != value
                        for key, value in child.payload.items()
                    )
                ):
                    raise WorkflowException(
                        "Authenticated recovery child identity conflicts with TaskORM"
                    )
                # Child was already admitted (possibly even executed) on
                # another replica. Repair only derived graph provenance; do
                # not generate another approval, task or external call.
                await self._persist_task_dependency(parent_stub, prior)
                return None
        else:
            # Keep the preexisting unsigned/manual legacy chain behavior.
            await self._persist_task_dependency(parent_stub, child)
        await self.schedule_task(child)
        if durable:
            # Missing Neo4j leaves only a repairable graph projection gap,
            # never an orphan child or fake prior execution receipt.
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
                    already_approved_parked = (
                        task.status == "awaiting_approval"
                        and task.approval_required
                        and isinstance(task.payload, dict)
                        and task.payload.get("operator_approved") is True
                        and isinstance(task.payload.get("approval_id"), str)
                    )
                    if task.status == "pending" or already_approved_parked:
                        if self.temporal_enabled:
                            # The Temporal gate restores missing completed
                            # parents from the durable task store as needed.
                            await self._assign_task(task)
                            continue
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
                            if existing.status != "pending" and not (
                                existing.status == "awaiting_approval"
                                and existing.approval_required
                                and isinstance(existing.payload, dict)
                                and existing.payload.get("operator_approved") is True
                                and isinstance(existing.payload.get("approval_id"), str)
                            ):
                                continue
                            task = existing

                        self._tasks[task.id] = task
                        if self.temporal_enabled or all(
                            self._tasks.get(dep_id) is not None
                            and self._tasks[dep_id].status == "completed"
                            for dep_id in task.dependencies
                        ):
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
        # Differential replay scheduling previously received ctx.task_executor
        # as None. A nested agent must never invent ad-hoc browser executions
        # without a PostgreSQL-backed scheduler and signed approval lifecycle.
        # Bind only the Workflow agent, and only when it shares this exact
        # authoritative persistence instance with the scheduler.
        if (
            isinstance(self.session_memory, SessionMemory)
            and getattr(agent.ctx, "agent_type", None) == AgentType.WORKFLOW
            and getattr(agent.ctx, "session_memory", None) is self.session_memory
        ):
            agent.ctx.task_executor = self
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
        if self._terminal_dispatcher is not None:
            await self._terminal_dispatcher.stop()
            self._terminal_dispatcher = None
        if self._supervision_outbox is not None:
            await self._supervision_outbox.stop()
            self._supervision_outbox = None
        handles = [handle for handle in self._inflight_tasks.values() if not handle.done()]
        for handle in handles:
            handle.cancel()
        if handles:
            await asyncio.wait(handles, timeout=5.0)

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

        # Provenance sinks queue writes asynchronously, and share the session
        # database. Drain them before the storage backend is closed.
        for sink in (self.mcp_registry, self.llm_client):
            drain = getattr(sink, "drain_provenance", None)
            if callable(drain):
                try:
                    await drain()
                except Exception as exc:
                    logger.warning("provenance_drain_failed", error=str(exc))

        await self.session_memory.close()
        await self.graph_memory.close()
