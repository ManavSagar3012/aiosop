"""
Central Orchestrator
Task scheduling, state management, agent coordination, and workflow enforcement.
"""

import asyncio
from typing import Any, Callable, Dict, List, Optional

import redis.exceptions
import sqlalchemy.exc
import structlog
from cachetools import TTLCache

from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import settings
from ai_osop.core.enums import AgentType
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.approval_coordinator import ApprovalCoordinator
from ai_osop.orchestrator.coordination_bus import AgentCoordinationBus
from ai_osop.orchestrator.engagement_manager import EngagementManager
from ai_osop.orchestrator.phase_monitor import PhaseMonitor
from ai_osop.orchestrator.recovery_service import RecoveryService
from ai_osop.orchestrator.state_machine import EngagementStateMachine
from ai_osop.orchestrator.task_scheduler import TaskScheduler
from ai_osop.orchestrator.temporal_worker import (
    TemporalTaskScheduler,
    TemporalUnavailableError,
    temporal_available,
)
from ai_osop.reliability.agent_reaper import AgentReaper
from ai_osop.reliability.dlq import DeadLetterQueue
from ai_osop.safety.rate_limiter import RateLimiter

logger = structlog.get_logger("ai_osop.orchestrator")
from ai_osop.core.config import VALID_TRANSITIONS as _CONFIG_VALID_TRANSITIONS
from ai_osop.core.enums import EngagementPhase
from ai_osop.orchestrator.state import OrchestrationState


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

    # GAP-3-2: single source of truth. Previously this duplicated the dict in
    # core.config; the copies could drift. Reference the canonical config table.
    VALID_TRANSITIONS = _CONFIG_VALID_TRANSITIONS

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
        state: Optional[OrchestrationState] = None,
        temporal_scheduler: Optional[TemporalTaskScheduler] = None,
        coordination_bus: Optional[AgentCoordinationBus] = None,
    ):
        self.state = state or OrchestrationState()
        self.session_memory = session_memory
        self.graph_memory = graph_memory
        self.mcp_registry = mcp_registry
        self.llm_client = llm_client
        self.rate_limiter = RateLimiter()
        self.temporal_scheduler = temporal_scheduler
        self.temporal_enabled = settings.temporal_enabled
        self.coordination_bus = coordination_bus or AgentCoordinationBus()
        self.session_store = SessionStore(session_memory, self.graph_memory)
        self.dlq = DeadLetterQueue(session_memory)

        # Sprint 9: Extracted sub-components for Architecture Excellence
        self.engagement_state_machine = EngagementStateMachine(session_memory)
        self.task_scheduler = TaskScheduler(self, self.engagement_state_machine)
        self.approval_coordinator = ApprovalCoordinator(self, self.engagement_state_machine)
        self.phase_monitor = PhaseMonitor(self, self.engagement_state_machine)
        self.engagement_manager = EngagementManager(self, self.engagement_state_machine)
        self.recovery_service = RecoveryService(self, self.engagement_state_machine)
        self.agent_reaper = AgentReaper(self, self.engagement_state_machine)

        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        self._reaper_task: Optional[asyncio.Task] = None
        self._phase_monitor_task: Optional[asyncio.Task] = None
        # P2b: background poller that pulls submission outcomes into the corpus.
        self._outcome_ingestion_task: Optional[asyncio.Task] = None
        self.finding_corpus_service: Optional[Any] = None
        # Sprint 1.3: chain-first consume loop — reads primitives, escalates +
        # composes chains, and gates them through the Triager Gate.
        self._chain_analysis_task: Optional[asyncio.Task] = None
        # Graph-integrity sweep: detects orphan / ghost nodes at runtime so
        # schema drift is surfaced (and self-heals via cleanup) without waiting
        # for a manual CLI run. None until initialize() starts it.
        self._graph_integrity_task: Optional[asyncio.Task] = None
        self._approval_callbacks: List[Callable[[ApprovalRequest], None]] = []
        # GAP-2-6: handles for in-flight agent executions, keyed by task_id, so
        # halt_engagement can actually cancel running coroutines (not just flip a
        # status flag). Runtime-only — not recovered across restarts.
        self._task_handles: Dict[str, asyncio.Task] = {}

        # AIOSOP-CACHE-001 (2026-07-22): TTLCache for _is_phase_complete results.
        # Phase monitor calls this on every tick (every 10s) for each active
        # engagement. With ~50 engagements, that's ~300 Neo4j queries/minute.
        # Cache results for 5s so repeated ticks within the same window skip
        # the expensive durable-store read until task statuses settle.
        self._phase_complete_cache: TTLCache = TTLCache(maxsize=256, ttl=5)

        # Start phase monitor if an event loop is running (avoids test errors)
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                self._phase_monitor_task = loop.create_task(self.phase_monitor._phase_monitor())
        except RuntimeError:
            pass

    # ---- Shared-state proxies -------------------------------------------------
    # State lives in OrchestrationState (self.state). The extracted components and
    # tests address it through these legacy names; the properties return the live
    # dicts so in-place mutation (self._tasks[id] = task) works transparently.
    @property
    def _tasks(self) -> Dict[str, Task]:
        return self.state.tasks

    @_tasks.setter
    def _tasks(self, value: Dict[str, Task]) -> None:
        self.state.tasks = value

    @property
    def _sessions(self) -> Dict[str, SessionState]:
        return self.state.sessions

    @_sessions.setter
    def _sessions(self, value: Dict[str, SessionState]) -> None:
        from ai_osop.orchestrator.state import SessionDict

        self.state.sessions = SessionDict(value)

    @property
    def _agents(self) -> Dict[str, Any]:
        return self.state.agents

    @_agents.setter
    def _agents(self, value: Dict[str, Any]) -> None:
        self.state.agents = value

    @property
    def _approval_requests(self) -> Dict[str, ApprovalRequest]:
        return self.state.approval_requests

    @_approval_requests.setter
    def _approval_requests(self, value: Dict[str, ApprovalRequest]) -> None:
        self.state.approval_requests = value

    @property
    def _auto_transition_failures(self) -> Dict[str, Dict[str, Any]]:
        return self.state.auto_transition_failures

    @_auto_transition_failures.setter
    def _auto_transition_failures(self, value: Dict[str, Dict[str, Any]]) -> None:
        self.state.auto_transition_failures = value

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
        # P2b learning loop: periodically fold real submission outcomes into the
        # findings corpus so confidence calibration learns from ground truth.
        # Best-effort and a no-op without bug-bounty credentials.
        try:
            self._outcome_sync_interval = int(
                getattr(settings, "bug_bounty_outcome_sync_interval_seconds", 3600)
            )
            if self._outcome_sync_interval > 0:
                from ai_osop.adapters.bug_bounty_adapter import BugBountyAdapter
                from ai_osop.core.findings_corpus import FindingCorpusService

                self.finding_corpus_service = FindingCorpusService(
                    self.graph_memory,
                    self.session_memory,
                    bug_bounty_adapter=BugBountyAdapter(),
                )
                self._outcome_ingestion_task = asyncio.create_task(self._outcome_ingestion_loop())
        except Exception as e:  # noqa: BLE001 - learning loop is optional
            logger.warning("Outcome ingestion poller not started: %s", e)
        # Sprint 1.3 chain-first loop: periodically read persisted primitives, escalate
        # + compose chains, and gate them through the Triager Gate so only reproducible,
        # gate-passed chains become report-ready. No-op without a wired primitive ledger.
        try:
            self._chain_analysis_interval = int(
                getattr(settings, "chain_analysis_interval_seconds", 900)
            )
            if (
                self._chain_analysis_interval > 0
                and getattr(self.graph_memory, "primitive_ledger", None) is not None
            ):
                self._chain_analysis_task = asyncio.create_task(self._chain_analysis_loop())
        except Exception as e:  # noqa: BLE001 - chain loop is optional
            logger.warning("Chain analysis pass not started: %s", e)
        # Retention service: automated cleanup of old data
        from ai_osop.memory.retention_service import RetentionService

        self._retention_service = RetentionService(self.graph_memory, self.session_memory)
        await self._retention_service.start()
        # Phase monitor drives auto-transitions. __init__ only starts it when a loop
        # is already running at construction; start it here (idempotently) so the
        # canonical construct-then-initialize path can never leave it dead.
        if self._phase_monitor_task is None or self._phase_monitor_task.done():
            self._phase_monitor_task = asyncio.create_task(self.phase_monitor._phase_monitor())
        # Graph integrity sweep: run once at startup (so drift is detected before
        # any operator action), then on a fixed interval. Self-heals orphan
        # Vulnerability / ghost Workflow nodes by archiving them (soft-delete).
        # Failures are logged and swallowed — a wedged sweep must never block
        # orchestrator startup or kill the scheduler loop.
        self._graph_integrity_task = asyncio.create_task(self._graph_integrity_loop())
        # NOTE: ALL restart recovery (sessions, tasks, pending approvals, approval
        # re-gating, recovery-attempt cap) is owned by the single recover_state()
        # call above. The previously-duplicated inline recovery block here was
        # removed (GAP-6-2): it re-loaded tasks a second time and never re-gated
        # approvals, which let a persisted operator_approved survive restart.

    async def create_engagement(
        self, scope: ScopeDefinition, roe: Dict[str, Any], created_by: Optional[str] = None
    ) -> SessionState:
        """Create new engagement session. Delegated to EngagementManager."""
        return await self.engagement_manager.create_engagement(scope, roe, created_by)

    async def transition_phase(self, session_id: str, new_phase: EngagementPhase) -> SessionState:
        """Transition engagement to new phase with validation. Delegated to EngagementManager."""
        return await self.engagement_manager.transition_phase(session_id, new_phase)

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution. Delegated to TaskScheduler."""
        return await self.task_scheduler.schedule_task(task)

    async def _assign_task(self, task: Task) -> None:
        """Assign task to appropriate agent. Delegated to TaskScheduler."""
        result = await self.task_scheduler._assign_task(task)
        # AIOSOP-CACHE-INVALIDATE-001: task status changed (pending→running);
        # invalidate phase-complete cache so the monitor sees the new state.
        await self._invalidate_phase_complete_cache(task.engagement_id)
        return result

    async def _find_available_agent(
        self, agent_type: AgentType, task_type: str = ""
    ) -> Optional[Any]:
        """Find and atomically claim an idle agent. Delegated to TaskScheduler."""
        return await self.task_scheduler._find_available_agent(agent_type, task_type)

    async def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release an agent claim. Delegated to TaskScheduler."""
        await self.task_scheduler._release_agent(agent_id)

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
        ret = await self.task_scheduler._on_task_success(task, result)
        # AIOSOP-CACHE-INVALIDATE-001: task reached terminal success state;
        # invalidate cache so next phase-monitor tick sees the completion.
        await self._invalidate_phase_complete_cache(task.engagement_id)
        return ret

    async def _on_task_failure(self, task: Task, result: Dict[str, Any]) -> None:
        """Handle task failure. Delegated to TaskScheduler."""
        ret = await self.task_scheduler._on_task_failure(task, result)
        # AIOSOP-CACHE-INVALIDATE-001: task reached terminal failure state;
        # invalidate cache so next phase-monitor tick sees the failure.
        await self._invalidate_phase_complete_cache(task.engagement_id)
        return ret

    async def _trigger_downstream_tasks(self, completed_task: Task) -> None:
        """Trigger tasks that depend on completed task. Delegated to TaskScheduler."""
        return await self.task_scheduler._trigger_downstream_tasks(completed_task)

    async def _chain_authenticated_surface(
        self, task: Task, result: Optional[Dict[str, Any]] = None
    ) -> None:
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
            records = await self.graph_memory.run_read_query(cypher, {"workflow_id": workflow_id})
            if not records:
                return False
            record = records[0]
            exists = record.get("workflow_exists")
            step_count = record.get("step_count")
            evidence_count = record.get("evidence_count")
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
        except (sqlalchemy.exc.SQLAlchemyError, redis.exceptions.RedisError) as e:
            logger.debug("engagement_is_authenticated_lookup_failed", error=str(e))
            return False
        return any(not s.is_expired() for s in sessions)

    async def _pick_auth_user_label(self, engagement_id: str) -> Optional[str]:
        """Return the label of the first non-expired imported session, if any."""
        try:
            sessions = await self.session_store.list_sessions(engagement_id)
        except (sqlalchemy.exc.SQLAlchemyError, redis.exceptions.RedisError):
            return None
        for s in sessions:
            if not s.is_expired():
                return s.user_label
        return None

    async def _has_existing_map_workflow(self, engagement_id: str) -> bool:
        """Restart-safe check: is there already a map_workflow for this engagement,
        either in memory (_tasks) or persisted in Neo4j (survives a process restart,
        since _tasks is in-memory only)?"""
        for t in list(self.state.get_all_tasks().values()):
            if t.engagement_id == engagement_id and t.type == "map_workflow":
                return True
        cypher = "MATCH (t:Task {engagement_id: $eid, type: 'map_workflow'}) RETURN count(t) AS c"
        try:
            records = await self.graph_memory.run_read_query(cypher, {"eid": engagement_id})
            if records:
                return bool(records[0].get("c", 0) > 0)
            return False
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
                # Scheme heuristic (http for localhost/private, https for real
                # targets) — forcing https on an HTTP local target broke navigation.
                url = self.engagement_manager._domain_to_url(session.scope.domains[0])

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

    async def resolve_approval(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Resolve an approval request. Delegated to ApprovalCoordinator."""
        return await self.approval_coordinator.resolve_approval(
            request_id, decision, operator_id, notes
        )

    async def halt_engagement(self, session_id: str, reason: str) -> None:
        """Emergency halt of engagement. Delegated to EngagementManager."""
        return await self.engagement_manager.halt_engagement(session_id, reason)

    async def claim_auto_discovery(
        self, engagement_id: str, auth_user_label: str, source_task_id: str
    ) -> None:
        """Claim autonomous discovery. Delegated to EngagementManager."""
        return await self.engagement_manager.claim_auto_discovery(
            engagement_id, auth_user_label, source_task_id
        )

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

    async def _outcome_ingestion_loop(self) -> None:
        """Periodically fold real submission outcomes into the findings corpus (P2b).

        This is the write half of the calibration feedback loop: without a caller
        that pulls accept/reject/duplicate outcomes into the corpus, historical
        success rates stay at the neutral 0.5 and calibration never fires. Runs on
        an interval, best-effort — a sync failure never stops the loop.
        """
        interval = max(1, int(getattr(self, "_outcome_sync_interval", 3600)))
        while self._running:
            await asyncio.sleep(interval)
            if not self._running:
                break
            try:
                await self._ingest_outcomes_once()
            except Exception as e:  # noqa: BLE001 - advisory, keep looping
                logger.warning("outcome_ingestion_tick_failed error=%s", e)

    async def _ingest_outcomes_once(self) -> int:
        """One outcome-ingestion pass over the active engagements. Returns the total
        number of outcomes ingested (0 without a corpus service or credentials)."""
        if self.finding_corpus_service is None:
            return 0
        total = 0
        for engagement_id in list(self._sessions.keys()):
            try:
                total += await self.finding_corpus_service.ingest_outcomes(engagement_id)
            except Exception as e:  # noqa: BLE001 - per-engagement best-effort
                logger.warning(
                    "outcome_ingestion_failed engagement_id=%s error=%s", engagement_id, e
                )
        if total:
            logger.info("outcome_ingestion_complete ingested=%s", total)
        return total

    async def _chain_analysis_loop(self) -> None:
        """Periodically run the chain-first consume pass (Sprint 1.3).

        Reads persisted primitives, escalates + composes chains, and gates each chain
        through the Triager Gate. Runs on an interval, best-effort — one failing pass
        never stops the loop.
        """
        interval = max(1, int(getattr(self, "_chain_analysis_interval", 900)))
        while self._running:
            await asyncio.sleep(interval)
            if not self._running:
                break
            try:
                await self._analyze_chains_once()
            except Exception as e:  # noqa: BLE001 - advisory, keep looping
                logger.warning("chain_analysis_tick_failed error=%s", e)

    async def _analyze_chains_once(self) -> Dict[str, int]:
        """One chain-analysis pass over active engagements.

        For each engagement: pull unpromoted primitives from the ledger, run the
        escalate→compose→gate pipeline, persist every composed chain, and promote the
        primitives behind any chain the gate would EMIT (VALIDATED) so future passes do
        not re-chain them. External submission stays a separate, deliberately gated
        action — this pass never auto-reports to a platform. Returns pass counters.
        """
        ledger = getattr(self.graph_memory, "primitive_ledger", None)
        if ledger is None:
            return {"chains": 0, "emit": 0}

        from ai_osop.core.chain_analysis import (
            analyze_primitives,
            evidence_from_primitive,
            primitive_from_node,
        )
        from ai_osop.core.models import TriageVerdict
        from ai_osop.core.triager_gate import TriagerGate

        total_chains = 0
        total_emit = 0
        for engagement_id in list(self._sessions.keys()):
            try:
                nodes = await ledger.query_unpromoted(engagement_id)
            except Exception as e:  # noqa: BLE001 - per-engagement best-effort
                logger.warning(
                    "chain_analysis_query_failed engagement_id=%s error=%s",
                    engagement_id,
                    e,
                )
                continue
            primitives = [primitive_from_node(n) for n in (nodes or [])]
            if len(primitives) < 2:
                continue

            evidence_by_primitive = {}
            for p in primitives:
                ev = evidence_from_primitive(p)
                if ev is not None:
                    evidence_by_primitive[p.id] = ev

            gate = TriagerGate()
            out = analyze_primitives(
                primitives, gate=gate, evidence_by_primitive=evidence_by_primitive
            )
            chains = out.get("chains", [])
            reports = {r.chain_id: r for r in out.get("reports", []) if r.chain_id}

            for chain in chains:
                try:
                    await ledger.upsert_chain(chain)
                    total_chains += 1
                except Exception as e:  # noqa: BLE001 - persistence best-effort
                    logger.warning("chain_upsert_failed chain_id=%s error=%s", chain.id, e)
                    continue
                report = reports.get(chain.id)
                if report is not None and report.verdict == TriageVerdict.EMIT:
                    total_emit += 1
                    # Report-ready: promote its primitives so we don't re-chain them.
                    for prim_id in chain.primitive_ids:
                        try:
                            await ledger.promote_to_finding(prim_id, chain.id)
                        except Exception as e:  # noqa: BLE001 - best-effort
                            logger.warning(
                                "primitive_promote_failed primitive_id=%s error=%s",
                                prim_id,
                                e,
                            )

        if total_chains:
            logger.info(
                "chain_analysis_complete chains=%s emit_ready=%s",
                total_chains,
                total_emit,
            )
        return {"chains": total_chains, "emit": total_emit}

    async def recover_state(self) -> Dict[str, Any]:
        """Restart recovery. Delegated to RecoveryService."""
        return await self.recovery_service.recover_state()

    async def _scheduler_loop(self) -> None:
        """Background task scheduler."""
        while self._running:
            try:
                # AIOSOP-LOGHYGIENE-002: per-tick scheduler heartbeat removed (unwired
                # log level meant this DEBUG line still emitted every tick).

                # AIOSOP-SCALE-001 (2026-07-12): per-engagement inflight cap.
                # Count only RUNNING tasks per engagement (tasks actively occupying
                # an agent slot). Pending tasks are queue depth, not agent utilization
                # — including them would cap at 0 the moment >40 tasks exist and
                # deadlock the engagement (all tasks skipped, none ever assigned).
                inflight_counts: Dict[str, int] = {}
                for t in self.state.get_all_tasks().values():
                    if t.status == "running":
                        eid = t.engagement_id or "_"
                        inflight_counts[eid] = inflight_counts.get(eid, 0) + 1

                # 1. Process pending tasks already in memory (Issue 15: task leakage)
                # SCHEDULER-YIELD-001 (2026-07-12): yield to the event loop after
                # every batch of processed tasks so background _execute_via_agent
                # coroutines (dispatched via asyncio.create_task) actually get CPU
                # time. Without this, the scheduler loop monopolises the event loop
                # when there are thousands of recovered pending tasks, starving the
                # background tasks and stranding agents in "running" forever.
                _tasks_processed_this_tick = 0
                _max_per_tick = 200  # cap to prevent event loop starvation
                for task in list(self.state.get_all_tasks().values()):
                    if _tasks_processed_this_tick >= _max_per_tick:
                        break
                    if task.status == "pending":
                        # Admission control: skip if engagement hit inflight cap
                        eid = task.engagement_id or "_"
                        current = inflight_counts.get(eid, 0)
                        if current >= settings.max_inflight_tasks_per_engagement:
                            continue
                        # Check dependencies
                        if not task.dependencies:
                            inflight_counts[eid] = current + 1
                            await self._assign_task(task)
                        else:
                            all_deps_complete = all(
                                self.state.get_task(dep_id)
                                and self.state.get_task(dep_id).status == "completed"
                                for dep_id in task.dependencies
                            )
                            if all_deps_complete:
                                inflight_counts[eid] = current + 1
                                await self._assign_task(task)
                        # SCHEDULER-YIELD-001: every 5 tasks, yield so background
                        # _execute_via_agent tasks are not starved by a long loop.
                        _tasks_processed_this_tick += 1
                        if _tasks_processed_this_tick % 5 == 0:
                            await asyncio.sleep(0)

                # 2. Process new tasks from queues
                for session_id, session in list(self._sessions.items()):
                    if session.phase == EngagementPhase.HALTED.value:
                        continue

                    task_data = await self.session_memory.pop_task_queue(
                        f"tasks:{session.session_id}"
                    )
                    if task_data:
                        task = Task(**task_data)
                        if self.state.get_task(task.id):
                            existing = self.state.get_task(task.id)
                            if existing.status in ["running", "completed", "failed"]:
                                continue

                        self.state.add_task(task)
                        # Tasks arriving from the queue are from an UNTRUSTED producer
                        # (agents push here too). Sanitize approval tokens + re-apply
                        # REL-006 before assignment (GAP-2-1).
                        await self.task_scheduler.ingest_queued_task(task)

                # 3. Health check agents
                for agent_id, agent in list(self.state.get_all_agents().items()):
                    status = await agent.get_status()
                    if status["status"] == "shutdown":
                        self.state.unregister_agent(agent_id)

                await asyncio.sleep(2)

            except Exception as e:
                # Log but don't crash scheduler
                logger.error("scheduler_error", error=str(e))
                await asyncio.sleep(10)

    async def _audit_log(self, event: AuditEvent) -> None:
        """Write audit event."""
        await self.session_memory.write_audit_event(event)

    async def register_agent(self, agent: Any) -> None:
        """Register an agent with the orchestrator."""
        self.state.register_agent(agent)
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
        """Check if all tasks for the current phase are finished.

        Results are cached in ``self._phase_complete_cache`` (TTL 5s) to avoid
        re-reading the durable task store on every phase-monitor tick. The cache
        is keyed by ``(session_id, phase.value)`` so distinct engagements and
        phases never collide.
        """
        cache_key = (session_id, phase.value)
        _cache = getattr(self, "_phase_complete_cache", None)
        if _cache is not None:
            cached = _cache.get(cache_key)
            if cached is not None:
                return cached

        if phase == EngagementPhase.INITIALIZED:
            return True

        # Map phase to corresponding AgentTypes
        phase_agent_mapping = {
            # RECON must wait for the WORKFLOW discovery tasks (guest browser XHR
            # capture + login-probe), not just the RECON GET crawler. Otherwise the
            # fast full_recon finishes first, RECON is judged complete, and
            # VULNERABILITY_DISCOVERY selects injection targets before the browser
            # login-probe has persisted the login endpoint — so the auth-gated POST
            # SQLi (JS-001) is missed by a race. (AIOSOP-SPA-XHR-RECON)
            EngagementPhase.RECONNAISSANCE: {AgentType.RECON, AgentType.WORKFLOW},
            EngagementPhase.VULNERABILITY_DISCOVERY: {
                AgentType.VULN_ANALYSIS,
                AgentType.SSTI_SCANNER,
                AgentType.SSRF_SCANNER,
                AgentType.CSRF_SCANNER,
                AgentType.JWT_SCANNER,
                AgentType.SMUGGLING_SCANNER,
                AgentType.RACE_SCANNER,
                AgentType.UPLOAD_SCANNER,
                AgentType.POLLUTION_SCANNER,
                AgentType.WEBSOCKET_SCANNER,
                AgentType.SAML_SCANNER,
                AgentType.TAKEOVER_SCANNER,
            },
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

        # AIOSOP-RECON-WORKFLOW-GATE: only gate the phase on agent types that
        # actually have a registered agent. RECON now includes WORKFLOW so it waits
        # for the browser API-discovery tasks — but if NO WORKFLOW agent is
        # registered (a browser-less deployment, or an agent-pool outage), those
        # tasks sit 'pending' forever (the reaper only fails 'running' tasks) and
        # RECON would hang. Dropping unregistered agent types lets the phase still
        # complete on the work that can actually run.
        try:
            registered = {
                str(getattr(getattr(a, "ctx", None), "agent_type", ""))
                for a in list(self._agents.values())
            }
            if registered:
                allowed_agents = {a for a in allowed_agents if str(a) in registered}
        except Exception as e:  # noqa: BLE001 - never let this gate helper crash completion
            logger.warning("phase_gate_agent_filter_failed", error=str(e))

        # GAP-3-3: merge the in-memory view with the durable store. self._tasks can be
        # incomplete (e.g. mid-recovery, or another worker scheduled a task we haven't
        # hydrated), and trusting memory alone lets the monitor advance the phase while
        # durable pending tasks still exist. Union by task id; the durable record wins
        # for status so a not-yet-hydrated pending task still blocks completion.
        #
        # engagement_id resolution: the phase monitor now passes the CANONICAL
        # engagement id (scope.engagement_id) into _is_phase_complete, and every
        # task writer has been migrated to that same canonical form
        # (AIOSOP-FINDINGS-KEY, 2026-07-20). So tasks carry a SINGLE engagement_id
        # and we match on it directly — no more dual-form comparison.
        #
        # The legacy dual-key match is kept as a fallback for tasks written by
        # older code paths (or recovered from Postgres warm store) that may still
        # carry the FULL session_id form. Once every writer is migrated, the
        # fallback branch never matches and can be removed.
        _session = self._sessions.get(session_id)
        _short_eid = _session.scope.engagement_id if _session else session_id
        _full_sid = _session.session_id if _session else None
        by_id: Dict[str, Task] = {
            t.id: t
            for t in list(self.state.get_all_tasks().values())
            if t.engagement_id == session_id
            or t.engagement_id == _short_eid
            or (_full_sid is not None and t.engagement_id == _full_sid)
        }
        try:
            for t in await self.session_memory.load_all_active_tasks():
                if (
                    t.engagement_id == session_id
                    or t.engagement_id == _short_eid
                    or (_full_sid is not None and t.engagement_id == _full_sid)
                ):
                    by_id[t.id] = t  # durable active task overrides/augments memory
        except Exception as e:
            logger.warning("is_phase_complete_durable_read_failed", error=str(e))

        phase_tasks = [t for t in by_id.values() if t.agent_type in allowed_agents]

        # If no tasks exist yet for this phase: pass-through phases are complete;
        # work-scheduling phases are not (we must wait for their tasks to appear).
        if not phase_tasks:
            return phase in PASS_THROUGH_PHASES

        # AIOSOP-PHASEGATE-001 (2026-07-03): decide completion by an explicit TERMINAL
        # allowlist, not an in-flight denylist. The prior check treated a task as
        # "done" whenever its status was not in ["pending","running","awaiting_approval"],
        # which silently counted genuinely in-flight statuses the denylist forgot —
        # notably "scheduled" (Temporal-durable tasks, task_scheduler.py) and
        # "requeued" — as complete, so the phase auto-advanced while work was still
        # queued. Worse, it treated terminally-*failed*/reaped tasks (reaper sets
        # status="failed") as "complete", letting a hollow phase masquerade as done —
        # the exact over-claim this audit targets.
        #
        # Allowlist rationale: an unknown/new status now fails safe toward "not
        # complete" (a visible, debuggable stall) instead of a silent premature
        # advance. Keep this set in sync with the statuses tasks can actually reach.
        TERMINAL_SUCCESS = {"completed", "approved"}
        TERMINAL_FAILURE = {"failed", "error", "timeout", "cancelled", "discarded"}
        terminal = TERMINAL_SUCCESS | TERMINAL_FAILURE

        if not all(t.status in terminal for t in phase_tasks):
            return False

        # All phase tasks have reached a terminal state -> the phase will make no more
        # progress, so it is "complete" and the pipeline may advance (the deliberate
        # no-hang design; see _resolve_auto_next). But if NOTHING succeeded, record the
        # truth loudly rather than advancing as if the phase accomplished its goal.
        if not any(t.status in TERMINAL_SUCCESS for t in phase_tasks):
            logger.warning(
                "phase_completed_without_success",
                session_id=session_id,
                phase=phase.value,
                task_count=len(phase_tasks),
                statuses=sorted({t.status for t in phase_tasks}),
            )
        result = True
        # Cache the result so repeated phase-monitor ticks skip the read.
        _cache = getattr(self, "_phase_complete_cache", None)
        if _cache is not None:
            _cache[cache_key] = result
        return result

    async def _invalidate_phase_complete_cache(self, engagement_id: str) -> None:
        """Invalidate cached phase-completion results for an engagement.

        Called from task lifecycle hooks so a status transition is immediately
        visible on the next phase-monitor tick rather than waiting for TTL expiry.
        """
        _cache = getattr(self, "_phase_complete_cache", None)
        if _cache is None:
            return
        keys_to_delete = [k for k in _cache if k[0] == engagement_id]
        for k in keys_to_delete:
            try:
                del _cache[k]
            except KeyError:
                pass

    async def _graph_integrity_loop(self) -> None:
        """Background sweep that detects orphan / ghost nodes in the Neo4j graph
        at runtime and self-heals them by archiving (soft-delete).

        Why this exists: ``graph_integrity_checker`` was previously a CLI-only
        script (Phase-1 issue #4) — schema drift went undetected in production
        until an operator remembered to run it manually. Wiring it into the
        orchestrator's background loop makes drift a surfaced metric, not a
        silent corruption.

        Behaviour:
        - Runs once immediately on startup, then every
          ``settings.graph_integrity_check_interval_seconds`` (default 600s /
          10min — frequent enough to catch drift before an operator relies on
          a corrupt graph, rare enough to not add measurable Neo4j load).
        - On each tick: runs ``run_integrity_check`` (read-only COUNTs), exports
          the counts as structured logs, and if any orphans of the
          auto-archive classes (Vulnerability, Workflow) are found, calls
          ``cleanup_orphan_vulnerabilities`` to soft-delete them.
        - Swallows all exceptions: a wedged sweep logs a warning and reschedules
          on the next tick. It must never crash the orchestrator.
        """
        from ai_osop.memory.graph_integrity_checker import (
            cleanup_orphan_vulnerabilities,
            run_integrity_check,
        )

        interval = int(getattr(settings, "graph_integrity_check_interval_seconds", 600))
        # First tick runs immediately so drift is caught before any operator
        # action; subsequent ticks respect the configured interval.
        while True:
            try:
                report = await run_integrity_check(self.graph_memory, emit_prints=False)
                total = report.get("total_issues", 0)
                if total > 0:
                    logger.warning(
                        "graph_integrity_issues_detected",
                        total=total,
                        ghost_workflows=report.get("ghost_workflows", 0),
                        orphan_vulnerabilities=report.get("orphan_vulnerabilities", 0),
                        orphan_diff_auth_findings=report.get("orphan_diff_auth_findings", 0),
                        orphan_exploits=report.get("orphan_exploits", 0),
                    )
                    # Self-heal: archive orphan Vulnerabilities + ghost Workflows.
                    # Never hard-deletes; archived nodes remain queryable for audit.
                    try:
                        await cleanup_orphan_vulnerabilities(self.graph_memory)
                    except Exception as e:  # noqa: BLE001 - sweep must not crash loop
                        logger.warning("graph_integrity_cleanup_failed error=%s", e)
                else:
                    logger.info("graph_integrity_ok total=0")
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - sweep must not crash loop
                logger.warning("graph_integrity_sweep_failed error=%s", e)
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                raise

    async def shutdown(self) -> None:
        """Graceful shutdown."""
        self._running = False

        for bg in (
            self._scheduler_task,
            self._reaper_task,
            self._phase_monitor_task,
            self._outcome_ingestion_task,
            self._chain_analysis_task,
            self._graph_integrity_task,
        ):
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
        for agent in self.state.get_all_agents().values():
            await agent.shutdown()

        await self.session_memory.close()
        await self.graph_memory.close()
