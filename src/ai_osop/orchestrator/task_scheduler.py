"""TaskScheduler — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all task scheduling, assignment, execution, retry, and lifecycle management.
The Orchestrator retains ownership of shared state (agents, tasks, busy_agents)
and passes itself as context so the scheduler can access it.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.enums import AgentType, EngagementPhase, VulnClass
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.execution_trace import (
    ExecutionStage,
    FailureCategory,
    attach_trace,
    record_failure,
    record_stage,
)
from ai_osop.core.knowledge_engine import get_knowledge_engine
from ai_osop.core.models import ApprovalRequest, AuditEvent, Task
from ai_osop.core.observability import record_task
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span
from ai_osop.orchestrator.state_machine import EngagementStateMachine

logger = structlog.get_logger("ai_osop.orchestrator.task_scheduler")


class TaskScheduler:
    """Schedule, assign, execute, and retry tasks."""

    # Terminal failure statuses that should not trigger retry success path
    _FAILURE_STATUSES = {"failed", "error", "timeout", "cancelled"}

    # AIOSOP-TASKCLAIM-001: value stored in the per-task NX lock. Constant is fine —
    # NX guarantees a single holder, and only that holder reaches the release path.
    _TASK_LOCK_VALUE = "claimed"

    # These task types cannot produce a meaningful result without the real
    # Playwright server.  Keep this mapping centrally rather than relying on a
    # late adapter exception, which previously consumed a full task timeout and
    # pinned the engagement phase when browser-mcp was a stub.
    _TASK_MCP_REQUIREMENTS: Dict[str, List[tuple]] = {
        task_type: [("browser-mcp", "execute")]
        for task_type in (
            "navigate",
            "authenticate",
            "register",
            "map_workflow",
            "capture_session",
            "capture_authenticated_surface",
            "extract_semantics",
            "map_business_logic",
        )
    }

    # Emit a single starvation WARNING once a task has waited this long for an
    # idle agent of its type. An agent-pool outage (e.g. agents transiently
    # unregistered during an API restart) was previously silent — a task looped
    # no_agent_found for 610s with zero alerting. This makes the outage visible.
    AGENT_STARVATION_WARN_SECONDS = 60

    # ── Dynamic agent fallback (GAP-3-4) ──────────────────────────────────────
    #
    # When a scanner task exhausts its retry budget, the scheduler tries an
    # ALTERNATE technique for the same vulnerability class rather than giving
    # up entirely. The table below maps ``task_type`` to a list of
    # ``(technique_marker, AgentType)`` tuples.
    #
    # Unlike the original task type (e.g. ``sqli_scan``), the fallback uses the
    # **same** task type but injects ``technique`` into the payload so the agent
    # can branch on it. This avoids requiring agents to register handlers for
    # novel type names like ``sqli_manual_scan``.
    #
    # The first entry is the PRIMARY alternate; the second (if present) is a
    # secondary fallback. The chain stops after one level since alternate types
    # are not themselves in this table.
    _ALTERNATE_TECHNIQUES: Dict[str, List[tuple]] = {
        # SQLi: sqlmap MCP -> manual payload injection
        "sqli_scan": [
            ("sqli_scan", AgentType.VULN_ANALYSIS, {"technique": "manual"}),
        ],
        # XSS: browser-based -> HTTP payload injection
        "xss_scan": [
            ("xss_scan", AgentType.VULN_ANALYSIS, {"technique": "manual"}),
        ],
        # SSRF: OAST-based -> timing-based probe
        "ssrf_scan": [
            ("ssrf_scan", AgentType.SSRF_SCANNER, {"technique": "timing"}),
        ],
        # SSTI: template detection -> RCE probe
        "ssti_scan": [
            ("ssti_scan", AgentType.SSTI_SCANNER, {"technique": "manual"}),
        ],
        # CSRF: automatic -> manual verification
        "csrf_scan": [
            ("csrf_scan", AgentType.CSRF_SCANNER, {"technique": "manual"}),
        ],
        # JWT: alg confusion -> key brute-force
        "jwt_scan": [
            ("jwt_scan", AgentType.JWT_SCANNER, {"technique": "brute"}),
        ],
        # SMUGGLING: CL.TE -> TE.CL
        "smuggling_scan": [
            ("smuggling_scan", AgentType.SMUGGLING_SCANNER, {"technique": "reverse"}),
        ],
        # RACE: single-packet -> multi-connection
        "race_scan": [
            ("race_scan", AgentType.RACE_SCANNER, {"technique": "multi"}),
        ],
        # UPLOAD / LFI: path traversal -> extension bypass
        "upload_scan": [
            ("upload_scan", AgentType.UPLOAD_SCANNER, {"technique": "mime"}),
        ],
        # SAML: signature exclusion -> XML wrapping
        "saml_scan": [
            ("saml_scan", AgentType.SAML_SCANNER, {"technique": "xml"}),
        ],
        # POLLUTION: prototype -> constructor
        "pollution_scan": [
            ("pollution_scan", AgentType.POLLUTION_SCANNER, {"technique": "deep"}),
        ],
        # WEBSOCKET: message flooding -> URL manipulation
        "websocket_scan": [
            ("websocket_scan", AgentType.WEBSOCKET_SCANNER, {"technique": "url"}),
        ],
        # TAKEOVER: DNS probe -> HTTP fingerprint
        "takeover_scan": [
            ("takeover_scan", AgentType.TAKEOVER_SCANNER, {"technique": "http"}),
        ],
    }

    def __init__(
        self, orchestrator: Any, state_machine: Optional[EngagementStateMachine] = None
    ) -> None:
        self._orch = orchestrator
        self.state_machine = state_machine or getattr(
            orchestrator, "engagement_state_machine", None
        )
        # Task ids already warned about agent starvation (warn once, not per tick).
        self._starvation_warned: set = set()

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution."""
        from ai_osop.core.telemetry import inject_trace_context

        # Attach an Execution Observatory trace to this task
        attach_trace(task)

        if not task.trace_context:
            inject_trace_context(task.trace_context)
        RequestContext.bind(
            task_id=task.id,
            engagement_id=task.engagement_id,
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
            # REL-006: dangerous-class tasks ALWAYS require approval and may never
            # carry a caller-supplied approval token. Only resolve_approval (after a
            # real operator decision) re-adds the token. Sanitizing here closes the
            # GAP-2-1 self-authorization vector for anything entering via schedule_task.
            # AIOSOP-APPROVAL-SURFACE-001: widened from 2 hardcoded strings to the
            # canonical DANGEROUS_TASK_MARKERS set so naming variants cannot slip through.
            if self._is_dangerous_task(task):
                task.approval_required = True
            self._sanitize_external_payload(task)
            self._orch._tasks[task.id] = task

            record_stage(task, ExecutionStage.TASK_PERSISTED, metadata={"store": "memory"})
            await self._orch.graph_memory.upsert_task(task)
            await self._orch.session_memory.store_task(task)

            record_stage(
                task,
                ExecutionStage.REDIS_CONNECTED,
                metadata={"store": "session_memory", "operation": "store_task"},
            )
            record_stage(
                task,
                ExecutionStage.NEO4J_CONNECTED,
                metadata={"store": "graph_memory", "operation": "upsert_task"},
            )
            record_stage(
                task,
                ExecutionStage.POSTGRES_CONNECTED,
                metadata={"store": "session_memory", "operation": "store_task"},
            )

            record_stage(task, ExecutionStage.TASK_QUEUED, metadata={"store": "redis"})
            await self._orch.coordination_bus.publish(
                "task.scheduled",
                {
                    "task_id": task.id,
                    "task_type": task.type,
                    "agent_type": task.agent_type.value,
                    "engagement_id": task.engagement_id,
                },
                "orchestrator",
            )
            from ai_osop.core.tenant_isolation import tenant_queue_key

            _session = self._orch._sessions.get(task.engagement_id)
            _tenant = "default"
            _scope = getattr(_session, "scope", None)
            if _scope is not None:
                _org = getattr(_scope, "organization_id", None)
                if isinstance(_org, str) and _org:
                    _tenant = _org
            await self._orch.session_memory.push_task_queue(
                tenant_queue_key(_tenant, f"tasks:{task.engagement_id}"), task.model_dump()
            )
            # Wake remote scheduler loops immediately.  The ZSET remains the
            # durable source of truth; this event only removes the polling delay.
            await self._orch.session_memory.publish_event(
                "task.queue.ready",
                {"task_id": task.id, "engagement_id": task.engagement_id},
            )

            if self._orch.temporal_enabled and self._orch.temporal_scheduler:
                workflow_id = await self._orch.temporal_scheduler.start_task_workflow(
                    task.model_dump()
                )
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
        record_stage(task, ExecutionStage.PERSISTENCE_COMPLETED, metadata={"store": "durable"})

        while True:
            record_stage(
                task,
                ExecutionStage.WORKER_LEASE_REQUESTED,
                metadata={"agent_type": str(task.agent_type)},
            )
            agent = await self._find_available_agent(task.agent_type, task.type)
            if agent:
                record_stage(
                    task,
                    ExecutionStage.WORKER_LEASE_GRANTED,
                    metadata={"agent_id": agent.ctx.agent_id},
                )
                task.assigned_agent_id = agent.ctx.agent_id
                task.status = "running"
                task.started_at = datetime.utcnow()
                record_stage(
                    task, ExecutionStage.WORKER_ASSIGNED, metadata={"agent_id": agent.ctx.agent_id}
                )
                try:
                    result = await agent.execute_task(task)
                    status = result.get("status") if isinstance(result, dict) else None
                    contract_error = self._execution_contract_error(task, result)
                    if contract_error:
                        result = {"status": "failed", "error": contract_error}
                    if (
                        result is None
                        or not isinstance(result, dict)
                        or status in self._FAILURE_STATUSES
                    ):
                        task.status = "failed"
                        task.result = (
                            result
                            if isinstance(result, dict)
                            else {"status": "failed", "error": "empty or invalid agent result"}
                        )
                        task.error = task.result.get("error") or "empty or invalid agent result"
                        record_failure(
                            task,
                            FailureCategory.SCANNER,
                            str(task.error),
                            component=agent.ctx.agent_id,
                        )
                    else:
                        task.status = "completed"
                        task.result = result
                        record_stage(
                            task, ExecutionStage.TASK_COMPLETED, metadata={"status": "completed"}
                        )
                    # MIN-4 (2026-07-21): write terminal status to Neo4j so the
                    # task node reflects completion (previously only session_memory
                    # / Redis-Postgres was updated, leaving tasks shown as 'running'
                    # in the graph). The agent's own finally block in
                    # BaseAgent.execute_task already writes to Neo4j for the agent
                    # path; this is the durable/Temporal executor path's own write.
                    await self._orch.graph_memory.upsert_task(
                        task, result_summary=result if isinstance(result, dict) else None
                    )
                    await self._orch.session_memory.store_task(task)
                    return task.result
                except Exception as e:
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                    task.error = str(e)
                    record_failure(
                        task, FailureCategory.SCANNER, str(e), component=agent.ctx.agent_id
                    )
                    # MIN-4: write terminal failure to Neo4j
                    await self._orch.graph_memory.upsert_task(
                        task, result_summary={"error": str(e)[:300]}
                    )
                    await self._orch.session_memory.store_task(task)
                    return task.result
                finally:
                    await self._release_agent(agent.ctx.agent_id)

            if asyncio.get_event_loop().time() - start_time > timeout:
                task.status = "failed"
                task.result = {"status": "failed", "error": "Timeout waiting for agent"}
                record_failure(
                    task,
                    FailureCategory.QUEUE,
                    "Timeout waiting for agent",
                    component="task_scheduler",
                )
                # MIN-4: write terminal timeout to Neo4j
                await self._orch.graph_memory.upsert_task(
                    task, result_summary={"error": "Timeout waiting for agent"}
                )
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
            if session is not None and self.state_machine is not None:
                try:
                    self.state_machine.assert_task_allowed(task, EngagementPhase(session.phase))
                except WorkflowException as e:
                    logger.warning("task_phase_violation", task_id=task.id, error=str(e))
                    record_failure(task, FailureCategory.PLANNER, str(e), component="phase_monitor")
                    await self._on_task_failure(
                        task, {"error": str(e), "error_type": "PhaseViolation"}
                    )
                    return

            capability_failure = self._mcp_capability_failure(task)
            if capability_failure is not None:
                logger.error(
                    "task_mcp_capability_unavailable",
                    task_id=task.id,
                    task_type=task.type,
                    error=capability_failure["error"],
                )
                record_failure(
                    task,
                    FailureCategory.MCP,
                    str(capability_failure["error"]),
                    component="mcp_preflight",
                )
                await self._on_task_failure(task, capability_failure)
                return

            # GAP-2-4: tamper detection for exploit-class tasks. If the engagement's
            # scope carries a signature that no longer verifies, the manifest was
            # altered after creation — refuse to run the exploit and audit it.
            # P0-005: fail closed on unsigned scopes too; legacy unsigned scopes are
            # no longer permitted for exploit-class tasks.
            # AIOSOP-APPROVAL-SURFACE-001: same canonical dangerous set as the
            # approval gate, so a renamed exploit cannot skip scope verification either.
            if self._is_dangerous_task(task):
                _sess = self._orch._sessions.get(task.engagement_id)
                _scope = getattr(_sess, "scope", None) if _sess is not None else None
                if _scope is None or not getattr(_scope, "signature", None):
                    logger.error("scope_unsigned_or_missing", task_id=task.id)
                    record_failure(
                        task,
                        FailureCategory.WORKER,
                        "scope is unsigned or unavailable",
                        component="scope_check",
                    )
                    await self._on_task_failure(
                        task,
                        {"error": "scope is unsigned or unavailable", "error_type": "ScopeTamper"},
                    )
                    return
                from ai_osop.core.config import scope_signing_key

                if not _scope.verify_signature(scope_signing_key()):
                    logger.error("scope_signature_invalid", task_id=task.id)
                    record_failure(
                        task,
                        FailureCategory.WORKER,
                        "scope signature invalid",
                        component="scope_check",
                    )
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
                # AIOSOP-APPROVAL-DEDUPE-001: raise an approval only if none is already
                # pending for this task. Concurrent/re-entrant _assign_task calls — e.g.
                # the same task present in memory AND reloaded from durable state as two
                # separate objects, each still "pending" — otherwise raced past the status
                # guard above and each raised its own ApprovalRequest, flooding the
                # operator with duplicates for a single task.
                if not self._orch.approval_coordinator.has_pending_approval(task.id):
                    # AIOSOP-APPROVAL-RISK-001: derive approval risk from the finding
                    # severity instead of hardcoding "high". Every gated task was
                    # previously flagged "high" regardless of the underlying finding
                    # (info-severity SSL/DNS detections included), inflating risk and
                    # burying genuinely dangerous actions in noise. Unknown -> "high"
                    # (conservative: an un-triaged action is treated as high-risk).
                    _sev = str(task.payload.get("severity", "")).strip().lower()
                    _risk = {
                        "critical": "critical",
                        "high": "high",
                        "medium": "medium",
                        "low": "low",
                        "info": "low",
                        "informational": "low",
                    }.get(_sev, "high")
                    request = ApprovalRequest(
                        task_id=task.id,
                        agent_id="",
                        action_type=task.type,
                        target=str(task.payload.get("url", task.payload.get("target", "unknown"))),
                        payload_summary=str(task.payload),
                        risk_assessment=_risk,
                        engagement_id=task.engagement_id,
                    )
                    from ai_osop.core.observability import record_approval_requested

                    record_approval_requested(request.id)
                    await self._orch.approval_coordinator._raise_approval(request)
                # Always return on the unapproved path — never fall through to execution
                # for a task that still requires (but lacks) operator approval.
                return

            # AIOSOP-APPROVAL-ID-001: approval-gated + genuinely approved -> derive the
            # operator approval_id from the trusted ApprovalRequest record and hand it to
            # the executor. The payload token is stripped on retry/ingress (GAP-2-1/2-3),
            # so without this a retried-but-approved exploit_validation runs with no
            # approval_id and fails "requires an approval_id".
            if task.approval_required and isinstance(task.payload, dict):
                _aid = self._orch.approval_coordinator.approved_request_id(task.id)
                if _aid:
                    task.payload["approval_id"] = _aid
                    task.payload["operator_approved"] = True

            # Find + atomically claim an available agent
            record_stage(
                task,
                ExecutionStage.WORKER_LEASE_REQUESTED,
                metadata={"agent_type": str(task.agent_type)},
            )
            agent = await self._find_available_agent(task.agent_type, task.type)
            if not agent:
                await self._warn_if_starved(task)
                logger.info("no_agent_found", task_id=task.id)
            if agent:
                self._starvation_warned.discard(task.id)
                # AIOSOP-TASKCLAIM-001: claim the TASK before executing. _find_available_agent
                # locks the AGENT, not the task — so the same task present as two objects
                # (in-memory pending scan + a copy popped from the Redis queue, plus the retry
                # path which re-queues AND re-assigns the same id) each claimed a *different*
                # idle agent and ran concurrently: same identity on the shared browser, all
                # stomping each other until the 180s timeout, then retrying into more dupes.
                # Growing the pool 3->6 amplified it (more idle agents to double-claim). An NX
                # lock keyed by task id serialises dispatch: the loser releases its agent and
                # drops out; the queued copy runs once the winner frees the lock. TTL exceeds
                # the exec timeout so it never expires mid-run; _execute_via_agent's finally
                # frees it for legitimate retries.
                _task_lock = f"lock:task:{task.id}"
                _task_lock_ttl = (getattr(task, "timeout_seconds", None) or 300) + 60
                if not await self._orch.session_memory.acquire_lock(
                    _task_lock, self._TASK_LOCK_VALUE, ttl=_task_lock_ttl
                ):
                    logger.info(
                        "task_already_claimed", task_id=task.id, agent_id=agent.ctx.agent_id
                    )
                    await self._release_agent(agent.ctx.agent_id)
                    return
                record_stage(
                    task,
                    ExecutionStage.WORKER_LEASE_GRANTED,
                    metadata={"agent_id": agent.ctx.agent_id},
                )
                started_execution = False
                try:
                    task.assigned_agent_id = agent.ctx.agent_id
                    task.status = "running"
                    task.started_at = datetime.utcnow()
                    task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                    record_stage(
                        task,
                        ExecutionStage.WORKER_ASSIGNED,
                        metadata={"agent_id": agent.ctx.agent_id},
                    )
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)
                    await self._orch.coordination_bus.publish(
                        "task.assigned",
                        {
                            "task_id": task.id,
                            "agent_id": agent.ctx.agent_id,
                            "engagement_id": task.engagement_id,
                        },
                        "orchestrator",
                    )
                    # GAP-2-6: retain the handle so halt_engagement can cancel it.
                    handle = asyncio.create_task(self._execute_via_agent(agent, task))
                    started_execution = True
                    handles = getattr(self._orch, "_task_handles", None)
                    if handles is not None:
                        handles[task.id] = handle
                except Exception as e:
                    logger.error(
                        "assign_task_persistence_failed",
                        task_id=task.id,
                        agent_id=agent.ctx.agent_id,
                        error=str(e),
                    )
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                    record_failure(
                        task, FailureCategory.PERSISTENCE, str(e), component="assign_task"
                    )
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)
                finally:
                    # P0-009: if _execute_via_agent was never started, the agent lock
                    # would leak forever. Release it here as a safety net.
                    # AIOSOP-TASKCLAIM-001: same for the task lock — when execution never
                    # started (persistence failed above), _execute_via_agent's finally will
                    # not run, so free the task claim here or it lingers until TTL and blocks
                    # this task's retry for the whole TTL window.
                    if not started_execution:
                        await self._release_agent(agent.ctx.agent_id)
                        await self._release_task_claim(task.id)
            else:
                task.status = "pending"
                record_stage(task, ExecutionStage.WORKER_LEASE_REQUESTED, error="no_agent_found")
                await self._orch.graph_memory.upsert_task(task)
                await self._orch.session_memory.store_task(task)

    async def _warn_if_starved(self, task: Task) -> bool:
        """Emit a single WARNING (+ best-effort audit) when a task has waited past
        AGENT_STARVATION_WARN_SECONDS for an idle agent of its type.

        Assignment latency is sub-second in steady state; a task waiting far
        longer means no idle agent of its type exists (a pool outage), which was
        previously silent. Warns at most once per task id; returns True if it
        warned this call.
        """
        if task.id in self._starvation_warned:
            return False
        created = getattr(task, "created_at", None)
        if not created:
            return False
        waited = (datetime.utcnow() - created).total_seconds()
        if waited < self.AGENT_STARVATION_WARN_SECONDS:
            return False
        self._starvation_warned.add(task.id)
        logger.warning(
            "task_starved_no_agent",
            task_id=task.id,
            agent_type=str(task.agent_type),
            waited_seconds=round(waited, 1),
        )
        try:
            from ai_osop.core.models import AuditEvent

            await self._orch._audit_log(
                AuditEvent(
                    event_type="agent_starvation",
                    severity="warning",
                    actor_type="system",
                    actor_id="task_scheduler",
                    action={"reason": "no_idle_agent_of_type", "agent_type": str(task.agent_type)},
                    result={"waited_seconds": round(waited, 1)},
                    context={"task_id": task.id, "task_type": task.type},
                    engagement_id=getattr(task, "engagement_id", "") or "",
                )
            )
        except Exception:  # noqa: BLE001 - audit is best-effort, never break scheduling
            pass
        return True

    def _mcp_capability_failure(self, task: Task) -> Optional[Dict[str, str]]:
        """Return a deterministic failure for a declared missing MCP tool.

        An ``unknown`` server is intentionally allowed through so that normal
        lazy reconnection remains available after a service restart.  Only a
        missing registry/server or an initialized server that lacks a required
        tool is a stable contract violation.
        """
        requirements = [
            (requirement.server_id, requirement.tool_name) for requirement in task.mcp_requirements
        ]
        requirements.extend(self._TASK_MCP_REQUIREMENTS.get(task.type, []))
        requirements = list(dict.fromkeys(requirements))
        if not requirements:
            return None

        registry = getattr(self._orch, "mcp_registry", None)
        # Lightweight unit/integration scheduler harnesses intentionally omit
        # MCP wiring.  A real Orchestrator always owns a registry, so preserve
        # the contract there without turning those isolated scheduler tests into
        # a false configuration failure.
        if registry is None:
            return None
        checker = getattr(registry, "check_tool_requirements", None)
        if not callable(checker):
            return {
                "error": "MCP tool contract unavailable: registry is not configured",
                "error_type": "MCPToolContractUnavailable",
            }

        unavailable = [
            item
            for item in checker(requirements)
            if item.get("state") in {"server_missing", "tool_missing"}
        ]
        if not unavailable:
            return None

        details = ", ".join(
            f"{item['server_id']}/{item['tool_name']} ({item['state']})" for item in unavailable
        )
        return {
            "error": f"MCP tool contract unavailable: {details}",
            "error_type": "MCPToolContractUnavailable",
        }

    async def _find_available_agent(
        self, agent_type: AgentType, task_type: str = ""
    ) -> Optional[Any]:
        """Find and atomically claim an idle agent."""
        for agent in list(self._orch._agents.values()):
            # AIOSOP-LOGHYGIENE-002 (2026-07-03): removed per-agent, per-tick matcher
            # telemetry (matching_debug / lock_attempt / lock_result). At INFO it emitted
            # ~N_agents lines every scheduler tick (~3.7k lines per run) and — because
            # structlog is not level-filtered here (OSOP_LOG_LEVEL is unwired, see
            # AIOSOP-LOGCFG-001) — could not be quieted by lowering the level. It also
            # actively drowned real diagnostics during live triage.
            if str(agent.ctx.agent_type) == str(agent_type) and agent.ctx.status == "idle":
                if task_type and hasattr(agent, "supports_task_type"):
                    supports_task_type = agent.supports_task_type(task_type)
                    if inspect.isawaitable(supports_task_type):
                        supports_task_type = await supports_task_type
                    if not supports_task_type:
                        continue

                # Acquire distributed lock to prevent multi-orchestrator collisions
                lock_key = f"lock:agent:{agent.ctx.agent_id}"
                success = await self._orch.session_memory.acquire_lock(lock_key, "locked")
                if not success:
                    continue

                await self._orch.session_memory.add_busy_agent(agent.ctx.agent_id)
                # AIOSOP-LOCKWIN-001 (2026-07-03): flip status to "running" at claim
                # time. The claim (lock + busy set) and the agent's own status flip
                # (execute_task sets "running" only once it runs, on a later
                # create_task tick) were decoupled, so during that window a concurrent
                # scheduler tick matched this agent as "idle", then failed acquire_lock
                # and emitted a spurious no_agent_found — delaying the losing task a
                # full scheduler cycle under contention. Setting status here makes the
                # claim atomic w.r.t. the availability predicate on line ~280.
                agent.ctx.status = "running"
                return agent
        return None

    async def _release_agent(self, agent_id: Optional[str]) -> None:
        """Release an agent claim — the exact inverse of the claim in
        _find_available_agent (busy set, lock, status)."""
        if agent_id:
            # AIOSOP-LOCKWIN-001 / AIOSOP-AGENTLEAK-001: flip the in-memory status FIRST.
            # It cannot fail, and it is what makes the agent claimable again. Doing the
            # Redis ops first (as before) meant a Redis blip mid-release — observed live
            # when the container dropped — raised before the flip and stranded the agent
            # in "running" forever, permanently shrinking the pool. The 30s lock TTL
            # self-heals the distributed lock if the release below is skipped.
            agent = self._orch._agents.get(agent_id)
            if agent is not None:
                agent.ctx.status = "idle"
            try:
                await self._orch.session_memory.remove_busy_agent(agent_id)
                lock_key = f"lock:agent:{agent_id}"
                await self._orch.session_memory.release_lock(lock_key, "locked")
            except Exception as e:  # noqa: BLE001 — never strand an agent on a Redis hiccup
                logger.warning(
                    "release_agent_redis_cleanup_failed", agent_id=agent_id, error=str(e)
                )

    async def _release_task_claim(self, task_id: str) -> None:
        """Release the AIOSOP-TASKCLAIM-001 per-task dispatch lock. Best-effort:
        the NX lock's TTL self-heals a missed release, so never let a Redis blip
        break the caller's finally."""
        try:
            await self._orch.session_memory.release_lock(
                f"lock:task:{task_id}", self._TASK_LOCK_VALUE
            )
        except Exception as e:  # noqa: BLE001 — TTL self-heals a missed release
            logger.warning("task_lock_release_failed", task_id=task_id, error=str(e))

    # AIOSOP-APPROVAL-SURFACE-001 (2026-08-01): canonical set of task types that must
    # ALWAYS require operator approval regardless of what the producer set. Previously
    # only {"validate_exploit","exploit_validation"} (2 strings) forced the gate, so an
    # operator could enqueue e.g. task_type="exploit" / "exploit_chain" / "sqlmap" (no
    # underscore) — or any active-attack scanner — straight through create_task without
    # a human ever seeing it. This set is matched as a SUBSTRING against the lowercase
    # task type so naming variants (exploit, exploit_chain, exploit_validation, ...) all
    # catch. Keep it aligned with ApprovalGate.HIGH_IMPACT_ACTIONS in safety/scope.py.
    DANGEROUS_TASK_MARKERS = (
        "exploit",  # exploit, validate_exploit, exploit_validation, exploit_chain
        "validate_exploit",
        "rce",
        "sqli",
        "sqlmap",
        "lateral_movement",
        "data_exfiltration",
        "exfil",
        "privilege_escalation",
        "privesc",
        "persistence",
        "backdoor",
        "command_injection",
        "code_exec",
        "shell",
    )

    @classmethod
    def _is_dangerous_task(cls, task: "Task") -> bool:
        """True if a task must be forced behind the operator-approval gate.

        Centralizes the previously-duplicated exploit-guard checks. Matches the
        canonical dangerous markers as substrings of the lowercase task type, and
        always treats the EXPLOIT_VALIDATION agent class as dangerous.
        """
        if task.agent_type == AgentType.EXPLOIT_VALIDATION:
            return True
        t = (task.type or "").lower()
        return any(marker in t for marker in cls.DANGEROUS_TASK_MARKERS)

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
        exploit_validation task straight to the queue and bypass the gate.
        AIOSOP-APPROVAL-SURFACE-001: widened from 2 hardcoded strings to the
        canonical DANGEROUS_TASK_MARKERS set so a renamed exploit bypass cannot
        slip past Redis ingress either."""
        if self._is_dangerous_task(task):
            task.approval_required = True
        self._sanitize_external_payload(task)
        await self._assign_task(task)

    @staticmethod
    def _strip_stale_approval(task: Task) -> None:
        """Drop persisted approval grant so gate re-fires."""
        if task.approval_required and isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)

    # Deterministic contract/config errors that will fail identically on every
    # retry — retrying them just burns the budget (the live audit saw 66 retries
    # across 12 tasks on "Tool run_sqlmap not available"). Transient failures
    # (timeouts, connection refused, 5xx, ServiceUnavailable) are NOT listed here
    # and still retry normally.
    _NON_RETRYABLE_MARKERS = (
        "mcp tool contract unavailable",
        "not available on server",
        "not registered",
        "unknown tool",
        "no such tool",
        "tool not found",
        "unsupported tool",
        "invalid argument",
        "invalid parameter",
    )

    # Scanner task types that must prove execution. R3 (2026-07-20): this is the
    # scheduler-side backstop for the framework honesty guard in
    # ``BaseAgent._validate_output`` (base.py:595). The base guard downgrades an
    # un-evidenced ``status=success`` to ``status=error``, but it is satisfied by
    # *any* non-empty ``tool_result``/``raw_result``/``response`` key — which is
    # the right low-friction contract for arbitrary tasks. Scanner tasks need a
    # tighter contract: they must carry a verifiable ``tool`` identifier AND an
    # ``execution_verified`` flag (or a non-empty ``findings`` list with
    # evidence) so a future scanner that forgets the flag cannot silently report
    # success. ``burp_scan`` and ``nuclei_scan`` have always been gated here;
    # the per-class scanner types (sqli_scan, xss_scan, ssrf_scan, ...) are now
    # gated too — closing the gap surfaced in the Phase-1 audit.
    _TOOL_BINDING_SCAN_TYPES = {
        # task_type -> expected ``result.tool`` value
        "burp_scan": "burp_scanner",
        "nuclei_scan": "nuclei",
    }

    _EVIDENCE_BEARING_SCAN_TYPES = {
        "sqli_scan",
        "xss_scan",
        "ssrf_scan",
        "ssti_scan",
        "csrf_scan",
        "jwt_scan",
        "smuggling_scan",
        "race_scan",
        "upload_scan",
        "saml_scan",
        "pollution_scan",
        "websocket_scan",
        "takeover_scan",
        "mass_assignment_scan",
    }

    @classmethod
    def _execution_contract_error(cls, task: Task, result: Any) -> Optional[str]:
        """Return an error if a scanner claims success without execution proof.

        Two tiers of contract, by task type:

        * ``_TOOL_BINDING_SCAN_TYPES`` (burp_scan, nuclei_scan): the result
          must identify the expected external tool AND carry
          ``execution_verified=True``. These wrap a third-party tool whose
          identity we can assert on.
        * ``_EVIDENCE_BEARING_SCAN_TYPES`` (per-class scanners): the result
          must either carry ``execution_verified=True`` or contain at least one
          finding with a non-empty ``evidence`` list. The external tool here is
          usually an internal oracle (sqli_oracle, diff_auth_engine) and the
          contract is "produced real evidence", not "named a specific tool".
        """
        is_tool_bound = task.type in cls._TOOL_BINDING_SCAN_TYPES
        is_evidence_bound = task.type in cls._EVIDENCE_BEARING_SCAN_TYPES
        if not (is_tool_bound or is_evidence_bound):
            return None
        if not isinstance(result, dict):
            return "scanner returned no structured execution result"

        # Tier 1: tool-binding scanners must identify the expected tool.
        if is_tool_bound:
            expected_tool = cls._TOOL_BINDING_SCAN_TYPES[task.type]
            if result.get("tool") != expected_tool:
                return f"{task.type} result did not identify the expected tool"

        # Both tiers: ``execution_verified=True`` short-circuits the contract.
        if result.get("execution_verified") is True:
            return None

        # Tier 2 (and Tier 1 fallback): a finding with real evidence also
        # proves execution. A scanner that found nothing is fine — it must
        # simply say so honestly via ``status`` rather than ``status=success``
        # with an empty findings list.
        findings = result.get("findings") or []
        if findings and any((f.get("evidence") if isinstance(f, dict) else None) for f in findings):
            return None

        if is_tool_bound:
            return f"{task.type} result did not prove tool execution"
        return (
            f"{task.type} result claimed success without execution_verified "
            "and without any finding carrying evidence"
        )

    @classmethod
    def _is_non_retryable(cls, result: Dict[str, Any]) -> bool:
        err = str(result.get("error") or result.get("status") or "").lower()
        return any(m in err for m in cls._NON_RETRYABLE_MARKERS)

    async def _maybe_retry(self, task: Task, result: Dict[str, Any]) -> bool:
        """Requeue a failed task if retry budget remains."""
        # Short-circuit deterministic errors straight to the DLQ — no backoff loop.
        if self._is_non_retryable(result):
            logger.warning(
                "task_non_retryable",
                task_id=task.id,
                task_type=task.type,
                error=str(result.get("error") or result.get("status") or "")[:300],
            )
            try:
                await self._orch.dlq.enqueue(
                    task,
                    reason="non_retryable_error",
                    final_error=str(result.get("error") or result.get("status") or ""),
                )
            except Exception as e:
                logger.error("dlq_enqueue_failed", task_id=task.id, error=str(e))
            return False

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
        # Recovery rebuilds its active task set from the warm store, not only
        # from the Redis queue. Persist the incremented retry count and pending
        # status before the backoff so a process restart cannot resurrect the
        # prior running row and silently reset the retry budget.
        await self._orch.session_memory.store_task(task)
        await self._orch._retry_sleep(backoff)
        # Phase-1 issue #6 fix: a retry that goes straight to _assign_task
        # lives ONLY in the in-memory _tasks dict. If the orchestrator
        # restarts between this retry dispatch and execution, the task is
        # lost — recovery restores its active task set from the warm store
        # (persisted above), while the queue is still needed to wake normal
        # scheduler consumers. Re-queue to Redis, THEN attempt immediate
        # assignment. If assignment fails (no agent available) the task stays
        # queued and the scheduler loop picks it up on its next tick.
        try:
            from ai_osop.core.tenant_isolation import tenant_queue_key

            _session = self._orch._sessions.get(task.engagement_id)
            _tenant = "default"
            _scope = getattr(_session, "scope", None)
            if _scope is not None:
                _org = getattr(_scope, "organization_id", None)
                if isinstance(_org, str) and _org:
                    _tenant = _org
            await self._orch.session_memory.push_task_queue(
                tenant_queue_key(_tenant, f"tasks:{task.engagement_id}"), task.model_dump()
            )
        except Exception as e:  # noqa: BLE001 - never strand a retry on a Redis blip
            logger.warning(
                "retry_push_queue_failed",
                task_id=task.id,
                error=str(e),
            )
        await self._orch._assign_task(task)
        return True

    async def _retry_sleep(self, seconds: float) -> None:
        """Sleep for retry backoff with short wake-ups for responsiveness."""
        await asyncio.sleep(seconds)

    async def _execute_via_agent(self, agent: Any, task: Task) -> None:
        """Execute task through assigned agent."""
        logger.info(
            "_execute_via_agent_started",
            task_id=task.id,
            agent_id=agent.ctx.agent_id,
            task_type=task.type,
        )
        from ai_osop.core.telemetry import extract_trace_context
        from ai_osop.core.tracing import trace_span_with_parent

        parent_span_context = extract_trace_context(task.trace_context)

        record_stage(
            task,
            ExecutionStage.DEPENDENCY_INJECTION_COMPLETE,
            metadata={"agent_id": agent.ctx.agent_id},
        )

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

        _POST_EXECUTION_TIMEOUT = 30

        with span_ctx:
            try:
                _timeout = getattr(task, "timeout_seconds", None) or 300
                result = await asyncio.wait_for(agent.execute_task(task), timeout=_timeout)
                status = result.get("status") if isinstance(result, dict) else None
                contract_error = self._execution_contract_error(task, result)
                if contract_error:
                    result = {"status": "failed", "error": contract_error}
                    status = "failed"
                if (
                    result is None
                    or not isinstance(result, dict)
                    or status in self._FAILURE_STATUSES
                ):
                    normalized = (
                        result
                        if isinstance(result, dict)
                        else {"status": "failed", "error": "empty or invalid agent result"}
                    )
                    await self._handle_failure_with_timeout(
                        task, normalized, _POST_EXECUTION_TIMEOUT, "_maybe_retry/_on_task_failure"
                    )
                else:
                    await self._handle_success_with_timeout(task, result, _POST_EXECUTION_TIMEOUT)

            except asyncio.TimeoutError:
                record_failure(
                    task,
                    FailureCategory.WORKER,
                    f"agent execution exceeded {_timeout}s hard timeout",
                    component=agent.ctx.agent_id,
                )
                err = {
                    "error": f"agent execution exceeded {_timeout}s hard timeout",
                    "error_type": "TaskTimeout",
                }
                await self._handle_failure_with_timeout(
                    task,
                    err,
                    _POST_EXECUTION_TIMEOUT,
                    "_maybe_retry/_on_task_failure (timeout path)",
                )

            except asyncio.CancelledError:
                record_failure(
                    task,
                    FailureCategory.WORKER,
                    "execution cancelled",
                    component=agent.ctx.agent_id,
                )
                try:
                    await asyncio.wait_for(
                        self._on_task_failure(
                            task, {"error": "execution cancelled", "error_type": "CancelledError"}
                        ),
                        timeout=_POST_EXECUTION_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    logger.error(
                        "post_execution_handler_timeout",
                        task_id=task.id,
                        handler="_on_task_failure (cancelled path)",
                        timeout=_POST_EXECUTION_TIMEOUT,
                    )
                raise
            except Exception as e:
                err = {"error": str(e)}
                await self._handle_failure_with_timeout(
                    task,
                    err,
                    _POST_EXECUTION_TIMEOUT,
                    "_maybe_retry/_on_task_failure (exception path)",
                )
            finally:
                await self._release_agent(agent.ctx.agent_id)
                await self._release_task_claim(task.id)
                handles = getattr(self._orch, "_task_handles", None)
                if handles is not None:
                    handles.pop(task.id, None)

    async def _handle_failure_with_timeout(
        self,
        task: Task,
        result: Dict[str, Any],
        timeout: float,
        handler_label: str,
    ) -> None:
        """Run _maybe_retry then _on_task_failure both bounded by a timeout.

        Extracted to DRY up the 3 identical post-execution handler blocks
        in _execute_via_agent (normal, TimeoutError, and generic Exception
        paths). The CancelledError path is intentionally omitted — cancelled
        tasks should not be retried.
        """
        try:
            _retried = await asyncio.wait_for(
                self._maybe_retry(task, result),
                timeout=timeout,
            )
            if not _retried:
                await asyncio.wait_for(
                    self._on_task_failure(task, result),
                    timeout=timeout,
                )
        except asyncio.TimeoutError:
            logger.error(
                "post_execution_handler_timeout",
                task_id=task.id,
                handler=handler_label,
                timeout=timeout,
            )

    async def _handle_success_with_timeout(
        self,
        task: Task,
        result: Dict[str, Any],
        timeout: float,
    ) -> None:
        """Run _on_task_success bounded by a timeout."""
        try:
            await asyncio.wait_for(
                self._on_task_success(task, result),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.error(
                "post_execution_handler_timeout",
                task_id=task.id,
                handler="_on_task_success",
                timeout=timeout,
            )

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
            record_stage(task, ExecutionStage.PERSISTENCE_COMPLETED)
            await self._orch.graph_memory.upsert_task(task, result_summary=result)
            await self._orch.session_memory.store_task(task)
            # Auto-persist the execution trace to Redis for querying after restart
            from ai_osop.core.execution_trace import get_trace as _gt
            from ai_osop.core.execution_trace import store_trace_to_redis as _str

            _trace = _gt(task)
            if _trace is not None:
                await _str(self._orch.session_memory, _trace)
            await self._orch.coordination_bus.publish(
                "task.completed",
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    "result": result,
                    "engagement_id": task.engagement_id,
                },
                "orchestrator",
            )
            record_stage(
                task,
                ExecutionStage.DASHBOARD_UPDATED,
                metadata={"via": "coordination_bus", "topic": "task.completed"},
            )
            record_stage(task, ExecutionStage.TASK_COMPLETED, metadata={"status": "completed"})
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
            await self._schedule_autonomous_next_steps(task, result)
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"downstream_triggered": True}
            )
            await self._orch.session_memory.store_task(task)

    async def _schedule_autonomous_next_steps(self, task: Task, result: Dict[str, Any]) -> None:
        """Dynamically schedule follow-up scanner tasks on confirmed findings."""
        status = result.get("status", "").lower()
        if status not in ("vulnerable", "confirmed"):
            return

        target_url = task.payload.get("url")
        if not target_url:
            return

        # Resolve the current vulnerability class from the completed task
        task_type_to_vuln_class = {
            "sqli_scan": VulnClass.SQLI,
            "xss_scan": VulnClass.XSS,
            "ssti_scan": VulnClass.SSTI,
            "ssrf_scan": VulnClass.SSRF,
            "csrf_scan": VulnClass.CSRF,
            "jwt_scan": VulnClass.JWT_ABUSE,
            "smuggling_scan": VulnClass.REQUEST_SMUGGLING,
            "race_scan": VulnClass.RACE_CONDITION,
            "saml_scan": VulnClass.AUTHENTICATION_WEAKNESS,
            "upload_scan": VulnClass.LFI,
            "pollution_scan": VulnClass.DESERIALIZATION,
            "websocket_scan": VulnClass.VULN_SCAN,
        }

        current_vuln_class = task_type_to_vuln_class.get(task.type)
        if not current_vuln_class:
            return

        knowledge_engine = get_knowledge_engine()
        next_vuln_classes = knowledge_engine.get_next_steps(current_vuln_class)

        vuln_class_to_task_details = {
            VulnClass.SQLI: ("sqli_scan", AgentType.VULN_ANALYSIS),
            VulnClass.XSS: ("xss_scan", AgentType.VULN_ANALYSIS),
            VulnClass.SSTI: ("ssti_scan", AgentType.SSTI_SCANNER),
            VulnClass.SSRF: ("ssrf_scan", AgentType.SSRF_SCANNER),
            VulnClass.CSRF: ("csrf_scan", AgentType.CSRF_SCANNER),
            VulnClass.JWT_ABUSE: ("jwt_scan", AgentType.JWT_SCANNER),
            VulnClass.REQUEST_SMUGGLING: ("smuggling_scan", AgentType.SMUGGLING_SCANNER),
            VulnClass.RACE_CONDITION: ("race_scan", AgentType.RACE_SCANNER),
            VulnClass.SUBDOMAIN_TAKEOVER: ("takeover_scan", AgentType.TAKEOVER_SCANNER),
            VulnClass.AUTHENTICATION_WEAKNESS: ("saml_scan", AgentType.SAML_SCANNER),
            VulnClass.LFI: ("upload_scan", AgentType.UPLOAD_SCANNER),
            VulnClass.DESERIALIZATION: ("pollution_scan", AgentType.POLLUTION_SCANNER),
            VulnClass.CLOUD_VULN: ("probe_metadata", AgentType.CLOUD_SPECIALIST),
        }

        for next_vc in next_vuln_classes:
            details = vuln_class_to_task_details.get(next_vc)
            if details:
                next_task_type, next_agent_type = details
                # Build the task payload matching the scanner's expected structure
                next_payload = {"url": target_url}

                # Special cases for certain scanner types if they expect different payload schemas
                if next_task_type == "sqli_scan":
                    # Use level=1 (was 2) to align with the phase_monitor fix (AIOSOP-SQLI-BUDGET-003):
                    # level=2 multiplies HTTP requests and causes ~677s network_wait against
                    # slow external targets, exhausting the 900s budget. level=1 reduces
                    # requests by ~40% and completes in ~400-500s for the same target.
                    next_payload = {"url": target_url, "level": 1, "risk": 1}

                follow_up_task = Task(
                    type=next_task_type,
                    priority=9,
                    agent_type=next_agent_type,
                    payload=next_payload,
                    engagement_id=task.engagement_id,
                    timeout_seconds=900,
                )
                logger.info(
                    "autonomous_follow_up_scheduled",
                    parent_task_id=task.id,
                    parent_task_type=task.type,
                    next_task_type=next_task_type,
                    url=target_url,
                )
                await self.schedule_task(follow_up_task)

    async def _schedule_fallback_task(self, task: Task, result: Dict[str, Any]) -> bool:
        """Schedule an alternate technique when a scanner task exhausts retries.

        Returns True if a fallback was dispatched, False if no alternate exists
        (the task goes to the DLQ normally).

        The fallback uses the **same** task type as the original, but injects
        a ``technique`` key into the payload so the agent can branch on it
        without needing to register handlers for novel type names.
        """
        alternates = self._ALTERNATE_TECHNIQUES.get(task.type)
        if not alternates:
            return False

        # Determine which alternate index to try based on prior fallback attempts.
        # The task payload records ``_fallback_index`` — 0 for first alternate,
        # 1 for second, etc. If the index exceeds the list, all alternates have
        # been exhausted.
        fallback_idx = task.payload.get("_fallback_index", 0)
        if fallback_idx >= len(alternates):
            return False

        next_task_type, next_agent_type, payload_overrides = alternates[fallback_idx]

        # Build the fallback payload: start with a copy of the original, merge
        # in the technique override + fallback metadata.
        fallback_payload = {
            **task.payload,
            **payload_overrides,
            "_fallback_index": fallback_idx + 1,
            "_fallback_of": task.id,
            "_fallback_reason": str(result.get("error", ""))[:200],
        }

        fallback_task = Task(
            type=next_task_type,
            priority=max(task.priority - 1, 1),  # slightly lower priority
            agent_type=next_agent_type,
            payload=fallback_payload,
            engagement_id=task.engagement_id,
            timeout_seconds=task.timeout_seconds,
        )

        logger.info(
            "dynamic_fallback_scheduled",
            parent_task_id=task.id,
            parent_task_type=task.type,
            fallback_technique=payload_overrides.get("technique", "unknown"),
            fallback_attempt=fallback_idx + 1,
            reason=str(result.get("error", ""))[:120],
        )

        # Audit the fallback decision
        try:
            await self._orch._audit_log(
                AuditEvent(
                    event_type="dynamic_fallback_scheduled",
                    severity="info",
                    actor_type="system",
                    actor_id="task_scheduler",
                    action={
                        "parent_task_id": task.id,
                        "parent_task_type": task.type,
                        "fallback_technique": payload_overrides.get("technique", "unknown"),
                        "fallback_attempt": fallback_idx + 1,
                        "reason": str(result.get("error", ""))[:200],
                    },
                    result={"fallback_task_id": fallback_task.id},
                    context={"engagement_id": task.engagement_id},
                    engagement_id=task.engagement_id,
                )
            )
        except Exception:  # noqa: BLE001 — audit is best-effort
            pass

        await self.schedule_task(fallback_task)
        return True

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
            # Classify the failure from the structured error_type field or error string
            error_str = str(result.get("error", "") or "")
            error_type = str(result.get("error_type", "") or "")
            failure_category = FailureCategory.UNKNOWN
            if error_type in ("TaskTimeout", "ScannerTimeout"):
                failure_category = FailureCategory.WORKER
            elif error_type in ("PhaseViolation",):
                failure_category = FailureCategory.PLANNER
            elif error_type in ("ScopeTamper",):
                failure_category = FailureCategory.WORKER
            elif error_type in ("CancelledError",):
                failure_category = FailureCategory.WORKER
            elif "timeout" in error_str.lower() or "timed out" in error_str.lower():
                failure_category = FailureCategory.WORKER
            elif "mcp" in error_str.lower() or "circuit" in error_str.lower():
                failure_category = FailureCategory.MCP
            elif "phase" in error_str.lower():
                failure_category = FailureCategory.PLANNER
            record_failure(
                task, failure_category, error_str[:200], component=task.assigned_agent_id
            )
            task.result = result
            task.status = "failed"
            task.completed_at = datetime.utcnow()
            await self._orch.graph_memory.upsert_task(
                task, result_summary={"error": str(result.get("error", ""))[:300]}
            )
            await self._orch.session_memory.store_task(task)
            await self._orch.coordination_bus.publish(
                "task.failed",
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    "result": result,
                    "engagement_id": task.engagement_id,
                },
                "orchestrator",
            )
            record_stage(
                task,
                ExecutionStage.DASHBOARD_UPDATED,
                metadata={"via": "coordination_bus", "topic": "task.failed"},
            )
            if self._is_non_retryable(result) or task.retry_count >= task.max_retries:
                # Retries exhausted: try an alternate technique before giving up
                fallback_dispatched = await self._schedule_fallback_task(task, result)
                if not fallback_dispatched:
                    try:
                        await self._orch.dlq.enqueue(
                            task,
                            reason="terminal_failure",
                            final_error=str(result.get("error") or result.get("status") or ""),
                        )
                    except Exception as e:
                        logger.error("dlq_enqueue_fallback_failed", task_id=task.id, error=str(e))
                # A terminally-failed task is a satisfied (failed) dependency for
                # anything waiting on it. Release those dependents so they can run
                # and terminalise instead of hanging 'pending' forever — otherwise
                # a failed `register` orphans its dependent `authenticate`, which
                # pins RECONNAISSANCE and yields 0 findings.
                # (AIOSOP-DEPGATE-DEADLOCK-2026-07-26)
                await self._trigger_downstream_tasks(task)

    async def _trigger_downstream_tasks(self, parent: Task) -> None:
        """Promote child tasks whose dependencies are now all terminal.

        Called when ``parent`` reaches a TERMINAL state — completed OR failed.
        Dependents are discovered from (1) Neo4j ``SPAWNED`` edges when present
        and (2) the durable ``dependencies`` field carried on in-memory and
        active durable tasks. The field is authoritative even when the graph
        edge was never persisted: register→authenticate never wrote a SPAWNED
        edge, so the graph-only lookup returned nothing and left ``authenticate``
        pending forever — which pinned RECONNAISSANCE (it gates on all WORKFLOW
        tasks being terminal) and produced 0 findings on every run.
        (AIOSOP-DEPGATE-DEADLOCK-2026-07-26)

        A failed dependency counts as satisfied: a doomed child (e.g. authenticate
        after register failed) is promoted so it runs and terminalises, letting
        the phase advance rather than deadlock. Only ``pending`` children with
        EVERY dependency terminal are promoted.
        """
        TERMINAL = {
            "completed",
            "approved",
            "failed",
            "error",
            "timeout",
            "cancelled",
            "discarded",
        }

        # 1. Gather candidate dependents from all sources, de-duped by id.
        candidates: Dict[str, Task] = {}
        try:
            for cid in await self._orch.graph_memory.get_task_dependents(parent.id):
                t = self._orch._tasks.get(cid)
                if t is not None:
                    candidates[t.id] = t
        except Exception as e:
            logger.debug("graph_dependents_lookup_failed", parent_id=parent.id, error=str(e))
        for t in list(self._orch._tasks.values()):
            if parent.id in (t.dependencies or []):
                candidates[t.id] = t
        try:
            for t in await self._orch.session_memory.load_all_active_tasks():
                if parent.id in (t.dependencies or []):
                    candidates.setdefault(t.id, t)
        except Exception as e:
            logger.debug("durable_dependents_lookup_failed", parent_id=parent.id, error=str(e))

        # 2. Resolve dependency statuses. ``parent`` is terminal by definition
        #    (we are called from its terminal handler); other deps come from the
        #    in-memory task view. An unknown dep stays 'pending' → child waits.
        status_of: Dict[str, str] = {parent.id: parent.status or "completed"}
        for t in self._orch._tasks.values():
            status_of[t.id] = t.status

        for child in candidates.values():
            if child.status != "pending":
                continue
            deps = child.dependencies or []
            if not all(status_of.get(d, "pending") in TERMINAL for d in deps):
                continue
            # Propagate payloads from any successfully-completed dependency.
            for dep_id in deps:
                dep_task = self._orch._tasks.get(dep_id)
                if (
                    dep_task
                    and dep_task.status == "completed"
                    and isinstance(dep_task.result, dict)
                ):
                    payloads = dep_task.result.get("payloads")
                    if isinstance(payloads, list) and payloads:
                        first_p = payloads[0]
                        child.payload["payload"] = (
                            first_p.get("content") if isinstance(first_p, dict) else str(first_p)
                        )
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
            # AIOSOP-LOCKWIN-001: this is an availability probe only — claim_auto_discovery
            # re-resolves its own agent and never uses this handle. _find_available_agent
            # claims (lock + busy + status=running), so release immediately or the claim
            # leaks until the 30s lock TTL and the recon agent looks permanently busy.
            await self._release_agent(recon_agent.ctx.agent_id)

            auth_user_label = await self._orch._pick_auth_user_label(eid)
            if not auth_user_label:
                logger.info("no_auth_user_label_for_chained_surface", engagement_id=eid)
                return

            await self._orch.claim_auto_discovery(eid, auth_user_label, task.id)
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
        await self._orch.graph_memory.run_write_query(
            "MATCH (p:Task {id: $parent_id}), (c:Task {id: $child_id}) MERGE (p)-[:SPAWNED]->(c)",
            {"parent_id": task.id, "child_id": child.id},
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
