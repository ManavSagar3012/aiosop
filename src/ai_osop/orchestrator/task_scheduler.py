"""TaskScheduler — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all task scheduling, assignment, execution, retry, and lifecycle management.
The Orchestrator retains ownership of shared state (agents, tasks, busy_agents)
and passes itself as context so the scheduler can access it.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.config import AgentType, EngagementPhase
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ApprovalRequest, AuditEvent, Task
from ai_osop.core.observability import record_task
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.orchestrator.task_scheduler")


class TaskScheduler:
    """Schedule, assign, execute, and retry tasks."""

    # Terminal failure statuses that should not trigger retry success path
    _FAILURE_STATUSES = {"failed", "error", "timeout", "cancelled"}

    # TOOL-REALITY-001 (charter section 4): task types whose execution REQUIRES a
    # specific MCP server, mapped server_id. The scheduler consults this before
    # dispatching so a down tool BLOCKS the task instead of burning retries into
    # an open circuit breaker (observed live: burp_scan failed 3x against a dead
    # burp-mcp with the opaque error "circuit breaker is open").
    # Only verified mappings are listed — unmapped task types are ungated.
    #
    # BURP-COMMUNITY-001 (2026-08-31): "burp_scan" was REMOVED from this map.
    # The task is now capability-driven: Burp Pro runs its own audit, Burp
    # Community routes active scanning to nuclei-mcp + web_audit, and a fully
    # unreachable burp-mcp degrades to internal_routed mode (Burp passive layer
    # skipped, reason recorded in degraded_components). Every outcome succeeds
    # without parking, so a hard requirement would only stall the discovery
    # phase. Same for "intruder_fuzz": its deterministic engine sends through
    # Burp's HTTP engine (every edition) with a scope-gated internal fallback
    # — it never calls turbo-intruder-mcp, so that mapping was false.
    TASK_TYPE_SERVER_REQUIREMENTS: Dict[str, str] = {
        "nuclei_scan": "nuclei-mcp",
        "xss_scan": "browser-mcp",
        "sqli_scan": "security-bridge",
        "full_recon": "recon-mcp",
        "dns_enumeration": "recon-mcp",
        "port_scan": "recon-mcp",
        "service_probe": "recon-mcp",
        "technology_fingerprint": "recon-mcp",
    }
    BLOCK_RECHECK_INTERVAL_SEC = 10.0
    BLOCK_MAX_WAIT_SEC = 900.0  # park at most 15 min, then fail with reason

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator
        self.state_machine = None  # Injected by Orchestrator post-init to break circularity
        # tool-reality parking lot: task_id -> (task, parked_at_monotonic)
        self._blocked_tasks: Dict[str, tuple] = {}
        self._block_reaper_started = False
        # FIX (assign-race-2026-08-30): _assign_task is invoked concurrently by the
        # orchestrator's _scheduler_loop AND the API's _auto_dispatch_loop, with many
        # awaits between the caller's "status == pending" check and the
        # status="running" write inside this method. Two dispatchers could therefore
        # both pass the check and execute the same task on two different agents (or a
        # tight poll could observe it wedged "pending" mid-assignment). The per-task
        # lock serializes assignment; the re-check below makes the second caller a
        # no-op once the first has moved the task out of pending.
        self._assign_locks: Dict[str, asyncio.Lock] = {}

    async def schedule_task(self, task: Task) -> Task:
        """Schedule a task for execution."""
        from ai_osop.core.telemetry import inject_trace_context

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
                {
                    "task_id": task.id,
                    "task_type": task.type,
                    "agent_type": task.agent_type.value,
                    "engagement_id": task.engagement_id,
                },
                "orchestrator",
            )
            await self._orch.session_memory.push_task_queue(
                f"tasks:{task.engagement_id}", task.model_dump()
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
                        task.error = result.get("error")
                    else:
                        task.status = "completed"
                        task.result = (
                            result
                            if isinstance(result, dict)
                            else {"status": "success", "raw": result}
                        )
                    await self._orch.session_memory.store_task(task)
                    return task.result
                except Exception as e:
                    task.status = "failed"
                    task.result = {"status": "failed", "error": str(e)}
                    task.error = str(e)
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

    async def _server_ready(self, server_id: str) -> tuple:
        """Return (ready, detail) for an MCP server using REAL runtime state.

        Tool Reality check: registration alone is not enough — the connection
        must be initialized, its circuit breaker closed, and /mcp/state ready.
        """
        registry = getattr(self._orch, "mcp_registry", None)
        conn = registry.get_server(server_id) if registry is not None else None
        if conn is None:
            return False, f"server {server_id} not registered"
        if getattr(conn, "_circuit_open", False):
            return False, f"server {server_id} circuit breaker open"
        # Tiered liveness probe:
        #   1) /mcp/state (Python SDK servers) -> authoritative status
        #   2) /health      (universal; Go SDK servers have no /mcp/state and
        #      answer 404 there -- FIX (tool-reality-404-2026-08-24): a 404 on
        #      /mcp/state previously misjudged HEALTHY Go servers as down).
        try:
            state = await asyncio.wait_for(conn.get_state(), timeout=3.0)
            if getattr(state, "status", "") == "ready":
                return True, "ready"
        except Exception:  # noqa: BLE001 - fall through to /health
            pass
        try:
            import aiohttp

            session = getattr(conn, "_session", None)
            if session is None or session.closed:
                # TOOL-REALITY-RECONNECT-001: Bypass the MCP connection layer and
                # probe the server directly via HTTP. The MCP connection may have
                # been closed during startup when servers weren't ready, but the
                # servers are now healthy. A direct HTTP probe avoids the circuit
                # breaker and stale session issues.
                try:
                    import aiohttp as _aio
                    async with _aio.ClientSession() as _probe_session:
                        async with _probe_session.get(
                            f"http://{conn.host}:{conn.port}/health",
                            timeout=_aio.ClientTimeout(total=3.0),
                        ) as resp:
                            if resp.status != 200:
                                return False, f"server {server_id} direct /health HTTP {resp.status}"
                            body = await resp.json(content_type=None)
                            if str(body.get("status", "")).lower() == "ready":
                                # Reconnect the MCP session for future tool calls
                                try:
                                    conn._circuit_open = False
                                    conn._half_open = False
                                    await conn.connect(max_retries=2)
                                except Exception:  # noqa: BLE001
                                    pass  # session may still be None but server is reachable
                                return True, "ready (reconnected)"
                            return False, f"server {server_id} /health status={body.get('status')}"
                except Exception:  # noqa: BLE001
                    return False, f"server {server_id} direct probe failed"
            async with session.get(
                f"http://{conn.host}:{conn.port}/health",
                timeout=aiohttp.ClientTimeout(total=3.0),
            ) as resp:
                if resp.status != 200:
                    return False, f"server {server_id} /health HTTP {resp.status}"
                body = await resp.json(content_type=None)
                if str(body.get("status", "")).lower() == "ready":
                    return True, "ready"
                return False, f"server {server_id} /health status={body.get('status')}"
        except Exception as e:  # noqa: BLE001 - any probe failure means not ready
            return False, f"server {server_id} probe failed: {e}"

    def _start_block_reaper(self) -> None:
        """Lazily start the background loop that revives/fails parked tasks."""
        if self._block_reaper_started:
            return
        self._block_reaper_started = True
        asyncio.create_task(self._blocked_task_reaper())

    async def _blocked_task_reaper(self) -> None:
        while True:
            await asyncio.sleep(self.BLOCK_RECHECK_INTERVAL_SEC)
            await self._reap_blocked_once()

    async def _reap_blocked_once(self) -> None:
        """One revival/timeout pass over parked tasks (unit-testable)."""
        import time as _time

        for task_id in list(self._blocked_tasks.keys()):
            task, parked_at = self._blocked_tasks[task_id]
            server_id = (task.result or {}).get("blocked_on_tool", "")
            ok, _detail = await self._server_ready(server_id)
            if ok:
                del self._blocked_tasks[task_id]
                task.status = "pending"
                task.result = None
                await self._orch.session_memory.store_task(task)
                await self._orch.graph_memory.upsert_task(task)
                logger.info(
                    f"task_unblocked task_id={task.id} server={server_id} "
                    f"tool_recovered=true"
                )
                asyncio.create_task(self._assign_task(task))
                continue
            waited = _time.monotonic() - parked_at
            if waited >= self.BLOCK_MAX_WAIT_SEC:
                del self._blocked_tasks[task_id]
                logger.error(
                    f"task_block_timeout task_id={task.id} server={server_id} "
                    f"waited_s={int(waited)}"
                )
                await self._on_task_failure(
                    task,
                    {
                        "status": "failed",
                        "error": (
                            f"required tool '{server_id}' remained unavailable "
                            f"for {int(waited)}s"
                        ),
                        "error_type": "ToolUnavailable",
                    },
                )

    async def _assign_task(self, task: Task) -> None:
        """Assign task to appropriate agent — serialized per task id.

        FIX (assign-race-2026-08-30): wraps _assign_task_inner with a per-task lock
        plus an entry-state re-check. Callers (scheduler loop, API auto-dispatch,
        approval resume, blocked-task revival) race on the same task; without this,
        two dispatchers could both pass a stale "pending" check and execute the task
        on two agents simultaneously. Entry states: "pending" (normal) and
        "awaiting_approval" (operator-approved re-dispatch).
        """
        lock = self._assign_locks.setdefault(task.id, asyncio.Lock())
        if lock.locked():
            # Another dispatcher is mid-assignment for this exact task — its own
            # status transition (running / blocked / awaiting_approval / failed)
            # is the outcome; a second pass would double-execute it.
            return
        async with lock:
            if task.status not in ("pending", "awaiting_approval"):
                return
            await self._assign_task_inner(task)

    async def _assign_task_inner(self, task: Task) -> None:
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
                    self.state_machine.assert_task_allowed(task, EngagementPhase(session.phase))
                except WorkflowException as e:
                    logger.warning("task_phase_violation", task_id=task.id, error=str(e))
                    await self._on_task_failure(
                        task, {"error": str(e), "error_type": "PhaseViolation"}
                    )
                    return

            # TOOL-REALITY-001: refuse to dispatch tasks whose required MCP server
            # is down. Park as 'blocked' (charter lifecycle) with automatic revival
            # when the tool recovers, or fail with an actionable reason on timeout.
            required_server = self.TASK_TYPE_SERVER_REQUIREMENTS.get(task.type)
            if required_server is not None:
                ok, detail = await self._server_ready(required_server)
                if not ok:
                    already = task.status == "blocked"
                    task.status = "blocked"
                    task.result = {
                        "status": "blocked",
                        "blocked_on_tool": required_server,
                        "reason": detail,
                    }
                    await self._orch.session_memory.store_task(task)
                    await self._orch.graph_memory.upsert_task(task)
                    if not already:
                        logger.warning(
                            f"task_blocked_on_tool task_id={task.id} type={task.type} "
                            f"server={required_server} reason='{detail}'"
                        )
                        await self._orch.coordination_bus.publish(
                            "task.blocked",
                            {
                                "task_id": task.id,
                                "task_type": task.type,
                                "agent_type": task.agent_type.value,
                                "engagement_id": task.engagement_id,
                                "blocked_on_tool": required_server,
                                "reason": detail,
                            },
                            "orchestrator",
                        )
                    import time as _time
                    self._blocked_tasks[task.id] = (task, _time.monotonic())
                    self._start_block_reaper()
                    return

            # GAP-2-4: tamper detection for exploit-class tasks. If the engagement's
            # scope carries a signature that no longer verifies, the manifest was
            # altered after creation — refuse to run the exploit and audit it.
            # P0-005: fail closed on unsigned scopes too; legacy unsigned scopes are
            # no longer permitted for exploit-class tasks.
            if task.agent_type == AgentType.EXPLOIT_VALIDATION or task.type in (
                "validate_exploit",
                "exploit_validation",
            ):
                _sess = self._orch._sessions.get(task.engagement_id)
                _scope = getattr(_sess, "scope", None) if _sess is not None else None
                if _scope is None or not getattr(_scope, "signature", None):
                    logger.error("scope_unsigned_or_missing", task_id=task.id)
                    await self._on_task_failure(
                        task,
                        {"error": "scope is unsigned or unavailable", "error_type": "ScopeTamper"},
                    )
                    return
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
            agent = await self._find_available_agent(task.agent_type, task.type)
            if not agent:
                logger.info("no_agent_found", task_id=task.id)
            if agent:
                started_execution = False
                try:
                    task.assigned_agent_id = agent.ctx.agent_id
                    task.status = "running"
                    task.started_at = datetime.utcnow()
                    task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
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
                    await self._orch.graph_memory.upsert_task(task)
                    await self._orch.session_memory.store_task(task)
                finally:
                    # P0-009: if _execute_via_agent was never started, the agent lock
                    # would leak forever. Release it here as a safety net.
                    if not started_execution:
                        await self._release_agent(agent.ctx.agent_id)
            else:
                task.status = "pending"
                await self._orch.graph_memory.upsert_task(task)
                await self._orch.session_memory.store_task(task)

    async def _find_available_agent(
        self, agent_type: AgentType, task_type: str = ""
    ) -> Optional[Any]:
        """Find and atomically claim an idle agent."""
        for agent in self._orch._agents.values():
            # AIOSOP-LOGHYGIENE-002 (2026-07-03): removed per-agent, per-tick matcher
            # telemetry (matching_debug / lock_attempt / lock_result). At INFO it emitted
            # ~N_agents lines every scheduler tick (~3.7k lines per run) and — because
            # structlog is not level-filtered here (OSOP_LOG_LEVEL is unwired, see
            # AIOSOP-LOGCFG-001) — could not be quieted by lowering the level. It also
            # actively drowned real diagnostics during live triage.
            # FIX (agent-type-normalize-2026-08-30): str(AgentType.X) yields
            # "AgentType.EXPLOIT_VALIDATION" while task.agent_type deserialized from
            # durable state / API payloads is the .value ("exploit_validation") — so
            # every task restored from Postgres/Redis or created via POST /tasks
            # matched NO agent ("no_agent_found") and wedged pending forever. Compare
            # normalized enum values on both sides instead of raw str().
            _agent_type_norm = getattr(agent_type, "value", str(agent_type))
            _ctx_type_norm = getattr(
                agent.ctx.agent_type, "value", str(agent.ctx.agent_type)
            )
            if _agent_type_norm == _ctx_type_norm and agent.ctx.status == "idle":
                if task_type and hasattr(agent, "supports_task_type"):
                    if not agent.supports_task_type(task_type):
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
            await self._orch.session_memory.remove_busy_agent(agent_id)
            lock_key = f"lock:agent:{agent_id}"
            await self._orch.session_memory.release_lock(lock_key, "locked")
            # AIOSOP-LOCKWIN-001: the claim set status="running"; restore "idle" so the
            # agent is claimable again. On the normal execution path execute_task has
            # already reset "idle" (harmless double-set); this is what covers the paths
            # where execution never ran — assign-time persistence failure and the
            # availability-only probe in _on_task_success — so a claimed agent can
            # never get stuck "running" forever.
            agent = self._orch._agents.get(agent_id)
            if agent is not None:
                agent.ctx.status = "idle"
                # HEARTBEAT-TRUTH-001: mirror the claim — a cancelled/hard-timed-out
                # execute_task skips its own cleanup, which used to leave
                # ctx.current_task bound to a finished task, making the heartbeat
                # report a phantom running task until the next assignment.
                agent.ctx.current_task = None

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
        """Requeue a failed task if retry budget remains.

        Tunnel-aware: when the failure looks like a Cloudflare 524 (tunnel
        timeout), use a much longer backoff (60-120s) and a higher effective
        retry cap.  The model behind the tunnel is likely still alive — it
        just needs breathing room.
        """
        error_str = str(result.get("error") or result.get("status") or "")
        is_tunnel_timeout = "524" in error_str or "tunnel" in error_str.lower()

        # Tunnel errors get a generous retry budget: the model is alive but
        # slow, so burning retries at 2-4-8s is wasteful.
        effective_max = task.max_retries * 3 if is_tunnel_timeout else task.max_retries

        if task.retry_count >= effective_max:
            try:
                await self._orch.dlq.enqueue(
                    task,
                    reason="retry_budget_exhausted",
                    final_error=error_str,
                )
            except Exception as e:
                logger.error("dlq_enqueue_failed", task_id=task.id, error=str(e))
            return False

        task.retry_count += 1

        if is_tunnel_timeout:
            # Long, patient backoff for tunnel timeouts:
            # 60s, 75s, 90s, 105s, 120s, 120s…
            backoff = min(60 + 15 * (task.retry_count - 1), 120)
        else:
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
                    "max_retries": effective_max,
                    "backoff_seconds": backoff,
                    "is_tunnel_timeout": is_tunnel_timeout,
                    "error": error_str[:300],
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
            max_retries=effective_max,
            backoff=backoff,
            is_tunnel_timeout=is_tunnel_timeout,
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
                # HANG GUARD (2026-07-05): bound every agent execution. An agent whose
                # external call (LLM / MCP / browser) never returns would otherwise pin
                # the task at 'running' FOREVER and never release the agent slot — the
                # root cause of 0/372 tasks ever completing and of stalled autonomous
                # runs. wait_for cancels the hung coroutine and we fail/retry the task,
                # so every task is guaranteed to reach a terminal state.
                _timeout = getattr(task, "timeout_seconds", None) or 600
                result = await asyncio.wait_for(agent.execute_task(task), timeout=_timeout)
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

            except asyncio.TimeoutError:
                err = {
                    "error": f"agent execution exceeded {_timeout}s hard timeout",
                    "error_type": "TaskTimeout",
                }
                if not await self._maybe_retry(task, err):
                    await self._on_task_failure(task, err)

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

            # FINDINGS-PIPELINE-001: Extract and persist findings from completed tasks
            # into canonical_findings so the LLM's observations become real, queryable
            # findings instead of being lost in ephemeral audit events.
            try:
                await self._extract_and_store_findings(task, result)
            except Exception as f_err:  # noqa: BLE001 - findings pipeline is best-effort
                logger.warning(
                    f"findings_extraction_failed task_id={task.id} error={f_err}"
                )

            # AUTONOMY-LOOP-001 (charter 22): scan-completing tasks trigger
            # hypothesis regeneration automatically — previously this only ran
            # when an operator hit the /intelligence API endpoint, so the
            # cognitive layer never advanced on its own.
            if task.type in ("nuclei_scan", "burp_scan", "full_recon",
                             "assess_services"):
                asyncio.create_task(self._regenerate_hypotheses(task.engagement_id))

            # JS-DISCOVERY-LOOP (charter section 11): after recon completes,
            # automatically schedule JS analysis for any discovered JavaScript
            # bundles so newly found endpoints feed back into the attack graph
            # and hypothesis engine. Closes the loop: recon -> JS -> endpoints
            # -> hypotheses -> testing.
            if task.type == "full_recon":
                asyncio.create_task(
                    self._auto_schedule_js_analysis(task.engagement_id, result))

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

    async def _extract_and_store_findings(
        self, task: Task, result: Dict[str, Any]
    ) -> None:
        """Extract findings from a completed task result and persist them
        to canonical_findings.

        FINDINGS-PIPELINE-001: Previously, task results were stored in the task
        record but never flowed into canonical_findings — the table existed with
        0 rows. This method bridges that gap by:
          1. Extracting vulnerability-like observations from the result
          2. Deduplicating using the finding_fingerprint from finding_intelligence
          3. Persisting each unique finding as a canonical_findings row
        """
        # Only extract from scan/analysis tasks that produce findings
        FINDING_TASK_TYPES = {
            "nuclei_scan", "burp_scan", "full_recon", "assess_services",
            "xss_scan", "sqli_scan", "validate_exploit", "exploit_validation",
            "analyze_js", "replay_for_diff_auth",
        }
        if task.type not in FINDING_TASK_TYPES:
            return

        # Extract raw findings from various result shapes
        raw_findings: List[Dict[str, Any]] = []

        # Shape 1: nuclei-style results with 'findings' list
        if isinstance(result.get("findings"), list):
            raw_findings.extend(result["findings"])

        # Shape 2: result contains 'vulnerabilities' key
        if isinstance(result.get("vulnerabilities"), list):
            raw_findings.extend(result["vulnerabilities"])

        # Shape 3: conclusion contains structured data parsed as findings
        if isinstance(result.get("parsed_findings"), list):
            raw_findings.extend(result["parsed_findings"])

        # Shape 4: MCP tool output with 'items' list (nuclei-style)
        mcp_output = result.get("mcp_output")
        if isinstance(mcp_output, dict) and isinstance(mcp_output.get("items"), list):
            for item in mcp_output["items"]:
                if isinstance(item, dict):
                    raw_findings.append(item)
        elif isinstance(mcp_output, list):
            for item in mcp_output:
                if isinstance(item, dict):
                    raw_findings.append(item)

        # Shape 5: The 'result' dict itself might be a single finding
        if not raw_findings and result.get("status") in (None, "success"):
            if result.get("severity") or result.get("vuln_type") or result.get("template"):
                raw_findings.append(result)

        # Shape 6: Agent conclusion text with embedded findings
        conclusion = str(result.get("conclusion", ""))
        if not raw_findings and conclusion:
            # Check if conclusion mentions specific vuln types
            import re
            vuln_patterns = [
                (r"sql[_ ]injection", "SQL Injection", "high", "sqli"),
                (r"cross[_ ]site[_ ]scripting|\bxss\b", "Cross-Site Scripting", "medium", "xss"),
                (r"\bidor\b|insecure[_ ]direct[_ ]object", "IDOR", "high", "idor"),
                (r"\bssrf\b|server[_ ]side[_ ]request", "SSRF", "high", "ssrf"),
                (r"\bssti\b|server[_ ]side[_ ]template", "SSTI", "critical", "ssti"),
                (r"\blfi\b|local[_ ]file[_ ]inclusion|path[_ ]traversal", "Path Traversal", "high", "lfi"),
                (r"\brce\b|remote[_ ]code[_ ]execution", "Remote Code Execution", "critical", "rce"),
                (r"open[_ ]redirect", "Open Redirect", "medium", "redirect"),
                (r"missing[_ ]security[_ ]header|security[_ ]header", "Missing Security Headers", "low", "headers"),
                (r"\bcors\b|cross[_ ]origin", "CORS Misconfiguration", "medium", "cors"),
                (r"\bjwt\b|json[_ ]web[_ ]token", "JWT Issue", "medium", "jwt"),
                (r"\bcsrf\b|cross[_ ]site[_ ]request[_ ]forgery", "CSRF", "medium", "csrf"),
            ]
            for pattern, title, severity, vuln_type in vuln_patterns:
                if re.search(pattern, conclusion, re.IGNORECASE):
                    raw_findings.append({
                        "title": title,
                        "severity": severity,
                        "vuln_type": vuln_type,
                        "description": conclusion[:500],
                    })

        if not raw_findings:
            return

        # Deduplicate and persist using SQLAlchemy
        persisted = 0
        dedup_keys_seen: set = set()
        now = datetime.utcnow()

        for finding in raw_findings:
            if not isinstance(finding, dict):
                continue

            title = finding.get("title") or finding.get("name") or finding.get("template") or "Unknown Finding"
            severity = (finding.get("severity") or "medium").lower()
            vuln_class = finding.get("vuln_type") or finding.get("type") or "unknown"
            target = finding.get("url") or finding.get("target") or finding.get("endpoint") or ""
            confidence = float(finding.get("confidence", 0.5))

            # Build dedup key
            dedup_raw = f"{task.engagement_id}|{title}|{target}|{severity}"
            dedup_key = hashlib.sha256(dedup_raw.encode()).hexdigest()[:20]

            # Skip if already seen in this batch
            if dedup_key in dedup_keys_seen:
                continue
            dedup_keys_seen.add(dedup_key)

            finding_id = f"cf-{uuid.uuid4().hex[:12]}"
            try:
                from sqlalchemy import text as sql_text

                async with self._orch.session_memory._async_session() as session:
                    # Check if already exists
                    exists_result = await session.execute(
                        sql_text("SELECT id FROM canonical_findings WHERE dedup_key = :dk"),
                        {"dk": dedup_key},
                    )
                    if exists_result.scalar_one_or_none():
                        continue

                    await session.execute(
                        sql_text(
                            "INSERT INTO canonical_findings "
                            "(id, dedup_key, tenant_id, engagement_id, asset_id, endpoint_id, "
                            "vulnerability_class, title, severity, lifecycle_state, "
                            "confidence_score, reproducibility_score, "
                            "source_task_id, source_result_id, "
                            "merged_into_finding_id, policy_eligible, "
                            "unsupported_claim_reasons, created_at, updated_at) "
                            "VALUES (:id, :dk, :tid, :eid, :aid, :epid, "
                            ":vc, :title, :sev, :ls, "
                            ":cs, :rs, "
                            ":stid, :srid, "
                            ":mifid, :pe, "
                            ":ucr, :cat, :uat)"
                        ),
                        {
                            "id": finding_id,
                            "dk": dedup_key,
                            "tid": "default",
                            "eid": task.engagement_id,
                            "aid": "",
                            "epid": target,
                            "vc": vuln_class,
                            "title": title,
                            "sev": severity,
                            "ls": "detected",
                            "cs": confidence,
                            "rs": 0.0,
                            "stid": task.id,
                            "srid": "",
                            "mifid": None,
                            "pe": True,
                            "ucr": json.dumps([]),
                            "cat": now,
                            "uat": now,
                        },
                    )
                    # FIX (canonical-commit-2026-08-30): this session was closed
                    # without a commit, so EVERY insert here rolled back —
                    # canonical_findings sat at 0 rows forever while the log
                    # claimed canonical_finding_persisted. Commit per finding.
                    await session.commit()
                    persisted += 1
                logger.info(
                    f"canonical_finding_persisted finding_id={finding_id} "
                    f"title={title} severity={severity} task_id={task.id}"
                )
            except Exception as ins_err:  # noqa: BLE001
                logger.warning(
                    f"canonical_finding_insert_failed task_id={task.id} "
                    f"title={title} error={ins_err}"
                )

        if persisted:
            logger.info(
                f"findings_extracted task_id={task.id} "
                f"count={persisted} total_raw={len(raw_findings)}"
            )

    async def _auto_schedule_js_analysis(self, engagement_id: str,
                                          scan_result: Dict[str, Any]) -> None:
        """Discover JS bundles from scan results and schedule analyze_js tasks.

        Looks for .js URLs in the scan result endpoints/assets. For each unique
        bundle found, schedules an analyze_js task through the normal pipeline
        (which applies scope gating and tool-reality checks automatically).
        """
        try:
            js_urls = set()

            def _harvest(obj: Any) -> None:
                if isinstance(obj, dict):
                    for v_ in obj.values():
                        _harvest(v_)
                elif isinstance(obj, (list, tuple)):
                    for item in obj:
                        _harvest(item)
                elif isinstance(obj, str) and obj.rstrip("?").endswith(".js")                         and "http" in obj.lower():
                    js_urls.add(obj.strip())

            _harvest(scan_result)

            # Also query the graph for known JS endpoints from this engagement
            try:
                rows = await self._orch.graph_memory.run_read_query(
                    "MATCH (e:Endpoint {engagement_id: $eid}) "
                    "WHERE e.url =~ '.*\.js(\?.*)?$' "
                    "RETURN e.url AS url LIMIT 20",
                    {"eid": engagement_id},
                )
                for r in rows or []:
                    u = r.get("url", "")
                    if u:
                        js_urls.add(u)
            except Exception:  # noqa: BLE001 - graph query is best-effort
                pass

            if not js_urls:
                return

            scheduled = 0
            for js_url in list(js_urls)[:10]:  # cap to avoid flooding
                task_id = f"task-js-{hashlib.md5(js_url.encode()).hexdigest()[:10]}"
                # Skip if already scheduled (idempotent re-runs)
                if task_id in self._orch._tasks:
                    continue

                from ai_osop.core.models import Task

                js_task = Task(
                    id=task_id,
                    type="analyze_js",
                    agent_type=AgentType.RECON,
                    engagement_id=engagement_id,
                    payload={"url": js_url},
                    priority=6,
                    scope_check=True,
                )
                await self.schedule_task(js_task)
                scheduled += 1

            if scheduled:
                logger.info(
                    f"js_discovery_scheduled engagement_id={engagement_id} "
                    f"bundles={scheduled}"
                )
        except Exception as e:  # noqa: BLE001 - feedback loop is best-effort
            logger.warning(
                f"js_discovery_scheduling_failed engagement_id={engagement_id} error={e}"
            )

    async def _regenerate_hypotheses(self, engagement_id: str) -> None:
        """Fire-and-forget cognitive refresh; failures never affect the task."""
        try:
            from ai_osop.core.hypothesis_engine import HypothesisEngine

            engine = HypothesisEngine(
                self._orch.graph_memory,
                getattr(self._orch, "skill_engine", None),
                session_memory=getattr(self._orch, "session_memory", None),
            )
            hyps = await engine.generate_and_persist(engagement_id)
            logger.info(
                f"hypotheses_regenerated engagement_id={engagement_id} count={len(hyps)}"
            )
        except Exception as e:  # noqa: BLE001 - cognitive loop is best-effort
            logger.warning(f"hypothesis_regeneration_failed engagement_id={engagement_id} error={e}")

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
                {
                    "task_id": task.id,
                    "agent_id": task.assigned_agent_id,
                    "result": result,
                    "engagement_id": task.engagement_id,
                },
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
        """Launch child tasks that depend on parent completion.

        Propagates results from parent tasks to child tasks (e.g., payload generation
        results flow into exploit validation tasks).
        """
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
                    self._orch._tasks.get(
                        dep_id,
                        Task(id=dep_id, type="", agent_type=AgentType.RECON, engagement_id=""),
                    ).status
                    in ("completed", "failed")
                    for dep_id in all_deps
                ):
                    # Inject payload results from generate_payloads into exploit_validation
                    if parent.type == "generate_payloads" and child.type == "exploit_validation":
                        await self._inject_payload_to_child(parent, child)

                    await self._assign_task(child)

    async def _inject_payload_to_child(self, parent: Task, child: Task) -> None:
        """Inject payload results from generate_payloads task into exploit_validation child.

        Extracts top payload from parent result and populates child.payload["payload"]
        before the child task is assigned to an agent.
        """
        try:
            if not parent.result:
                logger.debug("parent_task_no_result", parent_id=parent.id)
                return

            # Extract payloads from parent result
            payloads = parent.result.get("payloads", [])
            if payloads:
                # Use first (highest-fitness) payload
                top_payload = payloads[0]
                if isinstance(top_payload, dict):
                    child.payload["payload"] = top_payload
                else:
                    # If it's a Payload object, convert to dict
                    child.payload["payload"] = (
                        top_payload.model_dump()
                        if hasattr(top_payload, "model_dump")
                        else str(top_payload)
                    )

                logger.info(
                    "payload_injected_to_child",
                    parent_id=parent.id,
                    child_id=child.id,
                    payload_count=len(payloads),
                )
                # Persist the updated child task
                await self._orch.graph_memory.upsert_task(child)
        except Exception as e:
            logger.error(
                "payload_injection_failed", parent_id=parent.id, child_id=child.id, error=str(e)
            )

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
