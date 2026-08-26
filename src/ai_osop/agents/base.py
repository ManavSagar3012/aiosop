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
from typing import Any, Awaitable, Callable, Dict, List, Optional

import structlog

from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import AgentException
from ai_osop.core.models import AuditEvent, ScopeDefinition, Task
from ai_osop.core.observability import record_task
from ai_osop.core.telemetry import RequestContext, extract_trace_context
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
        # FIX (audit-callback-typing-2026-08-24): annotated as sync Callable but
        # every caller awaits it and the orchestrator supplies an async method;
        # the old annotation made type checkers flag correct code and would
        # bless a sync callback that returns an unawaited coroutine.
        audit_callback: Callable[[AuditEvent], Awaitable[None]],
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
    DEFAULT_TASK_TIMEOUT_SECONDS = 900

    async def execute_task(self, task: Task) -> Dict[str, Any]:
        """
        Execute a task using a hypothesis-driven cognitive loop.
        """
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
            self.ctx.current_task = task
            self.ctx.status = "running"
            self.ctx.session_id = task.engagement_id

            if isinstance(task.payload, dict):
                p = task.payload
                url_aliases = ("url", "target_url", "target", "domain")
                resolved_url = next((p[k] for k in url_aliases if p.get(k)), None)
                if resolved_url:
                    for k in url_aliases:
                        if k not in p:
                            p[k] = resolved_url
                task.payload = p

            try:
                await self._validate_task(task)
            except Exception as e:
                self.ctx.status = "error"
                return {"status": "failed", "error": str(e)}

            start_time = time.time()
            timeout_s = getattr(task, "timeout_seconds", None) or self.DEFAULT_TASK_TIMEOUT_SECONDS

            # Retrieve MCP tools available to this agent
            available_tools = []
            for server_id, conn in self.ctx.mcp_registry._servers.items():
                tools = await conn.list_tools()
                for t in tools:
                    available_tools.append(
                        {
                            "server": server_id,
                            "name": t.name,
                            "description": t.description,
                            "parameters": [p.model_dump() for p in t.parameters],
                        }
                    )

            objective_met = False
            iteration = 0
            max_iterations = 20
            final_result = {"status": "success", "iterations": 0}

            while (
                not objective_met
                and (time.time() - start_time) < timeout_s
                and iteration < max_iterations
            ):
                iteration += 1

                # 1. Build context
                context_payload = await self._build_cognitive_context(task)

                # 2. LLM thinks and chooses next tool
                action_plan = await self._think_autonomous(context_payload, available_tools, task)

                # 2.5 Log Decision Ledger
                reasoning = action_plan.get("reasoning", {})
                from ai_osop.core.models import DecisionRecord

                decision = DecisionRecord(
                    engagement_id=task.engagement_id,
                    task_id=task.id,
                    agent_id=self.ctx.agent_id,
                    iteration=iteration,
                    action_type=action_plan.get("action", "unknown"),
                    action_target=action_plan.get("tool_call", {}).get("name", "complete"),
                    trigger=reasoning.get("observation", ""),
                    hypothesis_id=reasoning.get("hypothesis_id"),
                    alternatives_considered=reasoning.get("alternatives_considered", []),
                    reasoning=reasoning.get("why_chosen", ""),
                    expected_gain=reasoning.get("expected_information_gain", ""),
                )
                # Save decision record to session memory so it persists in context
                await self._record_observation(
                    task.engagement_id, {"decision_record": decision.model_dump()}
                )

                # T2.1: Stagnation detection — check if agent is going in circles
                try:
                    _detector = getattr(self.ctx, '_stagnation_detector', None)
                    if _detector is None:
                        # Try to get from orchestrator via the task's engagement
                        pass  # detector is attached per-agent, skip if not set
                    else:
                        _conf = reasoning.get('confidence', 0.0)
                        _tool = action_plan.get('tool_call', {}).get('name', 'complete')
                        _detector.record_observation(
                            self.ctx.agent_id, task.id, _tool, action_plan, _conf, iteration
                        )
                        _stagnation = _detector.check_stagnation(
                            self.ctx.agent_id, task.id, iteration, _conf
                        )
                        if _stagnation and _stagnation.severity == 'high':
                            agent_logger.warning(
                                "stagnation_detected agent=%s type=%s recommendation=%s",
                                self.ctx.agent_id,
                                _stagnation.stagnation_type,
                                _stagnation.recommendation,
                            )
                            # Auto-complete if severely stagnated
                            if iteration >= 10:
                                final_result["status"] = "partial"
                                final_result["conclusion"] = f"Completed early: {_stagnation.recommendation}"
                                objective_met = True
                                break
                except Exception:
                    pass  # stagnation detection is advisory, never fatal

                # Auto-complete at iteration 8+ to prevent infinite loops.
                # First try to count graph assets; if graph is unreachable,
                # still auto-complete to avoid burning the full timeout.
                if iteration >= 8 and not objective_met:
                    a_n, e_n = 0, 0
                    try:
                        asset_count = await asyncio.wait_for(
                            self.ctx.graph_memory.run_read_query(
                                "MATCH (a:Asset {engagement_id: $sid}) RETURN count(a) as c",
                                {"sid": task.engagement_id},
                            ),
                            timeout=10.0,
                        )
                        ep_count = await asyncio.wait_for(
                            self.ctx.graph_memory.run_read_query(
                                "MATCH (e:Endpoint {engagement_id: $sid}) RETURN count(e) as c",
                                {"sid": task.engagement_id},
                            ),
                            timeout=10.0,
                        )
                        a_n = asset_count[0].get("c", 0) if asset_count else 0
                        e_n = ep_count[0].get("c", 0) if ep_count else 0
                    except Exception:
                        pass  # graph unreachable — still auto-complete

                    # Auto-complete if we found data OR if we've done enough iterations
                    if a_n > 0 or e_n > 0 or iteration >= 10:
                        final_result["status"] = "success"
                        final_result["conclusion"] = (
                            f"Recon complete after {iteration} iterations: "
                            f"{a_n} assets, {e_n} endpoints discovered."
                        )
                        objective_met = True
                        break

                if action_plan.get("action") == "complete":
                    objective_met = True
                    final_result["conclusion"] = action_plan.get("conclusion", "Task completed.")
                    break

                if action_plan.get("action") == "failed":
                    # LLM could not produce valid JSON — fail fast instead of
                    # burning remaining iterations on the same broken model.
                    final_result["status"] = "failed"
                    final_result["error"] = action_plan.get("error", "LLM JSON parse failure")
                    final_result["conclusion"] = action_plan.get("conclusion", "")
                    objective_met = True
                    break

                if action_plan.get("action") == "tool":
                    tool_call = action_plan.get("tool_call", {})
                    server_id = tool_call.get("server")
                    tool_name = tool_call.get("name")
                    tool_params = tool_call.get("parameters", {})

                    # T1.1: Validate tool call before execution
                    try:
                        from ai_osop.safety.tool_call_validator import ToolCallValidator
                        _validator = ToolCallValidator(mcp_registry=self.ctx.mcp_registry)
                        _scope = getattr(self.ctx, 'scope', None)
                        if _scope is None:
                            # Load scope from engagement session
                            try:
                                _session = await self.ctx.session_memory.load_session_state(task.engagement_id)
                                _scope = getattr(_session, 'scope', None) if _session else None
                            except Exception:
                                _scope = None
                        _vr = _validator.validate(self.ctx.agent_type, tool_call, _scope)
                        if not _vr.allowed:
                            agent_logger.warning(
                                "tool_call_blocked agent=%s reason=%s",
                                self.ctx.agent_id, _vr.reason,
                            )
                            await self._record_observation(
                                task.engagement_id,
                                {"tool_blocked": tool_name, "reason": _vr.reason},
                            )
                            continue
                        # Apply sanitized params
                        if _vr.sanitized_params:
                            tool_params = _vr.sanitized_params
                        if _vr.warnings:
                            for w in _vr.warnings:
                                agent_logger.warning("tool_call_warning agent=%s msg=%s", self.ctx.agent_id, w)
                    except Exception as _v_err:
                        agent_logger.debug("tool_validation_skip error=%s", _v_err)

                    try:
                        # 3. Execute tool
                        if server_id == "internal":
                            observation = await self._execute_internal_tool(
                                tool_name, tool_params, task
                            )
                        else:
                            observation = await self.ctx.mcp_registry.execute_tool(
                                server_id, tool_name, tool_params
                            )

                        # Unwrap MCP response wrapper if needed
                        if hasattr(observation, "data"):
                            observation = observation.data
                        elif hasattr(observation, "content"):
                            observation = observation.content
                        # 4. Write evidence to memory
                        obs_data = observation.data if hasattr(observation, "data") else observation
                        await self._record_observation(
                            task.engagement_id,
                            {
                                "tool": f"{server_id}:{tool_name}",
                                "params": tool_params,
                                "result": obs_data,
                            },
                        )

                        # 4b. Auto-extract assets/endpoints from tool results
                        # so vulnerability_discovery phase has data to scan.
                        try:
                            await self._auto_extract_assets_from_result(
                                task.engagement_id, tool_name, obs_data, task
                            )
                        except Exception as _ae_err:
                            agent_logger.debug(
                                "auto_extract_assets_error",
                                agent_id=self.ctx.agent_id,
                                error=str(_ae_err),
                            )
                    except Exception as e:
                        await self._record_observation(
                            task.engagement_id,
                            {"tool": f"{server_id}:{tool_name}", "error": str(e)},
                        )

            if not objective_met:
                final_result["status"] = "failed"
                final_result["error"] = (
                    "Max iterations or timeout reached without completing objective."
                )

            final_result["iterations"] = iteration

            try:
                final_result = await self._validate_output(final_result)
            except Exception as e:
                logger.error(f"Agent output validation failed: {str(e)}")

            self.ctx.status = "idle"
            self.ctx.current_task = None
            return final_result

    @abstractmethod
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Agent-specific task execution logic."""
        pass

    async def _build_cognitive_context(self, task: Task) -> Dict[str, Any]:
        """
        Construct a normalized state representation from GraphMemory and SessionMemory.
        This becomes the JSON context the LLM observes on every loop iteration.
        """
        engagement_id = task.engagement_id

        # 1. Fetch assets (parameterized to prevent Cypher injection)
        assets = await self.ctx.graph_memory.run_read_query(
            "MATCH (a:Asset {engagement_id: $eid}) RETURN a",
            {"eid": engagement_id},
        )

        # 2. Fetch endpoints
        endpoints = await self.ctx.graph_memory.run_read_query(
            "MATCH (e:Endpoint {engagement_id: $eid}) RETURN e",
            {"eid": engagement_id},
        )

        # 3. Fetch current hypotheses
        hypotheses_nodes = await self.ctx.graph_memory.run_read_query(
            "MATCH (h:Hypothesis {engagement_id: $eid}) RETURN h",
            {"eid": engagement_id},
        )

        # 3.5 Fetch Candidate Vulnerabilities
        findings_nodes = await self.ctx.graph_memory.run_read_query(
            "MATCH (v:CandidateVulnerability {engagement_id: $eid}) RETURN v",
            {"eid": engagement_id},
        )

        # 4. Fetch recent observations (audit log / previous actions / decision ledgers)
        observations = await self.ctx.session_memory.query_audit_log(
            engagement_id=engagement_id, limit=10
        )

        return {
            "task_type": task.type,
            "payload": task.payload,
            "known_assets": [a.get("a", {}) for a in assets],
            "known_endpoints": [e.get("e", {}) for e in endpoints],
            "active_hypotheses": [h.get("h", {}) for h in hypotheses_nodes],
            "candidate_vulnerabilities": [f.get("v", {}) for f in findings_nodes],
            "recent_actions_and_decisions": [obs.model_dump() for obs in observations],
            "identities": (
                list(self.ctx.session_memory._users.keys())
                if hasattr(self.ctx.session_memory, "_users")
                else []
            ),
        }

    async def _record_observation(self, engagement_id: str, observation: Dict[str, Any]) -> None:
        """
        Records an observation into the audit log so the LLM can see its own history.
        """
        from ai_osop.core.models import AuditEvent

        event = AuditEvent(
            event_type="agent_observation",
            severity="info",
            actor_type="agent",
            actor_id=self.ctx.agent_id,
            action=json.loads(json.dumps(observation, default=str)),
            result={"status": "recorded"},
            context={"agent_type": self.ctx.agent_type.value if hasattr(self.ctx, "agent_type") else "unknown"},
            engagement_id=engagement_id
        )
        await self.ctx.session_memory.write_audit_event(event)

    async def _execute_internal_tool(
        self, name: str, params: Dict[str, Any], task: Task
    ) -> Dict[str, Any]:
        """Handle graph memory manipulation tools."""
        import uuid

        from ai_osop.core.models import Asset, Endpoint

        engagement_id = task.engagement_id
        try:
            if name == "manage_hypothesis":
                hyp_id = params.get("id") or f"hyp-{uuid.uuid4().hex[:8]}"
                await self.ctx.graph_memory.run_write_query(
                    "MERGE (h:Hypothesis {id: $hyp_id, engagement_id: $eid}) "
                    "SET h.statement = $statement, h.status = $status, "
                    "h.confidence = $confidence, h.updated_at = timestamp()",
                    {
                        "hyp_id": hyp_id,
                        "eid": engagement_id,
                        "statement": params.get("statement", ""),
                        "status": params.get("status", "open").lower(),
                        "confidence": float(params.get("confidence", 0.0)),
                    },
                )
                return {
                    "status": "success",
                    "message": f"Hypothesis '{params.get('statement')}' recorded.",
                    "id": hyp_id,
                }

            elif name == "store_asset":
                asset = Asset(
                    id=f"asset-{engagement_id}-{params.get('value')}",
                    type=params.get("type", "unknown"),
                    value=params.get("value", ""),
                    source="autonomous_agent",
                    confidence=1.0,
                    engagement_id=engagement_id,
                )
                await self.ctx.graph_memory.add_asset(asset)
                return {
                    "status": "success",
                    "message": f"Asset {params.get('value')} stored.",
                    "id": asset.id,
                }

            elif name == "store_endpoint":
                url = params.get("url", "")
                endpoint = Endpoint(
                    id=f"ep-{uuid.uuid4().hex[:8]}",
                    url=url,
                    method=params.get("method", "GET"),
                    parameters=params.get("parameters", []),
                    engagement_id=engagement_id,
                )
                await self.ctx.graph_memory.add_endpoint(endpoint)
                return {
                    "status": "success",
                    "message": f"Endpoint {url} stored.",
                    "id": endpoint.id,
                }

            elif name == "propose_vulnerability":
                vuln_id = f"candvuln-{uuid.uuid4().hex[:8]}"
                # Store as CandidateVulnerability to be validated later
                await self.ctx.graph_memory.run_write_query(
                    "MERGE (v:CandidateVulnerability {id: $vuln_id, engagement_id: $eid}) "
                    "SET v.title = $title, v.severity = $severity, "
                    "v.target = $target, v.hypothesis_id = $hypothesis_id, "
                    "v.created_at = timestamp()",
                    {
                        "vuln_id": vuln_id,
                        "eid": engagement_id,
                        "title": params.get("title", ""),
                        "severity": params.get("severity", "medium"),
                        "target": params.get("target", ""),
                        "hypothesis_id": params.get("hypothesis_id", ""),
                    },
                )
                return {
                    "status": "success",
                    "message": f"Candidate Vulnerability {params.get('title')} proposed.",
                    "id": vuln_id,
                }

            return {"status": "error", "message": f"Unknown internal tool: {name}"}

        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def _think_autonomous(
        self, context: Dict[str, Any], tools: List[Dict[str, Any]], task: Task
    ) -> Dict[str, Any]:
        """
        The autonomous reasoning core. Feeds the structured state + tool schemas to the LLM
        and expects a JSON action plan in return.
        """
        import json

        internal_tools = [
            {
                "server": "internal",
                "name": "manage_hypothesis",
                "description": "Create a new hypothesis or update the status of an existing hypothesis (e.g. OPEN, TESTING, SUPPORTED, REFUTED, CONFIRMED).",
                "parameters": [
                    {
                        "name": "id",
                        "type": "string",
                        "description": "Hypothesis ID (leave blank to create new)",
                    },
                    {
                        "name": "statement",
                        "type": "string",
                        "description": "What you are hypothesizing",
                    },
                    {
                        "name": "status",
                        "type": "string",
                        "description": "HypothesisStatus (OPEN, TESTING, SUPPORTED, REFUTED, CONFIRMED, ABANDONED)",
                    },
                    {
                        "name": "confidence",
                        "type": "number",
                        "description": "0.0 to 1.0 confidence score",
                    },
                ],
            },
            {
                "server": "internal",
                "name": "store_asset",
                "description": "Store a discovered asset (e.g., domain, IP) into the knowledge graph.",
                "parameters": [
                    {
                        "name": "type",
                        "type": "string",
                        "description": "Asset type (e.g. 'domain', 'ip')",
                    },
                    {
                        "name": "value",
                        "type": "string",
                        "description": "The asset value (e.g. 'example.com')",
                    },
                ],
            },
            {
                "server": "internal",
                "name": "store_endpoint",
                "description": "Store a discovered API or web endpoint into the knowledge graph.",
                "parameters": [
                    {
                        "name": "url",
                        "type": "string",
                        "description": "The full URL of the endpoint",
                    },
                    {
                        "name": "method",
                        "type": "string",
                        "description": "HTTP method (e.g. 'GET', 'POST')",
                    },
                    {
                        "name": "parameters",
                        "type": "array",
                        "description": "List of parameter names discovered",
                    },
                ],
            },
            {
                "server": "internal",
                "name": "propose_vulnerability",
                "description": "Propose a candidate vulnerability to be validated by the system. Do NOT assume it is confirmed until validated.",
                "parameters": [
                    {
                        "name": "title",
                        "type": "string",
                        "description": "Title of the vulnerability",
                    },
                    {
                        "name": "severity",
                        "type": "string",
                        "description": "Severity (low, medium, high, critical)",
                    },
                    {
                        "name": "target",
                        "type": "string",
                        "description": "The affected URL or asset value",
                    },
                    {
                        "name": "hypothesis_id",
                        "type": "string",
                        "description": "The hypothesis ID this vulnerability validates",
                    },
                ],
            },
        ]
        all_tools = tools + internal_tools

        prompt = (
            "You are an autonomous AI cybersecurity agent executing a task.\n"
            "You operate in a loop: Observe State -> Form Hypothesis -> Choose Tool -> Validate.\n\n"
            "CURRENT STATE:\n"
            f"{json.dumps(context, indent=2, default=str)}\n\n"
            "AVAILABLE TOOLS:\n"
            f"{json.dumps(all_tools, indent=2, default=str)}\n\n"
            "INSTRUCTIONS:\n"
            "Based on the current state and task payload, what is your next action?\n"
            "You must return ONLY a JSON object with one of two shapes:\n"
            "1. To use a tool:\n"
            "   {\n"
            '     "action": "tool",\n'
            '     "reasoning": {\n'
            '       "observation": "What did you just observe?",\n'
            '       "hypothesis_id": "ID of hypothesis (if applicable)",\n'
            '       "confidence": 0.8,\n'
            '       "alternatives_considered": ["list of other tools you could have run"],\n'
            '       "expected_information_gain": "What you expect this tool to return",\n'
            '       "why_chosen": "Why this tool is the best next step"\n'
            "     },\n"
            '     "tool_call": {\n'
            '       "server": "server_id",\n'
            '       "name": "tool_name",\n'
            '       "parameters": { ... }\n'
            "     }\n"
            "   }\n"
            "2. If the task objective is completely met or you are stuck:\n"
            "   {\n"
            '     "action": "complete",\n'
            '     "reasoning": { "why_chosen": "Reasoning for stopping" },\n'
            '     "conclusion": "Summary of findings."\n'
            "   }\n"
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "CRITICAL RULE: You MUST output ONLY a raw JSON object. "
                    "Start your entire response with { and end with }. "
                    "No markdown fences, no explanation, no text before or after the JSON. "
                    "If you write anything other than a JSON object, the system will crash."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        if hasattr(self.ctx.llm_client, "complete"):
            # --- Attempt 1: normal call with JSON mode hint ---
            try:
                result = await self.ctx.llm_client.complete(
                    messages, max_tokens=1500, response_format={"type": "json_object"}
                )
                content = result.get("content", "") if isinstance(result, dict) else str(result)
                agent_logger.info(
                    "llm_raw_output",
                    agent_id=self.ctx.agent_id,
                    content_len=len(content),
                    first_200=content[:200],
                    last_100=content[-100:] if len(content) > 100 else content,
                )
                return self._parse_json_action(content)
            except Exception as first_err:
                # --- Attempt 2: retry with a strict JSON-only system prompt ---
                try:
                    strict_messages = [
                        {
                            "role": "system",
                            "content": (
                                "CRITICAL: You must output ONLY a valid JSON object. "
                                "No markdown, no fences, no explanation, no text before or after. "
                                "Just the raw JSON starting with { and ending with }."
                            ),
                        },
                        messages[-1],  # keep the user prompt
                    ]
                    result2 = await self.ctx.llm_client.complete(
                        strict_messages, max_tokens=1500, response_format={"type": "json_object"}
                    )
                    content2 = result2.get("content", "") if isinstance(result2, dict) else str(result2)
                    return self._parse_json_action(content2)
                except Exception as second_err:
                    # Both attempts failed — report as FAILED so the scheduler retries
                    agent_logger.warning(
                        "llm_json_parse_failed_both_attempts",
                        agent_id=self.ctx.agent_id,
                        first_error=str(first_err),
                        second_error=str(second_err),
                    )
                    return {
                        "status": "failed",
                        "action": "failed",
                        "conclusion": "LLM could not produce valid JSON.",
                        "error": str(second_err),
                    }

        return {"action": "complete", "conclusion": "No LLM client available."}

    @staticmethod
    def _parse_json_action(raw: str) -> Dict[str, Any]:
        """Extract a JSON action object from raw LLM output.

        Handles: bare JSON, markdown-fenced JSON, JSON embedded in prose,
        and models that prepend/append explanation text.
        Returns the parsed dict or raises ValueError on total failure.
        """
        import re as _re

        stripped = (raw or "").strip()
        if not stripped:
            raise ValueError("empty LLM output")

        # 1. Try bare parse first
        try:
            return json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            pass

        # 2. Strip markdown fences: ```json ... ``` or ``` ... ```
        m = _re.search(r"```(?:json)?\s*(.*?)\s*```", stripped, _re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1).strip())
            except (json.JSONDecodeError, ValueError):
                pass

        # 3. Find the first balanced JSON object { ... }
        start = stripped.find("{")
        if start >= 0:
            depth = 0
            for i in range(start, len(stripped)):
                if stripped[i] == "{":
                    depth += 1
                elif stripped[i] == "}":
                    depth -= 1
                if depth == 0:
                    candidate = stripped[start : i + 1]
                    try:
                        return json.loads(candidate)
                    except (json.JSONDecodeError, ValueError):
                        break

        # 4. Aggressive regex: find ANY {...} that looks like action/tool_call
        #    This catches cases where the model mixes prose with JSON.
        for m in _re.finditer(r'\{[^{}]*"action"[^{}]*\}', stripped):
            try:
                return json.loads(m.group())
            except (json.JSONDecodeError, ValueError):
                continue
        for m in _re.finditer(r'\{[^{}]*"tool_call"[^{}]*\}', stripped):
            try:
                return json.loads(m.group())
            except (json.JSONDecodeError, ValueError):
                continue
        # Last resort: find any {...} with "action" or "status" key
        for m in _re.finditer(r'\{[^{}]{10,}\}', stripped):
            candidate = m.group()
            if '"action"' in candidate or '"status"' in candidate:
                try:
                    return json.loads(candidate)
                except (json.JSONDecodeError, ValueError):
                    continue

        # 5. Find the first balanced JSON array [ ... ] (tool results sometimes)
        start = stripped.find("[")
        if start >= 0:
            depth = 0
            for i in range(start, len(stripped)):
                if stripped[i] == "[":
                    depth += 1
                elif stripped[i] == "]":
                    depth -= 1
                if depth == 0:
                    candidate = stripped[start : i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            return parsed
                    except (json.JSONDecodeError, ValueError):
                        break

        raise ValueError(f"no valid JSON found in LLM output ({len(stripped)} chars)")

    async def _validate_task(self, task: Task) -> None:
        """Validate task before execution.

        FIX (validate-task-stub-2026-08-24): this method was a literal `pass`
        stub — the `task.scope_check` flag flowed through the entire pipeline
        (models -> scheduler -> agent) and enforced NOTHING, and dependency
        validation never ran, so tasks could execute with failed/missing
        prerequisites. Both checks are now real and fail loudly:
          * scope_check=True requires a scope bound on the AgentContext
          * every dependency must exist and be status="completed"
        Raises AgentTaskFailed so the orchestrator records the failure
        instead of silently proceeding.
        """
        from ai_osop.core.exceptions import AgentTaskFailed

        # 1. Scope gate: active-work flag demands an authorized engagement scope.
        # FIX (validate-task-scope-source-2026-08-24): the authoritative scope is
        # the ENGAGEMENT SESSION's ScopeDefinition, not AgentContext.scope —
        # long-lived shared agents keep ctx.scope=None by design ("no override"),
        # which made this check reject every legitimately scoped task.
        if task.scope_check:
            session = await self.ctx.session_memory.load_session_state(task.engagement_id)
            scope = getattr(session, "scope", None) if session is not None else None
            if scope is None:
                raise AgentTaskFailed(
                    f"Task {task.id} ({task.type}) sets scope_check but engagement "
                    f"'{task.engagement_id}' has no authorized ScopeDefinition bound; "
                    f"refusing to run."
                )

        # 2. Dependency gate: all prerequisites must be completed.
        for dep_id in task.dependencies or []:
            dep = await self.ctx.session_memory.load_task(dep_id)
            if dep is None:
                raise AgentTaskFailed(f"Task {task.id} depends on {dep_id} which does not exist")
            if dep.status != "completed":
                raise AgentTaskFailed(
                    f"Task {task.id} depends on {dep_id} whose status is "
                    f"'{dep.status}' (expected 'completed')"
                )

    async def _validate_output(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate agent output against schema and detect hallucinations.

        Validates:
          1. Required keys (status) exist and have valid values.
          2. Numeric fields (confidence, evScore) are within [0.0, 1.0].
          3. Hallucinated tool/server names not in the live MCP registry.
          4. Finding titles contain only ASCII-printable characters (flags likely
             LLM fabrications with unicode tricks).
        """
        if not isinstance(result, dict):
            agent_logger.warning(
                "output_validation_failed_not_dict",
                agent_id=self.ctx.agent_id,
                result_type=type(result).__name__,
            )
            return {"status": "error", "error": "Agent returned non-dict output"}

        # 1. Schema: status must be a known terminal value
        VALID_STATUSES = {"success", "failed", "error", "partial", "timeout"}
        status = result.get("status")
        if status not in VALID_STATUSES:
            agent_logger.warning(
                "output_validation_bad_status",
                agent_id=self.ctx.agent_id,
                status=status,
            )
            result["status"] = "failed"
            result["error"] = f"Invalid status: {status}"

        # 2. Confidence / score range check
        for field in ("confidence", "evScore", "cvss_score"):
            val = result.get(field)
            if val is not None:
                try:
                    fval = float(val)
                    if not (0.0 <= fval <= 1.0) and field != "cvss_score":
                        agent_logger.warning(
                            "output_validation_score_out_of_range",
                            agent_id=self.ctx.agent_id,
                            field=field,
                            value=fval,
                        )
                        result[field] = max(0.0, min(1.0, fval))
                except (TypeError, ValueError):
                    pass

        # 3. Hallucination detection: check tool names against live registry
        tool_call = result.get("tool_call")
        if tool_call and isinstance(tool_call, dict):
            server_id = tool_call.get("server")
            tool_name = tool_call.get("name")
            if server_id and server_id != "internal":
                known_servers = set(self.ctx.mcp_registry._servers.keys()) if hasattr(self.ctx.mcp_registry, "_servers") else set()
                if known_servers and server_id not in known_servers:
                    agent_logger.warning(
                        "output_validation_hallucinated_server",
                        agent_id=self.ctx.agent_id,
                        server=server_id,
                        known=list(known_servers),
                    )
                    result["status"] = "failed"
                    result["error"] = f"Hallucinated MCP server: {server_id}"

        # 4. Finding-level validation (for results containing findings list)
        findings = result.get("findings") or result.get("vulnerabilities")
        if isinstance(findings, list):
            validated_findings = []
            for f in findings:
                if not isinstance(f, dict):
                    continue
                title = f.get("title", "")
                # Flag non-ASCII titles (likely LLM fabrications)
                if title and not all(ord(c) < 128 for c in title):
                    agent_logger.warning(
                        "output_validation_non_ascii_finding",
                        agent_id=self.ctx.agent_id,
                        title=title[:100],
                    )
                    f["confidence"] = min(float(f.get("confidence", 0.5)), 0.3)
                validated_findings.append(f)
            if "findings" in result:
                result["findings"] = validated_findings
            elif "vulnerabilities" in result:
                result["vulnerabilities"] = validated_findings

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

    async def _auto_extract_assets_from_result(
        self, engagement_id: str, tool_name: str, obs_data: Any, task: Task
    ) -> None:
        """Parse tool results and auto-store Assets/Endpoints in the graph.

        This ensures the vulnerability_discovery phase has data to scan even
        when the recon agent doesn't explicitly call store_asset/store_endpoint.
        Handles: subfinder, httpx, nuclei, and generic tool outputs.
        """
        import re as _re

        text = json.dumps(obs_data, default=str) if not isinstance(obs_data, str) else obs_data
        if not text or len(text) < 10:
            return

        domain = (
            task.payload.get("domain")
            or task.payload.get("target")
            or task.payload.get("url")
            or "unknown"
        )
        sid = engagement_id

        # Extract domains from subfinder/enum results
        domain_pattern = _re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)')
        found_domains = set()
        for match in domain_pattern.finditer(text):
            d = match.group(1)
            # Filter out common false positives
            if not any(fp in d for fp in ('.json', '.xml', '.txt', '.log', '.css', '.js', 'example.com', 'localhost')):
                found_domains.add(d)

        for d in list(found_domains)[:20]:  # cap at 20
            try:
                await self.ctx.graph_memory.run_write_query(
                    """MERGE (a:Asset {value: $value, engagement_id: $sid})
                       SET a.type = 'domain', a.source = $tool,
                           a.discovered_at = datetime()""",
                    {"value": d, "sid": sid, "tool": tool_name},
                )
            except Exception:
                pass

        # Extract URLs/endpoints from httpx/nuclei results
        url_pattern = _re.compile(r'(https?://[a-zA-Z0-9._\-:/]+[a-zA-Z0-9/\-_.?=&#]*)')
        found_urls = set()
        for match in url_pattern.finditer(text):
            u = match.group(1)
            if len(u) < 200:  # skip overly long URLs
                found_urls.add(u)

        for u in list(found_urls)[:30]:  # cap at 30
            try:
                await self.ctx.graph_memory.run_write_query(
                    """MERGE (e:Endpoint {url: $url, engagement_id: $sid})
                       SET e.method = 'GET', e.status_code = 200,
                           e.source = $tool, e.discovered_at = datetime()""",
                    {"url": u, "sid": sid, "tool": tool_name},
                )
            except Exception:
                pass

        # Extract IPs if present
        ip_pattern = _re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
        found_ips = set(ip_pattern.findall(text))
        for ip in list(found_ips)[:10]:
            try:
                await self.ctx.graph_memory.run_write_query(
                    """MERGE (a:Asset {value: $value, engagement_id: $sid})
                       SET a.type = 'ip', a.source = $tool,
                           a.discovered_at = datetime()""",
                    {"value": ip, "sid": sid, "tool": tool_name},
                )
            except Exception:
                pass

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
        while self._running:
            try:
                self.ctx.last_heartbeat = datetime.utcnow()

                if self.ctx.current_task:
                    self.ctx.current_task.lease_expires = datetime.utcnow() + timedelta(seconds=90)
                    await self.ctx.session_memory.store_task(self.ctx.current_task)

                await self.ctx.session_memory.update_agent_heartbeat(
                    self.ctx.agent_id,
                    {
                        "agent_id": self.ctx.agent_id,
                        "agent_type": str(self.ctx.agent_type),
                        "status": self.ctx.status,
                        "task_id": self.ctx.current_task.id if self.ctx.current_task else None,
                        "engagement_id": self.ctx.session_id,
                        "version": "8.0",
                        "pid": os.getpid(),
                        # socket.gethostname() is cross-platform; os.uname() does
                        # not exist on Windows and previously killed this loop on
                        # the first iteration, freezing all heartbeats.
                        "hostname": socket.gethostname(),
                    },
                )
            except (asyncio.CancelledError, GeneratorExit):
                break
            except RuntimeError as e:
                # AIOSOP-LIFECYCLE-001: expected during interpreter/event-loop teardown
                # (agent started without a matching shutdown()); exit quietly.
                if "Event loop is closed" in str(e) or "no running event loop" in str(e):
                    break
                agent_logger.warning(
                    "heartbeat_loop_error", agent_id=self.ctx.agent_id, error=str(e)
                )
            except Exception as e:
                # One bad iteration must never permanently stop heartbeats.
                agent_logger.warning(
                    "heartbeat_loop_error", agent_id=self.ctx.agent_id, error=str(e)
                )
            try:
                await asyncio.sleep(5)
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

        from ai_osop.core.config import settings

        try:
            await asyncio.wait_for(
                self._cleanup_resources(),
                timeout=settings.agent_cleanup_timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "agent_cleanup_timed_out",
                agent_id=self.ctx.agent_id,
                timeout_seconds=settings.agent_cleanup_timeout_seconds,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.warning("cleanup_resources_error", agent_id=self.ctx.agent_id, error=str(e))

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
            "cost_incurred": getattr(self, "cost_incurred", 0.0),
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
