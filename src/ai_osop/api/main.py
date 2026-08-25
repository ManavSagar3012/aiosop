"""AI-OSOP API Gateway
FastAPI-based REST API for operator interaction, agent management,
and engagement control.

REFACTOR (2026-06-19): Decomposed from 1,539-line monolith into router modules:
  routers/engagements.py  — engagement lifecycle
  routers/tasks.py        — task creation & status
  routers/agents.py       — agent listing & status
  routers/approvals.py    — approval workflow
  routers/sessions.py     — user session CRUD
  routers/findings.py     — findings, diff-auth, evidence vault
  routers/intelligence.py — attack graph, paths, education
  routers/system.py       — health, config, sandbox status
"""

import asyncio
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter
from ai_osop.api.deps import require_role, state  # verify_token imported at WS section below (F811 fix)
from ai_osop.api.health import router as health_router
from ai_osop.api.health import run_startup_self_test

# Router imports
from ai_osop.api.routers import (
    agents,
    approvals,
    dlq,
    engagements,
    findings,
    intelligence,
    sessions,
    system,
    tasks,
)
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import settings
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.metrics import BUILD_INFO, ERRORS_TOTAL, REQUEST_DURATION, REQUESTS_TOTAL
from ai_osop.core.observability import render_prometheus
from ai_osop.core.tracing import init_tracing, trace_span
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.vector_memory import VectorMemory
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.safety.rate_limiter import RateLimiter
from ai_osop.safety.scope import SandboxManager

# ============== Global State ==============

# NOTE: Pydantic models, auth deps, and shared singletons live in api/deps.py
# so routers can import them without circular imports.


# ============== MCP Server Registration ==============


logger = logging.getLogger("ai_osop.api")


from ai_osop.reliability.retry import retry_with_backoff

logger = logging.getLogger("ai_osop.api")


async def connect_with_retry(
    connector,
    name: str,
    max_retries: int = 10,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> bool:
    """Connect to a dependency with exponential backoff.

    Sprint 8: Delegates to the shared retry_with_backoff utility to eliminate
    code duplication and ensure consistent retry behavior across the platform.
    """
    try:
        await retry_with_backoff(
            connector,
            max_retries=max_retries,
            base_delay=base_delay,
            max_delay=max_delay,
            retry_name=f"{name}.connect",
        )
        logger.info(f"{name} connected successfully")
        return True
    except Exception as e:
        logger.critical(f"{name} unavailable after {max_retries + 1} attempts: {e}")
        return False


async def register_optional_mcp_servers(mcp_registry: MCPRegistry) -> None:
    """Register configured MCP servers without blocking API startup if absent."""
    servers = [
        ("burp-mcp", settings.burp_mcp_host, settings.burp_mcp_port, settings.burp_api_key),
        ("recon-mcp", settings.recon_mcp_host, settings.recon_mcp_port, None),
        ("payload-mcp", settings.payload_mcp_host, settings.payload_mcp_port, None),
        ("nuclei-mcp", settings.nuclei_mcp_host, settings.nuclei_mcp_port, None),
        ("shodan-mcp", settings.shodan_mcp_host, settings.shodan_mcp_port, settings.shodan_api_key),
        ("browser-mcp", settings.browser_mcp_host, settings.browser_mcp_port, None),
        ("security-bridge", settings.security_bridge_host, settings.security_bridge_port, None),
        ("threat-intel-mcp", settings.threat_intel_mcp_host, settings.threat_intel_mcp_port, None),
        ("cloud-mcp", settings.cloud_mcp_host, settings.cloud_mcp_port, None),
        (
            "turbo-intruder-mcp",
            settings.turbo_intruder_mcp_host,
            settings.turbo_intruder_mcp_port,
            None,
        ),
    ]
    # Critical MCPs whose ABSENCE is logged loudly. NOTE: this set only governs
    # log severity on failure — it must NOT gate whether a server is initialized.
    # (AIOSOP-RECON-PERSIST-2026-06-24)
    critical_mcps = {
        "recon-mcp",
        "nuclei-mcp",
        "burp-mcp",
        "browser-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
    }
    import logging

    mcp_log = logging.getLogger("ai_osop.mcp")

    async def init_server(server_id, host, port, token, is_critical):
        try:
            # connect_retries=0: single fast attempt at startup so unreachable
            # optional servers don't block boot ~31s each. Adapters lazily
            # reconnect (with full retries) on first real use.
            await mcp_registry.register_server(server_id, host, port, token, connect_retries=0)
            await mcp_registry.initialize_server(
                server_id,
                scope={},
                credentials={},
                session_id="api-bootstrap",
            )
            mcp_log.info(f"MCP server {server_id} registered and initialized.")
        except Exception as exc:
            (mcp_log.critical if is_critical else mcp_log.warning)(
                f"MCP server {server_id} at {host}:{port} registration/init failed: {exc}"
            )

    tasks = [init_server(s, h, p, t, s in critical_mcps) for s, h, p, t in servers]
    await asyncio.gather(*tasks)


# ============== Lifespan ==============


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    import logging

    logger = logging.getLogger("ai_osop.api")

    # AIOSOP-LOGCFG-001: wire OSOP_LOG_LEVEL into structlog so DEBUG is actually
    # suppressible (structlog was unconfigured -> no level filtering). Format preserved.
    from ai_osop.core.telemetry import configure_log_level

    configure_log_level()

    # 0. Fail closed on insecure secrets before doing anything else (OSOP-P2-11/P0-03).
    from ai_osop.core.config import assert_production_secrets

    assert_production_secrets()

    # Startup
    health_status = {
        "redis": "unknown",
        "neo4j": "unknown",
        "browser-mcp": "unknown",
        "security-bridge": "unknown",
        "payload-mcp": "unknown",
        "nuclei-mcp": "unknown",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }

    # 0. OpenTelemetry tracing
    init_tracing()

    # 0a. Sentry — only when SENTRY_DSN is set and not in development
    if settings.sentry_dsn and settings.environment.lower() not in (
        "development",
        "dev",
        "local",
        "test",
    ):
        import sentry_sdk

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.environment,
            traces_sample_rate=settings.sentry_traces_sample_rate,
            profiles_sample_rate=settings.sentry_profiles_sample_rate,
        )
        logger.info(f"Sentry SDK initialized environment={settings.environment}")
    else:
        logger.info("Sentry SDK disabled (no SENTRY_DSN or development environment)")

    with trace_span("api.startup", attributes={"version": "1.0.0"}):
        session_memory = SessionMemory()
        graph_memory = GraphMemory()
        vector_memory = VectorMemory(settings.postgres_uri)
        mcp_registry = MCPRegistry()
        rate_limiter = RateLimiter()
        threat_intel_adapter = ThreatIntelAdapter()

        # 1. Redis (critical)
        redis_ok = await connect_with_retry(session_memory.connect, "redis", max_retries=10)
        if redis_ok:
            try:
                await session_memory._redis.ping()
                health_status["redis"] = "healthy"
            except Exception as e:
                health_status["redis"] = f"unhealthy: {e}"
                logger.warning(f"Redis ping failed: {e}")
        else:
            health_status["redis"] = "unhealthy: exhausted retries"
            logger.critical("Redis unavailable after retries — proceeding in degraded mode")

        # 2. Neo4j (critical)
        neo4j_ok = await connect_with_retry(graph_memory.connect, "neo4j", max_retries=10)
        if neo4j_ok:
            health_status["neo4j"] = "healthy"
        else:
            health_status["neo4j"] = "unhealthy: exhausted retries"
            logger.critical("Neo4j unavailable after retries — proceeding in degraded mode")

        # 3. Vector Memory (pgvector)
        try:
            await vector_memory.connect()
        except Exception as e:
            logger.warning(f"Vector memory initialization failed: {e}")

        # 4. MCP Servers
        await register_optional_mcp_servers(mcp_registry)

        # 5. Build Orchestrator
        llm_client = LiteLLMClient()

        # FIX (bus-connect-2026-08-23): the DistributedCoordinationBus was NEVER
        # connected at startup. get_coordination_bus() handed the orchestrator an
        # unconnected singleton (_running=False, redis=None), so every publish()
        # silently fell back to a process-local queue and subscribe() returned
        # immediately — the Redis Streams backbone, event replay, and the
        # dashboard's live swarm feed were all dead code at runtime. Connect the
        # bus here so publish/subscribe actually hit Redis.
        try:
            from ai_osop.orchestrator.distributed_bus import initialize_bus

            await initialize_bus(settings.redis_uri, engagement_id="default")
            logger.info("DistributedCoordinationBus connected.")
        except Exception as e:  # noqa: BLE001 - bus is resilient to being down
            logger.warning(f"DistributedCoordinationBus connect failed (local fallback): {e}")

        # AIOSOP-LLM-WARM-001: pre-load the chat models in the background so the first
        # real agent think() hits an already-resident model instead of a ~60s cold
        # load (which otherwise blew the completion timeout -> degraded reasoning).
        # Fire-and-forget: never blocks startup, and a down provider just no-ops.
        try:
            asyncio.create_task(llm_client.warm_up())
        except Exception as _e:  # noqa: BLE001
            logger.warning(f"llm warm-up scheduling failed (non-fatal): {_e}")

        # P2 learning brain: wire semantic findings memory so every real
        # persisted vulnerability auto-populates the knowledge base and can be
        # recalled on future engagements. Best-effort — never blocks startup.
        try:
            from ai_osop.core.findings_knowledge import FindingsKnowledge, VectorMemoryFindingsStore

            graph_memory.findings_knowledge = FindingsKnowledge(
                embed_fn=llm_client.get_embedding,
                store=VectorMemoryFindingsStore(vector_memory),
            )
            logger.info("Findings knowledge base wired to graph memory.")
        except Exception as e:  # noqa: BLE001 - learning brain is optional
            logger.warning(f"Findings knowledge wiring failed: {e}")

        # Chain-first loop: wire the primitive ledger so every confirmed finding is
        # also recorded as a typed primitive for the escalation/chain engine.
        # Best-effort — never blocks startup.
        try:
            from ai_osop.memory.primitive_ledger import PrimitiveLedgerStore

            if getattr(graph_memory, "_driver", None) is not None:
                _ledger = PrimitiveLedgerStore(graph_memory._driver)
                await _ledger.setup_schema()
                graph_memory.primitive_ledger = _ledger
                logger.info("Primitive ledger wired to graph memory.")
        except Exception as e:  # noqa: BLE001 - chain loop is optional
            logger.warning(f"Primitive ledger wiring failed: {e}")

        orch = Orchestrator(
            session_memory=session_memory,
            graph_memory=graph_memory,
            mcp_registry=mcp_registry,
            llm_client=llm_client,
        )

        # Reliability sprint: Run self-test after orchestrator initialization
        startup_results = await run_startup_self_test()
        if startup_results["status"] != "healthy":
            logger.critical(f"Startup self-test failed: {startup_results}")
            raise RuntimeError("Startup self-test failed — critical dependency unavailable")

        # 6. Session Store (user sessions for DiffAuth)
        try:
            _session_store_ref = SessionStore(session_memory)
            state["session_store"] = _session_store_ref
        except Exception as e:
            logger.warning(f"SessionStore initialization failed: {e}")

        # 7. Skill Engine
        try:
            import ai_osop.agents as _agents_pkg
            from ai_osop.core.skill_engine import SkillEngine

            skills_dir = os.path.join(os.path.dirname(_agents_pkg.__file__), "skills")
            _skill_engine_ref = SkillEngine(skills_dir, llm_client=llm_client)
            state["skill_engine"] = _skill_engine_ref
            logger.info(
                "SkillEngine initialized",
            )
        except Exception as e:
            logger.warning(f"SkillEngine initialization failed: {e}")

        # 8. Sandbox Manager
        try:
            sandbox_manager = SandboxManager()
            state["sandbox_manager"] = sandbox_manager
            logger.info("SandboxManager initialized.")
        except Exception as e:
            logger.warning(f"SandboxManager initialization failed: {e}")

        # 9. Register Agents
        try:
            await orch.initialize()

            # Instantiate and register the 11 core agents + 9 experimental agents
            from ai_osop.agents.attack_chain_agent import AttackChainAgent
            from ai_osop.agents.base import AgentContext
            from ai_osop.agents.cloud_agent import CloudSpecialistAgent
            from ai_osop.agents.codeql_agent import CodeQLAgent
            from ai_osop.agents.concurrency_agent import ConcurrencyAgent
            from ai_osop.agents.context_manager_agent import ContextManagerAgent
            from ai_osop.agents.exploit_agent import ExploitValidationAgent
            from ai_osop.agents.graphql_agent import GraphQLAgent
            from ai_osop.agents.human_oversight_agent import HumanOversightAgent
            from ai_osop.agents.js_analyzer_agent import JSAnalyzerAgent
            from ai_osop.agents.mobile_agent import MobileAnalysisAgent
            from ai_osop.agents.nextjs_agent import NextJSSpecialistAgent
            from ai_osop.agents.payload_agent import PayloadMutationAgent
            from ai_osop.agents.react_agent import ReactSpecialistAgent
            from ai_osop.agents.recon_agent import ReconAgent
            from ai_osop.agents.reporting_agent import ReportingAgent
            from ai_osop.agents.stack_profiler_agent import StackProfilerAgent
            from ai_osop.agents.service_agent import ServiceAssessmentAgent
            from ai_osop.agents.stateful_logic_agent import StatefulLogicAgent
            from ai_osop.agents.visual_agent import VisualContextAgent
            from ai_osop.agents.vuln_agent import VulnAnalysisAgent
            from ai_osop.agents.workflow_agent import PlaywrightAgent
            from ai_osop.core.config import AgentType

            bootstrap_session_id = "api-bootstrap"
            agents_to_register = [
                (AttackChainAgent, AgentType.ATTACK_CHAIN, "attack-chain-agent-001"),
                (ReconAgent, AgentType.RECON, "recon-agent-001"),
                # TOOL-REALITY Tier-1 service specialist (TLS/SSH probes)
                (ServiceAssessmentAgent, AgentType.RECON, "service-agent-001"),
                (VulnAnalysisAgent, AgentType.VULN_ANALYSIS, "vuln-agent-001"),
                (
                    VulnAnalysisAgent,
                    AgentType.VULN_ANALYSIS,
                    "vuln-agent-002",
                ),  # Second worker to prevent nuclei scan queueing
                (HumanOversightAgent, AgentType.HUMAN_OVERSIGHT, "human-oversight-agent-001"),
                (ExploitValidationAgent, AgentType.EXPLOIT_VALIDATION, "exploit-agent-001"),
                (PayloadMutationAgent, AgentType.PAYLOAD_MUTATION, "payload-agent-001"),
                (ReportingAgent, AgentType.REPORTING, "reporting-agent-001"),
                (ContextManagerAgent, AgentType.CONTEXT_MANAGER, "context-manager-agent-001"),
                (ConcurrencyAgent, AgentType.CONCURRENCY, "concurrency-agent-001"),
                (StackProfilerAgent, AgentType.CONTEXT_MANAGER, "stack-profiler-agent-001"),
                (PlaywrightAgent, AgentType.WORKFLOW, "playwright-agent-001"),
                (CloudSpecialistAgent, AgentType.CLOUD_SPECIALIST, "cloud-agent-001"),
                (CodeQLAgent, AgentType.SAST_ANALYSIS, "codeql-agent-001"),
                (GraphQLAgent, AgentType.VULN_ANALYSIS, "graphql-agent-001"),
                (JSAnalyzerAgent, AgentType.VULN_ANALYSIS, "js-analyzer-agent-001"),
                (MobileAnalysisAgent, AgentType.VULN_ANALYSIS, "mobile-agent-001"),
                (NextJSSpecialistAgent, AgentType.NEXTJS_SPECIALIST, "nextjs-agent-001"),
                (ReactSpecialistAgent, AgentType.REACT_SPECIALIST, "react-agent-001"),
                (StatefulLogicAgent, AgentType.STATEFUL_LOGIC, "stateful-logic-agent-001"),
                (VisualContextAgent, AgentType.VISUAL_CONTEXT, "visual-agent-001"),
            ]

            for agent_cls, agent_type, agent_id in agents_to_register:
                ctx = AgentContext(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    session_id=bootstrap_session_id,
                    session_memory=session_memory,
                    graph_memory=graph_memory,
                    vector_memory=vector_memory,
                    llm_client=llm_client,
                    mcp_registry=mcp_registry,
                    rate_limiter=rate_limiter,
                    threat_intel_adapter=threat_intel_adapter,
                    audit_callback=orch._audit_log,
                    coordination_bus=orch.coordination_bus,
                )
                ctx.skill_engine = state.get("skill_engine")
                agent_inst = agent_cls(ctx)
                await orch.register_agent(agent_inst)
        except Exception as e:
            logger.error(f"Orchestrator initialization/agent registration failed: {e}")

        # 10. Bind to shared state dict so routers see the live values
        logger.info(
            "ORCHESTRATOR BIND: orch=%s id=%s state_before=%s",
            type(orch).__name__,
            id(orch),
            state.get("orchestrator") is not None,
        )
        state["orchestrator"] = orch
        logger.info("ORCHESTRATOR BOUND: state_orch=%s", state["orchestrator"] is not None)

        # 11. Set build info for metrics
        BUILD_INFO.info({"version": "3.0", "git_sha": "2bb4379"})

        # 12. Start auto-dispatch loop — ensures queued tasks get assigned to
        # idle agents without requiring a separate orchestrator CLI process.
        async def _auto_dispatch_loop() -> None:
            """Background loop that polls task queues and dispatches to agents.

            The orchestrator's _scheduler_loop already does this, but tasks
            scheduled via the REST API sometimes land in the Redis queue before
            the scheduler tick picks them up. This loop acts as a safety net:
            it runs every 3 seconds, drains pending tasks from all active
            engagement queues, and calls _assign_task for each.

            It also recovers stale agent locks — if an agent's status is
            "running" but has no current task, it gets reset to "idle" so
            the dispatcher can claim it for new work.
            """
            _logger = logging.getLogger("ai_osop.api.dispatch")
            _logger.info("auto_dispatch_loop started")
            tick = 0
            while True:
                try:
                    await asyncio.sleep(3)
                    tick += 1
                    orch_ref = state.get("orchestrator")
                    if orch_ref is None or not getattr(orch_ref, "_running", False):
                        continue

                    # 0. Recover stale agent locks — agents stuck "running" with
                    #    no current task get reset to "idle" so they can be claimed.
                    for agent in list(orch_ref._agents.values()):
                        if agent.ctx.status == "running":
                            has_task = any(
                                t.status == "running" and t.assigned_agent_id == agent.ctx.agent_id
                                for t in orch_ref.state.get_all_tasks().values()
                            )
                            if not has_task:
                                agent.ctx.status = "idle"
                                await orch_ref.session_memory.remove_busy_agent(
                                    agent.ctx.agent_id
                                )
                                lock_key = f"lock:agent:{agent.ctx.agent_id}"
                                await orch_ref.session_memory.release_lock(
                                    lock_key, "locked"
                                )
                                _logger.info(
                                    "auto_dispatch: recovered stale agent %s",
                                    agent.ctx.agent_id,
                                )

                    # 1. Pick up pending in-memory tasks that the scheduler missed
                    dispatched = 0
                    for task in list(orch_ref.state.get_all_tasks().values()):
                        if task.status == "pending":
                            try:
                                await orch_ref.task_scheduler._assign_task(task)
                                dispatched += 1
                            except Exception as dispatch_err:
                                _logger.warning(
                                    "auto_dispatch: failed to dispatch %s: %s",
                                    task.id,
                                    dispatch_err,
                                )
                    if dispatched > 0 and tick % 5 == 1:
                        _logger.info("auto_dispatch: dispatched %d tasks this cycle", dispatched)

                    # 2. Drain Redis queues for active engagements
                    for sid, session in list(orch_ref._sessions.items()):
                        if getattr(session, "phase", "") == "halted":
                            continue
                        try:
                            while True:
                                task_data = (
                                    await orch_ref.session_memory.pop_task_queue(
                                        f"tasks:{session.session_id}"
                                    )
                                )
                                if not task_data:
                                    break
                                from ai_osop.core.models import Task

                                task = Task(**task_data)
                                if orch_ref.state.get_task(task.id):
                                    existing = orch_ref.state.get_task(task.id)
                                    if existing.status in (
                                        "running",
                                        "completed",
                                        "failed",
                                        "blocked",
                                    ):
                                        continue
                                orch_ref.state.add_task(task)
                                await orch_ref.task_scheduler.ingest_queued_task(task)
                                _logger.info(
                                    "auto_dispatch: ingested queued task %s type=%s",
                                    task.id,
                                    task.type,
                                )
                        except Exception as drain_err:
                            _logger.warning(
                                "auto_dispatch: queue drain error for %s: %s",
                                sid,
                                drain_err,
                            )

                except asyncio.CancelledError:
                    break
                except Exception as loop_err:
                    logging.getLogger("ai_osop.api.dispatch").error(
                        "auto_dispatch_loop error: %s", loop_err
                    )
                    await asyncio.sleep(10)

        _dispatch_task = asyncio.create_task(_auto_dispatch_loop())

    logger.info("AI-OSOP API startup complete.")
    yield

    # Shutdown
    logger.info("AI-OSOP API shutting down...")
    await orch.shutdown()
    await vector_memory.close()
    await mcp_registry.close_all()


# ============== FastAPI App ==============


app = FastAPI(
    title="AI-OSOP API",
    description="AI Offensive Security Orchestration Platform",
    version="1.0.0",
    lifespan=lifespan,
)


# ============== Middleware Stack ==============
#
# FIX (2026-06-28): All custom middlewares use pure ASGI middleware classes
# instead of BaseHTTPMiddleware or @app.middleware("http").
# BaseHTTPMiddleware has a known Starlette 0.37.x bug where nested instances
# cause EndOfStream errors (anyio stream consumed by inner middleware before
# outer can read it). @app.middleware("http") also uses BaseHTTPMiddleware
# internally in Starlette < 0.40.
#
# Pure ASGI middlewares call self.app(scope, receive, send) directly, which
# does NOT use anyio memory streams, so EndOfStream cannot occur.
#
# Middleware order: LAST added/appended = OUTERMOST = first to execute.
#   CatchAllErrorMiddleware       → outermost: catches ALL exceptions ASGI-level
#   correlation_id_middleware     → injects X-Request-ID, RequestContext
#   prometheus_metrics_middleware → request metrics (counts, durations, errors)
#   audit_log_middleware          → audit log for state-changing requests
#   add_security_headers          → adds security headers
#   CORSMiddleware                → CORS headers


class CatchAllErrorMiddleware:
    """Pure ASGI middleware that catches ALL exceptions and returns JSON 500.

    This runs at the ASGI protocol level, BEFORE any Starlette BaseHTTPMiddleware
    stream mechanism. It directly catches exceptions from self.app() and sends
    an error response via the ASGI send interface, bypassing the anyio memory
    stream that causes EndOfStream errors in Starlette 0.37.x.

    Must be the OUTERMOST middleware in the stack.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            await self.app(scope, receive, send)
        except Exception as exc:
            import traceback as _tb

            try:
                _tb_text = _tb.format_exc()
                logger.error("catch_all_error_handler: %s\n%s", exc, _tb_text)
            except Exception:
                pass
            try:
                body = json.dumps(
                    {
                        "detail": f"Internal server error: {type(exc).__name__}: {exc}",
                        "error_type": type(exc).__name__,
                    }
                ).encode("utf-8")
                await send(
                    {
                        "type": "http.response.start",
                        "status": 500,
                        "headers": [
                            (b"content-type", b"application/json"),
                        ],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": body,
                    }
                )
            except Exception:
                pass  # Can't do anything if the connection is already dead


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """
    Inject correlation ID into every request, bind to contextvars, and return in response.

    Converted from BaseHTTPMiddleware to @app.middleware("http") to avoid Starlette's
    EndOfStream bug with nested BaseHTTPMiddleware instances.
    """
    from ai_osop.core.telemetry import RequestContext, extract_trace_id_from_traceparent

    # 1. Extract or generate request ID
    header_id = request.headers.get("X-Request-ID")
    traceparent = request.headers.get("traceparent")
    trace_id = extract_trace_id_from_traceparent(traceparent) if traceparent else None
    if header_id:
        request_id = header_id
    elif trace_id:
        request_id = f"req-{trace_id[:16]}"
    else:
        import uuid

        request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    # 2. Extract user identity from auth if available
    user_id = None
    try:
        operator = request.scope.get("operator", {})
        if isinstance(operator, dict):
            user_id = operator.get("sub")
    except Exception:
        pass

    # 3. Bind to contextvars and create span
    RequestContext.bind(request_id=request_id, user_id=user_id or "anonymous")
    RequestContext.sync_from_otel()

    span_name = f"api.{request.method.lower()}.{request.url.path}"
    try:
        with trace_span(
            span_name,
            attributes={
                "ai_osop.request_id": request_id,
                "http.method": request.method,
                "http.target": request.url.path,
                "http.scheme": request.url.scheme,
                "http.host": request.url.hostname or "",
            },
        ):
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
        return response
    finally:
        RequestContext.clear()


@app.middleware("http")
async def prometheus_metrics_middleware(request: Request, call_next):
    """Track request counts, durations, and errors for Prometheus.

    FIX (2026-06-28): Catch all exceptions, log full traceback, return JSON 500.
    Before this fix, exceptions were re-raised and produced generic "Internal Server Error"
    with no error detail visible to the caller.
    """
    path = request.url.path
    method = request.method
    start = time.time()
    response = None
    try:
        response = await call_next(request)
    except Exception:
        ERRORS_TOTAL.labels(status_code="500", path=path).inc()
        import sys as _sys
        import traceback as _tb

        _tb_content = _tb.format_exc()
        _exc_type = _sys.exc_info()[0].__name__ if _sys.exc_info()[0] else "Exception"
        logger.error("unhandled_500: %s %s\n%s", method, path, _tb_content)
        return JSONResponse(
            status_code=500,
            content={
                "detail": f"Internal server error processing {method} {path}",
                "error_type": _exc_type,
            },
        )
    finally:
        duration = time.time() - start
        REQUEST_DURATION.labels(method=method, path=path).observe(duration)
        status_code = str(response.status_code) if response is not None else "500"
        REQUESTS_TOTAL.labels(method=method, path=path, status_code=status_code).inc()
        if response is not None and response.status_code >= 400:
            ERRORS_TOTAL.labels(status_code=str(response.status_code), path=path).inc()
    return response


@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    """Log all state-changing API requests with operator and engagement context."""
    response = await call_next(request)
    method = request.method
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        request_id = getattr(request.state, "request_id", "unknown")
        op = request.scope.get("operator", {})
        operator_id = op.get("sub", "anonymous") if isinstance(op, dict) else "anonymous"
        # FIX (audit-log-kwargs-2026-08-23): structlog-style kwargs on a stdlib
        # logger raise TypeError once INFO logging is enabled, which surfaced as
        # a 500 from CatchAllErrorMiddleware on EVERY state-changing request even
        # though the route handler had already succeeded. Log plain text instead.
        logger.info(
            f"api_audit method={method} path={request.url.path} "
            f"operator_id={operator_id} status_code={response.status_code} "
            f"user_agent={request.headers.get('user-agent', '')} "
            f"client_ip={request.client.host if request.client else ''} "
            f"request_id={request_id}"
        )
    return response


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Pure ASGI middleware: outermost catch-all error handler (bypasses BaseHTTPMiddleware stream bug)
app.add_middleware(CatchAllErrorMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# Register routers
app.include_router(health_router)
app.include_router(engagements.router)

app.include_router(tasks.router)
app.include_router(agents.router)
app.include_router(approvals.router)
app.include_router(dlq.router)
app.include_router(sessions.router)
app.include_router(findings.router)
app.include_router(intelligence.router)
app.include_router(system.router)


# ============== Metrics (protected) ==============


@app.get("/metrics")
async def metrics(operator: Dict[str, Any] = Depends(require_role("senior_operator"))):
    """Prometheus metrics endpoint."""
    content = render_prometheus()
    return Response(content, media_type=CONTENT_TYPE_LATEST)


# ============== WebSocket (kept inline; needs auth via query param) ==============


from ai_osop.api.deps import assert_engagement_access, verify_token  # noqa: E402


@app.websocket("/ws/engagements/{engagement_id}")
async def websocket_engagement(websocket: WebSocket, engagement_id: str):
    """WebSocket for real-time engagement updates."""
    await websocket.accept()

    # Auth via query parameter
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return

    try:
        operator = await verify_token(token=token)
    except HTTPException:
        await websocket.close(code=1008, reason="Invalid token")
        return

    # Ownership check: operator must own the engagement to receive real-time updates
    try:
        await assert_engagement_access(operator, engagement_id)
    except HTTPException:
        await websocket.close(code=1008, reason="Access denied")
        return

    orch = state["orchestrator"]
    session = orch._sessions.get(engagement_id)
    if not session:
        await websocket.close(code=1008, reason="Engagement not found")
        return

    # AIOSOP-WS-PUSH-001 (2026-07-03): the handler was request-response ONLY, so the
    # dashboard's heartbeat/telemetry (LATENCY / THROUGHPUT) and live phase updates
    # never fired — the client subscribes to pushed events, but the server never sent
    # any (both metrics sat at 0, and the UI only refreshed on navigation). Run a
    # concurrent push loop that emits a heartbeat carrying a REAL backend latency (a
    # Redis PING round-trip) plus a phase_transition event whenever the engagement's
    # phase changes, so the dashboard reflects live progress without a reload.
    import asyncio as _asyncio
    import time as _time

    async def _push_loop() -> None:
        last_phase = None
        while True:
            latency_ms = 0.0
            try:
                _r = getattr(orch.session_memory, "_redis", None)
                if _r is not None:
                    _t0 = _time.monotonic()
                    await _r.ping()
                    latency_ms = round((_time.monotonic() - _t0) * 1000, 2)
            except Exception:  # noqa: BLE001 - telemetry is best-effort
                latency_ms = 0.0
            _sess = orch._sessions.get(engagement_id)
            _phase = _sess.phase if _sess else None
            try:
                await websocket.send_json(
                    {
                        "event_type": "heartbeat",
                        "engagement_id": engagement_id,
                        "data": {"latency_ms": latency_ms},
                    }
                )
                if _phase and _phase != last_phase:
                    last_phase = _phase
                    await websocket.send_json(
                        {
                            "event_type": "phase_transition",
                            "engagement_id": engagement_id,
                            "data": {"phase": _phase, "new_phase": _phase},
                        }
                    )
            except Exception:  # noqa: BLE001 - client gone / socket closed
                break
            # 2s cadence: frequent enough that the client's 1s throughput sampler sees
            # liveness, cheap enough that N concurrent sockets don't hammer Redis.
            await _asyncio.sleep(2)

    async def _forward_bus() -> None:
        """AIOSOP-WS-STREAM-001 (2026-07-03, revised): forward live swarm activity
        from the in-process coordination bus to THIS engagement's dashboard.

        The original attempt subscribed to an 'observation' topic, but
        base.record_observation has no callers so that topic never fires. The
        genuinely live signal is the scheduler's task lifecycle — task.scheduled /
        assigned / completed / failed — each of which now carries engagement_id so
        it can be routed to the right socket. Forward them as `agent_observation`
        (the dashboard appends every non-heartbeat event to its live timeline and
        counts it toward throughput), so the swarm feed and EV/S reflect real work
        instead of only the 2s heartbeat. A compact projection is sent — never the
        full task `result` blob — to keep WS frames small (cf. report-bloat fix)."""
        _TOPICS = ("task.scheduled", "task.assigned", "task.completed", "task.failed")

        async def _forward_distributed() -> None:
            # FIX (ws-bus-subscribe-2026-08-23): two defects here.
            # 1) The legacy in-memory bus iterator API raised TypeError against
            #    DistributedCoordinationBus, so the live swarm feed never delivered
            #    task lifecycle events at all. subscribe_iter() bridges that gap.
            # 2) The first revision of this fix ran one pump PER TOPIC but shared a
            #    single consumer group across them; Redis delivers each stream entry
            #    to exactly ONE member of a group, so most events landed on a
            #    wrong-topic pump and were silently filtered. A single subscription
            #    over all topics with the event's own topic forwarded fixes both.
            bus = orch.coordination_bus
            if not hasattr(bus, "subscribe_iter"):
                return  # legacy in-memory bus handled by per-topic pumps below
            consumer = f"ws-{engagement_id}-{id(websocket)}"
            group = f"ws-feed-{engagement_id}-{id(websocket)}"
            async for ev in bus.subscribe_iter(list(_TOPICS), consumer, group):
                payload = getattr(ev, "payload", {}) or {}
                if payload.get("engagement_id") != engagement_id:
                    continue
                data = {
                    "topic": ev.topic,
                    "task_id": payload.get("task_id"),
                    "agent_id": payload.get("agent_id"),
                    "agent_type": payload.get("agent_type"),
                    "task_type": payload.get("task_type"),
                }
                try:
                    await websocket.send_json(
                        {
                            "event_type": "agent_observation",
                            "engagement_id": engagement_id,
                            "data": data,
                        }
                    )
                except Exception:  # noqa: BLE001 - socket closed; disconnect handler tears down
                    return

        async def _pump(topic: str) -> None:
            # Legacy in-memory bus path (per-topic queues, no consumer groups).
            async for ev in orch.coordination_bus.subscribe(topic):
                payload = getattr(ev, "payload", {}) or {}
                if payload.get("engagement_id") != engagement_id:
                    continue
                data = {
                    "topic": topic,
                    "task_id": payload.get("task_id"),
                    "agent_id": payload.get("agent_id"),
                    "agent_type": payload.get("agent_type"),
                    "task_type": payload.get("task_type"),
                }
                try:
                    await websocket.send_json(
                        {
                            "event_type": "agent_observation",
                            "engagement_id": engagement_id,
                            "data": data,
                        }
                    )
                except Exception:  # noqa: BLE001 - socket closed; disconnect handler tears down
                    return

        if hasattr(orch.coordination_bus, "subscribe_iter"):
            pumps = [_asyncio.create_task(_forward_distributed())]
        else:
            pumps = [_asyncio.create_task(_pump(t)) for t in _TOPICS]
        try:
            await _asyncio.gather(*pumps)
        except _asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - bus iteration error must not crash the socket
            pass
        finally:
            for _p in pumps:
                if not _p.done():
                    _p.cancel()

    push_task = _asyncio.create_task(_push_loop())
    forward_task = _asyncio.create_task(_forward_bus())
    # AIOSOP-WS-HARDEN-2026-08-25: rate-limit inbound messages and cap payload
    # size to prevent flooding and oversized-payload DoS.
    _WS_MAX_MSG_BYTES = 65536  # 64 KB
    _WS_RATE_LIMIT = 50  # max messages per second per socket
    _ws_msg_count = 0
    _ws_rate_start = _time.monotonic()
    try:
        while True:
            data = await websocket.receive_text()
            # Size guard
            if len(data) > _WS_MAX_MSG_BYTES:
                await websocket.send_json({"type": "error", "message": "Payload too large"})
                continue
            # Rate-limit guard
            _ws_msg_count += 1
            _now = _time.monotonic()
            if _now - _ws_rate_start >= 1.0:
                _ws_msg_count = 0
                _ws_rate_start = _now
            elif _ws_msg_count > _WS_RATE_LIMIT:
                await websocket.send_json({"type": "error", "message": "Rate limit exceeded"})
                continue
            # Parse guard
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
                continue
            if not isinstance(message, dict):
                await websocket.send_json({"type": "error", "message": "Expected JSON object"})
                continue
            action = message.get("action")

            if action == "ping":
                await websocket.send_json({"type": "pong"})
            elif action == "status":
                await websocket.send_json(
                    {
                        "type": "status",
                        "session_id": engagement_id,
                        "phase": session.phase,
                        "tasks": len(orch._tasks),
                        "agents": len(orch._agents),
                    }
                )
            elif action == "halt":
                if not (await require_role("senior_operator")(operator)):
                    await websocket.send_json(
                        {"type": "error", "message": "halt requires senior_operator role"}
                    )
                    continue
                await orch.halt_engagement(engagement_id, message.get("reason", "Operator halt"))
                await websocket.send_json({"type": "halted", "session_id": engagement_id})
            else:
                await websocket.send_json({"type": "error", "message": "Unknown action"})
    except Exception as exc:
        import logging as _logging

        _logging.getLogger("ai_osop.api.websocket").warning(
            "websocket_handler_exception: %s - %s (engagement_id=%s)",
            type(exc).__name__,
            str(exc),
            engagement_id,
        )
        try:
            await websocket.close(code=1011, reason="Internal server error")
        except Exception as e:
            logger.warning(f"broad_exception_caught error={e}")
            pass  # connection may already be closed
    finally:
        # AIOSOP-WS-PUSH-001 / WS-STREAM-001: always stop the background tasks when the
        # client disconnects so they can't leak or keep sending to a dead socket.
        for _bg in (push_task, forward_task):
            _bg.cancel()
            try:
                await _bg
            except Exception:
                pass
