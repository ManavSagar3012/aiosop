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
import sys
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
from ai_osop.api.deps import require_role, state, verify_ws_token
from ai_osop.api.health import router as health_router
from ai_osop.api.health import run_startup_self_test

# Router imports
from ai_osop.api.routers import (
    agents,
    approvals,
    cognition,
    dlq,
    engagements,
    findings,
    intelligence,
    observatory,
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

# Force UTF-8 stdio (AIOSOP-UTF8-STDIO). On Windows the default console/file codec
# is cp1252, so logging a string containing a non-cp1252 character — e.g. sqlmap
# output with a '→' arrow — raises UnicodeEncodeError, and uncaught inside an
# agent it FAILS the whole task (observed: the autonomous login SQLi scan crashed
# on '→'). Reconfigure stdio to UTF-8 with a replacement fallback so logging
# can never crash execution. No-op where stdio is already UTF-8 (Linux/PYTHONUTF8).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

# ============== Global State ==============

# NOTE: Pydantic models, auth deps, and shared singletons live in api/deps.py
# so routers can import them without circular imports.


# ============== MCP Server Registration ==============


logger = logging.getLogger("ai_osop.api")


from ai_osop.reliability.retry import retry_with_backoff  # noqa: E402

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
        ("shodan-mcp", settings.shodan_mcp_host, settings.shodan_mcp_port, settings.shodan_api_key),
        ("recon-mcp", settings.recon_mcp_host, settings.recon_mcp_port, settings.api_token),
        ("payload-mcp", settings.payload_mcp_host, settings.payload_mcp_port, settings.api_token),
        ("nuclei-mcp", settings.nuclei_mcp_host, settings.nuclei_mcp_port, settings.api_token),
        ("browser-mcp", settings.browser_mcp_host, settings.browser_mcp_port, settings.api_token),
        (
            "security-bridge",
            settings.security_bridge_host,
            settings.security_bridge_port,
            settings.api_token,
        ),
        (
            "threat-intel-mcp",
            settings.threat_intel_mcp_host,
            settings.threat_intel_mcp_port,
            settings.api_token,
        ),
        ("cloud-mcp", settings.cloud_mcp_host, settings.cloud_mcp_port, settings.api_token),
        (
            "turbo-intruder-mcp",
            settings.turbo_intruder_mcp_host,
            settings.turbo_intruder_mcp_port,
            settings.api_token,
        ),
        (
            "source-map-mcp",
            settings.source_map_mcp_host,
            settings.source_map_mcp_port,
            settings.api_token,
        ),
        ("oast-mcp", settings.oast_mcp_host, settings.oast_mcp_port, settings.api_token),
        (
            "session-memory-mcp",
            settings.session_memory_mcp_host,
            settings.session_memory_mcp_port,
            settings.api_token,
        ),
        (
            "reporting-mcp",
            settings.reporting_mcp_host,
            settings.reporting_mcp_port,
            settings.api_token,
        ),
        (
            "attack-graph-mcp",
            settings.attack_graph_mcp_host,
            settings.attack_graph_mcp_port,
            settings.api_token,
        ),
    ]
    # Critical MCPs whose ABSENCE is logged loudly. NOTE: this set only governs
    # log severity on failure — it must NOT gate whether a server is initialized.
    # (AIOSOP-RECON-PERSIST-2026-06-24)
    critical_mcps = {
        # "recon-mcp",
        # "nuclei-mcp",
        # "burp-mcp",
        # "browser-mcp",
        # "source-map-mcp",
        # "cloud-mcp",
        # "turbo-intruder-mcp",
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
                # AIOSOP-MCP-AUTH-BOOT-001: pass the server's bearer token as the
                # auth credential so servers that enforce an Authorization header
                # (e.g. shodan-mcp, source-map-mcp) actually init instead of
                # staying registered-with-no-tools forever. Previously the boot
                # handshake ran with credentials={} and the server rejected it.
                credentials={"auth_token": token} if token else {},
                session_id="api-bootstrap",
            )
            mcp_log.info(f"MCP server {server_id} registered and initialized.")
        except Exception as exc:
            (mcp_log.critical if is_critical else mcp_log.warning)(
                f"MCP server {server_id} at {host}:{port} registration/init failed: {exc}"
            )

    # Every connection uses one non-blocking startup attempt, so initialize all
    # servers concurrently and await the bounded warm-up.  Previously these were
    # fire-and-forget tasks: the orchestrator could schedule browser-dependent
    # work before the registry knew which tools the server actually exposed.
    tasks = [init_server(s, h, p, t, s in critical_mcps) for s, h, p, t in servers]
    await asyncio.gather(*tasks)


# ============== Lifespan ==============


# Adapter tool-name → server contract. If a server no longer registers a tool an
# adapter calls, every task using it fails silently at runtime (the sqli path once
# called "run_sqlmap" while the bridge registered "sqlmap" → 0 findings, no error
# surfaced). Assert these at boot so a rename/stale-deploy is caught immediately.
_CRITICAL_TOOL_CONTRACTS = {
    "security-bridge": ["sqlmap"],
}


async def _verify_critical_tool_names(logger) -> None:
    """Warn LOUDLY if a critical adapter tool name is missing from its live server."""
    import httpx

    from ai_osop.core.config import settings

    hosts = {
        "security-bridge": (settings.security_bridge_host, settings.security_bridge_port),
    }
    for server_id, required in _CRITICAL_TOOL_CONTRACTS.items():
        host, port = hosts.get(server_id, (None, None))
        if not host:
            continue
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.post(f"http://{host}:{port}/mcp/initialize", json={})
                names = {t.get("name") for t in (r.json() or {}).get("tools", [])}
            missing = [t for t in required if t not in names]
            if missing:
                logger.critical(
                    "AIOSOP-TOOLGUARD: server %s is missing required tool(s) %s "
                    "(registered: %s). Tasks using it will fail silently — check for a "
                    "tool rename or a stale process.",
                    server_id,
                    missing,
                    sorted(n for n in names if n),
                )
        except Exception as e:  # noqa: BLE001 - guard is advisory, never fatal
            logger.warning("AIOSOP-TOOLGUARD probe of %s failed (non-fatal): %s", server_id, e)


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
        logger.info("Sentry SDK initialized", environment=settings.environment)
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

        # 4a. Guard: critical adapter tool names must resolve on their live servers.
        await _verify_critical_tool_names(logger)

        # 5. Build Orchestrator
        llm_client = LiteLLMClient()

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

        # P2b calibration engine: wire to graph_memory so validate_vulnerability()
        # feeds accepted findings into the Beta-Binomial feedback loop.
        try:
            from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine

            graph_memory.calibration_engine = ConfidenceCalibrationEngine(
                session_memory=session_memory,
            )
            logger.info("Calibration engine wired to graph memory.")
        except Exception as e:  # noqa: BLE001 - learning is optional
            logger.warning(f"Calibration engine wiring failed: {e}")

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
        # 5a. Outbox Processor (Transactional sync)
        try:
            from ai_osop.memory.outbox_processor import OutboxProcessor

            outbox_processor = OutboxProcessor(session_memory, graph_memory)
            asyncio.create_task(outbox_processor.run())
            logger.info("OutboxProcessor started.")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"OutboxProcessor initialization failed: {e}")

        # 5b. Neo4j pool metrics export (every 15s)
        try:
            await graph_memory.start_pool_metrics_export(interval=15)
            logger.info("Neo4j pool metrics export started (15s interval).")
        except Exception as e:  # noqa: BLE001 — pool metrics are advisory
            logger.warning(f"Neo4j pool metrics export start failed: {e}")

        orch = Orchestrator(
            session_memory=session_memory,
            graph_memory=graph_memory,
            mcp_registry=mcp_registry,
            llm_client=llm_client,
        )

        # 5c. Wire coordination bus to graph_memory so finding.recorded events
        # are published on every persist (enables the reasoning loop's
        # event-driven hypothesis re-generation). Must happen AFTER the
        # orchestrator is created so orch.coordination_bus exists.
        graph_memory.coordination_bus = orch.coordination_bus
        mcp_registry.coordination_bus = orch.coordination_bus
        mcp_registry.start_health_publisher()
        logger.info("Coordination bus wired to graph_memory (finding.recorded events).")

        # Reliability sprint: Run self-test after orchestrator initialization
        startup_results = await run_startup_self_test()
        if startup_results["status"] != "healthy":
            logger.critical(
                f"Startup self-test failed: {startup_results} — proceeding in degraded mode"
            )

        # 6. Session Store (user sessions for DiffAuth)
        try:
            _session_store_ref = SessionStore(session_memory, graph_memory)
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
            from ai_osop.orchestrator.agent_registry import register_all_agents

            await register_all_agents(
                orch=orch,
                session_memory=session_memory,
                graph_memory=graph_memory,
                vector_memory=vector_memory,
                llm_client=llm_client,
                mcp_registry=mcp_registry,
                rate_limiter=rate_limiter,
                threat_intel_adapter=threat_intel_adapter,
                state=state,
            )
        except Exception as e:
            logger.error(f"Agent registration failed: {e}")

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

    logger.info("AI-OSOP API startup complete.")
    yield

    # Shutdown
    logger.info("AI-OSOP API shutting down...")
    await graph_memory.stop_pool_metrics_export()
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
        logger.info(
            "api_audit",
            method=method,
            path=request.url.path,
            operator_id=operator_id,
            status_code=response.status_code,
            user_agent=request.headers.get("user-agent", ""),
            client_ip=request.client.host if request.client else "",
            request_id=request_id,
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
app.include_router(observatory.router)
app.include_router(cognition.router)


# ============== Metrics (protected) ==============


@app.get("/metrics")
async def metrics(operator: Dict[str, Any] = Depends(require_role("senior_operator"))):
    """Prometheus metrics endpoint."""
    content = render_prometheus()
    return Response(content, media_type=CONTENT_TYPE_LATEST)


# ============== WebSocket (kept inline; needs auth via query param) ==============


from ai_osop.api.deps import assert_engagement_access  # noqa: E402


async def get_websocket_operator(websocket: WebSocket) -> Dict[str, Any]:
    # Order: query param (legacy compat) -> Authorization header -> Sec-WebSocket-Protocol.
    # The protocol channel is how browser clients pass a bearer token without
    # putting it in the URL (which leaks into proxy logs, history, Referer).
    token = websocket.query_params.get("token")
    if not token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
    if not token:
        proto = websocket.headers.get("sec-websocket-protocol")
        if proto:
            # Accept either a bare token or a "bearer.<token>" scheme entry.
            for part in proto.split(","):
                part = part.strip()
                if part.lower().startswith("bearer."):
                    token = part[len("bearer."):]
                    break
                if part and not part.startswith("osop"):
                    token = part
    if not token:
        raise HTTPException(status_code=403, detail="Missing token")
    return await verify_ws_token(token)


async def get_websocket_session(
    engagement_id: str,
    operator: Dict[str, Any] = Depends(get_websocket_operator),
):
    return await assert_engagement_access(operator, engagement_id)


@app.websocket("/ws/engagements/{engagement_id}")
async def websocket_engagement(
    websocket: WebSocket,
    engagement_id: str,
    operator: Dict[str, Any] = Depends(get_websocket_operator),
    session=Depends(get_websocket_session),
):
    """WebSocket for real-time engagement updates."""
    # Must echo back the FIRST supported subprotocol ("osop") so the browser's
    # WebSocket handshake succeeds — the client sends ["osop", "bearer.<token>"].
    await websocket.accept(subprotocol="osop")
    orch = state["orchestrator"]
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
        _TOPICS = (
            "task.scheduled", "task.assigned", "task.completed", "task.failed",
            "finding.recorded", "hypothesis.generated", "chain.discovered",
            "feedback.payload_validated",
        )

        async def _pump(topic: str) -> None:
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
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
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
                if operator.get("role") != "senior_operator":
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
            logger.warning(f"broad_exception_caught: {e}")
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
