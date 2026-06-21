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
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter
from ai_osop.api.deps import require_role, state, verify_token

# Router imports
from ai_osop.api.routers import (
    agents,
    approvals,
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
from ai_osop.core.observability import render_prometheus, update_active_agents
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
        ("source-map-mcp", settings.source_map_mcp_host, settings.source_map_mcp_port, None),
        ("cloud-mcp", settings.cloud_mcp_host, settings.cloud_mcp_port, None),
        (
            "turbo-intruder-mcp",
            settings.turbo_intruder_mcp_host,
            settings.turbo_intruder_mcp_port,
            None,
        ),
    ]
    critical_mcps = {
        "browser-mcp",
        "nuclei-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
    }
    for server_id, host, port, token in servers:
        is_critical = server_id in critical_mcps
        try:
            await mcp_registry.register_server(server_id, host, port, token)
            if is_critical:
                await mcp_registry.initialize_server(
                    server_id,
                    scope={},
                    credentials={},
                    session_id="api-bootstrap",
                )
            import logging

            logging.getLogger("ai_osop.mcp").info(f"MCP server {server_id} registered.")
        except Exception as exc:
            if is_critical:
                import logging

                logging.getLogger("ai_osop.mcp").error(
                    f"Critical MCP server {server_id} at {host}:{port} failed: {exc}"
                )
                raise RuntimeError(
                    f"Startup self-test failed: Critical MCP {server_id} is unavailable: {exc}"
                )
            else:
                import logging

                logging.getLogger("ai_osop.mcp").warning(
                    f"Skipping MCP server {server_id} at {host}:{port}: {exc}"
                )


# ============== Lifespan ==============


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    import logging

    logger = logging.getLogger("ai_osop.api")

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
    with trace_span("api.startup", attributes={"version": "1.0.0"}):
        session_memory = SessionMemory()
        graph_memory = GraphMemory()
        vector_memory = VectorMemory(settings.postgres_uri)
        mcp_registry = MCPRegistry()
        rate_limiter = RateLimiter()
        threat_intel_adapter = ThreatIntelAdapter()

        # 1. Redis
        try:
            await session_memory.connect()
            await session_memory._redis.ping()
            health_status["redis"] = "healthy"
        except Exception as e:
            health_status["redis"] = f"unhealthy: {e}"
            logger.critical(f"Redis connection failed: {e}")

        # 2. Neo4j
        try:
            await graph_memory.connect()
            health_status["neo4j"] = "healthy"
        except Exception as e:
            health_status["neo4j"] = f"unhealthy: {e}"
            logger.critical(f"Neo4j connection failed: {e}")

        # 3. Vector Memory (pgvector)
        try:
            await vector_memory.connect()
        except Exception as e:
            logger.warning(f"Vector memory initialization failed: {e}")

        # 4. MCP Servers
        try:
            await register_optional_mcp_servers(mcp_registry)
            health_status["browser-mcp"] = "healthy"
        except Exception as e:
            health_status["browser-mcp"] = f"unhealthy: {e}"

        # 5. Build Orchestrator
        llm_client = LiteLLMClient()
        orch = Orchestrator(
            session_memory=session_memory,
            graph_memory=graph_memory,
            mcp_registry=mcp_registry,
            llm_client=llm_client,
        )

        # 6. Session Store (user sessions for DiffAuth)
        try:
            _session_store_ref = SessionStore(session_memory)
            state["session_store"] = _session_store_ref
        except Exception as e:
            logger.warning(f"SessionStore initialization failed: {e}")

        # 7. Skill Engine
        try:
            from ai_osop.core.skill_engine import SkillEngine

            _skill_engine_ref = SkillEngine(graph_memory, session_memory)
            state["skill_engine"] = _skill_engine_ref
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
            from ai_osop.agents.concurrency_agent import ConcurrencyAgent
            from ai_osop.agents.context_manager_agent import ContextManagerAgent
            from ai_osop.agents.exploit_agent import ExploitValidationAgent
            from ai_osop.agents.human_oversight_agent import HumanOversightAgent
            from ai_osop.agents.payload_agent import PayloadMutationAgent
            from ai_osop.agents.recon_agent import ReconAgent
            from ai_osop.agents.reporting_agent import ReportingAgent
            from ai_osop.agents.stack_profiler_agent import StackProfilerAgent
            from ai_osop.agents.vuln_agent import VulnAnalysisAgent
            from ai_osop.agents.workflow_agent import PlaywrightAgent
            from ai_osop.agents.experimental.cloud_agent import CloudSpecialistAgent
            from ai_osop.agents.experimental.codeql_agent import CodeQLAgent
            from ai_osop.agents.experimental.graphql_agent import GraphQLAgent
            from ai_osop.agents.experimental.js_analyzer_agent import JSAnalyzerAgent
            from ai_osop.agents.experimental.mobile_agent import MobileAnalysisAgent
            from ai_osop.agents.experimental.nextjs_agent import NextJSSpecialistAgent
            from ai_osop.agents.experimental.react_agent import ReactSpecialistAgent
            from ai_osop.agents.experimental.stateful_logic_agent import StatefulLogicAgent
            from ai_osop.agents.experimental.visual_agent import VisualContextAgent
            from ai_osop.core.config import AgentType

            bootstrap_session_id = "api-bootstrap"
            agents_to_register = [
                (AttackChainAgent, AgentType.ATTACK_CHAIN, "attack-chain-agent-001"),
                (ReconAgent, AgentType.RECON, "recon-agent-001"),
                (VulnAnalysisAgent, AgentType.VULN_ANALYSIS, "vuln-agent-001"),
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
                    audit_callback=orch.write_audit_event,
                    coordination_bus=orch.coordination_bus,
                )
                agent_inst = agent_cls(ctx)
                await orch.register_agent(agent_inst)
        except Exception as e:
            logger.error(f"Orchestrator initialization/agent registration failed: {e}")

        # 10. Bind to shared state dict so routers see the live values
        state["orchestrator"] = orch

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


# Security Headers Middleware (P2 fix)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


# Audit Logging Middleware (P2 fix)
class AuditLogMiddleware(BaseHTTPMiddleware):
    """Log all state-changing API requests with operator and engagement context."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        response = await call_next(request)
        method = request.method
        if method in ("POST", "PUT", "PATCH", "DELETE"):
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
            )
        return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditLogMiddleware)

# Register routers
app.include_router(engagements.router)
app.include_router(tasks.router)
app.include_router(agents.router)
app.include_router(approvals.router)
app.include_router(sessions.router)
app.include_router(findings.router)
app.include_router(intelligence.router)
app.include_router(system.router)


# ============== Health & Metrics (protected) ==============


@app.get("/health")
async def health(operator: Dict[str, Any] = Depends(verify_token)):
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/metrics")
async def metrics(operator: Dict[str, Any] = Depends(require_role("senior_operator"))):
    """Prometheus metrics endpoint."""
    content = render_prometheus()
    return Response(content, media_type=CONTENT_TYPE_LATEST)


# ============== WebSocket (kept inline; needs auth via query param) ==============


from ai_osop.api.deps import verify_token  # noqa: E402


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

    orch = state["orchestrator"]
    session = orch._sessions.get(engagement_id)
    if not session:
        await websocket.close(code=1008, reason="Engagement not found")
        return

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
                # P1: re-verify senior_operator role before allowing halt via WebSocket
                if operator.get("role") != "senior_operator":
                    await websocket.send_json(
                        {"type": "error", "message": "halt requires senior_operator role"}
                    )
                    continue
                await orch.halt_engagement(engagement_id, message.get("reason", "Operator halt"))
                await websocket.send_json({"type": "halted", "session_id": engagement_id})
            else:
                await websocket.send_json({"type": "error", "message": "Unknown action"})
    except Exception:
        pass
