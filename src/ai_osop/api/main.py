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
import logging
import json
import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse

from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter
from ai_osop.api.deps import require_role, state, verify_token
from ai_osop.api.browser_current_custody_readback import (
    create_browser_current_custody_router,
)
from ai_osop.api.source_map_host_witness_operator import (
    create_source_map_host_witness_router,
)
from ai_osop.api.mcp_transport_operator_diagnostics import (
    router as mcp_transport_operator_diagnostics_router,
)
from ai_osop.api.mcp_eleven_supervised_recovery_join_20261022 import (
    router as mcp_eleven_supervised_recovery_router,
)
from ai_osop.api.middleware import CorrelationIdMiddleware
from ai_osop.api.health import router as health_router

# Router imports
from ai_osop.api.routers import (
    agents,
    approvals,
    auth,
    diagnostics,
    engagements,
    findings,
    flow_artifacts,
    candidate_evidence_artifacts,
    flow_artifact_reviews,
    flow_resource_aliases,
    flow_resource_folders,
    flow_mcp_actions,
    flow_mcp_readiness,
    flow_tool_proposals,
    flows,
    intelligence,
    mcp_tool_catalog,
    native_browser_source_authority,
    native_browser_current_authority,
    native_sourcemap_source_authority,
    native_sourcemap_status_authority,
    native_mcp_redemption,
    native_mcp_grants,
    native_mcp_resources,
    native_mcp_stage_receipts,
    native_mcp_supervision,
    native_inert_fleet,
    operator_knowledge,
    operator_global_library,
    reviewed_library_flow_import,
    unified_knowledge_search,
    provider_invoices,
    provider_route_policy_reviews,
    provider_credential_profile_refs,
    report_attestations,
    sessions,
    supervision,
    durable_supervision_subscriptions,
    system,
    target_authority,
    verified_finding_reviews,
    tasks,
)
from ai_osop.auth.session_store import SessionStore
from ai_osop.core.config import settings
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.observability import render_prometheus, update_active_agents
from ai_osop.core.metrics import BUILD_INFO, REQUESTS_TOTAL, REQUEST_DURATION, ERRORS_TOTAL
from prometheus_client import CONTENT_TYPE_LATEST
from ai_osop.core.tracing import init_tracing, trace_span
from ai_osop.mcp.protocol import MCPInitializeResponse, MCPRegistry
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


logger = logging.getLogger("ai_osop.api")


async def connect_with_retry(
    connector,
    name: str,
    max_retries: int = 10,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
) -> bool:
    """Connect to a dependency with exponential backoff.

    Uses retry_with_backoff while interpreting max_retries as the maximum
    *total attempts* for this API startup wrapper.
    """
    from ai_osop.reliability.retry import retry_with_backoff

    try:
        await retry_with_backoff(
            connector,
            max_retries=max(0, max_retries - 1),
            base_delay=base_delay,
            max_delay=max_delay,
            retry_name=f"{name}.connect",
        )
        logger.info(f"{name} connected successfully")
        return True
    except Exception as e:
        logger.critical(f"{name} unavailable after {max(1, max_retries)} attempts: {e}")
        return False


_MCP_BOOTSTRAP_INIT_TIMEOUT_SECONDS = 8.0


def configured_mcp_server_specs() -> list[tuple[str, str, int, Optional[str]]]:
    """Single source for bootstrap and explicit senior-initiated reconnects.

    Callers must NEVER serialize returned credentials/addresses into an API
    response or allow the operator to override a configured endpoint.
    """
    configured = [
        ("burp-mcp", settings.burp_mcp_host, settings.burp_mcp_port, settings.burp_api_key),
        ("recon-mcp", settings.recon_mcp_host, settings.recon_mcp_port, None),
        ("payload-mcp", settings.payload_mcp_host, settings.payload_mcp_port, None),
        ("nuclei-mcp", settings.nuclei_mcp_host, settings.nuclei_mcp_port, None),
        ("shodan-mcp", settings.shodan_mcp_host, settings.shodan_mcp_port, settings.shodan_api_key),
        (
            "browser-mcp",
            settings.browser_mcp_host,
            settings.browser_mcp_port,
            settings.browser_mcp_auth_token,
        ),
        ("security-bridge", settings.security_bridge_host, settings.security_bridge_port, None),
        ("threat-intel-mcp", settings.threat_intel_mcp_host, settings.threat_intel_mcp_port, None),
        (
            "source-map-mcp",
            settings.source_map_mcp_host,
            settings.source_map_mcp_port,
            os.environ.get("OSOP_SOURCEMAP_MCP_BEARER_TOKEN"),
        ),
        (
            "cloud-mcp",
            settings.cloud_mcp_host,
            settings.cloud_mcp_port,
            settings.cloud_mcp_auth_token,
        ),
        (
            "turbo-intruder-mcp",
            settings.turbo_intruder_mcp_host,
            settings.turbo_intruder_mcp_port,
            None,
        ),
    ]
    # The historical settings defaults use "localhost". Canonicalize this
    # literal to numeric IPv4 loopback before constructing any *plain HTTP*
    # MCP session (which may hold an operator-provisioned bearer). Avoid a
    # hosts-file/DNS resolution or a mismatch with explicit local recovery.
    # Explicit non-local operator configuration stays unchanged and does NOT
    # become eligible for loopback-only recovery.
    return [
        (name, "127.0.0.1" if host == "localhost" else host, port, token)
        for name, host, port, token in configured
    ]


async def register_optional_mcp_servers(
    mcp_registry: MCPRegistry,
    *,
    readiness: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Record each connection and trusted initialization separately.

    A successful register_server only establishes a transport connection.
    ALL eleven services must negotiate initialization: optional services
    cannot execute even inert tools while left uninitialized. Initialization
    must return the exact ready declaration and leave the matching registry
    connection initialized. Neither proves runtime health, signed Task
    admission, or permission to execute a security scanner.
    """
    servers = configured_mcp_server_specs()
    critical_mcps = {
        "browser-mcp",
        "nuclei-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
    }
    report = readiness if readiness is not None else {}
    report.clear()
    for server_id, _, _, _ in servers:
        report[server_id] = {
            "critical": server_id in critical_mcps,
            "registered": False,
            "initialized": False,
            "status": "unavailable",
            "runtime_health_verified": False,
        }

    for server_id, host, port, token in servers:
        is_critical = server_id in critical_mcps
        record = report[server_id]
        try:
            await mcp_registry.register_server(server_id, host, port, token)
            record["registered"] = True
            record["status"] = "registered"
            declaration = await asyncio.wait_for(
                mcp_registry.initialize_server(
                    server_id,
                    scope={},
                    credentials={},
                    session_id="api-bootstrap",
                ),
                timeout=_MCP_BOOTSTRAP_INIT_TIMEOUT_SECONDS,
            )
            registered = getattr(mcp_registry, "_servers", None)
            connection = registered.get(server_id) if isinstance(registered, dict) else None
            if (
                not isinstance(declaration, MCPInitializeResponse)
                or declaration.server_id != server_id
                or declaration.status != "ready"
                or not declaration.tools
                or len({tool.name for tool in declaration.tools}) != len(declaration.tools)
                or connection is None
                or getattr(connection, "server_id", None) != server_id
                or getattr(connection, "_initialized", None) is not True
                or getattr(connection, "_session", None) is None
            ):
                raise RuntimeError("MCP initialize readiness not established")
            record["initialized"] = True
            record["status"] = "initialized"
            logging.getLogger("ai_osop.mcp").info("MCP %s: %s", server_id, record["status"])
        except Exception as exc:
            if record["registered"]:
                registered = getattr(mcp_registry, "_servers", None)
                connection = registered.get(server_id) if isinstance(registered, dict) else None
                if connection is not None:
                    # A transport-level initialize may have set _initialized
                    # before bootstrap rejected an unusable/ambiguous manifest.
                    # Never leave that connection dispatchable after denial.
                    connection._initialized = False
                    connection._tools = {}
                    connection._capabilities = []
            record["initialized"] = False
            record["status"] = "unavailable"
            if is_critical:
                logging.getLogger("ai_osop.mcp").error(
                    "Critical MCP %s initialization unavailable (%s)",
                    server_id,
                    type(exc).__name__,
                )
            else:
                logging.getLogger("ai_osop.mcp").warning(
                    "Optional MCP %s registration unavailable (%s)",
                    server_id,
                    type(exc).__name__,
                )
    if settings.environment.strip().lower() in {"production", "prod"} and any(
        report[server_id]["status"] != "initialized" for server_id in critical_mcps
    ):
        raise RuntimeError("Required critical MCP initialization unavailable")
    return report


async def _bootstrap_mcp_readiness(
    mcp_registry: MCPRegistry, health_status: Dict[str, str]
) -> None:
    """Publish sanitized per-service facts even if strict bootstrap aborts."""
    report: Dict[str, Dict[str, Any]] = {}
    try:
        await register_optional_mcp_servers(mcp_registry, readiness=report)
    finally:
        for server_id, record in report.items():
            health_status[server_id] = record["status"]
        # Do not confuse registry registration with a verified runtime health
        # probe. No remote credentials, URL, manifest or error text is stored.
        state["mcp_bootstrap_readiness"] = {key: dict(value) for key, value in report.items()}


# ============== Lifespan ==============


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    import logging

    logger = logging.getLogger("ai_osop.api")
    temporal_worker_task = None
    bound_temporal_worker = None
    safety_monitor = None

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
        vector_memory = VectorMemory(settings.postgres_uri, session_memory=session_memory)
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
            # SessionMemory.connect also applies PostgreSQL migrations. A
            # failed connection/migration cannot be reported as a usable API;
            # accepting writes without durable state would lose task/approval
            # data and permit inconsistent recovery.
            logger.critical("Required session storage initialization failed")
            raise RuntimeError("Required session storage or schema migration unavailable")

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
            logger.warning(
                "Tenant-scoped semantic memory unavailable", error_class=type(e).__name__
            )
            if settings.environment.strip().lower() in {"production", "prod"}:
                # Do not continue a production execution fleet which could
                # silently drop tenant-scoped knowledge and resume from stale
                # legacy unscoped payloads.
                raise RuntimeError("Required signed semantic memory unavailable") from e

        # 4. MCP Servers
        await _bootstrap_mcp_readiness(mcp_registry, health_status)

        # 5. Build Orchestrator
        from ai_osop.memory.model_usage import ModelUsageLedger

        # Bind before any agent, planner or Temporal worker can receive the
        # client. Provider calls also refuse to run from standalone clients
        # that were never bound to the durable usage ledger.
        # A reviewed credential reference or environment API key is not a
        # host-enrolled 11-root signed vault/route/ledger dispatch authority.
        # Until a separately trusted host bootstrap can inject that authority,
        # production (and unknown deployment modes) MUST deny paid model calls.
        # Do not allow an unset or misspelled environment to bypass the guard.
        if settings.environment.strip().lower() in {"development", "dev", "test", "testing"}:
            llm_client = LiteLLMClient(usage_store=ModelUsageLedger(session_memory))
        else:
            from ai_osop.core.host_vault_guard_admission import pending_guarded_client
            from ai_osop.core.provider_host_runtime_slot_20261022 import (
                host_enrolled_provider_runtime,
            )

            # Production defaults to the audited mandatory-deny client. An
            # explicitly installed *host-process-only* independent signed
            # vault + durable cross-replica one-use CAS fence can supply the
            # protected constructor. No enrollment is ever made here and no
            # API request, profile, environment key or symbolic ref can
            # enable this branch. Without a host join, dispatch stays DENIED.
            host_vault = host_enrolled_provider_runtime()
            llm_client = (
                host_vault.construct_client(usage_store=ModelUsageLedger(session_memory))
                if host_vault is not None
                else pending_guarded_client(usage_store=ModelUsageLedger(session_memory))
            )
        # Correlate sanitized tool/LLM receipts with the same engagement store.
        # Errors in this best-effort observability path never execute a tool.
        if hasattr(mcp_registry, "set_provenance_callback"):
            mcp_registry.set_provenance_callback(session_memory.record_action_adapter)
        if hasattr(mcp_registry, "set_budget_callback"):
            mcp_registry.set_budget_callback(session_memory.consume_mcp_tool_budget)
        if hasattr(llm_client, "set_provenance_callback"):
            llm_client.set_provenance_callback(session_memory.record_action_adapter)
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
                    audit_callback=orch._audit_log,
                    coordination_bus=orch.coordination_bus,
                )
                agent_inst = agent_cls(ctx)
                await orch.register_agent(agent_inst)
        except Exception as e:
            logger.error(f"Orchestrator initialization/agent registration failed: {e}")
            # Do not advertise an operational security platform when the
            # scheduler or mandatory agent fleet failed to initialize.
            raise RuntimeError("Orchestrator or agent initialization failed") from e

        # 10. Bind to shared state dict so routers see the live values
        state["orchestrator"] = orch

        # Supervise already-authorized running tasks.  This monitor never
        # initiates security tests; violations use the audited halt workflow.
        if orch._running:
            from ai_osop.tasks.safety_monitor import run_safety_monitor

            safety_monitor = await run_safety_monitor(orch)

        if orch.temporal_enabled is True:
            # Temporal execution runs against the same initialized agent fleet
            # as the API. A bound worker is required; scheduling alone cannot
            # establish that an activity is executing.
            from ai_osop.orchestrator.temporal_worker import build_bound_worker

            if not orch._agents:
                raise RuntimeError("Temporal enabled without registered agents")
            bound_temporal_worker = build_bound_worker(orch)
            temporal_worker_task = asyncio.create_task(bound_temporal_worker.run())
            await asyncio.sleep(0)
            if temporal_worker_task.done():
                await temporal_worker_task
                raise RuntimeError("Temporal worker exited during startup")

        # 11. Set build info for metrics
        # Release identifiers are supplied by the image/build pipeline.
        # A fixed source-code SHA is misleading once the code has changed.
        BUILD_INFO.info(
            {
                "version": os.environ.get("OSOP_BUILD_VERSION", "unknown"),
                "git_sha": os.environ.get("OSOP_GIT_SHA", "unknown"),
            }
        )

    logger.info("AI-OSOP API startup complete.")
    yield

    # Shutdown
    logger.info("AI-OSOP API shutting down...")
    # Never leave independently host-pinned, explicitly started inert Go child
    # processes running after their owning API stops. No auto-start or grant.
    from ai_osop.api.native_inert_fleet_control import shutdown_host_native_inert_fleet_control

    try:
        await shutdown_host_native_inert_fleet_control(app)
    except Exception:
        logger.error("Host-owned inert fleet shutdown outcome UNKNOWN")
    if safety_monitor is not None:
        await safety_monitor.shutdown()
    if bound_temporal_worker is not None:
        await bound_temporal_worker.shutdown()
    if temporal_worker_task is not None:
        await asyncio.gather(temporal_worker_task, return_exceptions=True)
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
    """Log all state-changing API requests with operator and engagement context.

    Includes request_id from CorrelationIdMiddleware for full trace/log correlation.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        response = await call_next(request)
        method = request.method
        request_id = getattr(request.state, "request_id", "unknown")
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            op = request.scope.get("operator", {})
            operator_id = op.get("sub", "anonymous") if isinstance(op, dict) else "anonymous"
            logger.info(
                "api_audit",
                extra={
                    "method": method,
                    "path": request.url.path,
                    "operator_id": operator_id,
                    "status_code": response.status_code,
                    "user_agent": request.headers.get("user-agent", ""),
                    "client_ip": request.client.host if request.client else "",
                    "request_id": request_id,
                },
            )
        return response


class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """Track request counts, durations, and errors for Prometheus.

    Prometheus metrics use route templates (e.g. /engagements/{session_id})
    rather than raw entity IDs to prevent high time-series cardinality.
    """

    @staticmethod
    def _get_path_template(request: Request) -> str:
        """Extract matched route template or collapse dynamic entity IDs."""
        route = request.scope.get("route")
        if route and hasattr(route, "path"):
            return getattr(route, "path")
        raw_path = request.url.path
        # Normalize dynamic entity prefixes and UUIDs to avoid high cardinality
        normalized = re.sub(
            r"/(eng|asset|ep|endpoint|vuln|payload|task|apr|evt|dlq|flow|art)-[a-zA-Z0-9_\-]+",
            r"/\1-{id}",
            raw_path,
        )
        normalized = re.sub(
            r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            r"/{id}",
            normalized,
        )
        return normalized

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        method = request.method
        start = time.time()
        response = None
        try:
            response = await call_next(request)
        except Exception:
            path_label = self._get_path_template(request)
            ERRORS_TOTAL.labels(status_code="500", path=path_label).inc()
            raise
        finally:
            path_label = self._get_path_template(request)
            duration = time.time() - start
            REQUEST_DURATION.labels(method=method, path=path_label).observe(duration)
            status_code = str(response.status_code) if response is not None else "500"
            REQUESTS_TOTAL.labels(method=method, path=path_label, status_code=status_code).inc()
            if response is not None and response.status_code >= 400:
                ERRORS_TOTAL.labels(status_code=str(response.status_code), path=path_label).inc()
        return response


# Middleware stack (applied in order: LAST added = OUTERMOST = first to execute):
#   CorrelationIdMiddleware    → outermost: injects X-Request-ID, binds RequestContext, OTel span
#   PrometheusMetricsMiddleware → counts/durations/errors (within trace context)
#   AuditLogMiddleware          → audit log for state-changing requests (has request_id)
#   SecurityHeadersMiddleware   → innermost: adds security headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(PrometheusMetricsMiddleware)
app.add_middleware(CorrelationIdMiddleware)

# Register routers
app.include_router(health_router)
app.include_router(auth.router)
app.include_router(engagements.router)
app.include_router(report_attestations.router)
app.include_router(diagnostics.router)
app.include_router(flows.router)
app.include_router(flow_artifacts.router)
app.include_router(candidate_evidence_artifacts.router)
app.include_router(flow_artifact_reviews.router)
app.include_router(flow_tool_proposals.router)
app.include_router(flow_resource_aliases.router)
app.include_router(flow_resource_folders.router)
app.include_router(flow_mcp_actions.router)
app.include_router(flow_mcp_readiness.router)
app.include_router(operator_knowledge.router)
app.include_router(operator_global_library.router)
app.include_router(reviewed_library_flow_import.router)
app.include_router(unified_knowledge_search.router)
app.include_router(mcp_tool_catalog.router)
app.include_router(native_browser_source_authority.router)
app.include_router(native_browser_current_authority.router)
app.include_router(create_browser_current_custody_router())
app.include_router(native_sourcemap_source_authority.router)
app.include_router(native_sourcemap_status_authority.router)
app.include_router(native_mcp_redemption.router)
app.include_router(native_mcp_grants.router)
app.include_router(native_mcp_resources.router)
app.include_router(native_mcp_stage_receipts.router)
app.include_router(native_mcp_supervision.router)
app.include_router(native_inert_fleet.router)
app.include_router(mcp_transport_operator_diagnostics_router)
app.include_router(mcp_eleven_supervised_recovery_router)
app.include_router(create_source_map_host_witness_router())
app.include_router(supervision.router)
app.include_router(durable_supervision_subscriptions.router)
app.include_router(provider_invoices.router)
app.include_router(provider_route_policy_reviews.router)
app.include_router(provider_credential_profile_refs.router)
app.include_router(tasks.router)
app.include_router(agents.router)
app.include_router(approvals.router)
app.include_router(sessions.router)
app.include_router(findings.router)
app.include_router(target_authority.router)
app.include_router(verified_finding_reviews.router)
app.include_router(intelligence.router)
app.include_router(system.router)


# ============== Metrics (protected) ==============


@app.get("/metrics")
async def metrics(operator: Dict[str, Any] = Depends(require_role("senior_operator"))):
    """Prometheus metrics endpoint."""
    content = render_prometheus()
    return Response(content, media_type=CONTENT_TYPE_LATEST)


# ============== Authenticated engagement WebSocket ==============


from ai_osop.api.deps import assert_engagement_access, verify_token  # noqa: E402


_WS_AUTH_RECHECK_SECONDS = 30.0


@app.websocket("/ws/engagements/{engagement_id}")
async def websocket_engagement(websocket: WebSocket, engagement_id: str):
    """Require headerless-browser first-frame bearer authentication.

    Browser WS cannot send an Authorization header. A bounded first message
    contains the bearer token only in the encrypted WS payload (never URL,
    subprotocol, close reason, error body, metrics, or logs).
    """
    import re
    from fastapi.security import HTTPAuthorizationCredentials
    from starlette.websockets import WebSocketDisconnect

    async def deny(code: int = 1008) -> None:
        # Close reasons intentionally never echo credentials or exceptions.
        await websocket.close(code=code)

    async def bounded_message(timeout: Optional[float] = None) -> Dict[str, Any]:
        # Receive raw ASGI text and check size *before* parsing; never echo
        # untrusted input or accept binary frames.
        frame = (
            await asyncio.wait_for(websocket.receive(), timeout=timeout)
            if timeout is not None
            else await websocket.receive()
        )
        if frame.get("type") != "websocket.receive":
            raise WebSocketDisconnect(code=1000)
        body = frame.get("text")
        if not isinstance(body, str):
            raise ValueError("Non-text WebSocket frame")
        if len(body.encode("utf-8")) > 8192:
            raise OverflowError("Oversized WebSocket frame")
        parsed = json.loads(body)
        if not isinstance(parsed, dict):
            raise ValueError("Non-object WebSocket message")
        return parsed

    async def current_owner(principal: Dict[str, Any]) -> Any:
        # Never trust _sessions, a pre-handshake snapshot, or cached ownership.
        orch = state.get("orchestrator")
        if orch is None or not getattr(orch, "session_memory", None):
            raise PermissionError("Durable engagement unavailable")
        authoritative = await asyncio.wait_for(
            orch.session_memory.load_session_state(engagement_id), timeout=3.0
        )
        if (
            authoritative is None
            or authoritative.session_id != engagement_id
            or authoritative.scope.engagement_id != engagement_id
        ):
            raise PermissionError("No durable engagement")
        if principal.get("role") not in ("senior_operator", "operator"):
            raise PermissionError("Operator role required")
        if principal["role"] != "senior_operator" and (
            not authoritative.created_by or authoritative.created_by != principal.get("sub")
        ):
            raise PermissionError("Engagement not owned by operator")
        return authoritative

    # An Origin header is sent by browsers and checked independently of
    # CORSMiddleware (which does not protect WebSocket handshakes).
    origin = websocket.headers.get("origin")
    allowlist = settings.cors_allowed_origins
    prod = settings.environment.strip().lower() in {"production", "prod"}
    if websocket.query_params or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", engagement_id):
        await deny()
        return
    if origin is not None and ("*" in allowlist or origin not in allowlist):
        await deny()
        return
    if websocket.url.scheme != "wss" and (
        prod or websocket.url.hostname not in {"localhost", "127.0.0.1", "::1"}
    ):
        # Plaintext WS is allowed for loopback development only. Secure
        # reverse proxies must convey the actual ASGI wss scheme.
        await deny()
        return
    if prod and not origin:
        await deny()
        return

    await websocket.accept()
    try:
        first = await bounded_message(timeout=5.0)
        if set(first) != {"type", "token"} or first.get("type") != "auth":
            await deny()
            return
        bearer = first.get("token")
        if not isinstance(bearer, str) or not bearer or len(bearer) > 4096:
            await deny()
            return
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=bearer)

        # The JWT may expire while WS remains open: recheck on every message.
        async def principal() -> Dict[str, Any]:
            verified = await verify_token(credentials=credentials, token=None)
            if (
                not isinstance(verified, dict)
                or verified.get("role") not in ("operator", "senior_operator")
                or not verified.get("sub")
            ):
                raise PermissionError("Operator role required")
            return verified

        await current_owner(await principal())
        await websocket.send_json({"type": "auth_ready", "session_id": engagement_id})

        while True:
            try:
                message = await bounded_message(timeout=_WS_AUTH_RECHECK_SECONDS)
            except asyncio.TimeoutError:
                # Without a client frame, an idle WebSocket could outlive an
                # emergency account disable indefinitely. Recheck the
                # PostgreSQL-backed bearer and tenant owner periodically;
                # never deliver new events or commands on a revoked channel.
                await current_owner(await principal())
                continue
            if set(message) != {"action"} and set(message) != {"action", "reason"}:
                await deny()
                return
            action = message.get("action")
            operator = await principal()
            session = await current_owner(operator)
            if action == "ping":
                await websocket.send_json({"type": "pong"})
            elif action == "status":
                # Revocation blocks execution, not harmless owned display.
                # Never expose global cross-engagement task/agent counters.
                await websocket.send_json(
                    {"type": "status", "session_id": engagement_id, "phase": session.phase}
                )
            elif action == "halt":
                if operator.get("role") != "senior_operator":
                    await deny()
                    return
                reason = message.get("reason", "Operator halt")
                if (
                    not isinstance(reason, str)
                    or not (1 <= len(reason) <= 128)
                    or any(ord(c) < 32 or ord(c) == 127 for c in reason)
                ):
                    await deny()
                    return
                orch = state["orchestrator"]
                # Mutating commands must use current, signed, unrevoked PG ROE.
                # A cached authorization_ref is never sufficient.
                await asyncio.wait_for(
                    orch.session_memory.assert_signed_authorization(engagement_id),
                    timeout=3.0,
                )
                await orch.halt_engagement(engagement_id, reason)
                # A workflow halt receipt does not prove a remote scanner
                # stopped. Do not send an unjustified "halted" confirmation.
                await websocket.send_json(
                    {
                        "type": "halt_requested",
                        "session_id": engagement_id,
                        "remote_stop_confirmed": False,
                    }
                )
            else:
                await deny()
                return
    except OverflowError:
        await deny(code=1009)
    except (asyncio.TimeoutError, ValueError, PermissionError, HTTPException):
        await deny()
    except WebSocketDisconnect:
        return
    except Exception:
        # DB outage, revoked signing key, or execution failure must not leak
        # exception text or leave the channel implicitly authorized.
        try:
            await deny()
        except (RuntimeError, WebSocketDisconnect):
            pass
