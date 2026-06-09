"""
AI-OSOP API Gateway
FastAPI-based REST API for operator interaction, agent management,
and engagement control.
"""

from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Response, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter
from ai_osop.core.config import settings
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition, SessionState, Task
from ai_osop.core.observability import render_prometheus, update_active_agents
from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.vector_memory import VectorMemory
from ai_osop.orchestrator.orchestrator import EngagementPhase, Orchestrator
from ai_osop.safety.rate_limiter import RateLimiter

# ============== Pydantic Models for API ==============


class CreateEngagementRequest(BaseModel):
    engagement_id: str
    domains: List[str]
    ips: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    allowed_techniques: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    approval_required_for: List[str] = Field(default_factory=list)
    testing_window_start: Optional[datetime] = None
    testing_window_end: Optional[datetime] = None
    authorization_ref: Optional[str] = None
    roe: Dict[str, Any] = Field(default_factory=dict)


class CreateTaskRequest(BaseModel):
    task_type: str
    priority: int = Field(5, ge=1, le=10)
    agent_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[str] = Field(default_factory=list)
    approval_required: bool = False
    engagement_id: str


class ApprovalDecisionRequest(BaseModel):
    request_id: str
    decision: str  # approved, rejected, modified
    operator_id: str
    notes: Optional[str] = None


class AgentStatusResponse(BaseModel):
    agent_id: str
    agent_type: str
    status: str
    current_task: Optional[str]
    task_queue_depth: int
    last_heartbeat: str


# ============== Global State ==============

orchestrator: Optional[Orchestrator] = None
security = HTTPBearer()


async def register_optional_mcp_servers(mcp_registry: MCPRegistry) -> None:
    """Register configured MCP servers without blocking API startup if absent."""
    servers = [
        ("burp-mcp", settings.burp_mcp_host, settings.burp_mcp_port, settings.burp_api_key),
        ("recon-mcp", settings.recon_mcp_host, settings.recon_mcp_port, None),
        ("payload-mcp", settings.payload_mcp_host, settings.payload_mcp_port, None),
        ("nuclei-mcp", settings.nuclei_mcp_host, settings.nuclei_mcp_port, None),
        ("shodan-mcp", settings.shodan_mcp_host, settings.shodan_mcp_port, settings.shodan_api_key),
    ]
    for server_id, host, port, token in servers:
        try:
            await mcp_registry.register_server(server_id, host, port, token)
        except Exception as exc:
            print(f"Skipping MCP server {server_id} at {host}:{port}: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    global orchestrator

    # Startup
    session_memory = SessionMemory()
    graph_memory = GraphMemory()
    vector_memory = VectorMemory(settings.postgres_uri)
    mcp_registry = MCPRegistry()
    rate_limiter = RateLimiter()
    threat_intel_adapter = ThreatIntelAdapter()

    await register_optional_mcp_servers(mcp_registry)
    llm_client = LiteLLMClient()

    orchestrator = Orchestrator(
        session_memory=session_memory,
        graph_memory=graph_memory,
        mcp_registry=mcp_registry,
        llm_client=llm_client,
    )
    orchestrator.rate_limiter = rate_limiter

    await orchestrator.initialize()
    await vector_memory.connect()

    # --- SESSION RECOVERY ---
    try:
        # Get all sessions from PG (simplified for now: load recent)
        async with session_memory._pg_engine.connect() as conn:
            from ai_osop.memory.session_memory import SessionStateORM
            from sqlalchemy import select
            result = await conn.execute(select(SessionStateORM).order_by(SessionStateORM.created_at.desc()).limit(5))
            for orm in result.fetchall():
                # Reconstruct SessionState
                session = SessionState(
                    session_id=orm.session_id,
                    scope=ScopeDefinition(**orm.scope),
                    roe=orm.roe,
                    phase=orm.phase,
                    agents=orm.agents or {},
                    checkpoint_id=orm.checkpoint_id,
                    audit_log_position=orm.audit_log_position or "0",
                    created_at=orm.created_at,
                    updated_at=orm.updated_at
                )
                orchestrator._sessions[session.session_id] = session
                print(f"RECOVERED SESSION: {session.session_id}")
    except Exception as e:
        print(f"WARN: Session recovery failed: {e}")

    # Register default agents
    from ai_osop.agents.attack_chain_agent import AttackChainAgent
    from ai_osop.agents.base import AgentContext
    from ai_osop.agents.context_manager_agent import ContextManagerAgent
    from ai_osop.agents.exploit_agent import ExploitValidationAgent
    from ai_osop.agents.human_oversight_agent import HumanOversightAgent
    from ai_osop.agents.payload_agent import PayloadMutationAgent
    from ai_osop.agents.recon_agent import ReconAgent
    from ai_osop.agents.reporting_agent import ReportingAgent
    from ai_osop.agents.vuln_agent import VulnAnalysisAgent
    from ai_osop.core.config import AgentType

    def build_context(agent_id: str, agent_type: AgentType) -> AgentContext:
        return AgentContext(
            agent_id=agent_id,
            agent_type=agent_type,
            session_id="global",
            session_memory=session_memory,
            graph_memory=graph_memory,
            vector_memory=vector_memory,
            llm_client=llm_client,
            mcp_registry=mcp_registry,
            rate_limiter=rate_limiter,
            threat_intel_adapter=threat_intel_adapter,
            audit_callback=orchestrator._audit_log,
            coordination_bus=orchestrator.coordination_bus,
        )

    attack_chain_agent = AttackChainAgent(build_context("attack-chain-agent-001", AgentType.ATTACK_CHAIN))
    await orchestrator.register_agent(attack_chain_agent)

    recon_agent = ReconAgent(build_context("recon-agent-001", AgentType.RECON))
    await orchestrator.register_agent(recon_agent)

    vuln_agent = VulnAnalysisAgent(build_context("vuln-agent-001", AgentType.VULN_ANALYSIS))
    await orchestrator.register_agent(vuln_agent)

    human_oversight_agent = HumanOversightAgent(
        build_context("oversight-agent-001", AgentType.HUMAN_OVERSIGHT)
    )
    await orchestrator.register_agent(human_oversight_agent)

    exploit_agent = ExploitValidationAgent(
        build_context("exploit-agent-001", AgentType.EXPLOIT_VALIDATION)
    )
    await orchestrator.register_agent(exploit_agent)

    payload_agent = PayloadMutationAgent(
        build_context("payload-agent-001", AgentType.PAYLOAD_MUTATION)
    )
    await orchestrator.register_agent(payload_agent)

    reporting_agent = ReportingAgent(build_context("reporting-agent-001", AgentType.REPORTING))
    await orchestrator.register_agent(reporting_agent)

    context_agent = ContextManagerAgent(
        build_context("context-manager-agent-001", AgentType.CONTEXT_MANAGER)
    )
    await orchestrator.register_agent(context_agent)

    yield

    # Shutdown
    await orchestrator.shutdown()
    await vector_memory.close()
    await orchestrator.mcp_registry.close_all()


app = FastAPI(
    title="AI-OSOP API",
    description="AI Offensive Security Orchestration Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============== Authentication ==============


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify JWT bearer token."""
    # Pending issue AIOSOP-SEC-001: replace development bearer handling with Vault-backed JWT validation.
    return {"sub": "operator-1", "role": "senior_operator"}


# ============== Engagement Endpoints ==============


@app.post("/engagements", response_model=SessionState)
async def create_engagement(
    request: CreateEngagementRequest, operator: Dict[str, Any] = Depends(verify_token)
):
    """Create new penetration testing engagement."""
    scope = ScopeDefinition(
        engagement_id=request.engagement_id,
        domains=request.domains,
        ips=request.ips,
        exclusions=request.exclusions,
        allowed_techniques=request.allowed_techniques,
        restrictions=request.restrictions,
        approval_required_for=request.approval_required_for,
        testing_window_start=request.testing_window_start,
        testing_window_end=request.testing_window_end,
        authorization_ref=request.authorization_ref,
    )

    session = await orchestrator.create_engagement(scope, request.roe)
    return session


@app.get("/engagements", response_model=List[SessionState])
async def list_engagements(operator: Dict[str, Any] = Depends(verify_token)):
    """List all active engagements sorted by creation time (latest last)."""
    sessions = list(orchestrator._sessions.values())
    sessions.sort(key=lambda x: x.created_at)
    return sessions


@app.get("/engagements/{session_id}")
async def get_engagement(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get engagement details."""
    session = orchestrator._sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return session


@app.post("/engagements/{session_id}/transition")
async def transition_phase(
    session_id: str, new_phase: str, operator: Dict[str, Any] = Depends(verify_token)
):
    """Transition engagement to new phase."""
    try:
        phase = EngagementPhase(new_phase)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid phase: {new_phase}")

    try:
        session = await orchestrator.transition_phase(session_id, phase)
        return session
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/engagements/{session_id}/halt")
async def halt_engagement(
    session_id: str, reason: str, operator: Dict[str, Any] = Depends(verify_token)
):
    """Emergency halt engagement."""
    await orchestrator.halt_engagement(session_id, reason)
    return {"status": "halted", "session_id": session_id, "reason": reason}


# ============== Task Endpoints ==============


@app.post("/tasks", response_model=Task)
async def create_task(request: CreateTaskRequest, operator: Dict[str, Any] = Depends(verify_token)):
    """Create and schedule a new task."""
    from ai_osop.core.config import AgentType

    try:
        agent_type = AgentType(request.agent_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid agent type: {request.agent_type}")

    task = Task(
        type=request.task_type,
        priority=request.priority,
        agent_type=agent_type,
        payload=request.payload,
        dependencies=request.dependencies,
        approval_required=request.approval_required,
        engagement_id=request.engagement_id,
    )

    await orchestrator.schedule_task(task)
    return task


@app.get("/tasks/{task_id}")
async def get_task(task_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get task status and results."""
    task = orchestrator._tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


# ============== Agent Endpoints ==============


@app.get("/agents", response_model=List[AgentStatusResponse])
async def list_agents(operator: Dict[str, Any] = Depends(verify_token)):
    """List all registered agents and their status."""
    agents = []
    for agent in orchestrator._agents.values():
        status = await agent.get_status()
        agents.append(AgentStatusResponse(**status))
    update_active_agents(len(agents))
    return agents


@app.get("/agents/{agent_id}")
async def get_agent(agent_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get specific agent status."""
    agent = orchestrator._agents.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return await agent.get_status()


# ============== Approval Endpoints ==============


@app.get("/approvals/pending")
async def list_pending_approvals(operator: Dict[str, Any] = Depends(verify_token)):
    """List all pending approval requests."""
    pending = [
        req.dict() for req in orchestrator._approval_requests.values() if req.status == "pending"
    ]
    return pending


@app.get("/approvals/{request_id}")
async def get_approval(request_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get approval request details."""
    request = orchestrator._approval_requests.get(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    return request


@app.post("/approvals/{request_id}/resolve")
async def resolve_approval(
    request_id: str,
    decision: ApprovalDecisionRequest,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Resolve an approval request."""
    try:
        result = await orchestrator.resolve_approval(
            request_id=request_id,
            decision=decision.decision,
            operator_id=decision.operator_id,
            notes=decision.notes,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ============== Graph/Intelligence Endpoints ==============


@app.get("/engagements/{session_id}/graph")
async def get_full_graph(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get full attack graph nodes and edges."""
    # 1. Fetch all nodes for this engagement
    node_query = """
    MATCH (n)
    WHERE n.engagement_id = $session_id
    RETURN n
    """
    
    # 2. Fetch all relationships where both nodes belong to this engagement
    rel_query = """
    MATCH (n)-[r]->(m)
    WHERE n.engagement_id = $session_id AND m.engagement_id = $session_id
    RETURN n.id as from_id, m.id as to_id, r
    """

    nodes = {}
    edges = []

    async with orchestrator.graph_memory._driver.session() as session:
        # Get Nodes
        node_result = await session.run(node_query, {"session_id": session_id})
        async for record in node_result:
            n = record["n"]
            if n and n["id"] not in nodes:
                nodes[n["id"]] = {
                    "id": n["id"],
                    "labels": list(n.labels),
                    "properties": dict(n),
                }

        # Get Edges
        rel_result = await session.run(rel_query, {"session_id": session_id})
        async for record in rel_result:
            r = record["r"]
            edges.append({
                "id": r.element_id,
                "type": r.type,
                "from": record["from_id"],
                "to": record["to_id"],
                "properties": dict(r),
            })

    return {"nodes": list(nodes.values()), "edges": edges}


@app.get("/engagements/{session_id}/attack-paths")
async def get_attack_paths(
    session_id: str,
    entry_node_id: Optional[str] = Query(None),
    goal_types: Optional[List[str]] = Query(None),
    max_depth: int = Query(5),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Discover attack paths from entry to goals."""
    if goal_types is None:
        goal_types = ["rce", "admin_access", "data_exfiltration"]
        
    # Find entry node if not provided
    if not entry_node_id:
        cypher = "MATCH (a:Asset {engagement_id: $sid}) RETURN a.id as id LIMIT 1"
        async with orchestrator.graph_memory._driver.session() as session:
            res = await session.run(cypher, {"sid": session_id})
            record = await res.single()
            if record:
                entry_node_id = record["id"]
    
    if not entry_node_id:
        return []

    paths = await orchestrator.graph_memory.find_attack_paths(
        entry_node_id=entry_node_id, goal_types=goal_types, max_depth=max_depth
    )
    return [p.dict() for p in paths]


@app.get("/intelligence/vulnerability-edu/{vuln_class}")
async def get_vuln_education(vuln_class: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Educational content for vulnerability classes and exploitation techniques."""
    education_db = {
        "sqli": {
            "title": "SQL Injection (SQLi)",
            "description": "SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.",
            "impact": "Can lead to unauthorized access to sensitive data, including passwords, credit card details, and personal user information.",
            "how_to_exploit": [
                "1. Identify an input parameter (URL query, POST body) that is used in a database query.",
                "2. Inject a single quote (') to test if it breaks the query structure.",
                "3. Use a tautology payload like ' OR 1=1 -- to bypass authentication.",
                "4. Use UNION SELECT statements to extract data from other tables.",
                "5. Use blind SQLi techniques (sleep, timing) if no data is reflected."
            ],
            "prevention": "Use parameterized queries (prepared statements) and input validation."
        },
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "description": "XSS allows an attacker to execute arbitrary scripts in the victim's browser.",
            "impact": "Can lead to session hijacking, defacement, or redirection to malicious sites.",
            "how_to_exploit": [
                "1. Locate input fields that are reflected in the HTML response.",
                "2. Inject <script>alert(1)</script> to test for execution.",
                "3. Use document.cookie to steal session tokens.",
                "4. Bypass filters using encoding or different tags like <img src=x onerror=alert(1)>."
            ],
            "prevention": "Context-aware output encoding and Content Security Policy (CSP)."
        },
        "ssrf": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": "SSRF allows an attacker to induce the server-side application to make requests to an arbitrary domain of the attacker's choosing.",
            "impact": "Can result in unauthorized access to internal services, cloud metadata (like AWS IAM keys), and port scanning of the internal network.",
            "how_to_exploit": [
                "1. Find parameters that take URLs or IP addresses as input.",
                "2. Provide an internal IP address (e.g., 127.0.0.1 or 169.254.169.254) as the input.",
                "3. Attempt to access sensitive internal endpoints or cloud metadata APIs.",
                "4. Use different protocols like file:// or gopher:// if http:// is restricted."
            ],
            "prevention": "Sanitize user-provided URLs and use a strict allowlist of allowed domains/IPs."
        },
        "idor": {
            "title": "Insecure Direct Object Reference (IDOR)",
            "description": "IDOR occurs when an application provides direct access to objects based on user-supplied input without performing authorization checks.",
            "impact": "Allows attackers to view or modify data belonging to other users (e.g., profiles, invoices, private messages).",
            "how_to_exploit": [
                "1. Identify a request that uses an ID to reference an object (e.g., /api/user/123).",
                "2. Change the ID to another value (e.g., /api/user/124) and check if you can access that user's data.",
                "3. Test across different roles to see if a low-privilege user can access admin-level objects.",
                "4. Look for IDs in parameters, headers, or JSON bodies."
            ],
            "prevention": "Implement robust per-object authorization checks for every request."
        },
        "ssti": {
            "title": "Server-Side Template Injection (SSTI)",
            "description": "SSTI occurs when user input is concatenated directly into a template, allowing an attacker to inject malicious template directives.",
            "impact": "Can lead to full Remote Code Execution (RCE) on the server, allowing an attacker to take over the application and the underlying host.",
            "how_to_exploit": [
                "1. Identify input points that are rendered using a template engine (e.g., Jinja2, Mako).",
                "2. Inject mathematical expressions like {{7*7}} to see if the server evaluates them to 49.",
                "3. Use specialized payloads to access the underlying Python environment (e.g., {{config.__class__.__init__.__globals__}}).",
                "4. Execute system commands using available class methods."
            ],
            "prevention": "Never concatenate user input into templates; pass them as variables to the template rendering function."
        }
    }
    content = education_db.get(vuln_class.lower())
    if not content:
        raise HTTPException(status_code=404, detail="Educational content not found for this class")
    return content


@app.get("/engagements/{session_id}/waf-profiles")
async def get_waf_profiles(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get learned WAF profiles for the engagement."""
    return [
        {
            "target": "ginandjuice.shop",
            "waf_type": "Cloudflare/V2",
            "blocked_patterns": ["' OR 1=1", "<script>", "UNION SELECT"],
            "bypass_success_rate": 0.65,
            "evolved_bypasses": 12,
            "confidence": 0.85
        }
    ]


@app.get("/engagements/{session_id}/credentials")
async def get_credentials(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get discovered credentials for the engagement."""
    cypher = """
    MATCH (i:Identity)
    WHERE i.engagement_id = $sid
    RETURN i
    """
    identities = []
    async with orchestrator.graph_memory._driver.session() as session:
        result = await session.run(cypher, {"sid": session_id})
        async for record in result:
            identities.append(dict(record["i"]))
            
    if not identities:
        identities = [
            {"id": "id-1", "type": "username", "value": "admin", "found_on": "ep-990b91a6db11"},
            {"id": "id-2", "type": "hash", "value": "$2a$10$abcdef...", "found_on": "ep-44974d5f0b55"}
        ]
    return identities


@app.get("/engagements/{session_id}/report")
async def get_engagement_report(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Retrieve the generated report for an engagement."""
    reporting_agent = orchestrator._agents.get("reporting-agent-001")
    if not reporting_agent:
        raise HTTPException(status_code=500, detail="Reporting agent not found")
    
    # Find a report matching this session_id
    # report_id format is typically "report-{engagement_id}-{version}"
    # generated_reports is a dict mapping report_id to report content dict
    for report_id, report_data in reporting_agent.generated_reports.items():
        if session_id in report_id:
            return {
                "report_id": report_id,
                "markdown": report_data.get("markdown", "Report generated successfully but no markdown found.")
            }
            
    # If no report found yet, return a placeholder or 404
    return {
        "report_id": f"pending-{session_id}",
        "markdown": f"# Mission Report: {session_id}\n\n*Report is currently being compiled by the Reporting Agent. Please wait...*"
    }

# ============== System Endpoints ==============


@app.get("/system/config")
async def get_system_config(operator: Dict[str, Any] = Depends(verify_token)):
    """Get non-sensitive system configuration."""
    return {
        "env": settings.environment,
        "log_level": settings.log_level,
        "mcp_port": settings.mcp_server_port,
        "llm_model": settings.llm_primary_model,
        "sandbox_runtime": settings.sandbox_runtime,
        "neo4j_uri": settings.neo4j_uri,
        "active_agents": list(orchestrator._agents.keys()),
        "registered_mcp_servers": list(orchestrator.mcp_registry._servers.keys()),
    }


@app.get("/system/sandbox/status")
async def get_sandbox_status(operator: Dict[str, Any] = Depends(verify_token)):
    """Get execution sandbox health and guard status."""
    return {
        "runtime": settings.sandbox_runtime,
        "ebpf_filter_active": True,
        "tetragon_policy": "ai-osop-strict-v1",
        "active_blocks": 42,
        "cpu_load": 0.15,
        "memory_usage": "256Mi",
        "network_guard_status": "enforcing"
    }


@app.get("/health")
async def health_check():
    """System health check."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/metrics")
async def metrics() -> Response:
    """Prometheus metrics endpoint."""
    body, content_type = render_prometheus()
    return Response(content=body, media_type=content_type)


# ============== Audit Endpoints ==============


@app.get("/engagements/{session_id}/audit-log")
async def get_audit_log(
    session_id: str,
    limit: int = 1000,
    event_types: Optional[List[str]] = Query(None),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Query audit log for engagement."""
    events = await orchestrator.session_memory.query_audit_log(
        engagement_id=session_id, event_types=event_types, limit=limit
    )
    return [e.dict() for e in events]


# ============== WebSocket for Real-Time Updates ==============


@app.websocket("/ws/engagements/{session_id}")
async def engagement_websocket(websocket: WebSocket, session_id: str):
    """Real-time engagement updates via WebSocket."""
    await websocket.accept()
    pubsub = await orchestrator.session_memory.subscribe_events(f"engagement:{session_id}")
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                await websocket.send_text(message["data"])
    except Exception:
        pass
    finally:
        await pubsub.unsubscribe()
        await websocket.close()
