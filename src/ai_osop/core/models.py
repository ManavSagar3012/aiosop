"""
AI-OSOP Shared Data Models
Pydantic models for all cross-component communication.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator

from ai_osop.core.config import AgentType, Severity, VulnClass

# ================= BASE ENTITIES =================


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: f"asset-{uuid.uuid4().hex[:12]}")
    type: str  # domain, subdomain, ip, endpoint, service, identity
    value: str
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    engagement_id: str


class Endpoint(BaseModel):
    id: str = Field(default_factory=lambda: f"ep-{uuid.uuid4().hex[:12]}")
    url: str
    method: str = "GET"
    type: str = "web"  # web, api, websocket, graphql
    engagement_id: str

    # Web-oriented fields
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    auth_required: bool = False
    asset_id: str = ""
    source: str = ""
    screenshot_path: Optional[str] = None

    # API-oriented fields (unified from APIEndpoint)
    host: str = ""
    path: str = ""
    query_keys: List[str] = Field(default_factory=list)
    has_body: bool = False
    content_type: str = ""
    body_schema_keys: List[str] = Field(default_factory=list)
    auth_class: str = "anonymous"  # anonymous | bearer | cookie | mixed
    request_headers_sample: Dict[str, str] = Field(default_factory=dict)
    status_codes_seen: List[int] = Field(default_factory=list)
    response_size_avg: int = 0
    response_content_type: str = ""
    user_label: str = ""
    workflow_id: str = ""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    observations: int = 0

    # Common
    confidence: float = Field(0.5, ge=0.0, le=1.0)


class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: f"vuln-{uuid.uuid4().hex[:12]}")
    cwe: Optional[str] = None
    vuln_type: VulnClass
    severity: Severity
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    title: str
    description: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    tool_source: str
    endpoint_id: Optional[str] = None
    asset_id: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    entry_point: bool = False  # Can be reached from unauthenticated position
    requires_auth: bool = False
    validated: bool = False
    exploitability: str = "unknown"  # high, medium, low, unknown
    impact: str = "unknown"
    correlated_ids: List[str] = Field(default_factory=list)
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Payload(BaseModel):
    id: str = Field(default_factory=lambda: f"payload-{uuid.uuid4().hex[:12]}")
    vuln_type: VulnClass
    content: str  # Actual payload string
    content_hash: str
    encoding_chain: List[str] = Field(default_factory=list)  # e.g., ["url", "base64"]
    context: Dict[str, Any] = Field(default_factory=dict)  # injection point details
    generation: int = 0  # Generation number in evolutionary algorithm
    parent_id: Optional[str] = None
    fitness_score: float = Field(0.0, ge=0.0, le=1.0)
    strategy: str = "template"  # template, llm, genetic, manual
    validated: bool = False
    success_indicator: float = Field(0.0, ge=0.0, le=1.0)
    waf_bypassed: Optional[bool] = None
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Exploit(BaseModel):
    id: str = Field(default_factory=lambda: f"exp-{uuid.uuid4().hex[:12]}")
    vuln_id: str
    payload_id: str
    type: str
    validated: bool = False
    operator_approved: bool = False
    approval_id: Optional[str] = None
    evidence_path: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    time_to_exploit: Optional[int] = None  # seconds
    impact_confirmed: Optional[str] = None
    engagement_id: str


class AttackPath(BaseModel):
    id: str = Field(default_factory=lambda: f"path-{uuid.uuid4().hex[:12]}")
    node_ids: List[str]
    edge_ids: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=10.0)
    total_time_estimate: int = 0  # seconds
    detection_risk: float = Field(0.0, ge=0.0, le=1.0)
    validated: bool = False
    entry_node_id: str
    goal_node_id: str
    engagement_id: str


class Task(BaseModel):
    id: str = Field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")
    type: str
    priority: int = Field(5, ge=1, le=10)
    agent_type: AgentType
    payload: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[str] = Field(default_factory=list)
    max_retries: int = 3
    timeout_seconds: int = 300
    scope_check: bool = True
    approval_required: bool = False
    status: str = "pending"  # pending, running, completed, failed, cancelled
    result: Optional[Dict[str, Any]] = None
    retry_count: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    engagement_id: str
    assigned_agent_id: Optional[str] = None


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:12]}")
    task_id: str
    agent_id: str
    action_type: str
    target: str
    payload_summary: str
    risk_assessment: str
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "pending"  # pending, approved, rejected, modified, timeout
    operator_id: Optional[str] = None
    operator_notes: Optional[str] = None
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    responded_at: Optional[datetime] = None
    engagement_id: str


class ScopeDefinition(BaseModel):
    engagement_id: str
    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    allowed_techniques: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    approval_required_for: List[str] = Field(default_factory=list)
    testing_window_start: Optional[datetime] = None
    testing_window_end: Optional[datetime] = None
    authorization_ref: Optional[str] = None  # Path to signed ROE document


class SessionState(BaseModel):
    session_id: str
    scope: ScopeDefinition
    roe: Dict[str, Any] = Field(default_factory=dict)
    phase: str = "initialized"
    agents: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    checkpoint_id: Optional[str] = None
    audit_log_position: str = "0"
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str
    severity: str
    actor_type: str  # agent, operator, system
    actor_id: str
    action: Dict[str, Any]
    result: Dict[str, Any]
    context: Dict[str, Any]
    integrity_hash: Optional[str] = None
    engagement_id: str


class DiffAuthFinding(BaseModel):
    """Result of a differential authorization comparison between two identities."""

    id: str = Field(default_factory=lambda: f"diff-{uuid.uuid4().hex[:12]}")
    category: str  # horizontal_pe, vertical_pe, tenant_escape, workflow_bypass
    resource_id: str
    test_identity_id: str  # The identity that attempted access
    expected_result: str  # e.g. "403 Forbidden"
    observed_result: str  # e.g. "200 OK"
    evidence_diff: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Resource(BaseModel):
    """A protected resource targeted by differential authorization tests."""

    id: str
    type: str  # endpoint, record, file, ...
    value: str
    owner_identity_id: str = ""
    discovery_step_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    engagement_id: str


class PermissionMatrix(BaseModel):
    """Per-identity expected access map. Used by DifferentialAuthEngine baselines."""

    id: str = Field(default_factory=lambda: f"pm-{uuid.uuid4().hex[:12]}")
    resource_id: str
    identity_id: str
    expected_allowed: bool = False
    engagement_id: str


class BrowserSession(BaseModel):
    """Captured browser identity envelope (cookies + storage)."""

    id: str = Field(default_factory=lambda: f"bs-{uuid.uuid4().hex[:12]}")
    user_label: str
    engagement_id: str
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    local_storage: Dict[str, Any] = Field(default_factory=dict)
    session_storage: Dict[str, Any] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=datetime.utcnow)


class Workflow(BaseModel):
    """A recorded user/agent journey across endpoints."""

    id: str = Field(default_factory=lambda: f"wf-{uuid.uuid4().hex[:12]}")
    name: str
    role: str = "guest"
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class WorkflowStep(BaseModel):
    """One step within a Workflow, linked to an Endpoint."""

    id: str = Field(default_factory=lambda: f"step-{uuid.uuid4().hex[:12]}")
    workflow_id: str
    endpoint_id: str
    order: int = 0
    action_type: str = "NAVIGATE"
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class WorkflowTransition(BaseModel):
    """Edge between two WorkflowSteps."""

    id: str = Field(default_factory=lambda: f"tr-{uuid.uuid4().hex[:12]}")
    from_step_id: str
    to_step_id: str
    trigger: str = "auto"
    engagement_id: str


class Observation(BaseModel):
    """Structured agent observation published to the coordination bus."""

    id: str = Field(default_factory=lambda: f"obs-{uuid.uuid4().hex[:12]}")
    type: str
    source_agent_id: str
    target_id: str
    data: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    provenance: str = "live"
    engagement_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ================= MISSING MODELS FOR SWARM GOVERNANCE & AUDITS =================


class OutcomeStatus(str, Enum):
    PAID = "paid"
    TRIAGED = "triaged"
    SUBMITTED = "submitted"
    VERIFIED = "verified"
    # AIOSOP-AUDIT-2026-06-16: referenced by BugBountyAdapter.sync_outcomes for
    # reports a program closes as not-applicable/duplicate/informative. Was missing,
    # which would raise AttributeError on the live H1 sync path.
    REJECTED = "rejected"


class OutcomeRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"out-{uuid.uuid4().hex[:12]}")
    finding_id: str
    finding_type: str
    status: Union[OutcomeStatus, str]
    severity: str
    cost_total: float = 0.0
    time_to_finding_seconds: Optional[int] = None
    agent_id_responsible: str
    program_name: Optional[str] = None
    external_report_id: Optional[str] = None
    program_payout: float = 0.0
    is_accepted: bool = False
    engagement_id: str
    stack: List[str] = Field(default_factory=list)
    workflow_intent: Optional[str] = None
    validated: bool = False
    initial_confidence: float = 0.0
    time_to_validate_seconds: Optional[int] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UncertaintyRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"unc-{uuid.uuid4().hex[:12]}")
    target_id: str
    knowns: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    blocked_paths: List[str] = Field(default_factory=list)
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class CriticalOperation(BaseModel):
    id: str = Field(default_factory=lambda: f"cop-{uuid.uuid4().hex[:12]}")
    name: str
    type: str
    source: str
    confidence: float
    related_node_id: str
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class VisualAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: f"va-{uuid.uuid4().hex[:12]}")
    screenshot_path: str
    workflow_step_id: str
    user_role: str
    visible_actions: List[Dict[str, Any]] = Field(default_factory=list)
    business_context: str
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class SwarmBudget(BaseModel):
    id: str = Field(default_factory=lambda: f"bud-{uuid.uuid4().hex[:12]}")
    total_budget: float
    spent_budget: float = 0.0
    system1_requests: int = 0
    system2_requests: int = 0
    engagement_id: str


class BusinessInvariant(BaseModel):
    id: str = Field(default_factory=lambda: f"inv-{uuid.uuid4().hex[:12]}")
    description: str
    target_resource_type: str
    required_state: Optional[str] = None
    violation_strategy: str
    actor_constraints: List[str] = Field(default_factory=list)
    engagement_id: str


class EvidenceProvenance(str, Enum):
    MOCK = "mock"
    SIMULATED = "simulated"
    LIVE = "live"


class VerificationStage(BaseModel):
    name: str
    status: str


class VerificationRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"ver-{uuid.uuid4().hex[:12]}")
    finding_id: str
    provenance: EvidenceProvenance = EvidenceProvenance.LIVE
    is_verified: bool = False
    overall_confidence: float = 0.0
    evidence_chain_score: float = 0.0
    stages: List[VerificationStage] = Field(default_factory=list)
    agreed_agents: List[str] = Field(default_factory=list)
    replayable: bool = False
    replayability_score: float = 0.0
    evidence_sources: List[str] = Field(default_factory=list)
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ProcessState(BaseModel):
    """A single state in a business-process state machine, used by the
    stateful-logic agent to model multi-step workflows (e.g. cart -> pay ->
    ship). Previously referenced but never defined, which broke the agent's
    import. (AIOSOP-AUDIT-2026-06-16)"""

    id: str = Field(default_factory=lambda: f"pstate-{uuid.uuid4().hex[:12]}")
    name: Optional[str] = None
    process_name: Optional[str] = None
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class GraphQLType(BaseModel):
    id: str = Field(default_factory=lambda: f"gql-type-{uuid.uuid4().hex[:12]}")
    name: str
    kind: str  # OBJECT, SCALAR, INTERFACE, UNION, ENUM, INPUT_OBJECT, LIST, NON_NULL
    fields: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class GraphQLOperation(BaseModel):
    id: str = Field(default_factory=lambda: f"gql-op-{uuid.uuid4().hex[:12]}")
    name: str
    type: str  # query, mutation, subscription
    schema_id: str
    is_hidden: bool = False
    description: Optional[str] = None


class GraphQLSchema(BaseModel):
    id: str = Field(default_factory=lambda: f"gql-schema-{uuid.uuid4().hex[:12]}")
    endpoint_url: str
    introspection_enabled: bool
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
