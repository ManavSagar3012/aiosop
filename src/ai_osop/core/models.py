"""
AI-OSOP Shared Data Models
Pydantic models for all cross-component communication.
"""

import hashlib
import hmac
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator

from ai_osop.core.config import AgentType, Severity, VulnClass

# ================= ID HELPERS =================


def make_asset_id(engagement_id: str, value: str) -> str:
    """
    Return a stable, engagement-scoped asset ID that is safe against
    cross-engagement Neo4j node collisions.

    Two engagements targeting the same domain used to produce identical IDs
    (``asset-{engagement_id}-{domain}``) because Neo4j MERGE matched on the
    *full* id string, and engagement_id was sometimes reused in tests. This
    function hashes both components together so the ID:
      - Is deterministic for the same (engagement, value) pair (idempotent MERGE)
      - Is unique across different engagements for the same value
      - Stays human-readable with a short prefix

    Format: ``asset-{eng8}-{val8}``
      eng8 = first 8 hex chars of SHA-256(engagement_id)
      val8 = first 8 hex chars of SHA-256(value.lower())
    """
    eng_hash = hashlib.sha256(engagement_id.encode()).hexdigest()[:8]
    val_hash = hashlib.sha256(value.lower().encode()).hexdigest()[:8]
    return f"asset-{eng_hash}-{val_hash}"


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
    # Free-form enrichment (recon tags, template, first/last-seen, source hints).
    # Previously several call sites passed metadata that pydantic silently dropped
    # because this field did not exist; it is now retained.
    metadata: Dict[str, Any] = Field(default_factory=dict)


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
    yield_metadata: Dict[str, Any] = Field(default_factory=dict)

    def is_simulated(self) -> bool:
        """True if this finding is fabricated/mock rather than a real observation
        (OSOP-P0-02). Used to keep simulated findings out of the real corpus, reports,
        and headline metrics. Signals: a mock tool_source, a "(Simulated)" title, or any
        evidence entry whose provenance is 'simulated'."""
        src = (self.tool_source or "").lower()
        if "mock" in src or src.endswith("-sim") or "simulated" in src:
            return True
        if "(simulated)" in (self.title or "").lower():
            return True
        for ev in self.evidence or []:
            if isinstance(ev, dict) and str(ev.get("provenance", "")).lower() == "simulated":
                return True
        return False


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
    # Sprint 6: trace context propagation across async boundaries
    trace_context: Dict[str, Any] = Field(default_factory=dict)
    lease_expires: Optional[datetime] = None


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
    signature: Optional[str] = None  # Cryptographic signature for ScopeDefinition

    def _signing_payload(self) -> str:
        """Canonical representation of the scope-defining fields that are signed."""
        return f"{self.engagement_id}:{','.join(self.domains)}:{','.join(self.ips)}"

    def sign(self, secret_key: bytes) -> str:
        """Compute and store the HMAC signature over the scope-defining fields.
        Used at engagement creation so the manifest is tamper-evident (GAP-2-4)."""
        self.signature = hmac.new(
            secret_key, self._signing_payload().encode(), hashlib.sha256
        ).hexdigest()
        return self.signature

    def verify_signature(self, secret_key: bytes) -> bool:
        if not self.signature:
            return False
        expected_signature = hmac.new(
            secret_key, self._signing_payload().encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected_signature)


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
    # Sprint 7: Outcome Feedback
    outcome: Optional[str] = None  # e.g., "accepted", "duplicate", "informative", "na"
    outcome_notes: Optional[str] = None
    outcome_at: Optional[datetime] = None
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
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NA = "na"
    REJECTED = "rejected"
    TRIAGED = "triaged"
    PAID = "paid"


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


class Hypothesis(BaseModel):
    """A testable security hypothesis inferred from observed engagement data."""

    id: str = Field(default_factory=lambda: f"hyp-{uuid.uuid4().hex[:12]}")
    title: str
    description: str
    category: str
    target_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_entities: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_tests: List[str] = Field(default_factory=list)
    recommended_skills: List[str] = Field(default_factory=list)
    status: str = "open"
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


class EvidencePackage(BaseModel):
    """A bundle of captured evidence backing a single finding.

    Holds the raw artifacts (requests/responses/screenshots/workflow trace) plus an
    optional ``replay_script`` — a self-contained command the ReplayabilityTruthEngine
    can re-execute in a sandbox to prove the finding still reproduces. The integrity
    hash pins the artifact set so tampering is detectable in a vault audit.
    """

    id: str = Field(default_factory=lambda: f"evp-{uuid.uuid4().hex[:12]}")
    finding_id: str
    engagement_id: str = ""
    raw_requests: List[Any] = Field(default_factory=list)
    raw_responses: List[Any] = Field(default_factory=list)
    screenshots: List[str] = Field(default_factory=list)
    workflow_trace: List[Any] = Field(default_factory=list)
    # A replay command (argv list) executed verbatim in the sandbox. Kept as a
    # concrete argv (not a shell string) so there is no shell-injection surface and
    # the re-execution is deterministic.
    replay_script: List[str] = Field(default_factory=list)
    integrity_hash: str = ""
    provenance: EvidenceProvenance = EvidenceProvenance.LIVE
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


# ================= PRIMITIVE LEDGER (Sprint 1.2) =================


class PrimitiveType(str, Enum):
    """Type taxonomy for raw signals entering the Primitive Ledger.

    Every confirmed signal is stored as a typed Primitive rather than a
    finding. The chain engine escalates from here; triager gate decides what
    is eventually emitted as a finding.
    """

    NUCLEI_SIGNAL = "nuclei_signal"  # Nuclei template hit (unvalidated)
    ENDPOINT_OBSERVED = "endpoint_observed"  # URL/endpoint seen in recon
    AUTH_SIGNAL = "auth_signal"  # Auth anomaly (diff-auth engine output)
    PORT_OPEN = "port_open"  # Open port from recon
    DNS_RECORD = "dns_record"  # DNS/subdomain discovered
    JS_SECRET = "js_secret"  # Potential secret extracted from JS
    HEADER_ANOMALY = "header_anomaly"  # Suspicious response header
    RATE_LIMIT_MISS = "rate_limit_miss"  # Endpoint has no rate limiting
    REDIRECT_CHAIN = "redirect_chain"  # Interesting redirect sequence
    SSRF_HINT = "ssrf_hint"  # Possible SSRF vector
    IDOR_HINT = "idor_hint"  # Possible IDOR vector
    GENERIC = "generic"  # Catch-all for unclassified signals


class PrimitiveLedger(BaseModel):
    """A single raw signal persisted as a typed Primitive node in Neo4j.

    Design contract:
      - Every tool output (Nuclei, recon, diff-auth, JS analysis) is a Primitive.
      - Primitives are NEVER emitted as findings directly.
      - The Escalation Engine queries the ledger to discover promotion paths.
      - The Triager Gate decides if a chain is strong enough to emit a finding.
      - Deduplication key = (engagement_id, primitive_type, dedup_key).
        The dedup_key is caller-supplied and should be a stable fingerprint
        of the signal (e.g. SHA-256 of url+template_id).

    Fields:
      raw        -- original tool output (JSON-serialisable dict)
      confidence -- 0.0-1.0 from tool/scoring logic
      source     -- tool that generated this (nuclei, recon_mcp, diff_auth, …)
      tags       -- free-form enrichment tags for downstream querying
    """

    id: str = Field(default_factory=lambda: f"prim-{uuid.uuid4().hex[:12]}")
    primitive_type: PrimitiveType
    engagement_id: str
    source: str  # e.g. "nuclei", "recon_mcp", "diff_auth"
    dedup_key: str  # Stable fingerprint; drives MERGE in Neo4j
    target: str  # URL, host, domain, port — the affected target
    raw: Dict[str, Any] = Field(default_factory=dict)  # Original tool output
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    severity_hint: str = "info"  # "critical" | "high" | "medium" | "low" | "info"
    tags: List[str] = Field(default_factory=list)
    # Escalation linkage (populated by EscalationEngine)
    escalated_from: Optional[str] = None  # parent prim-id if escalated
    chain_id: Optional[str] = None  # chain-id if part of a chain
    promoted_to_finding: bool = False  # True once TriagerGate emits a finding
    finding_id: Optional[str] = None  # back-ref once promoted
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ================= TRIAGER GATE (Sprint 1.3) =================


class TriageVerdict(str, Enum):
    """Decision output from the Triager Gate."""

    EMIT = "emit"  # Strong enough — emit as a finding
    ESCALATE = "escalate"  # Signal found, needs more evidence first
    DROP = "drop"  # Noise or duplicate — discard
    NEEDS_POC = "needs_poc"  # Interesting but missing runnable PoC


class TriageReport(BaseModel):
    """Structured verdict from the Triager Gate for a single primitive chain."""

    id: str = Field(default_factory=lambda: f"triage-{uuid.uuid4().hex[:12]}")
    primitive_id: str
    chain_id: Optional[str] = None
    verdict: TriageVerdict
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)  # human-readable rationale
    blockers: List[str] = Field(default_factory=list)  # what prevented EMIT
    reproducibility_score: float = Field(0.0, ge=0.0, le=1.0)
    has_poc: bool = False
    has_captured_evidence: bool = False
    is_duplicate: bool = False
    requires_manual_confirm: bool = False  # a detector flagged this as an unproven lead
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ================= ESCALATION (Sprint 2.1) =================


class EscalationPath(BaseModel):
    """One possible escalation step inferred by the Escalation Engine."""

    id: str = Field(default_factory=lambda: f"esc-{uuid.uuid4().hex[:12]}")
    source_primitive_id: str
    suggested_technique: str  # e.g. "nuclei_verify", "burp_active_scan"
    reason: str
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    required_skills: List[str] = Field(default_factory=list)
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ================= ATTACK CHAIN (Sprint 2.2 / 2.3) =================


class ChainStatus(str, Enum):
    BUILDING = "building"
    PENDING_POC = "pending_poc"
    VALIDATED = "validated"
    EMITTED = "emitted"
    DROPPED = "dropped"


class AttackChain(BaseModel):
    """An ordered sequence of Primitives representing a validated attack chain.

    The Chain Composer assembles chains; the Auto-PoC generator populates
    poc_script; the Triager Gate emits the finding once the chain is validated.
    """

    id: str = Field(default_factory=lambda: f"chain-{uuid.uuid4().hex[:12]}")
    engagement_id: str
    primitive_ids: List[str] = Field(default_factory=list)  # ordered chain
    title: str = ""
    description: str = ""
    status: ChainStatus = ChainStatus.BUILDING
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    severity: str = "medium"
    poc_script: List[str] = Field(default_factory=list)  # argv for replay
    triage_report_id: Optional[str] = None
    emitted_finding_id: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
