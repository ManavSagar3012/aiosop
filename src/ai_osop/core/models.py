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
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    auth_required: bool = False
    asset_id: str
    source: str
    confidence: float = Field(ge=0.0, le=1.0)
    engagement_id: str
    screenshot_path: Optional[str] = None


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
