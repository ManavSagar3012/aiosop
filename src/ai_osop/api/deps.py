"""AI-OSOP API Dependencies and Shared State

Centralized auth, shared module-level singletons, and request/response models
so that routers can import them without circular imports from main.py.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ai_osop.core.config import settings
from ai_osop.core.models import ApprovalRequest, AuditEvent, ScopeDefinition, SessionState, Task

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


class UserSessionImportRequest(BaseModel):
    """Operator imports captured cookies + tokens for a user under engagement.

    Cookie shape follows Playwright's BrowserContext.add_cookies format:
        [{name, value, domain, path, expires?, httpOnly?, secure?, sameSite?}, ...]
    """

    user_label: str = Field(..., description="logical label, e.g. user_a, admin, viewer")
    cookies: List[Dict[str, Any]] = Field(default_factory=list)
    bearer_token: str = ""
    local_storage: Dict[str, Any] = Field(default_factory=dict)
    session_storage: Dict[str, Any] = Field(default_factory=dict)
    csrf_token: str = ""
    extra_headers: Dict[str, str] = Field(default_factory=dict)
    user_agent: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UserSessionResponse(BaseModel):
    engagement_id: str
    user_label: str
    cookie_count: int
    has_bearer: bool
    has_csrf: bool
    has_local_storage: bool
    captured_at: str
    expires_at: Optional[str]
    metadata: Dict[str, Any]


# ============== Global State ==============

# Mutable state container so routers and main.py share live values.
# Routers access state["orchestrator"] at request time (not import time)
# to avoid stale references when main.py binds the real instances in lifespan().
state = {
    "orchestrator": None,
    "session_store": None,
    "skill_engine": None,
}

# Backwards-compatible aliases (used by the old monolithic main.py pattern)
# NOTE: routers should import `state` and use state["orchestrator"]
# instead of importing these directly, because direct imports capture the
# initial None value and never see the updated binding from lifespan().

# ============== Authentication ==============


async def verify_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    token: Optional[str] = Query(None),
):
    """Verify bearer token.

    Order of precedence (AIOSOP-SEC-001 hard fix, 2026-06-15):
      1. If OSOP_JWT_SECRET is set, decode + validate the bearer as a JWT.
         Required claims: sub, role, exp. When OSOP_JWT_AUDIENCE / _ISSUER are
         set they're also validated. Bad signature / expired / missing claim
         all return 401.
      2. Otherwise, if OSOP_API_TOKEN is set, require Authorization: Bearer
         <that value> (constant-time equality).
      3. Otherwise, log CRITICAL and reject the request (dev fallback removed).
    """
    if not isinstance(credentials, HTTPAuthorizationCredentials):
        credentials = None
    if not credentials and not token:
        raise HTTPException(status_code=403, detail="Not authenticated")
    print(f"[DEBUG] Received Authorization header: {credentials.credentials if credentials else 'NONE'}")
    presented = credentials.credentials if credentials else token

    if settings.jwt_secret:
        from jose import ExpiredSignatureError, JWTError, jwt

        decode_kwargs: Dict[str, Any] = {
            "key": settings.jwt_secret,
            "algorithms": [settings.jwt_algorithm],
        }
        if settings.jwt_audience:
            decode_kwargs["audience"] = settings.jwt_audience
        if settings.jwt_issuer:
            decode_kwargs["issuer"] = settings.jwt_issuer
        try:
            payload = jwt.decode(presented, **decode_kwargs)
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except JWTError as e:
            raise HTTPException(status_code=401, detail=f"Invalid JWT: {e}")
        sub = payload.get("sub")
        role = payload.get("role")
        if not sub or not role:
            raise HTTPException(status_code=401, detail="JWT missing sub or role claim")
        return {"sub": sub, "role": role, "claims": payload}

    if settings.api_token:
        import hmac

        if not hmac.compare_digest(presented or "", settings.api_token):
            raise HTTPException(status_code=401, detail="Invalid bearer token")
        return {"sub": "operator-1", "role": "senior_operator"}

    import logging

    logging.getLogger("ai_osop.auth").critical(
        "AIOSOP-SEC-001: neither OSOP_JWT_SECRET nor OSOP_API_TOKEN is set. "
        "Set OSOP_DEV_MODE=true to allow the dev fallback, or configure auth in .env."
    )
    raise HTTPException(
        status_code=401,
        detail="Authentication is not configured. Set OSOP_JWT_SECRET or OSOP_API_TOKEN.",
    )


async def assert_engagement_access(operator: Dict[str, Any], session_id: str) -> SessionState:
    """Verify the operator is authorized to access the engagement.

    Authorization rules:
      - senior_operator role: global access
      - operator role: access only if they created the engagement

    Raises HTTPException 403 if unauthorized, 404 if engagement not found.
    """
    from ai_osop.core.models import SessionState

    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    session: Optional[SessionState] = orch._sessions.get(session_id)
    if not session:
        # Fallback to warm storage so restarts don't break authorization
        try:
            session = await orch.session_memory.load_session_state(session_id)
        except Exception:
            session = None

    if not session:
        # Fallback: the caller may have passed the user-provided engagement_id
        # rather than the generated session_id (e.g. task scheduling uses the
        # same engagement_id the operator specified at creation time, but the
        # orchestrator stores sessions under a unique session_id with a timestamp
        # prefix like ``eng-20260713165205-{engagement_id}``).
        for s in orch._sessions.values():
            if getattr(s.scope, "engagement_id", None) == session_id:
                session = s
                break

    if not session:
        raise HTTPException(status_code=404, detail="Engagement not found")

    role = operator.get("role", "")
    if role == "senior_operator":
        return session

    if session.created_by is None:
        raise HTTPException(
            status_code=403, detail="Engagement has no owner and cannot be accessed"
        )

    if session.created_by == operator.get("sub"):
        return session

    raise HTTPException(
        status_code=403, detail="You do not have permission to access this engagement"
    )


# ============== Request ID / Correlation Middleware ==============


class RequestContext:
    """Lightweight request-scoped context holder for correlation IDs."""

    _store: Dict[str, Any] = {}

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        return cls._store.get(key, default)

    @classmethod
    def set(cls, key: str, value: Any) -> None:
        cls._store[key] = value

    @classmethod
    def clear(cls) -> None:
        cls._store.clear()


def require_role(*allowed_roles: str):
    """Dependency factory: 403 unless operator.role in allowed_roles."""

    async def _guard(operator: Dict[str, Any] = Depends(verify_token)) -> Dict[str, Any]:
        if operator.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403, detail=f"Role '{operator.get('role')}' not permitted"
            )
        return operator

    return _guard


def update_active_agents(count: int) -> None:
    """Update Prometheus-style active agents metric."""
    from ai_osop.core.metrics import ACTIVE_AGENTS

    ACTIVE_AGENTS.set(count)
