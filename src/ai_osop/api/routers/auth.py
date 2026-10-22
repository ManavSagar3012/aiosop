"""Expose the identity actually verified by the API's bearer verifier."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ai_osop.api.deps import verify_token
from ai_osop.api.deps import _operator_revocation_ledger
from ai_osop.core.config import settings
from ai_osop.memory.operator_revocation import OperatorRevocationUnavailable

router = APIRouter(prefix="/auth", tags=["authentication"])


class OperatorIdentity(BaseModel):
    sub: str
    role: str
    exp: Optional[int] = None


class OperatorStatusChange(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


async def _header_verified_operator(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    # The user-supplied JWT must never be accepted from query strings, even
    # on a development instance that still supports legacy API credentials.
    if request.query_params:
        raise HTTPException(status_code=403, detail="Query credentials are not accepted")
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer header required")
    return await verify_token(credentials=credentials, token=None)


@router.get("/me", response_model=OperatorIdentity)
async def authenticated_operator(
    response: Response,
    operator: Dict[str, Any] = Depends(_header_verified_operator),
) -> OperatorIdentity:
    """Return only verified operator claims, never the JWT or raw payload."""
    response.headers["Cache-Control"] = "no-store"
    sub, role = operator.get("sub"), operator.get("role")
    if not isinstance(sub, str) or not sub.strip():
        raise HTTPException(status_code=401, detail="Invalid operator subject")
    if not isinstance(role, str) or not role.strip():
        raise HTTPException(status_code=401, detail="Invalid operator role")

    claims = operator.get("claims")
    exp = claims.get("exp") if isinstance(claims, dict) else None
    if isinstance(claims, dict) and (type(exp) is not int or exp <= 0):
        # Both independently signed local and OIDC JWTs require an expiry.
        # The development-only shared token carries no JWT expiry or role.
        raise HTTPException(status_code=401, detail="JWT expiry claim required")
    return OperatorIdentity(sub=sub, role=role, exp=exp if type(exp) is int else None)


@router.post("/logout")
async def revoke_current_bearer(
    response: Response,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    principal: Dict[str, Any] = Depends(_header_verified_operator),
) -> Dict[str, str]:
    """Invalidate this exact signed access token on every replica after commit."""
    if not getattr(settings, "operator_revocation_required", False):
        raise HTTPException(status_code=503, detail="Durable operator revocation is not enabled")
    if credentials is None or not isinstance(credentials.credentials, str):
        raise HTTPException(status_code=401, detail="Bearer header required")
    if principal.get("role") not in {"viewer", "operator", "senior_operator"}:
        raise HTTPException(status_code=403, detail="Individually signed identity required")
    try:
        await _operator_revocation_ledger().revoke_token(credentials.credentials, principal)
    except (OperatorRevocationUnavailable, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Durable logout unavailable") from exc
    response.headers["Cache-Control"] = "no-store"
    return {"status": "revoked"}


@router.post("/operators/{subject}/disable")
async def disable_operator_account(
    subject: str,
    change: OperatorStatusChange,
    response: Response,
    principal: Dict[str, Any] = Depends(_header_verified_operator),
) -> Dict[str, str]:
    """Emergency senior-admin account disable; all existing bearers rejected."""
    if not getattr(settings, "operator_revocation_required", False):
        raise HTTPException(status_code=503, detail="Durable operator revocation is not enabled")
    if principal.get("role") != "senior_operator" or subject == principal.get("sub"):
        raise HTTPException(status_code=403, detail="Senior operator required")
    try:
        await _operator_revocation_ledger().disable_subject(
            subject, actor_id=principal["sub"], disabled=True, reason=change.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid operator subject") from exc
    except OperatorRevocationUnavailable as exc:
        raise HTTPException(status_code=503, detail="Durable operator status unavailable") from exc
    response.headers["Cache-Control"] = "no-store"
    return {"status": "disabled"}


@router.post("/operators/{subject}/enable")
async def enable_operator_account(
    subject: str,
    change: OperatorStatusChange,
    response: Response,
    principal: Dict[str, Any] = Depends(_header_verified_operator),
) -> Dict[str, str]:
    """Explicit senior-managed account recovery; per-token revocations remain."""
    if not getattr(settings, "operator_revocation_required", False):
        raise HTTPException(status_code=503, detail="Durable operator revocation is not enabled")
    if principal.get("role") != "senior_operator" or subject == principal.get("sub"):
        raise HTTPException(status_code=403, detail="Senior operator required")
    try:
        await _operator_revocation_ledger().disable_subject(
            subject, actor_id=principal["sub"], disabled=False, reason=change.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid operator subject") from exc
    except OperatorRevocationUnavailable as exc:
        raise HTTPException(status_code=503, detail="Durable operator status unavailable") from exc
    response.headers["Cache-Control"] = "no-store"
    return {"status": "enabled"}
