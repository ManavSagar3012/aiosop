"""Senior-only immutable Flow artifact review API.

Explicit review is tied to PostgreSQL artifact BYTES and current signed
authorization, independent of the upload actor. No raw content is exposed by
these routes and no review may be inferred from an upload hash.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from ai_osop.api.deps import _oidc_config, state, verify_token
from ai_osop.core.config import settings
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)

router = APIRouter(prefix="/flows", tags=["flow-artifact-reviews"])


class FlowArtifactReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: StrictStr = Field(pattern=r"^(approve|reject)$")
    expected_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    expected_revision: StrictInt = Field(ge=0)
    expected_authorization_version: StrictInt = Field(ge=1)
    expected_authorization_id: StrictStr = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]*$"
    )
    expected_authorization_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    reason: StrictStr = Field(min_length=1, max_length=512)


async def _senior_reviewer(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    """Require expiring human-signed senior credentials in the bearer header."""
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or "token" in request.query_params
    ):
        raise HTTPException(status_code=401, detail="Senior bearer header required")
    if not settings.jwt_secret and _oidc_config() is None:
        raise HTTPException(status_code=503, detail="Signed operator JWT unavailable")
    principal = await verify_token(credentials=credentials, token=None)
    claims = principal.get("claims")
    sub = principal.get("sub")
    expiry = claims.get("exp") if isinstance(claims, dict) else None
    if (
        principal.get("role") != "senior_operator"
        or not isinstance(sub, str)
        or len(sub) > 64
        or not sub.strip()
        or type(expiry) is not int
        or expiry <= datetime.now(timezone.utc).timestamp()
    ):
        raise HTTPException(status_code=403, detail="Signed senior reviewer required")
    # Carry only a digest to the transaction-local revocation fence. The
    # signed bearer itself must never enter SQL, receipts, or the event outbox.
    return {
        **principal,
        "_reviewer_token_sha256": hashlib.sha256(
            credentials.credentials.encode("utf-8")
        ).hexdigest(),
        "_reviewer_expires_at": expiry,
    }


def _store() -> FlowArtifactReviewStore:
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if memory is None:
        raise HTTPException(status_code=503, detail="Durable Flow reviews unavailable")
    return FlowArtifactReviewStore(memory)


def _http_denial(exc: ArtifactReviewDenied) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


@router.post("/{flow_id}/artifacts/{artifact_id}/review", status_code=201)
async def decide_flow_artifact_review(
    flow_id: str,
    artifact_id: str,
    request: FlowArtifactReviewDecision,
    response: Response,
    reviewer: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    try:
        receipt = await _store().decide(
            flow_id=flow_id,
            artifact_id=artifact_id,
            revision=request.expected_revision,
            version=request.expected_authorization_version,
            sha256=request.expected_sha256,
            authorization_id=request.expected_authorization_id,
            authorization_sha256=request.expected_authorization_sha256,
            reviewer_sub=reviewer["sub"],
            reviewer_role=reviewer["role"],
            decision=request.decision,
            reason=request.reason,
            reviewer_token_sha256=reviewer["_reviewer_token_sha256"],
            reviewer_expires_at=reviewer["_reviewer_expires_at"],
        )
    except ArtifactReviewDenied as exc:
        raise _http_denial(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return receipt


@router.get("/{flow_id}/artifacts/{artifact_id}/review")
async def get_flow_artifact_review(
    flow_id: str,
    artifact_id: str,
    response: Response,
    expected_sha256: str = Query(pattern=r"^[0-9a-f]{64}$"),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]*$"
    ),
    expected_authorization_sha256: str = Query(pattern=r"^[0-9a-f]{64}$"),
    reviewer: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    try:
        receipt = await _store().read_verified(
            flow_id=flow_id,
            artifact_id=artifact_id,
            revision=expected_revision,
            version=expected_authorization_version,
            sha256=expected_sha256,
            authorization_id=expected_authorization_id,
            authorization_sha256=expected_authorization_sha256,
            reviewer_sub=reviewer["sub"],
            reviewer_token_sha256=reviewer["_reviewer_token_sha256"],
            reviewer_expires_at=reviewer["_reviewer_expires_at"],
        )
    except ArtifactReviewDenied as exc:
        raise _http_denial(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return receipt


@router.get("/{flow_id}/artifact-reviews/candidates")
async def list_independent_review_candidates(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=1, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]*$"
    ),
    expected_authorization_sha256: str = Query(pattern=r"^[0-9a-f]{64}$"),
    limit: int = Query(default=10, ge=1, le=10),
    offset: int = Query(default=0, ge=0, le=64),
    reviewer: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """List independently SHA-verified, inert candidates for a separate senior."""
    try:
        result = await _store().list_review_candidates(
            flow_id=flow_id,
            engagement_id=expected_engagement_id,
            revision=expected_revision,
            version=expected_authorization_version,
            authorization_id=expected_authorization_id,
            authorization_sha256=expected_authorization_sha256,
            reviewer_sub=reviewer["sub"],
            reviewer_role=reviewer["role"],
            reviewer_token_sha256=reviewer["_reviewer_token_sha256"],
            reviewer_expires_at=reviewer["_reviewer_expires_at"],
            limit=limit,
            offset=offset,
        )
    except ArtifactReviewDenied as exc:
        raise _http_denial(exc) from exc
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return result


@router.get("/{flow_id}/artifact-reviews/{artifact_id}/content")
async def download_independent_review_source(
    flow_id: str,
    artifact_id: str,
    expected_engagement_id: str = Query(min_length=1, max_length=64),
    expected_sha256: str = Query(pattern=r"^[0-9a-f]{64}$"),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]*$"
    ),
    expected_authorization_sha256: str = Query(pattern=r"^[0-9a-f]{64}$"),
    reviewer: Dict[str, Any] = Depends(_senior_reviewer),
) -> Response:
    """Return the original byte-verified resource as a forced attachment."""
    try:
        info, content = await _store().read_review_source(
            flow_id=flow_id,
            engagement_id=expected_engagement_id,
            artifact_id=artifact_id,
            revision=expected_revision,
            version=expected_authorization_version,
            sha256=expected_sha256,
            authorization_id=expected_authorization_id,
            authorization_sha256=expected_authorization_sha256,
            reviewer_sub=reviewer["sub"],
            reviewer_role=reviewer["role"],
            reviewer_token_sha256=reviewer["_reviewer_token_sha256"],
            reviewer_expires_at=reviewer["_reviewer_expires_at"],
        )
    except ArtifactReviewDenied as exc:
        raise _http_denial(exc) from exc
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": 'attachment; filename="review-source.bin"',
            "X-Artifact-SHA256": info["sha256"],
        },
    )
