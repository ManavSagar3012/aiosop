"""Authenticated, inert signed-Flow provider route intent CRUD and senior review.

Never mounts, edits or overrides OSOP_VERIFIED_PROVIDER_ROUTES_JSON. An approved
intent DOES NOT authorize model dispatch, credentials, capabilities, or budget.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional, Type, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.api.routers.flow_artifact_reviews import _senior_reviewer
from ai_osop.memory.provider_route_policy_reviews import (
    ProviderPolicyDenied,
    ProviderRoutePolicyReviewStore,
)

router = APIRouter(prefix="/flows", tags=["provider-route-policy-reviews"])


class ProviderPolicyIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    provider: StrictStr = Field(min_length=1, max_length=32)
    model: StrictStr = Field(min_length=1, max_length=90)
    operations: list[StrictStr] = Field(min_length=1, max_length=2)
    allowed_roles: list[StrictStr] = Field(min_length=1, max_length=24)
    capabilities: list[StrictStr] = Field(min_length=1, max_length=5)
    max_output_tokens: StrictInt = Field(ge=1, le=16384)
    budget_source: Literal["signed_postgres_roe"]


async def _operator_principal(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    principal = await _operator(request, credentials)
    if credentials is None or not credentials.credentials:
        raise HTTPException(401, "Signed operator bearer required")
    return {
        **principal,
        "_reviewer_token_sha256": hashlib.sha256(
            credentials.credentials.encode("utf-8")
        ).hexdigest(),
    }


class CreateProviderPolicy(ProviderPolicyIntent):
    pass


class UpdateProviderPolicy(ProviderPolicyIntent):
    expected_policy_revision: StrictInt = Field(ge=1)


class DecideProviderPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_policy_revision: StrictInt = Field(ge=1)
    decision: Literal["approve", "revoke"]
    reason: StrictStr = Field(min_length=10, max_length=256)


def _store() -> ProviderRoutePolicyReviewStore:
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if memory is None:
        raise HTTPException(503, "Durable signed provider review unavailable")
    return ProviderRoutePolicyReviewStore(memory)


def _deny(exc: ProviderPolicyDenied) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


def _headers(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _distinct_fields(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate provider intent field")
        result[key] = value
    return result


_Body = TypeVar("_Body", bound=BaseModel)


async def _strict_json(request: Request, schema: Type[_Body]) -> _Body:
    """Reject ambiguous or oversized bodies even if Pydantic parses them."""
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Provider intent JSON body required")
    raw = bytearray()
    async for part in request.stream():
        if len(raw) + len(part) > 4096:
            raise HTTPException(413, "Provider intent metadata exceeds 4096 bytes")
        raw.extend(part)
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_distinct_fields,
            parse_constant=lambda *_: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(parsed, dict):
            raise ValueError()
        return schema.model_validate(parsed)
    except (ValidationError, ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(422, "Ambiguous or invalid provider intent JSON") from exc


def _scope(actor: Dict[str, Any]) -> Dict[str, Any]:
    claims = actor.get("claims")
    expiry = claims.get("exp") if isinstance(claims, dict) else None
    if (
        type(expiry) is not int
        or expiry <= int(datetime.now(timezone.utc).timestamp())
        or not isinstance(actor.get("sub"), str)
        or not 1 <= len(actor["sub"]) <= 64
    ):
        raise HTTPException(401, "Signed operator identity expired or unavailable")
    delegated = claims.get("provider_review_engagement_ids", [])
    if (
        type(delegated) is not list
        or len(delegated) > 32
        or any(type(eid) is not str or len(eid) > 64 for eid in delegated)
    ):
        raise HTTPException(403, "Invalid provider review tenant delegation")
    return {
        "actor": actor["sub"],
        "role": actor["role"],
        "delegated_tenants": delegated,
        "token_sha256": actor.get("_reviewer_token_sha256"),
        "token_expires_at": expiry,
    }


async def _invoke(
    *,
    action: str,
    flow_id: str,
    engagement_id: str,
    revision: int,
    authorization_version: int,
    authorization_id: str,
    authorization_sha256: str,
    actor: Dict[str, Any],
    review_id: Optional[str] = None,
    expected_policy_revision: Optional[int] = None,
    policy: Optional[Dict[str, Any]] = None,
    decision_reason: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> Dict[str, Any]:
    try:
        return await _store().perform(
            action=action,
            flow_id=flow_id,
            engagement_id=engagement_id,
            flow_revision=revision,
            version=authorization_version,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            review_id=review_id,
            expected_policy_revision=expected_policy_revision,
            policy=policy,
            decision_reason=decision_reason,
            limit=limit,
            offset=offset,
            **_scope(actor),
        )
    except ProviderPolicyDenied as exc:
        raise _deny(exc) from exc


# Explicit query fences on every action: clients cannot silently refresh to
# another Flow/ROE revision while updating a review in a different tab.
_FLOW_QUERY = r"^flow-[A-Za-z0-9._:-]{1,59}$"
_ENG_QUERY = r"^eng-[A-Za-z0-9._:-]{1,60}$"
_DIGEST_QUERY = r"^[0-9a-f]{64}$"


@router.post(
    "/{flow_id}/provider-route-policy-reviews",
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": CreateProviderPolicy.model_json_schema()}},
        }
    },
)
async def create_provider_policy_review(
    flow_id: str,
    response: Response,
    request: Request,
    expected_engagement_id: str = Query(pattern=_ENG_QUERY),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_DIGEST_QUERY),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    body = await _strict_json(request, CreateProviderPolicy)
    result = await _invoke(
        action="create",
        flow_id=flow_id,
        engagement_id=expected_engagement_id,
        revision=expected_revision,
        authorization_version=expected_authorization_version,
        authorization_id=expected_authorization_id,
        authorization_sha256=expected_authorization_sha256,
        actor=actor,
        policy=body.model_dump(),
    )
    _headers(response)
    return result


@router.get("/{flow_id}/provider-route-policy-reviews")
async def list_provider_policy_reviews(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(pattern=_ENG_QUERY),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_DIGEST_QUERY),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0, le=1000),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    result = await _invoke(
        action="list",
        flow_id=flow_id,
        engagement_id=expected_engagement_id,
        revision=expected_revision,
        authorization_version=expected_authorization_version,
        authorization_id=expected_authorization_id,
        authorization_sha256=expected_authorization_sha256,
        actor=actor,
        limit=limit,
        offset=offset,
    )
    _headers(response)
    return result


@router.get("/{flow_id}/provider-route-policy-reviews/{review_id}")
async def get_provider_policy_review(
    flow_id: str,
    review_id: str,
    response: Response,
    expected_engagement_id: str = Query(pattern=_ENG_QUERY),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_DIGEST_QUERY),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    result = await _invoke(
        action="detail",
        flow_id=flow_id,
        review_id=review_id,
        engagement_id=expected_engagement_id,
        revision=expected_revision,
        authorization_version=expected_authorization_version,
        authorization_id=expected_authorization_id,
        authorization_sha256=expected_authorization_sha256,
        actor=actor,
    )
    _headers(response)
    return result


@router.put(
    "/{flow_id}/provider-route-policy-reviews/{review_id}",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": UpdateProviderPolicy.model_json_schema()}},
        }
    },
)
async def update_provider_policy_review(
    flow_id: str,
    review_id: str,
    response: Response,
    request: Request,
    expected_engagement_id: str = Query(pattern=_ENG_QUERY),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_DIGEST_QUERY),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    body = await _strict_json(request, UpdateProviderPolicy)
    policy = body.model_dump(exclude={"expected_policy_revision"})
    result = await _invoke(
        action="update",
        flow_id=flow_id,
        review_id=review_id,
        engagement_id=expected_engagement_id,
        revision=expected_revision,
        authorization_version=expected_authorization_version,
        authorization_id=expected_authorization_id,
        authorization_sha256=expected_authorization_sha256,
        actor=actor,
        expected_policy_revision=body.expected_policy_revision,
        policy=policy,
    )
    _headers(response)
    return result


@router.post(
    "/{flow_id}/provider-route-policy-reviews/{review_id}/decision",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": DecideProviderPolicy.model_json_schema()}},
        }
    },
)
async def decide_provider_policy_review(
    flow_id: str,
    review_id: str,
    response: Response,
    request: Request,
    expected_engagement_id: str = Query(pattern=_ENG_QUERY),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_DIGEST_QUERY),
    actor: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    body = await _strict_json(request, DecideProviderPolicy)
    result = await _invoke(
        action=body.decision,
        flow_id=flow_id,
        review_id=review_id,
        engagement_id=expected_engagement_id,
        revision=expected_revision,
        authorization_version=expected_authorization_version,
        authorization_id=expected_authorization_id,
        authorization_sha256=expected_authorization_sha256,
        actor=actor,
        expected_policy_revision=body.expected_policy_revision,
        decision_reason=body.reason,
    )
    _headers(response)
    return result
