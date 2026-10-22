"""Signed, tenant-scoped *nonsecret* credential reference metadata and reviews.

No vault APIs, environment inspection, provider health, model activation or
remote calls are reachable here. Registration is not credential provisioning.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

from ai_osop.api.deps import state
from ai_osop.api.routers.provider_route_policy_reviews import _operator_principal, _scope
from ai_osop.memory.provider_credential_profile_refs import (
    CredentialProfileDenied,
    ProviderCredentialProfileRefStore,
)

router = APIRouter(prefix="/flows", tags=["provider-credential-profile-refs"])
_FLOW = r"^flow-[A-Za-z0-9._:-]{1,59}$"
_ENG = r"^eng-[A-Za-z0-9._:-]{1,60}$"
_SHA = r"^[0-9a-f]{64}$"
_REF = r"^pcref-[0-9a-f]{32}$"


class ProfileRefMutation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    operation: StrictStr
    operation_id: StrictStr = Field(pattern=r"^pcop-[0-9a-f]{32}$")
    ref_id: Optional[StrictStr] = Field(default=None, pattern=_REF)
    expected_ref_revision: Optional[StrictInt] = Field(default=None, ge=1)
    provider: Optional[StrictStr] = None
    slot: Optional[StrictStr] = None
    policy_review_id: Optional[StrictStr] = None
    policy_sha256: Optional[StrictStr] = Field(default=None, pattern=_SHA)
    reason: Optional[StrictStr] = Field(default=None, min_length=10, max_length=160)


_POST_FIELDS = {
    "register": frozenset(
        {
            "operation",
            "operation_id",
            "provider",
            "slot",
            "policy_review_id",
            "policy_sha256",
        }
    ),
    "rotate": frozenset(
        {
            "operation",
            "operation_id",
            "ref_id",
            "expected_ref_revision",
            "provider",
            "slot",
            "policy_review_id",
            "policy_sha256",
        }
    ),
    "approve": frozenset(
        {
            "operation",
            "operation_id",
            "ref_id",
            "expected_ref_revision",
            "reason",
        }
    ),
    "revoke": frozenset(
        {
            "operation",
            "operation_id",
            "ref_id",
            "expected_ref_revision",
            "reason",
        }
    ),
}


def _distinct(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("Ambiguous duplicate field")
        result[k] = v
    return result


async def _body(request: Request) -> ProfileRefMutation:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Nonsecret provider reference JSON required")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 4096:
            raise HTTPException(413, "Provider reference metadata exceeds 4096 bytes")
        raw.extend(chunk)
    try:
        data = json.loads(
            raw,
            object_pairs_hook=_distinct,
            parse_constant=lambda *_: (_ for _ in ()).throw(ValueError()),
        )
        if (
            type(data) is not dict
            or type(data.get("operation")) is not str
            or set(data) != _POST_FIELDS.get(data["operation"])
        ):
            raise ValueError("Unsupported or extra metadata")
        return ProfileRefMutation.model_validate(data)
    except (ValueError, ValidationError, TypeError, UnicodeError, OverflowError) as exc:
        raise HTTPException(422, "Invalid, ambiguous or secret-bearing reference metadata") from exc


def _store() -> ProviderCredentialProfileRefStore:
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if memory is None:
        raise HTTPException(503, "Durable signed provider reference store unavailable")
    try:
        return ProviderCredentialProfileRefStore(memory)
    except CredentialProfileDenied as exc:
        raise HTTPException(exc.status, str(exc)) from exc


def _headers(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


async def _invoke(
    *,
    operation: str,
    flow_id: str,
    expected_engagement_id: str,
    expected_revision: int,
    expected_authorization_version: int,
    expected_authorization_id: str,
    expected_authorization_sha256: str,
    actor: Dict[str, Any],
    ref_id: Optional[str] = None,
    operation_id: Optional[str] = None,
    expected_ref_revision: Optional[int] = None,
    provider: Optional[str] = None,
    slot: Optional[str] = None,
    policy_review_id: Optional[str] = None,
    policy_sha256: Optional[str] = None,
    reason: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
) -> Dict[str, Any]:
    try:
        return await _store().perform(
            operation=operation,
            flow_id=flow_id,
            engagement_id=expected_engagement_id,
            flow_revision=expected_revision,
            version=expected_authorization_version,
            authorization_id=expected_authorization_id,
            authorization_sha256=expected_authorization_sha256,
            ref_id=ref_id,
            operation_id=operation_id,
            expected_ref_revision=expected_ref_revision,
            provider=provider,
            slot=slot,
            policy_review_id=policy_review_id,
            policy_sha256=policy_sha256,
            reason=reason,
            limit=limit,
            offset=offset,
            **_scope(actor),
        )
    except CredentialProfileDenied as exc:
        raise HTTPException(exc.status, str(exc)) from exc


@router.get("/{flow_id}/provider-credential-profile-refs")
async def list_provider_credential_profile_refs(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(pattern=_ENG),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_SHA),
    limit: int = Query(default=20, ge=1, le=50),
    offset: int = Query(default=0, ge=0, le=1000),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    _headers(response)
    return await _invoke(
        operation="list",
        flow_id=flow_id,
        actor=actor,
        expected_engagement_id=expected_engagement_id,
        expected_revision=expected_revision,
        expected_authorization_version=expected_authorization_version,
        expected_authorization_id=expected_authorization_id,
        expected_authorization_sha256=expected_authorization_sha256,
        limit=limit,
        offset=offset,
    )


@router.get("/{flow_id}/provider-credential-profile-refs/{ref_id}")
async def get_provider_credential_profile_ref(
    flow_id: str,
    ref_id: str,
    response: Response,
    expected_engagement_id: str = Query(pattern=_ENG),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_SHA),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    _headers(response)
    return await _invoke(
        operation="detail",
        flow_id=flow_id,
        actor=actor,
        ref_id=ref_id,
        expected_engagement_id=expected_engagement_id,
        expected_revision=expected_revision,
        expected_authorization_version=expected_authorization_version,
        expected_authorization_id=expected_authorization_id,
        expected_authorization_sha256=expected_authorization_sha256,
    )


@router.post("/{flow_id}/provider-credential-profile-refs")
async def change_provider_credential_profile_ref(
    flow_id: str,
    response: Response,
    request: Request,
    expected_engagement_id: str = Query(pattern=_ENG),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(pattern=_SHA),
    actor: Dict[str, Any] = Depends(_operator_principal),
) -> Dict[str, Any]:
    _headers(response)
    payload = await _body(request)
    result = await _invoke(
        operation=payload.operation,
        flow_id=flow_id,
        actor=actor,
        expected_engagement_id=expected_engagement_id,
        expected_revision=expected_revision,
        expected_authorization_version=expected_authorization_version,
        expected_authorization_id=expected_authorization_id,
        expected_authorization_sha256=expected_authorization_sha256,
        **payload.model_dump(exclude_none=True, exclude={"operation"}),
    )
    response.status_code = (
        201 if payload.operation == "register" and not result.get("idempotent_replay") else 200
    )
    return result
