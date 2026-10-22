"""Human-confirmed tenant-owned mutable Flow folder METADATA only.

There is no file path, filesystem or sandbox transport in this API. Mount the
router under /flows alongside the original immutable artifact endpoints.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, ValidationError

from ai_osop.api.deps import state, verify_token
from ai_osop.memory.flow_artifact_reviews import ArtifactReviewDenied
from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.flow_resource_folders import FlowResourceFolders, FolderDenied


router = APIRouter(prefix="/flows", tags=["flow-resource-folders"])


class FolderMutation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operation: Literal["create", "rename", "delete", "assign", "unassign"]
    expected_catalog_revision: StrictInt = Field(ge=0)
    explicit_human_confirmation: StrictBool
    folder_id: Optional[StrictStr] = Field(default=None, max_length=64)
    name: Optional[StrictStr] = Field(default=None, max_length=48)
    artifact_id: Optional[StrictStr] = Field(default=None, max_length=64)
    artifact_sha256: Optional[StrictStr] = Field(default=None, max_length=64)


def _unique_fields(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate Flow resource folder JSON key")
        result[key] = value
    return result


async def _strict_mutation_json(request: Request) -> FolderMutation:
    """Bound JSON before parsing; duplicate consent/CAS fields are ambiguous."""
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Flow folder mutation requires JSON")
    raw = bytearray()
    async for chunk in request.stream():
        if len(chunk) > 2048 - len(raw):
            raise HTTPException(413, "Flow folder metadata exceeds 2048 bytes")
        raw.extend(chunk)
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_fields,
            parse_constant=lambda *_: (_ for _ in ()).throw(ValueError("Invalid JSON constant")),
        )
        if not isinstance(value, dict):
            raise ValueError("Flow folder mutation must be a JSON object")
        return FolderMutation.model_validate(value)
    except (ValidationError, ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(422, "Invalid or ambiguous Flow folder JSON") from exc


async def _operator(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or "token" in request.query_params
    ):
        raise HTTPException(401, "Expiring signed human operator bearer required")
    operator = await verify_token(credentials=credentials, token=None)
    claims = operator.get("claims")
    expire = claims.get("exp") if isinstance(claims, dict) else None
    sub = operator.get("sub")
    if (
        operator.get("role") not in {"operator", "senior_operator"}
        or not isinstance(sub, str)
        or not sub
        or len(sub) > 64
        or type(expire) is not int
        or expire <= int(datetime.now(timezone.utc).timestamp())
    ):
        raise HTTPException(403, "Current signed human operator required")
    return {
        "sub": sub,
        "token_sha256": hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest(),
        "expires_at": expire,
    }


def _service() -> FlowResourceFolders:
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if memory is None:
        raise HTTPException(503, "Durable Flow resource folders unavailable")
    return FlowResourceFolders(FlowArtifactStore(memory))


def _binding(
    flow_id: str,
    expected_engagement_id: str,
    expected_revision: int,
    expected_authorization_version: int,
    expected_authorization_id: str,
    expected_authorization_sha256: str,
    expected_manifest_sha256: str,
) -> Dict[str, Any]:
    return {
        "flow_id": flow_id,
        "engagement_id": expected_engagement_id,
        "revision": expected_revision,
        "version": expected_authorization_version,
        "authorization_id": expected_authorization_id,
        "authorization_sha256": expected_authorization_sha256,
        "manifest_sha256": expected_manifest_sha256,
    }


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, FolderDenied):
        return HTTPException(exc.status, str(exc))
    if isinstance(exc, (ArtifactDenied, ArtifactReviewDenied)):
        return HTTPException(exc.status, str(exc))
    return HTTPException(503, "Durable Flow folder metadata unavailable")


def _headers(response: Response, sha: str) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Resource-Manifest-SHA256"] = sha


@router.get("/{flow_id}/resource-folders")
async def list_flow_resource_folders(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=1, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(min_length=64, max_length=64),
    expected_manifest_sha256: str = Query(min_length=64, max_length=64),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    binding = _binding(
        flow_id,
        expected_engagement_id,
        expected_revision,
        expected_authorization_version,
        expected_authorization_id,
        expected_authorization_sha256,
        expected_manifest_sha256,
    )
    try:
        catalog = await _service().get(
            binding,
            operator["sub"],
            operator["token_sha256"],
            operator["expires_at"],
        )
    except (FolderDenied, ArtifactDenied, ArtifactReviewDenied) as exc:
        raise _error(exc) from exc
    _headers(response, catalog["source_manifest_sha256"])
    return catalog


@router.post("/{flow_id}/resource-folders")
async def mutate_flow_resource_folders(
    flow_id: str,
    request: Request,
    response: Response,
    expected_engagement_id: str = Query(min_length=1, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_authorization_id: str = Query(min_length=1, max_length=128),
    expected_authorization_sha256: str = Query(min_length=64, max_length=64),
    expected_manifest_sha256: str = Query(min_length=64, max_length=64),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    payload = await _strict_mutation_json(request)
    binding = _binding(
        flow_id,
        expected_engagement_id,
        expected_revision,
        expected_authorization_version,
        expected_authorization_id,
        expected_authorization_sha256,
        expected_manifest_sha256,
    )
    try:
        result = await _service().mutate(
            binding,
            operator["sub"],
            operator["token_sha256"],
            operator["expires_at"],
            operation=payload.operation,
            expected_catalog_revision=payload.expected_catalog_revision,
            explicit_human_confirmation=payload.explicit_human_confirmation,
            folder_id=payload.folder_id,
            name=payload.name,
            artifact_id=payload.artifact_id,
            artifact_sha256=payload.artifact_sha256,
        )
    except (FolderDenied, ArtifactDenied, ArtifactReviewDenied) as exc:
        raise _error(exc) from exc
    _headers(response, result["source_manifest_sha256"])
    response.status_code = 201 if payload.operation == "create" else 200
    return result
