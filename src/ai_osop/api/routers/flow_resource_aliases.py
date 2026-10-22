"""Signed owner-only, read-only Flow virtual folders and Task resource preview.

Mount alongside flow_artifacts under /flows. This is NOT a file/folder
CRUD API, upload, editable alias table, worker filesystem, or synchronization.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictStr

from ai_osop.api.routers.flow_artifacts import _operator, _store
from ai_osop.memory.flow_artifacts import ArtifactDenied
from ai_osop.memory.flow_resource_aliases import FlowResourceAliases


router = APIRouter(prefix="/flows", tags=["flow-resource-aliases"])


class TaskResourcePreview(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    engagement_id: StrictStr = Field(min_length=1, max_length=64)
    task_id: StrictStr = Field(min_length=1, max_length=64)
    artifact_id: StrictStr = Field(min_length=1, max_length=64)
    artifact_sha256: StrictStr = Field(min_length=64, max_length=64)
    authorization_sha256: StrictStr = Field(min_length=64, max_length=64)
    expected_manifest_sha256: StrictStr = Field(min_length=64, max_length=64)


def _service() -> FlowResourceAliases:
    return FlowResourceAliases(_store())


def _no_cache(response: Response, manifest_sha256: str) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Resource-Manifest-SHA256"] = manifest_sha256


@router.get("/{flow_id}/resource-aliases")
async def list_flow_resource_aliases(
    flow_id: str,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Classify a current SHA-verified immutable Flow into virtual folders."""
    try:
        catalog = await _service().list(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
        )
    except ArtifactDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    _no_cache(response, catalog["source_manifest_sha256"])
    return catalog


@router.get("/{flow_id}/resource-aliases/{artifact_id}/preview")
async def preview_flow_resource_alias(
    flow_id: str,
    artifact_id: str,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    expected_manifest_sha256: str = Query(min_length=64, max_length=64),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Metadata preview only, explicitly matched to the current manifest."""
    try:
        item = await _service().preview(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            artifact_id,
            expected_manifest_sha256,
        )
    except ArtifactDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    _no_cache(response, item["source_manifest_sha256"])
    return item


@router.post("/{flow_id}/resource-aliases/task-preview")
async def preview_approved_flow_task_resource(
    flow_id: str,
    request: TaskResourcePreview,
    response: Response,
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Current signed human-approved Task/resource eligibility; NO execution."""
    try:
        item = await _service().task_preview(
            flow_id,
            operator["sub"],
            expected_revision,
            expected_authorization_version,
            engagement_id=request.engagement_id,
            task_id=request.task_id,
            artifact_id=request.artifact_id,
            artifact_sha256=request.artifact_sha256,
            authorization_sha256=request.authorization_sha256,
            expected_manifest_sha256=request.expected_manifest_sha256,
        )
    except ArtifactDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    _no_cache(response, item["source_manifest_sha256"])
    return item
