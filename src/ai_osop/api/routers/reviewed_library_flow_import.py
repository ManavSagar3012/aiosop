"""Mounted 0039 original-global-to-Flow *preflight*, never an import grant.

Actual admission requires a separately host-enrolled four-root signed reviewer,
principal, current Flow and current Task/ROE service. A body cannot provide
roots, approvals or original content; no Flow writer is called. When that
independent infrastructure is absent the endpoint denies before database I/O.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.api.routers.operator_global_library import _BoundedUserLibraryRoute, _identity
from ai_osop.memory.reviewed_library_flow_import import (
    GlobalFlowImportRequest,
    ReviewedLibraryFlowImport,
    ReviewedLibraryFlowImportDenied,
)

router = APIRouter(
    prefix="/flows", tags=["reviewed-library-import"], route_class=_BoundedUserLibraryRoute
)
_HOST_SLOT = "_host_reviewed_global_flow_import_20261021"
_LOCKED_SLOT = "_host_reviewed_global_flow_locked_20261022"


class PreflightBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    engagement_id: StrictStr = Field(min_length=1, max_length=80)
    flow_owner: StrictStr = Field(min_length=1, max_length=64)
    expected_flow_revision: StrictInt = Field(ge=0)
    task_id: StrictStr = Field(min_length=1, max_length=128)
    authorization_id: StrictStr = Field(min_length=1, max_length=128)
    authorization_version: StrictInt = Field(ge=1)
    authorization_sha256: StrictStr = Field(min_length=64, max_length=64)
    global_document_id: StrictStr = Field(min_length=1, max_length=64)
    global_revision: StrictInt = Field(ge=1)
    global_sha256: StrictStr = Field(min_length=64, max_length=64)


def install_host_reviewed_library_preflight(app: Any, service: ReviewedLibraryFlowImport) -> None:
    """Host-only enrollment hook; never exposed by a request or environment.

    The independently enrolled signer services must own the four private keys;
    this API only receives their pinned public verification roots and readers.
    """
    app_state = getattr(app, "state", None)
    if (
        app_state is None
        or hasattr(app_state, _HOST_SLOT)
        or type(service) is not ReviewedLibraryFlowImport
        or service._enrolled_shape is not True
    ):
        raise ReviewedLibraryFlowImportDenied("Host independent authority unavailable")
    setattr(app_state, _HOST_SLOT, service)


def install_host_locked_reviewed_library_preflight(app: Any, writer: Any) -> None:
    """Install independently enrolled same-transaction 0039/Flow review checks.

    A separate, trusted host component must install the original four-root
    reviewer first. The process-bound writer must use that SAME signed service
    and the original Flow/0039 PostgreSQL transaction factory. Client input,
    symbolic reviewer flags and the HTTP router cannot install this writer.
    The writer is an immutable, pending-only current observation, NOT an import.
    """
    from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
        OperatorReviewedFlowAtomicWriter,
    )

    app_state = getattr(app, "state", None)
    original = getattr(app_state, _HOST_SLOT, None)
    if (
        app_state is None
        or hasattr(app_state, _LOCKED_SLOT)
        or type(writer) is not OperatorReviewedFlowAtomicWriter
        or type(original) is not ReviewedLibraryFlowImport
        or writer._preflight is not original
    ):
        raise ReviewedLibraryFlowImportDenied("Independent same-transaction review authority unavailable")
    try:
        writer._trusted_session_maker()
    except Exception:
        raise ReviewedLibraryFlowImportDenied("Independent same-transaction review authority unavailable") from None
    setattr(app_state, _LOCKED_SLOT, writer)


def _guarded_service(request: Request) -> ReviewedLibraryFlowImport:
    service = getattr(request.app.state, _HOST_SLOT, None)
    memory = getattr(state.get("orchestrator"), "session_memory", None)
    if (
        type(service) is not ReviewedLibraryFlowImport
        or service._enrolled_shape is not True
        or memory is None
        or service._library is None
        or service._library._maker is None
        or service._library._maker is not getattr(memory, "_async_session", None)
    ):
        raise HTTPException(
            503, "Independent reviewed-library original/Flow/ROE authority not enrolled"
        )
    return service


@router.post("/{flow_id}/reviewed-library-import/preflight")
async def reviewed_library_preflight(
    flow_id: str,
    body: PreflightBody,
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_operator),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Never accept an arbitrary client's issuer or subject, or a different
    # Flow owner from the current authenticated principal.
    issuer, _ = _identity(operator)
    if body.flow_owner != operator["sub"]:
        raise HTTPException(403, "Current signed Flow owner required")
    service = _guarded_service(request)
    proposal = GlobalFlowImportRequest(
        issuer=issuer,
        principal_subject=operator["sub"],
        flow_owner=operator["sub"],
        engagement_id=body.engagement_id,
        flow_id=flow_id,
        flow_revision=body.expected_flow_revision,
        task_id=body.task_id,
        authorization_id=body.authorization_id,
        authorization_version=body.authorization_version,
        authorization_sha256=body.authorization_sha256,
        global_document_id=body.global_document_id,
        global_revision=body.global_revision,
        global_sha256=body.global_sha256,
    )
    try:
        pending = await service.inspect_pending_citation(proposal)
        locked = getattr(request.app.state, _LOCKED_SLOT, None)
        if locked is not None:
            from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
                AtomicReviewedImportDenied,
                OperatorReviewedFlowAtomicWriter,
            )

            memory = getattr(state.get("orchestrator"), "session_memory", None)
            if (
                type(locked) is not OperatorReviewedFlowAtomicWriter
                or locked._preflight is not service
                or memory is None
                or getattr(locked._artifacts, "session_memory", None) is not memory
            ):
                raise ReviewedLibraryFlowImportDenied("Independent current locked review unavailable")
            try:
                observation = await locked.inspect_pending(proposal)
            except AtomicReviewedImportDenied:
                raise ReviewedLibraryFlowImportDenied("Independent current locked review unavailable") from None
            if (
                observation.source_id != pending.source_id
                or observation.source_revision != pending.original_revision
                or observation.source_sha256 != pending.original_sha256
                or observation.source_kind != pending.source_kind
                or observation.engagement_id != pending.engagement_id
                or observation.flow_id != pending.flow_id
                or observation.flow_revision != pending.flow_revision
                or observation.task_id != proposal.task_id
                or observation.authorization_version != proposal.authorization_version
                or observation.authorization_sha256 != proposal.authorization_sha256
                or observation.status != "pending_atomic_reviewed_citation_writer"
                or observation.transaction_committed_citation is not False
                or observation.approved_for_agent_context is not False
                or observation.verified_target_evidence is not False
                or observation.safe_for_execution is not False
                or observation.flow_local_document_created is not False
                or observation.source_original_returned is not False
            ):
                raise ReviewedLibraryFlowImportDenied("Independent locked citation changed")
    except ReviewedLibraryFlowImportDenied as error:
        raise HTTPException(
            409, "Original, reviewer or current signed authority unavailable"
        ) from error
    # Even four independently signed CURRENT readbacks lack the atomic writer.
    # No text, source owner identity, agent prompt or approval is returned.
    return asdict(pending)
