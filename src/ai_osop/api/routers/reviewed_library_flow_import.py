"""Mounted 0039 preflight and 0041 immutable citation, never an agent import grant.

Actual admission requires a separately host-enrolled four-root signed reviewer,
principal, current Flow and current Task/ROE service. A body cannot provide
roots, approvals or original content; no Flow writer is called. When that
independent infrastructure is absent the endpoint denies before database I/O.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.api.routers.operator_global_library import _BoundedUserLibraryRoute, _identity
from ai_osop.memory.reviewed_library_flow_import import (
    GlobalFlowImportRequest,
    ReviewedLibraryFlowImport,
    ReviewedLibraryFlowImportDenied,
)


class _PrivateReviewedImportRoute(_BoundedUserLibraryRoute):
    """Never reflect rejected untrusted original text in Pydantic 422 output.

    FastAPI normally serializes the rejected JSON field into detail[].input.
    An unauthorized body containing `content` could therefore be reflected
    verbatim even though our schema never stores or imports that content.
    Keep the existing strict bounded raw-body parser, then redact validation
    failures for just these sensitive reviewed-original Flow endpoints.
    """

    def get_route_handler(self):
        bounded = super().get_route_handler()

        async def private_validation(request: Request):
            try:
                return await bounded(request)
            except RequestValidationError:
                raise HTTPException(
                    422,
                    "Strict reviewed-library metadata required",
                    headers={
                        "Cache-Control": "private, no-store",
                        "X-Content-Type-Options": "nosniff",
                    },
                ) from None

        return private_validation


router = APIRouter(
    prefix="/flows", tags=["reviewed-library-import"], route_class=_PrivateReviewedImportRoute
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
        raise ReviewedLibraryFlowImportDenied(
            "Independent same-transaction review authority unavailable"
        )
    try:
        writer._trusted_session_maker()
    except Exception:
        raise ReviewedLibraryFlowImportDenied(
            "Independent same-transaction review authority unavailable"
        ) from None
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
            503,
            "Independent reviewed-library original/Flow/ROE authority not enrolled",
            headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
        )
    return service


def _locked_writer(request: Request, service: ReviewedLibraryFlowImport) -> Any:
    """Host-injected independent writer or 503; no request-supplied roots."""
    from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
        OperatorReviewedFlowAtomicWriter,
    )

    writer = getattr(request.app.state, _LOCKED_SLOT, None)
    memory = getattr(state.get("orchestrator"), "session_memory", None)
    if (
        type(writer) is not OperatorReviewedFlowAtomicWriter
        or writer._preflight is not service
        or memory is None
        or getattr(writer._artifacts, "session_memory", None) is not memory
    ):
        raise HTTPException(
            503,
            "Independent reviewed citation writer not enrolled",
            headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff"},
        )
    return writer


@router.post("/{flow_id}/reviewed-library-import/record-citation")
async def record_reviewed_library_citation(
    flow_id: str,
    body: PreflightBody,
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_operator),
) -> dict[str, Any]:
    """Persist reviewed original *metadata*, never Flow text or agent context.

    Safe only with independently installed four current signer roots and one
    original PostgreSQL transaction. Lost responses require explicit independent
    source/Flow readback; clients must not blindly retry the operation.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    issuer, _ = _identity(operator)
    if body.flow_owner != operator["sub"]:
        raise HTTPException(403, "Current signed Flow owner required")
    service = _guarded_service(request)
    writer = _locked_writer(request, service)
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
        from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
            AtomicReviewedImportDenied,
        )

        citation = await writer.record_reviewed_metadata_citation(proposal)
    except AtomicReviewedImportDenied as exc:
        raise HTTPException(
            409, "Current review or atomic citation unavailable or UNKNOWN"
        ) from exc
    return asdict(citation)


@router.post("/{flow_id}/reviewed-library-import/record-citation/readback")
async def readback_reviewed_library_citation(
    flow_id: str,
    body: PreflightBody,
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_operator),
) -> dict[str, Any]:
    """Read a committed original citation without replaying an uncertain write.

    Requires the same fresh four-root witness and original PostgreSQL locks;
    absent/stale rows return UNKNOWN, not a statement that an earlier request
    was never committed. Never returns original user text or execution grant.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    issuer, _ = _identity(operator)
    if body.flow_owner != operator["sub"]:
        raise HTTPException(403, "Current signed Flow owner required")
    service = _guarded_service(request)
    writer = _locked_writer(request, service)
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
        from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
            AtomicReviewedImportDenied,
        )

        citation = await writer.readback_reviewed_metadata_citation(proposal)
    except AtomicReviewedImportDenied as exc:
        raise HTTPException(409, "Current committed citation unconfirmed or UNKNOWN") from exc
    return asdict(citation)


@router.post("/{flow_id}/reviewed-library-import/store-reviewed-original")
async def store_reviewed_original_inert(
    flow_id: str,
    body: PreflightBody,
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_operator),
) -> dict[str, Any]:
    """Persist exact independently reviewed original with citation atomically.

    A separate operator action; no source text is supplied by the client or
    returned, and the immutable Flow original can never be auto-promoted to
    an agent prompt, target finding or execution authority.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    issuer, _ = _identity(operator)
    if body.flow_owner != operator["sub"]:
        raise HTTPException(403, "Current signed Flow owner required")
    service = _guarded_service(request)
    writer = _locked_writer(request, service)
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
        from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
            AtomicReviewedImportDenied,
        )

        receipt = await writer.store_reviewed_flow_original(proposal)
    except AtomicReviewedImportDenied as exc:
        raise HTTPException(
            409, "Current original/reviewer/Flow/ROE changed or transaction UNKNOWN"
        ) from exc
    return asdict(receipt)


@router.post("/{flow_id}/reviewed-library-import/store-reviewed-original/readback")
async def readback_stored_reviewed_original(
    flow_id: str,
    body: PreflightBody,
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_operator),
) -> dict[str, Any]:
    """Distinct nonmutating current 0041 + 0042 confirmation after lost ACK."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    issuer, _ = _identity(operator)
    if body.flow_owner != operator["sub"]:
        raise HTTPException(403, "Current signed Flow owner required")
    service = _guarded_service(request)
    writer = _locked_writer(request, service)
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
        from ai_osop.memory.operator_reviewed_flow_atomic_writer_20261022 import (
            AtomicReviewedImportDenied,
        )

        original = await writer.readback_reviewed_flow_original(proposal)
    except AtomicReviewedImportDenied as exc:
        raise HTTPException(409, "Current reviewed Flow original unconfirmed or UNKNOWN") from exc
    return asdict(original)


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
                raise ReviewedLibraryFlowImportDenied(
                    "Independent current locked review unavailable"
                )
            try:
                observation = await locked.inspect_pending(proposal)
            except AtomicReviewedImportDenied:
                raise ReviewedLibraryFlowImportDenied(
                    "Independent current locked review unavailable"
                ) from None
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
