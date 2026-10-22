"""Transaction-scoped *pending* 0039 -> 0019/0038 Flow citation checks.

The existing schema has no atomic, reviewed global-source provenance binding
or independently enrolled same-transaction citation writer. All paths here
remain read-only. A successful preflight is never an import authorization.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from sqlalchemy import text

from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql
from ai_osop.memory.flow_artifacts import ArtifactDenied, FlowArtifactStore
from ai_osop.memory.operator_global_library import (
    KnowledgeDenied,
    OperatorGlobalLibrary,
    _projection,
)
from ai_osop.memory.reviewed_library_flow_import import (
    GlobalFlowImportRequest,
    ReviewedLibraryFlowImport,
    ReviewedLibraryFlowImportDenied,
    _original_signature,
    _scope,
)

_TASK_LOCK = text(
    "SELECT id,engagement_id,flow_id,status,payload "
    "FROM tasks WHERE id=:task AND engagement_id=:eng "
    "AND flow_id=:flow FOR SHARE"
)
_EXCLUDED_WITNESS = frozenset({"nonce", "issued_at", "expires_at"})
_PENDING = "pending_atomic_reviewed_citation_writer"


class AtomicReviewedImportDenied(ReviewedLibraryFlowImportDenied):
    """Host-only authority or an actual atomic import transaction is missing."""


@dataclass(frozen=True)
class LockedReviewedCitationPlan:
    """Bounded, immutable, content-free observation; never a commit receipt."""

    source_id: str
    source_revision: int
    source_sha256: str
    source_kind: str
    engagement_id: str
    flow_id: str
    flow_revision: int
    task_id: str
    authorization_version: int
    authorization_sha256: str
    reviewed_identity_sha256: str
    status: str = _PENDING
    transaction_committed_citation: bool = False
    approved_for_agent_context: bool = False
    verified_target_evidence: bool = False
    safe_for_execution: bool = False
    flow_local_document_created: bool = False
    source_original_returned: bool = False


def _require_task_row(row: Any, request: GlobalFlowImportRequest) -> None:
    """Reject a forged / stale task even when the Flow's signed ROE is current."""
    if not isinstance(row, Mapping):
        raise AtomicReviewedImportDenied("Current authoritative Flow Task unavailable")
    payload = row.get("payload")
    if not isinstance(payload, dict):
        raise AtomicReviewedImportDenied("Current authoritative Task payload unavailable")
    revisions = [
        payload[k]
        for k in ("_flow_revision", "planner_flow_revision", "mcp_flow_revision")
        if k in payload
    ]
    if (
        row.get("id") != request.task_id
        or row.get("engagement_id") != request.engagement_id
        or row.get("flow_id") != request.flow_id
        or row.get("status") != "running"
        or type(payload.get("_authorization_version")) is not int
        or payload["_authorization_version"] != request.authorization_version
        or not revisions
        or any(type(value) is not int or value != request.flow_revision for value in revisions)
        or (
            "_authorization_sha256" in payload
            and payload["_authorization_sha256"] != request.authorization_sha256
        )
        or (
            "_authorization_id" in payload
            and payload["_authorization_id"] != request.authorization_id
        )
    ):
        raise AtomicReviewedImportDenied("Task, current Flow revision or signed ROE changed")


def _witness_identity(claims: Tuple[Dict[str, Any], ...]) -> str:
    """Only a stable identity digest crosses the transaction boundary."""
    if len(claims) != 4:
        raise AtomicReviewedImportDenied("Four independently signed authorities required")
    from ai_osop.memory.reviewed_library_flow_import import _canonical

    normalized = [
        {key: value for key, value in witness.items() if key not in _EXCLUDED_WITNESS}
        for witness in claims
    ]
    return hashlib.sha256(_canonical({"authorities": normalized})).hexdigest()


class OperatorReviewedFlowAtomicWriter:
    """Only safe read-only transaction planning; final citation creation DENIED.

    All dependencies come from trusted host bootstrap, not a request field.
    `ReviewedLibraryFlowImport` provides independently enrolled principal,
    reviewer, current Flow and Task/ROE readers and their four public roots.
    The 0039 library and Flow-local transaction maker must be literally the
    SAME session factory. A signer callback is never generated here.
    """

    def __init__(
        self,
        *,
        preflight: Optional[ReviewedLibraryFlowImport] = None,
        flow_artifacts: Optional[FlowArtifactStore] = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        self._preflight = preflight
        self._artifacts = flow_artifacts
        self._timeout = timeout_seconds

    def _trusted_session_maker(self) -> Any:
        checker = self._preflight
        artifacts = self._artifacts
        if (
            type(checker) is not ReviewedLibraryFlowImport
            or checker._enrolled_shape is not True
            or type(checker._library) is not OperatorGlobalLibrary
            or type(artifacts) is not FlowArtifactStore
            or type(self._timeout) not in (int, float)
            or not 0.1 <= self._timeout <= 5.0
        ):
            raise AtomicReviewedImportDenied(
                "Independent host reviewed-import authority unavailable"
            )
        source_maker = checker._library._maker
        flow_maker = getattr(artifacts.session_memory, "_async_session", None)
        if source_maker is None or source_maker is not flow_maker or not callable(source_maker):
            raise AtomicReviewedImportDenied("Same-database scoped atomic source and Flow required")
        return source_maker

    @staticmethod
    def pending_status() -> Dict[str, Any]:
        """Nonsecret status available before enrollment or transaction."""
        return {
            "status": "pending_independent_authority_and_atomic_bind",
            "atomic_citation_writer_enrolled": False,
            "flow_local_document_created": False,
            "approved_for_agent_context": False,
            "verified_target_evidence": False,
            "safe_for_execution": False,
            "source_original_returned": False,
        }

    async def _inspect_locked(
        self,
        db: Any,
        request: GlobalFlowImportRequest,
        owner_sha256: str,
        common: Mapping[str, Any],
    ) -> LockedReviewedCitationPlan:
        """Operate inside the *caller-owned* open transaction; no writes."""
        # Follow FlowArtifactStore order: session -> signed ROE -> Flow.
        sid, auth_sha = await FlowArtifactStore._fence(
            db,
            request.flow_id,
            request.flow_owner,
            request.flow_revision,
            request.authorization_version,
            writing=True,
        )
        if sid != request.engagement_id or not hmac.compare_digest(
            auth_sha, request.authorization_sha256
        ):
            raise AtomicReviewedImportDenied("Signed current tenant and ROE digest changed")
        signed = await guard_sql(
            db,
            sid,
            expected_version=request.authorization_version,
            expected_digest=request.authorization_sha256,
        )
        if (
            signed.authorization_id != request.authorization_id
            or signed.policy.get("created_by") != request.flow_owner
            or signed.session_id != sid
        ):
            raise AtomicReviewedImportDenied("Current original signed ROE differs")
        task = (
            (
                await db.execute(
                    _TASK_LOCK,
                    {
                        "task": request.task_id,
                        "eng": request.engagement_id,
                        "flow": request.flow_id,
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
        _require_task_row(task, request)
        # 0039 updates and deletes serialize on this SAME current-pointer row.
        owner_row = await OperatorGlobalLibrary._current(
            db,
            request.issuer,
            owner_sha256,
            request.global_document_id,
        )
        if owner_row is None:
            raise AtomicReviewedImportDenied("Owned current global original unavailable")
        # Projection rehashes exact source bytes. Never return them, even for a
        # signed readback. A digest without the immutable original is insufficient.
        source = _projection(owner_row, with_content=True)
        original_sha, kind, revision = _original_signature(source, request)
        checker = self._preflight
        signed_first = await checker._current_round(request, common)
        signed_second = await checker._current_round(request, common)
        first_identity = _witness_identity(signed_first)
        if first_identity != _witness_identity(signed_second):
            raise AtomicReviewedImportDenied("Principal, reviewer or current Flow/ROE changed")
        # The current row is locked until the transaction ends; this extra
        # check detects even a malformed fake adapter mutating under the lock.
        refreshed = await OperatorGlobalLibrary._current(
            db, request.issuer, owner_sha256, request.global_document_id
        )
        if refreshed is None or _original_signature(
            _projection(refreshed, with_content=True), request
        ) != (original_sha, kind, revision):
            raise AtomicReviewedImportDenied("Original revised during locked preflight")
        return LockedReviewedCitationPlan(
            source_id=request.global_document_id,
            source_revision=revision,
            source_sha256=original_sha,
            source_kind=kind,
            engagement_id=request.engagement_id,
            flow_id=request.flow_id,
            flow_revision=request.flow_revision,
            task_id=request.task_id,
            authorization_version=request.authorization_version,
            authorization_sha256=request.authorization_sha256,
            reviewed_identity_sha256=first_identity,
        )

    async def inspect_pending(self, request: GlobalFlowImportRequest) -> LockedReviewedCitationPlan:
        """Verify under a shared transaction and release *only* inert metadata.

        PostgreSQL locks serialize the 0039 current revision with update/delete
        and the Flow/ROE/Task rows with their writers during this observation.
        They cannot prevent future changes after COMMIT: the returned plan is
        ALWAYS pending and cannot be redeemed as an import grant.
        """
        try:
            owner_sha, common = _scope(request)
        except ReviewedLibraryFlowImportDenied:
            raise AtomicReviewedImportDenied("Invalid scoped global/Flow import request") from None
        if request.principal_subject != request.flow_owner:
            raise AtomicReviewedImportDenied("Global principal differs from Flow owner")
        maker = self._trusted_session_maker()
        try:
            async with asyncio.timeout(self._timeout * 5):
                async with maker() as db:
                    async with db.begin():
                        return await self._inspect_locked(db, request, owner_sha, common)
        except AtomicReviewedImportDenied:
            raise
        except ReviewedLibraryFlowImportDenied:
            raise AtomicReviewedImportDenied(
                "Original, principal, reviewer or current ROE changed"
            ) from None
        except (
            ArtifactDenied,
            AuthorizationDenied,
            KnowledgeDenied,
            ValueError,
            TypeError,
            asyncio.TimeoutError,
            OSError,
            RuntimeError,
        ):
            raise AtomicReviewedImportDenied(
                "Locked current original, reviewer, signed Task and Flow unavailable"
            ) from None
        except Exception:
            raise AtomicReviewedImportDenied("Atomic preflight unavailable") from None

    async def bind_to_flow(self, request: GlobalFlowImportRequest) -> None:
        """No independently authorized 0039/0019/0038 citation writer exists."""
        _scope(request)
        raise AtomicReviewedImportDenied(
            "Missing single-transaction 0039 original, reviewed citation and Flow-local writer"
        )
