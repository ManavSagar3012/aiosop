"""Current signed global-source review with scoped 0041/0042 PG writes.

The host must separately enroll independent principal/reviewer/Flow/ROE roots.
0041 citations and 0042 Flow original resources are immutable and inert: they
never grant agent-context, tool execution, or independent target evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import uuid
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
_CITATION_INSERT = text(
    "INSERT INTO operator_reviewed_global_flow_citations "
    "(id,principal_issuer,principal_owner_sha256,global_document_id,global_revision,"
    "global_sha256,source_kind,engagement_id,flow_id,flow_owner,flow_revision,"
    "task_id,authorization_version,authorization_sha256,reviewed_identity_sha256) "
    "VALUES (:id,:issuer,:owner_sha,:source,:revision,:sha,:kind,:eng,:flow,"
    ":flow_owner,:flow_revision,:task,:auth_version,:auth_sha,:review_sha) "
    "RETURNING id"
)
_CITATION_READBACK = text(
    "SELECT id FROM operator_reviewed_global_flow_citations "
    "WHERE principal_issuer=:issuer AND principal_owner_sha256=:owner_sha "
    "AND global_document_id=:source AND global_revision=:revision "
    "AND global_sha256=:sha AND source_kind=:kind "
    "AND engagement_id=:eng AND flow_id=:flow AND flow_owner=:flow_owner "
    "AND flow_revision=:flow_revision AND task_id=:task "
    "AND authorization_version=:auth_version AND authorization_sha256=:auth_sha "
    "AND reviewed_identity_sha256=:review_sha"
)
_FLOW_ORIGINAL_INSERT = text(
    "INSERT INTO operator_reviewed_flow_originals "
    "(citation_id,engagement_id,flow_id,flow_owner,sha256,source_kind,content,content_bytes) "
    "VALUES (:id,:eng,:flow,:flow_owner,:sha,:kind,:original,:bytes) "
    "RETURNING citation_id"
)
_FLOW_ORIGINAL_READBACK = text(
    "SELECT c.id,o.content_bytes FROM operator_reviewed_global_flow_citations c "
    "JOIN operator_reviewed_flow_originals o ON o.citation_id=c.id "
    "AND o.engagement_id=c.engagement_id AND o.flow_id=c.flow_id "
    "AND o.flow_owner=c.flow_owner AND o.sha256=c.global_sha256 "
    "AND o.source_kind=c.source_kind "
    "WHERE c.principal_issuer=:issuer AND c.principal_owner_sha256=:owner_sha "
    "AND c.global_document_id=:source AND c.global_revision=:revision "
    "AND c.global_sha256=:sha AND c.source_kind=:kind "
    "AND c.engagement_id=:eng AND c.flow_id=:flow AND c.flow_owner=:flow_owner "
    "AND c.flow_revision=:flow_revision AND c.task_id=:task "
    "AND c.authorization_version=:auth_version AND c.authorization_sha256=:auth_sha "
    "AND c.reviewed_identity_sha256=:review_sha "
    "AND o.approved_for_agent_context IS FALSE AND o.verified_target_evidence IS FALSE"
)


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


@dataclass(frozen=True)
class RecordedReviewedCitation:
    """Durable *metadata-only* citation, NOT a Flow knowledge/agent grant."""

    citation_id: str
    source_id: str
    source_revision: int
    source_sha256: str
    engagement_id: str
    flow_id: str
    task_id: str
    status: str = "recorded_untrusted_source_citation"
    transaction_committed_citation: bool = True
    flow_local_document_created: bool = False
    approved_for_agent_context: bool = False
    verified_target_evidence: bool = False
    safe_for_execution: bool = False
    source_original_returned: bool = False


@dataclass(frozen=True)
class StoredReviewedFlowOriginal:
    """Atomic committed Flow original, protected by the DB and current locks.

    Never project `content` to an API/UI/client or treat this as agent approval.
    """

    citation_id: str
    source_id: str
    source_revision: int
    source_sha256: str
    original_utf8_bytes: int
    engagement_id: str
    flow_id: str
    task_id: str
    status: str = "reviewed_flow_original_stored_inert"
    transaction_committed_source_and_citation: bool = True
    flow_local_original_stored: bool = True
    approved_for_agent_context: bool = False
    verified_target_evidence: bool = False
    safe_for_execution: bool = False
    source_original_returned: bool = False


def _citation_parameters(
    request: GlobalFlowImportRequest,
    plan: LockedReviewedCitationPlan,
    owner_sha256: str,
    citation_id: str,
) -> Dict[str, Any]:
    return {
        "id": citation_id,
        "issuer": request.issuer,
        "owner_sha": owner_sha256,
        "source": plan.source_id,
        "revision": plan.source_revision,
        "sha": plan.source_sha256,
        "kind": plan.source_kind,
        "eng": plan.engagement_id,
        "flow": plan.flow_id,
        "flow_owner": request.flow_owner,
        "flow_revision": plan.flow_revision,
        "task": plan.task_id,
        "auth_version": plan.authorization_version,
        "auth_sha": plan.authorization_sha256,
        "review_sha": plan.reviewed_identity_sha256,
    }


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
        # Existing legitimate Task writers persist the signed ROE VERSION,
        # not always its ID/digest. Both complete values are independently
        # required by the same-transaction guard_sql and four-role signer
        # readback below. Reject incorrect optional Task hints, never mint
        # missing identity or skip the verified current signed ROE check.
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
    """Host-gated signed-current readback, immutable citation/Flow resource.

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
        """Legacy *agent-context* bind DENIES; 0042 inert original is separate."""
        _scope(request)
        raise AtomicReviewedImportDenied(
            "Missing single-transaction approved Flow agent-context writer; use 0042 only for inert originals"
        )

    async def record_reviewed_metadata_citation(
        self, request: GlobalFlowImportRequest
    ) -> RecordedReviewedCitation:
        """Commit a reviewed SOURCE REFERENCE only, under the exact signed locks.

        This is a useful durable, immutable 0041 citation; it does *not* copy
        source text into Flow-local knowledge or an agent prompt. Real separately
        enrolled reviewer/Flow/ROE roots are required. An exception or
        cancellation rolls back; a lost HTTP response remains UNKNOWN and must
        be independently read back, never silently retried.
        """
        try:
            owner_sha, common = _scope(request)
            if request.principal_subject != request.flow_owner:
                raise AtomicReviewedImportDenied("Global principal differs from Flow owner")
            maker = self._trusted_session_maker()
            identifier = "citation-" + uuid.uuid4().hex
            async with asyncio.timeout(self._timeout * 5):
                async with maker() as db:
                    async with db.begin():
                        plan = await self._inspect_locked(db, request, owner_sha, common)
                        result = await db.execute(
                            _CITATION_INSERT,
                            _citation_parameters(request, plan, owner_sha, identifier),
                        )
                        if result.scalar_one() != identifier:
                            raise AtomicReviewedImportDenied("Atomic citation readback mismatch")
            # Transaction context has completed successfully; this boolean
            # says PostgreSQL COMMIT, not HTTP client receipt or agent approval.
            return RecordedReviewedCitation(
                citation_id=identifier,
                source_id=plan.source_id,
                source_revision=plan.source_revision,
                source_sha256=plan.source_sha256,
                engagement_id=plan.engagement_id,
                flow_id=plan.flow_id,
                task_id=plan.task_id,
            )
        except AtomicReviewedImportDenied:
            raise
        except asyncio.CancelledError:
            raise
        except (ReviewedLibraryFlowImportDenied, ArtifactDenied, AuthorizationDenied, KnowledgeDenied):
            raise AtomicReviewedImportDenied("Current signed citation admission unavailable") from None
        except Exception:
            raise AtomicReviewedImportDenied(
                "Durable reviewed metadata citation failed or completion UNKNOWN"
            ) from None

    async def store_reviewed_flow_original(
        self, request: GlobalFlowImportRequest
    ) -> StoredReviewedFlowOriginal:
        """Atomic reviewed 0039 original -> inert 0042 Flow resource + 0041 citation.

        Both inserts and all independently signed current review/source/Task/ROE
        checks occur in ONE PostgreSQL transaction. No content leaves it to a
        model, target, API, log, or client. The 0042 SQL constraints permanently
        prohibit setting the stored original's agent/evidence trust flags.
        """
        try:
            owner_sha, common = _scope(request)
            if request.principal_subject != request.flow_owner:
                raise AtomicReviewedImportDenied("Original owner and Flow owner mismatch")
            maker = self._trusted_session_maker()
            identifier = "citation-" + uuid.uuid4().hex
            async with asyncio.timeout(self._timeout * 5):
                async with maker() as db:
                    async with db.begin():
                        plan = await self._inspect_locked(db, request, owner_sha, common)
                        owner_row = await OperatorGlobalLibrary._current(
                            db, request.issuer, owner_sha, plan.source_id
                        )
                        if owner_row is None:
                            raise AtomicReviewedImportDenied("Reviewed source no longer current")
                        original = _projection(owner_row, with_content=True)
                        if _original_signature(original, request) != (
                            plan.source_sha256, plan.source_kind, plan.source_revision
                        ):
                            raise AtomicReviewedImportDenied("Reviewed exact UTF-8 source changed")
                        if (
                            type(original.get("content")) is not str
                            or type(original.get("content_bytes")) is not int
                            or not 1 <= original["content_bytes"] <= 8192
                        ):
                            raise AtomicReviewedImportDenied("Immutable reviewed original unavailable")
                        reference = await db.execute(
                            _CITATION_INSERT,
                            _citation_parameters(request, plan, owner_sha, identifier),
                        )
                        if reference.scalar_one() != identifier:
                            raise AtomicReviewedImportDenied("Reviewed citation return mismatch")
                        stored = await db.execute(
                            _FLOW_ORIGINAL_INSERT,
                            {
                                "id": identifier,
                                "eng": plan.engagement_id,
                                "flow": plan.flow_id,
                                "flow_owner": request.flow_owner,
                                "sha": plan.source_sha256,
                                "kind": plan.source_kind,
                                "original": original["content"],
                                "bytes": original["content_bytes"],
                            },
                        )
                        if stored.scalar_one() != identifier:
                            raise AtomicReviewedImportDenied("Reviewed original storage readback mismatch")
            return StoredReviewedFlowOriginal(
                citation_id=identifier,
                source_id=plan.source_id,
                source_revision=plan.source_revision,
                source_sha256=plan.source_sha256,
                original_utf8_bytes=original["content_bytes"],
                engagement_id=plan.engagement_id,
                flow_id=plan.flow_id,
                task_id=plan.task_id,
            )
        except AtomicReviewedImportDenied:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AtomicReviewedImportDenied(
                "Reviewed Flow original transaction unavailable or completion UNKNOWN"
            ) from None

    async def readback_reviewed_flow_original(
        self, request: GlobalFlowImportRequest
    ) -> StoredReviewedFlowOriginal:
        """Manual signed exact joint 0041+0042 confirmation, zero writes/replays.

        Absence cannot prove previous HTTP commit failed. The 0042 original is
        queried only by immutable citation and exact Flow/owner/SHA/Task/ROE
        lineage after independent currently signed review and source locks.
        """
        try:
            owner_sha, common = _scope(request)
            if request.principal_subject != request.flow_owner:
                raise AtomicReviewedImportDenied("Reviewed Flow original owner mismatch")
            maker = self._trusted_session_maker()
            async with asyncio.timeout(self._timeout * 5):
                async with maker() as db:
                    async with db.begin():
                        plan = await self._inspect_locked(db, request, owner_sha, common)
                        records = await db.execute(
                            _FLOW_ORIGINAL_READBACK,
                            _citation_parameters(request, plan, owner_sha, ""),
                        )
                        found = records.mappings().one_or_none()
                        if (
                            not isinstance(found, Mapping)
                            or type(found.get("id")) is not str
                            or not found["id"].startswith("citation-")
                            or len(found["id"]) != 41
                            or any(char not in "0123456789abcdef" for char in found["id"][9:])
                            or type(found.get("content_bytes")) is not int
                            or not 1 <= found["content_bytes"] <= 8192
                        ):
                            raise AtomicReviewedImportDenied("Reviewed original not independently confirmed: UNKNOWN")
            return StoredReviewedFlowOriginal(
                citation_id=found["id"],
                source_id=plan.source_id,
                source_revision=plan.source_revision,
                source_sha256=plan.source_sha256,
                original_utf8_bytes=found["content_bytes"],
                engagement_id=plan.engagement_id,
                flow_id=plan.flow_id,
                task_id=plan.task_id,
            )
        except AtomicReviewedImportDenied:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AtomicReviewedImportDenied("Current signed inert Flow original readback UNKNOWN") from None

    async def readback_reviewed_metadata_citation(
        self, request: GlobalFlowImportRequest
    ) -> RecordedReviewedCitation:
        """Manual current signed readback after an ambiguous HTTP ACK.

        An absent row does NOT prove a previous network request never committed;
        it can also mean the reviewer or ROE identity changed. Never issue a
        replacement INSERT, grant agent access, or automatically replay.
        """
        try:
            owner_sha, common = _scope(request)
            if request.principal_subject != request.flow_owner:
                raise AtomicReviewedImportDenied("Original principal and Flow owner mismatch")
            maker = self._trusted_session_maker()
            async with asyncio.timeout(self._timeout * 5):
                async with maker() as db:
                    async with db.begin():
                        plan = await self._inspect_locked(db, request, owner_sha, common)
                        result = await db.execute(
                            _CITATION_READBACK,
                            {
                                "issuer": request.issuer,
                                "owner_sha": owner_sha,
                                "source": plan.source_id,
                                "revision": plan.source_revision,
                                "sha": plan.source_sha256,
                                "kind": plan.source_kind,
                                "eng": plan.engagement_id,
                                "flow": plan.flow_id,
                                "flow_owner": request.flow_owner,
                                "flow_revision": plan.flow_revision,
                                "task": plan.task_id,
                                "auth_version": plan.authorization_version,
                                "auth_sha": plan.authorization_sha256,
                                "review_sha": plan.reviewed_identity_sha256,
                            },
                        )
                        identifier = result.scalar_one_or_none()
                        if (
                            type(identifier) is not str
                            or not identifier.startswith("citation-")
                            or len(identifier) != 41
                            or any(c not in "0123456789abcdef" for c in identifier[9:])
                        ):
                            raise AtomicReviewedImportDenied(
                                "No current independently confirmed citation; outcome UNKNOWN"
                            )
            return RecordedReviewedCitation(
                citation_id=identifier,
                source_id=plan.source_id,
                source_revision=plan.source_revision,
                source_sha256=plan.source_sha256,
                engagement_id=plan.engagement_id,
                flow_id=plan.flow_id,
                task_id=plan.task_id,
            )
        except AtomicReviewedImportDenied:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise AtomicReviewedImportDenied(
                "Current signed PostgreSQL citation readback unavailable or UNKNOWN"
            ) from None
