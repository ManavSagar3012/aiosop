"""Pending, *DENY-only* cross-source knowledge ingestion boundary.

0013/0015 can provide SHA-checked immutable artifact bytes and a distinct
senior's reviewed receipt. 0039 provides a current, versioned, tombstoned
principal-owned original. 0019/0038 provides an independently Flow-fenced,
mutable operator note. They do NOT provide an independently signed, durable
cross-source citation that binds a specific 0039 revision or 0019 revision
to the senior-reviewed 0013 artifact, current Task, issuer and owner.

Accordingly no caller, opt-in flag, mocked backend, metadata, or matching
SHA can promote those sources into agent/model instructions or report facts.
This module never touches a DB, calls a provider/tool, signs, or emits text
for prompt consumption. Pure checks of inert *caller-supplied* snapshots
below are NOT an admission or proof of durable storage readback.

PentAGI reference: pinned v2.2.0; sampled main files 2026-10-16 ONLY.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, NoReturn

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_GLOBAL = re.compile(r"lib-[0-9a-f]{32}\Z")
_FLOW_DOC = re.compile(r"knowledge-[0-9a-f]{32}\Z")
_ARTIFACT = re.compile(r"artifact-[0-9a-f]{32}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._:-]{1,59}\Z")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,127}\Z")
_OPT_IN = "OSOP_OPERATOR_KNOWLEDGE_REVIEWED_ADMISSION_ENABLED"


class ReviewedKnowledgeAdmissionDenied(PermissionError):
    """Missing independent cross-source citation/authority; never retry as approved."""


@dataclass(frozen=True)
class KnowledgeSourceReferences:
    """Inert proposed references; untrusted even if supplied by a current Task."""

    issuer: str
    principal_owner_sha256: str
    flow_owner: str
    engagement_id: str
    flow_id: str
    flow_revision: int
    task_id: str
    authorization_id: str
    authorization_version: int
    authorization_sha256: str
    global_document_id: str
    global_revision: int
    global_sha256: str
    flow_document_id: str
    flow_document_revision: int
    flow_document_sha256: str
    artifact_id: str
    artifact_sha256: str


def _digest(value: Any, *, max_bytes: int = 8192) -> str:
    if type(value) is not str:
        raise ReviewedKnowledgeAdmissionDenied("Source original text unavailable")
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ReviewedKnowledgeAdmissionDenied("Source original UTF-8 unavailable") from exc
    if not 1 <= len(raw) <= max_bytes or any(
        (ord(c) < 32 and c not in "\t\n\r") or ord(c) == 127 for c in value
    ):
        raise ReviewedKnowledgeAdmissionDenied("Source original text invalid")
    return hashlib.sha256(raw).hexdigest()


def _same(left: Any, right: Any) -> bool:
    return type(left) is str and type(right) is str and hmac.compare_digest(left, right)


def _byte_length(value: Any) -> int:
    if type(value) is not str:
        raise ReviewedKnowledgeAdmissionDenied("Original text is missing")
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise ReviewedKnowledgeAdmissionDenied("Original UTF-8 unavailable") from exc


def _candidate(value: KnowledgeSourceReferences) -> None:
    if type(value) is not KnowledgeSourceReferences:
        raise ReviewedKnowledgeAdmissionDenied("Complete source references required")
    for text, pattern in (
        (value.issuer, _IDENT),
        (value.flow_owner, _IDENT),
        (value.engagement_id, _IDENT),
        (value.task_id, _IDENT),
        (value.authorization_id, _IDENT),
        (value.flow_id, _FLOW),
        (value.global_document_id, _GLOBAL),
        (value.flow_document_id, _FLOW_DOC),
        (value.artifact_id, _ARTIFACT),
        (value.principal_owner_sha256, _DIGEST),
        (value.authorization_sha256, _DIGEST),
        (value.global_sha256, _DIGEST),
        (value.flow_document_sha256, _DIGEST),
        (value.artifact_sha256, _DIGEST),
    ):
        if type(text) is not str or pattern.fullmatch(text) is None:
            raise ReviewedKnowledgeAdmissionDenied("Invalid original source identity")
    if any(
        type(number) is not int or number < floor
        for number, floor in (
            (value.flow_revision, 0),
            (value.authorization_version, 1),
            (value.global_revision, 1),
            (value.flow_document_revision, 1),
        )
    ):
        raise ReviewedKnowledgeAdmissionDenied("Incomplete current revision identity")
    # Owner SHA is the stable 0039 issuer + subject namespace; this is a
    # *shape* check, not proof a supplied subject was JWT/OIDC authenticated.
    if not _same(
        value.principal_owner_sha256,
        hashlib.sha256((value.issuer + "\x00" + value.flow_owner).encode("utf-8")).hexdigest(),
    ):
        raise ReviewedKnowledgeAdmissionDenied("Principal owner mismatch")


def check_inert_projection_shapes(
    references: KnowledgeSourceReferences,
    *,
    global_original: Dict[str, Any],
    flow_original: Dict[str, Any],
    reviewed_artifact: Dict[str, Any],
) -> None:
    """Check inert snapshots for obvious mismatch; **not** signed admission.

    These dictionaries are *untrusted caller values*, not a durable DB read
    under current row locks. A successful return MUST NOT be interpreted as
    independently authenticated citation, approved content, or model input.
    """
    _candidate(references)
    if any(type(item) is not dict for item in (global_original, flow_original, reviewed_artifact)):
        raise ReviewedKnowledgeAdmissionDenied("Original source snapshots unavailable")
    g, f, r = global_original, flow_original, reviewed_artifact
    if (
        g.get("id") != references.global_document_id
        or type(g.get("revision")) is not int
        or g["revision"] != references.global_revision
        or g.get("deleted_at") is not None
        or g.get("status") == "tombstoned"
        or g.get("content_classification") != "untrusted_user_text"
        or g.get("approved_for_agent_context") is not False
        or g.get("verified_target_evidence") is not False
        or not _same(g.get("sha256"), references.global_sha256)
        or type(g.get("content_bytes")) is not int
        or _byte_length(g.get("content")) != g.get("content_bytes")
        or not _same(_digest(g.get("content")), references.global_sha256)
    ):
        raise ReviewedKnowledgeAdmissionDenied("Global original is stale or untrusted")
    if (
        f.get("id") != references.flow_document_id
        or f.get("flow_id") != references.flow_id
        or type(f.get("revision")) is not int
        or f["revision"] != references.flow_document_revision
        or f.get("source_flow_revision") != references.flow_revision
        or f.get("authorization_version") != references.authorization_version
        or f.get("deleted_at") is not None
        or f.get("approved_for_agent_context") is not False
        or not _same(f.get("sha256"), references.flow_document_sha256)
        or type(f.get("content_bytes")) is not int
        or _byte_length(f.get("untrusted_content")) != f.get("content_bytes")
        or not _same(_digest(f.get("untrusted_content")), references.flow_document_sha256)
    ):
        raise ReviewedKnowledgeAdmissionDenied("Flow original is stale or untrusted")
    if any(
        name in g or name in f
        for name in (
            "safe_for_execution",
            "system_prompt",
            "model_authority",
            "report_verified",
            "principal_subject",
            "principal_issuer",
            "owner_id",
        )
    ):
        raise ReviewedKnowledgeAdmissionDenied("Source authority escalation attempted")
    if (
        r.get("artifact_id") != references.artifact_id
        or r.get("flow_id") != references.flow_id
        or r.get("engagement_id") != references.engagement_id
        or r.get("flow_revision") != references.flow_revision
        or r.get("authorization_id") != references.authorization_id
        or r.get("authorization_version") != references.authorization_version
        or not _same(r.get("authorization_sha256"), references.authorization_sha256)
        or not _same(r.get("artifact_sha256"), references.artifact_sha256)
        or r.get("reviewer_role") != "senior_operator"
        or r.get("decision") != "approve"
        or r.get("verified_review") is not True
        or r.get("approved") is not True
        or r.get("uploader_sub") != references.flow_owner
        or type(r.get("reviewer_sub")) is not str
        or not r["reviewer_sub"]
        or r["reviewer_sub"] == references.flow_owner
        or r.get("reviewer_revoked") is True
        or r.get("review_revoked") is True
        or r.get("citation_signer_revoked") is True
        or r.get("text_trust_boundary") != "inert_reviewed_data_only"
        or r.get("security_evidence_verified") is not False
        or not _same(
            _digest(r.get("untrusted_reviewed_text"), max_bytes=4096),
            references.artifact_sha256,
        )
    ):
        raise ReviewedKnowledgeAdmissionDenied("Reviewed immutable original unavailable")
    # Even bit-for-bit identical text in all three sources would NOT prove
    # independently signed citation of either mutable note to this review.
    return None


class OperatorKnowledgeReviewedAdmission:
    """Host-callable pending boundary; cannot mint/promote source authority."""

    async def admit(
        self, references: KnowledgeSourceReferences, *, current_task: Any = None
    ) -> NoReturn:
        """Strict DENY regardless of caller data, fixture, env or fake approval."""
        raw = os.environ.get(_OPT_IN, "").strip().lower()
        if raw not in {"", "0", "false", "no", "1", "true", "yes"}:
            raise ReviewedKnowledgeAdmissionDenied("Invalid opt-in configuration")
        if raw not in {"1", "true", "yes"}:
            raise ReviewedKnowledgeAdmissionDenied("Cross-source ingestion is disabled")
        _candidate(references)
        # No independently enrolled senior/citation signer, signed per-source
        # citation ledger or atomic current Task/ROE+0039+0019+0013 readback
        # exists. Do not 'approve' by consulting a callback supplied by the
        # caller, a matching SHA, a token, or an in-memory boolean. In
        # particular this does NOT fetch original text or touch a provider.
        raise ReviewedKnowledgeAdmissionDenied(
            "Independent signed source citation and current durable admission unavailable"
        )
