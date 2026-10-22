"""Fail-closed, immutable qualification ledger: NO target-effect promotion.

Production evidence audit, 2026-10-16:
* `controlled_target_audit_oracle` is a test-only ASGI candidate signer.
* Signed target proof, ownership/access audit, provider receipt, graph flag and
  HTTP 200 are not an independent *production* target-effect observer.
* There is no independently provisioned production verifier that observes
  current owner-of-record, real private resource contents and all three live
  identities and binds that observation to an exact finding.

Until such a verifier is built, this module cannot emit VERIFIED. The database
schema itself refuses that transition. An UNKNOWN ledger record is merely an
immutable, restart-safe record that a particular current reviewed candidate
needs independent target-effect verification; it cannot authorize report
release, vulnerability status changes or a second target request.

The caller must supply an authenticated senior owner, an open PostgreSQL
transaction, and trusted same-transaction callbacks from the existing
candidate-review API. Do not build those callbacks from user input, an LLM,
an MCP/provider outcome or a test-only target oracle. No external I/O here.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy import text

from ai_osop.core.target_authority_proof import _canonical, _strict_json
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.verified_finding_decisions import (
    _record_integrity as _review_integrity,
    read_latest_candidate_review,
)

_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_FINDING = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._-]{1,58}\Z")
_SUB = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_RESOURCE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_REVIEW_ID = re.compile(r"vfdec-[0-9a-f]{32}\Z")
_ATTEMPT_ID = re.compile(r"teqa-[0-9a-f]{32}\Z")
_DOMAIN = b"AI-OSOP-UNKNOWN-TARGET-EFFECT-QUALIFICATION-V1\x00"
_REASON = "independent_target_effect_service_missing"

_CURRENT_REVIEW = text(
    "SELECT * FROM verified_target_finding_decisions "
    "WHERE engagement_id=:eng AND flow_id=:flow AND finding_id=:finding "
    "ORDER BY review_revision DESC LIMIT 1 FOR SHARE"
)
_CURRENT_ATTEMPT = text(
    "SELECT * FROM target_effect_qualification_attempts "
    "WHERE engagement_id=:eng AND flow_id=:flow AND finding_id=:finding "
    "ORDER BY revision DESC LIMIT 1 FOR SHARE"
)
_PROOF = text(
    "SELECT engagement_id,flow_id,proof_sha256,audit_corroboration_sha256,"
    "original_source_task_id,source_task_id,target_task_id,"
    "authorization_version,flow_revision,target_claims_json,"
    "ownership_audit_json,access_audit_json "
    "FROM target_authority_assertions "
    "WHERE engagement_id=:eng AND flow_id=:flow AND proof_sha256=:proof FOR SHARE"
)
_COLUMNS = (
    "id",
    "engagement_id",
    "flow_id",
    "finding_id",
    "revision",
    "review_decision_id",
    "review_decision_sha256",
    "review_revision",
    "original_source_task_id",
    "source_task_id",
    "target_task_id",
    "proof_sha256",
    "audit_corroboration_sha256",
    "observation_binding_sha256",
    "report_source_evidence_sha256",
    "authorization_id",
    "authorization_version",
    "authorization_sha256",
    "flow_revision",
    "reviewer_sub",
    "resource_id",
    "resource_owner_identity_sha256",
    "resource_visibility",
    "source_http_status",
    "target_http_status",
    "anonymous_http_status",
    "status",
    "reason_code",
    "independent_effect_verified",
    "finding_verified",
    "report_release_approved",
    "previous_attempt_id",
    "previous_attempt_sha256",
    "attempt_sha256",
)
_INSERT = text(
    "INSERT INTO target_effect_qualification_attempts ("
    + ",".join(_COLUMNS)
    + ") VALUES ("
    + ",".join(":" + field for field in _COLUMNS)
    + ") ON CONFLICT DO NOTHING RETURNING id"
)


class TargetEffectQualificationDenied(PermissionError):
    """Unsafe current state, stale CAS or unavailable transactional storage."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _valid(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _unknown(row: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "reason_code": _REASON,
        "revision": row.get("revision", 0) if row else 0,
        "qualification_id": row.get("id") if row else None,
        "qualification_sha256": row.get("attempt_sha256") if row else None,
        "finding_verified": False,
        "independent_target_effect_verified": False,
        "authorization_violation_verified": False,
        "finding_release_eligible": False,
        "report_release_approved": False,
    }


def _check_inputs(
    *,
    engagement_id: Any,
    flow_id: Any,
    finding_id: Any,
    review_decision_id: Any,
    review_decision_sha256: Any,
    proof_sha256: Any,
    audit_sha256: Any,
    authorization_version: Any,
    flow_revision: Any,
    reviewer_sub: Any,
    reviewer_role: Any,
    reviewer_token_sha256: Any,
    reviewer_expires_at: Any,
    expected_revision: Any,
) -> None:
    if not (
        _valid(_ENG, engagement_id)
        and _valid(_FLOW, flow_id)
        and _valid(_FINDING, finding_id)
        and _valid(_REVIEW_ID, review_decision_id)
        and all(
            _valid(_SHA, val)
            for val in (review_decision_sha256, proof_sha256, audit_sha256, reviewer_token_sha256)
        )
        and type(authorization_version) is int
        and authorization_version > 0
        and type(flow_revision) is int
        and flow_revision >= 0
        and _valid(_SUB, reviewer_sub)
        and reviewer_role == "senior_operator"
        and type(reviewer_expires_at) is int
        and reviewer_expires_at > 0
        and type(expected_revision) is int
        and 0 <= expected_revision < 1000000
    ):
        raise TargetEffectQualificationDenied(422, "Invalid bounded effect qualification")


def _fingerprint(row: Dict[str, Any]) -> str:
    return hashlib.sha256(
        _DOMAIN + _canonical({field: row[field] for field in _COLUMNS if field != "attempt_sha256"})
    ).hexdigest()


def _integrity(row: Any) -> bool:
    if not isinstance(row, dict) or not _valid(_SHA, row.get("attempt_sha256")):
        return False
    try:
        return hmac.compare_digest(_fingerprint(row), row["attempt_sha256"])
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        return False


async def _live_fence(
    db: Any,
    *,
    engagement_id: str,
    reviewer_sub: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    authorization_version: int,
    read_only: bool,
) -> Any:
    if (
        db is None
        or not callable(getattr(db, "execute", None))
        or not callable(getattr(db, "in_transaction", None))
        or db.in_transaction() is not True
    ):
        raise TargetEffectQualificationDenied(
            503, "Open caller-owned PostgreSQL transaction required"
        )
    owner = (
        await db.execute(
            text(
                "SELECT created_by FROM session_states WHERE session_id=:eng "
                + ("FOR SHARE" if read_only else "FOR UPDATE")
            ),
            {"eng": engagement_id},
        )
    ).scalar_one_or_none()
    if not _valid(_SUB, owner) or not hmac.compare_digest(owner, reviewer_sub):
        raise TargetEffectQualificationDenied(403, "Current signed engagement owner required")
    try:
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        signed = await guard_sql(db, engagement_id, expected_version=authorization_version)
    except Exception as exc:
        raise TargetEffectQualificationDenied(
            403, "Current senior/ROE authorization unavailable"
        ) from exc
    if (
        signed.session_id != engagement_id
        or signed.version != authorization_version
        or signed.policy.get("created_by") != owner
        or not _valid(_SHA, signed.policy_sha256)
        or not isinstance(signed.authorization_id, str)
        or not 1 <= len(signed.authorization_id) <= 128
    ):
        raise TargetEffectQualificationDenied(409, "Current signed ROE and owner differ")
    return signed


def _review_matches(
    row: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    proof_sha256: str,
    audit_sha256: str,
    authorization_version: int,
    flow_revision: int,
    reviewer_sub: str,
    signed: Any,
) -> bool:
    return bool(
        row is not None
        and _review_integrity(dict(row))
        and all(
            row.get(k) == v
            for k, v in {
                "id": review_decision_id,
                "decision_sha256": review_decision_sha256,
                "engagement_id": engagement_id,
                "flow_id": flow_id,
                "finding_id": finding_id,
                "reviewer_sub": reviewer_sub,
                "authorization_id": signed.authorization_id,
                "authorization_sha256": signed.policy_sha256,
                "authorization_version": authorization_version,
                "flow_revision": flow_revision,
                "proof_sha256": proof_sha256,
                "audit_corroboration_sha256": audit_sha256,
            }.items()
        )
        and type(row.get("review_revision")) is int
        and row["review_revision"] > 0
        and row.get("decision_status")
        in {"candidate_only", "UNKNOWN", "independent_verification_required"}
        and all(
            _valid(_SHA, row.get(field))
            for field in ("observation_binding_sha256", "report_source_evidence_sha256")
        )
        and all(
            _valid(_TASK, row.get(field))
            for field in ("original_source_task_id", "source_task_id", "target_task_id")
        )
        and len({row["original_source_task_id"], row["source_task_id"], row["target_task_id"]}) == 3
    )


async def _resource_candidate(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    review: Dict[str, Any],
    proof_sha256: str,
    audit_sha256: str,
    authorization_version: int,
    flow_revision: int,
    signed: Any,
) -> Dict[str, Any]:
    """Bounded candidate-only owner/status facts, NEVER a live owner-of-record."""
    source = (
        (
            await db.execute(
                _PROOF,
                {
                    "eng": engagement_id,
                    "flow": flow_id,
                    "proof": proof_sha256,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if source is None or any(
        source.get(key) != value
        for key, value in {
            "engagement_id": engagement_id,
            "flow_id": flow_id,
            "proof_sha256": proof_sha256,
            "audit_corroboration_sha256": audit_sha256,
            "original_source_task_id": review["original_source_task_id"],
            "source_task_id": review["source_task_id"],
            "target_task_id": review["target_task_id"],
            "authorization_version": authorization_version,
            "flow_revision": flow_revision,
        }.items()
    ):
        raise TargetEffectQualificationDenied(409, "Original immutable signed source unavailable")
    try:
        claims = _strict_json(source["target_claims_json"], max_bytes=4096)
        ownership = _strict_json(source["ownership_audit_json"], max_bytes=4096)
        access = _strict_json(source["access_audit_json"], max_bytes=4096)
        if any(
            _canonical(doc) != source[column]
            for doc, column in (
                (claims, "target_claims_json"),
                (ownership, "ownership_audit_json"),
                (access, "access_audit_json"),
            )
        ):
            raise ValueError("Noncanonical signed bytes")
        fields = (
            "engagement_id",
            "flow_id",
            "original_source_task_id",
            "source_task_id",
            "target_task_id",
            "flow_revision",
            "authorization_version",
            "authorization_id",
            "authorization_sha256",
            "source_identity",
            "target_identity",
            "resource_visibility",
            "resource_owner_identity",
            "source_http_status",
            "target_http_status",
            "anonymous_http_status",
            "source_response_sha256",
            "target_response_sha256",
        )
        if any(doc.get(key) != claims.get(key) for doc in (ownership, access) for key in fields):
            raise ValueError("Signed owner/access source changed")
        resource_id = ownership.get("resource_id")
        owner_identity = ownership.get("resource_owner_identity")
        if not (
            _valid(_RESOURCE, resource_id)
            and _valid(_SUB, owner_identity)
            and owner_identity == claims.get("source_identity")
            and owner_identity != claims.get("target_identity")
            and ownership.get("resource_visibility") == "private"
            and access.get("resource_visibility") == "private"
            and claims.get("resource_visibility") == "private"
            and ownership.get("resource_id") == access.get("resource_id")
            and claims.get("source_http_status") == 200
            and claims.get("target_http_status") == 200
            and claims.get("anonymous_http_status") in (401, 403, 404)
            and claims.get("cross_identity_disclosure_confirmed") is True
            and claims.get("target_access_forbidden") is True
            and claims.get("public_access") is False
            and claims.get("redirected") is False
            and claims.get("denied") is False
            and _valid(_SHA, claims.get("source_response_sha256"))
            and claims["source_response_sha256"] == claims.get("target_response_sha256")
            and claims.get("authorization_id") == signed.authorization_id
            and claims.get("authorization_sha256") == signed.policy_sha256
        ):
            raise ValueError("Unconfirmed candidate owner or anonymous denial")
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise TargetEffectQualificationDenied(
            409, "Signed owner-of-record candidate provenance invalid"
        ) from exc
    return {
        "resource_id": resource_id,
        "resource_owner_identity_sha256": hashlib.sha256(
            (engagement_id + "\x00" + owner_identity).encode("utf-8")
        ).hexdigest(),
        "resource_visibility": "private",
        "source_http_status": 200,
        "target_http_status": 200,
        "anonymous_http_status": claims["anonymous_http_status"],
    }


async def record_unknown_effect_qualification(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    proof_sha256: str,
    audit_sha256: str,
    authorization_version: int,
    flow_revision: int,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    expected_revision: int,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
) -> Dict[str, Any]:
    """CAS append a finding-specific UNKNOWN; never produces VERIFIED.

    The two callbacks MUST re-check current signed dual Task execution,
    revocation, fresh sessions, and signed report evidence using *this db*.
    A separately trusted production target-effect service does not yet exist.
    No caller-supplied `independent_verified=True` or synthetic result is
    accepted, persisted or capable of changing the state.

    For failures before INSERT, raise to roll back caller's transaction. For
    missing current review return unpersisted UNKNOWN (not a successful write).
    """
    _check_inputs(
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        expected_revision=expected_revision,
    )
    if not callable(trusted_current_verifier) or not callable(trusted_report_source_check):
        return _unknown()
    signed = await _live_fence(
        db,
        engagement_id=engagement_id,
        reviewer_sub=reviewer_sub,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        authorization_version=authorization_version,
        read_only=False,
    )
    args = {"eng": engagement_id, "flow": flow_id, "finding": finding_id}
    review = (await db.execute(_CURRENT_REVIEW, args)).mappings().one_or_none()
    if not _review_matches(
        review,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        signed=signed,
    ):
        return _unknown()
    approved = await read_latest_candidate_review(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        authorization_version=authorization_version,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
    )
    if (
        approved.get("decision_id") != review_decision_id
        or approved.get("decision_sha256") != review_decision_sha256
        or approved.get("status")
        not in {"candidate_only", "UNKNOWN", "independent_verification_required"}
        or approved.get("finding_verified") is not False
        or approved.get("report_release_approved") is not False
    ):
        return _unknown()
    # Re-parses the original signed candidate bytes; their signatures were
    # separately verified by read_latest_candidate_review in this transaction.
    candidate = await _resource_candidate(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        review=dict(review),
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        signed=signed,
    )
    previous = (await db.execute(_CURRENT_ATTEMPT, args)).mappings().one_or_none()
    if previous is not None and (
        not _integrity(dict(previous))
        or previous.get("status") != "UNKNOWN"
        or previous.get("reason_code") != _REASON
        or any(
            previous.get(k) is not False
            for k in ("independent_effect_verified", "finding_verified", "report_release_approved")
        )
    ):
        raise TargetEffectQualificationDenied(409, "Immutable qualification chain invalid")
    revision = previous["revision"] if previous is not None else 0
    if type(revision) is not int or revision != expected_revision:
        raise TargetEffectQualificationDenied(409, "Concurrent qualification revision changed")
    # Re-check both current source authorities and the human reviewer AFTER
    # every awaited source lookup, while holding the same tenant row lock.
    if (
        await trusted_current_verifier() is not True
        or await trusted_report_source_check(finding_id, review["report_source_evidence_sha256"])
        is not True
    ):
        raise TargetEffectQualificationDenied(409, "Current signed source revoked")
    try:
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        refreshed = await guard_sql(db, engagement_id, expected_version=authorization_version)
    except Exception as exc:
        raise TargetEffectQualificationDenied(403, "Current human/ROE authority revoked") from exc
    if (
        refreshed.authorization_id != signed.authorization_id
        or refreshed.version != signed.version
        or refreshed.policy_sha256 != signed.policy_sha256
    ):
        raise TargetEffectQualificationDenied(409, "Review authorization rotated")
    row = {
        "id": "teqa-" + uuid.uuid4().hex,
        "engagement_id": engagement_id,
        "flow_id": flow_id,
        "finding_id": finding_id,
        "revision": revision + 1,
        "review_decision_id": review_decision_id,
        "review_decision_sha256": review_decision_sha256,
        "review_revision": review["review_revision"],
        "original_source_task_id": review["original_source_task_id"],
        "source_task_id": review["source_task_id"],
        "target_task_id": review["target_task_id"],
        "proof_sha256": proof_sha256,
        "audit_corroboration_sha256": audit_sha256,
        "observation_binding_sha256": review["observation_binding_sha256"],
        "report_source_evidence_sha256": review["report_source_evidence_sha256"],
        "authorization_id": signed.authorization_id,
        "authorization_version": authorization_version,
        "authorization_sha256": signed.policy_sha256,
        "flow_revision": flow_revision,
        "reviewer_sub": reviewer_sub,
        **candidate,
        "status": "UNKNOWN",
        "reason_code": _REASON,
        "independent_effect_verified": False,
        "finding_verified": False,
        "report_release_approved": False,
        "previous_attempt_id": previous["id"] if previous else None,
        "previous_attempt_sha256": previous["attempt_sha256"] if previous else None,
    }
    row["attempt_sha256"] = _fingerprint(row)
    try:
        inserted = (await db.execute(_INSERT, row)).scalar_one_or_none()
    except Exception as exc:
        raise TargetEffectQualificationDenied(503, "Durable UNKNOWN record unavailable") from exc
    if inserted != row["id"]:
        raise TargetEffectQualificationDenied(409, "Concurrent qualification admission conflict")
    return _unknown(row)


async def read_target_effect_qualification(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    authorization_version: int,
    trusted_current_verifier: Optional[Callable[[], Awaitable[bool]]] = None,
    trusted_report_source_check: Optional[Callable[[str, str], Awaitable[bool]]] = None,
) -> Dict[str, Any]:
    """Reads only fresh UNKNOWN evidence. Revoked/absent source => UNKNOWN/0."""
    unknown = _unknown()
    if not (
        _valid(_ENG, engagement_id)
        and _valid(_FLOW, flow_id)
        and _valid(_FINDING, finding_id)
        and _valid(_SUB, reviewer_sub)
        and reviewer_role == "senior_operator"
        and _valid(_SHA, reviewer_token_sha256)
        and type(reviewer_expires_at) is int
        and reviewer_expires_at > 0
        and type(authorization_version) is int
        and authorization_version > 0
        and callable(trusted_current_verifier)
        and callable(trusted_report_source_check)
    ):
        return unknown
    try:
        signed = await _live_fence(
            db,
            engagement_id=engagement_id,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
            authorization_version=authorization_version,
            read_only=True,
        )
        args = {"eng": engagement_id, "flow": flow_id, "finding": finding_id}
        previous = (await db.execute(_CURRENT_ATTEMPT, args)).mappings().one_or_none()
        review = (await db.execute(_CURRENT_REVIEW, args)).mappings().one_or_none()
        if (
            previous is None
            or not _integrity(dict(previous))
            or previous.get("status") != "UNKNOWN"
            or any(
                previous.get(k) is not False
                for k in (
                    "independent_effect_verified",
                    "finding_verified",
                    "report_release_approved",
                )
            )
            or not _review_matches(
                review,
                engagement_id=engagement_id,
                flow_id=flow_id,
                finding_id=finding_id,
                review_decision_id=previous["review_decision_id"],
                review_decision_sha256=previous["review_decision_sha256"],
                proof_sha256=previous["proof_sha256"],
                audit_sha256=previous["audit_corroboration_sha256"],
                authorization_version=authorization_version,
                flow_revision=previous["flow_revision"],
                reviewer_sub=reviewer_sub,
                signed=signed,
            )
            or any(
                previous.get(k) != review.get(k)
                for k in (
                    "original_source_task_id",
                    "source_task_id",
                    "target_task_id",
                    "review_revision",
                    "observation_binding_sha256",
                    "report_source_evidence_sha256",
                )
            )
        ):
            return unknown
        current = await read_latest_candidate_review(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            reviewer_sub=reviewer_sub,
            reviewer_role=reviewer_role,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
            authorization_version=authorization_version,
            trusted_current_verifier=trusted_current_verifier,
            trusted_report_source_check=trusted_report_source_check,
        )
        if (
            current.get("decision_sha256") != previous["review_decision_sha256"]
            or current.get("status")
            not in ("candidate_only", "UNKNOWN", "independent_verification_required")
            or await trusted_current_verifier() is not True
            or await trusted_report_source_check(
                finding_id, previous["report_source_evidence_sha256"]
            )
            is not True
        ):
            return unknown
        owner_candidate = await _resource_candidate(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            review=dict(review),
            proof_sha256=previous["proof_sha256"],
            audit_sha256=previous["audit_corroboration_sha256"],
            authorization_version=authorization_version,
            flow_revision=previous["flow_revision"],
            signed=signed,
        )
        if any(previous.get(key) != value for key, value in owner_candidate.items()):
            return unknown
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        renewed = await guard_sql(db, engagement_id, expected_version=authorization_version)
        if (
            renewed.authorization_id != signed.authorization_id
            or renewed.policy_sha256 != signed.policy_sha256
            or renewed.version != signed.version
        ):
            return unknown
        return _unknown(dict(previous))
    except Exception:
        return unknown
