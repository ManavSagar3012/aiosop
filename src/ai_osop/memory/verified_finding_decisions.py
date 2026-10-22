"""Append-only, candidate-only PostgreSQL review of target-signed finding sources.

The title of the SQL table is historical terminology: its rows DO NOT prove
that a vulnerability, authorization violation, exploit, or report is verified.
The currently signed target claim plus two independent audit signatures prove
only their own origin; a separate future target-effect oracle is still needed.

Call these functions from an authenticated *senior* endpoint with a caller-owned
PostgreSQL transaction. Its trusted callbacks must be composed from current
PG authority, dispatch/session verification and independently checked signed
report evidence. No model, provider assertion or client-supplied status can
serve as a callback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy import text

from ai_osop.core.target_authority_proof import _canonical, _strict_json
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.target_finding_evidence import inspect_target_finding_evidence

_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._-]{1,58}\Z")
_FINDING = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SUB = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}\Z")
_EVENT = re.compile(r"evt-[A-Za-z0-9._-]{1,78}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED = frozenset({"candidate_only", "UNKNOWN", "independent_verification_required"})
_DOMAIN = b"AI-OSOP-TARGET-FINDING-CANDIDATE-REVIEW-V1\x00"
_OBS_DOMAIN = b"AI-OSOP-TARGET-SOURCE-OBSERVATIONS-V1\x00"

_LOCK_PARENT = text("SELECT created_by FROM session_states WHERE session_id=:eng FOR UPDATE")
_READ_PARENT = text("SELECT created_by FROM session_states WHERE session_id=:eng FOR SHARE")
_CURRENT = text(
    "SELECT * "
    "FROM verified_target_finding_decisions WHERE engagement_id=:eng AND "
    "flow_id=:flow AND finding_id=:finding "
    "ORDER BY review_revision DESC LIMIT 1 FOR SHARE"
)
_OBSERVED = text(
    "SELECT id,engagement_id,flow_id,type,status,parent_task_id,payload,result "
    "FROM tasks WHERE engagement_id=:eng AND flow_id=:flow AND "
    "id IN (:source,:target) FOR SHARE"
)
_ARCHIVED = text(
    "SELECT target_claims_json,proof_sha256,audit_corroboration_sha256,"
    "authorization_version,flow_revision,original_source_task_id,source_task_id,"
    "target_task_id FROM target_authority_assertions "
    "WHERE engagement_id=:eng AND flow_id=:flow AND proof_sha256=:proof "
    "FOR SHARE"
)
_INSERT_COLUMNS = (
    "id",
    "engagement_id",
    "flow_id",
    "finding_id",
    "review_revision",
    "previous_decision_id",
    "previous_decision_sha256",
    "decision_sha256",
    "decision_status",
    "reviewer_sub",
    "original_source_task_id",
    "source_task_id",
    "target_task_id",
    "replay_parent_task_id",
    "proof_sha256",
    "audit_corroboration_sha256",
    "authorization_id",
    "authorization_version",
    "authorization_sha256",
    "flow_revision",
    "source_event_id",
    "target_event_id",
    "source_provider_receipt_sha256",
    "target_provider_receipt_sha256",
    "source_request_sha256",
    "target_request_sha256",
    "source_session_sha256",
    "target_session_sha256",
    "source_response_sha256",
    "target_response_sha256",
    "source_identity_sha256",
    "target_identity_sha256",
    "observation_binding_sha256",
    "report_source_evidence_sha256",
)
_INSERT = text(
    "INSERT INTO verified_target_finding_decisions ("
    + ",".join(_INSERT_COLUMNS)
    + ") VALUES ("
    + ",".join(":" + c for c in _INSERT_COLUMNS)
    + ") ON CONFLICT DO NOTHING RETURNING id"
)


class FindingDecisionDenied(PermissionError):
    """Invalid, stale, unauthorized or unavailable finding review."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _valid(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _sha(value: Any) -> bool:
    return _valid(_SHA, value)


def _record_integrity(row: Any) -> bool:
    """Hash precisely immutable SQL columns, excluding only the derived digest."""
    if not isinstance(row, dict) or not _sha(row.get("decision_sha256")):
        return False
    try:
        value = hashlib.sha256(
            _DOMAIN
            + _canonical({key: row[key] for key in _INSERT_COLUMNS if key != "decision_sha256"})
        ).hexdigest()
        return hmac.compare_digest(value, row["decision_sha256"])
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return False


def _safe(record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return only review metadata; preserve a hard promotion/release fence."""
    status = record.get("decision_status") if record else None
    return {
        "status": status if status in _ALLOWED else "UNKNOWN",
        "review_revision": record.get("review_revision") if record else 0,
        "decision_id": record.get("id") if record else None,
        "decision_sha256": record.get("decision_sha256") if record else None,
        "finding_verified": False,
        "authorization_violation_verified": False,
        "independent_target_effect_verified": False,
        "report_release_approved": False,
        "finding_release_eligible": False,
    }


def _check_input(
    *,
    engagement_id: Any,
    flow_id: Any,
    finding_id: Any,
    original_source_task_id: Any,
    source_task_id: Any,
    target_task_id: Any,
    proof_sha256: Any,
    audit_sha256: Any,
    authorization_version: Any,
    flow_revision: Any,
    report_source_evidence_sha256: Any,
    reviewer_sub: Any,
    reviewer_role: Any,
    reviewer_token_sha256: Any,
    reviewer_expires_at: Any,
    expected_revision: Any,
    decision_status: Any,
) -> None:
    if not (
        _valid(_ENG, engagement_id)
        and _valid(_FLOW, flow_id)
        and _valid(_FINDING, finding_id)
        and all(
            _valid(_TASK, value)
            for value in (original_source_task_id, source_task_id, target_task_id)
        )
        and len({original_source_task_id, source_task_id, target_task_id}) == 3
        and all(
            _sha(v)
            for v in (
                proof_sha256,
                audit_sha256,
                report_source_evidence_sha256,
                reviewer_token_sha256,
            )
        )
        and _valid(_SUB, reviewer_sub)
        and reviewer_role == "senior_operator"
        and type(reviewer_expires_at) is int
        and reviewer_expires_at > 0
        and type(authorization_version) is int
        and authorization_version > 0
        and type(flow_revision) is int
        and flow_revision >= 0
        and type(expected_revision) is int
        and 0 <= expected_revision < 1_000_000
        and type(decision_status) is str
        and decision_status in _ALLOWED
    ):
        raise FindingDecisionDenied(422, "Invalid bounded candidate review source")


async def _fence(
    db: Any,
    *,
    engagement_id: str,
    reviewer_sub: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    authorization_version: int,
    writing: bool,
) -> Any:
    if (
        db is None
        or not callable(getattr(db, "execute", None))
        or not callable(getattr(db, "in_transaction", None))
        or db.in_transaction() is not True
    ):
        raise FindingDecisionDenied(503, "Caller-owned PostgreSQL transaction required")
    row = await db.execute(_LOCK_PARENT if writing else _READ_PARENT, {"eng": engagement_id})
    owner = row.scalar_one_or_none()
    if not _valid(_SUB, owner) or not hmac.compare_digest(owner, reviewer_sub):
        raise FindingDecisionDenied(403, "Engagement owner senior review required")
    try:
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        signed = await guard_sql(db, engagement_id, expected_version=authorization_version)
    except Exception as exc:
        raise FindingDecisionDenied(
            403, "Current signed senior review authorization unavailable"
        ) from exc
    if (
        signed.session_id != engagement_id
        or signed.version != authorization_version
        or not _sha(signed.policy_sha256)
        or signed.policy.get("created_by") != owner
    ):
        raise FindingDecisionDenied(409, "Review signed ROE no longer matches")
    return signed


async def _observation(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    original_source_task_id: str,
    source_task_id: str,
    target_task_id: str,
    proof_sha256: str,
    audit_sha256: str,
    authorization_version: int,
    flow_revision: int,
    report_source_evidence_sha256: str,
) -> Dict[str, Any]:
    archive = (
        (
            await db.execute(
                _ARCHIVED, {"eng": engagement_id, "flow": flow_id, "proof": proof_sha256}
            )
        )
        .mappings()
        .one_or_none()
    )
    if archive is None or any(
        archive.get(k) != v
        for k, v in {
            "proof_sha256": proof_sha256,
            "audit_corroboration_sha256": audit_sha256,
            "authorization_version": authorization_version,
            "flow_revision": flow_revision,
            "original_source_task_id": original_source_task_id,
            "source_task_id": source_task_id,
            "target_task_id": target_task_id,
        }.items()
    ):
        raise FindingDecisionDenied(409, "Immutable signed source missing")
    blob = archive.get("target_claims_json")
    if type(blob) is not bytes or not 1 <= len(blob) <= 4096:
        raise FindingDecisionDenied(409, "Immutable signed claim bytes missing")
    try:
        claim = _strict_json(blob, max_bytes=4096)
        if _canonical(claim) != blob:
            raise ValueError("Non-canonical target assertion")
    except Exception as exc:
        raise FindingDecisionDenied(409, "Immutable signed claim corrupt") from exc
    rows = (
        (
            await db.execute(
                _OBSERVED,
                {
                    "eng": engagement_id,
                    "flow": flow_id,
                    "source": source_task_id,
                    "target": target_task_id,
                },
            )
        )
        .mappings()
        .all()
    )
    if len(rows) != 2 or {r.get("id") for r in rows} != {source_task_id, target_task_id}:
        raise FindingDecisionDenied(409, "Independent replay Task pair unavailable")
    by_id = {r["id"]: r for r in rows}
    observation: Dict[str, Any] = {}
    replay_parent = None
    for role, task_id in (("source", source_task_id), ("target", target_task_id)):
        task = by_id[task_id]
        payload, result = task.get("payload"), task.get("result")
        if (
            task.get("engagement_id") != engagement_id
            or task.get("flow_id") != flow_id
            or task.get("type") != "navigate"
            or task.get("status") != "completed"
            or type(payload) is not dict
            or type(result) is not dict
            or payload.get("_comparison_role") != role
            or payload.get("method") != "GET"
            or result.get("comparison_role") != role
            or result.get("source_task_id") != original_source_task_id
            or result.get("status") != "success"
            or result.get("redirected") is not False
            or result.get("http_status_code") != 200
            or result.get("denied") is True
            or result.get("public_access") is True
            or type(result.get("provider_evidence")) is not dict
            or result["provider_evidence"].get("source_authenticity_verified") is not False
        ):
            raise FindingDecisionDenied(409, "Live replay observation invalid")
        event = result["provider_evidence"].get("provider_event_id")
        receipt_sha = result["provider_evidence"].get("provider_receipt_sha256")
        label = payload.get("user_label")
        if (
            not _valid(_EVENT, event)
            or not _sha(receipt_sha)
            or type(label) is not str
            or not 1 <= len(label) <= 64
            or label.casefold() in {"anonymous", "guest", "public", "unauthenticated"}
            or claim.get(role + "_identity") != label
            or claim.get(role + "_task_id") != task_id
            or not _sha(payload.get("_authority_request_sha256"))
            or not _sha(payload.get("_authority_session_sha256"))
            or not _sha(result.get("response_body_sha256"))
            or payload["_authority_request_sha256"] != claim.get(role + "_request_sha256")
            or payload["_authority_session_sha256"] != claim.get(role + "_session_sha256")
            or result["response_body_sha256"] != claim.get(role + "_response_sha256")
            or result.get("replay_parent_task_id") != task.get("parent_task_id")
        ):
            raise FindingDecisionDenied(409, "Request or signed response provenance changed")
        if replay_parent is None:
            replay_parent = task.get("parent_task_id")
        elif task.get("parent_task_id") != replay_parent:
            raise FindingDecisionDenied(409, "Source/target replay ancestry disagrees")
        observation.update(
            {
                role + "_event_id": event,
                role + "_provider_receipt_sha256": receipt_sha,
                role + "_request_sha256": payload["_authority_request_sha256"],
                role + "_session_sha256": payload["_authority_session_sha256"],
                role + "_response_sha256": result["response_body_sha256"],
                role
                + "_identity_sha256": hashlib.sha256(
                    (engagement_id + "\x00" + label).encode("utf-8")
                ).hexdigest(),
            }
        )
    if (
        not _valid(_TASK, replay_parent)
        or observation["source_event_id"] == observation["target_event_id"]
        or observation["source_provider_receipt_sha256"]
        == observation["target_provider_receipt_sha256"]
        or observation["source_session_sha256"] == observation["target_session_sha256"]
        or observation["source_identity_sha256"] == observation["target_identity_sha256"]
        or observation["source_response_sha256"] != observation["target_response_sha256"]
    ):
        raise FindingDecisionDenied(409, "Independent source/target records indistinct")
    if any(
        claim.get(k) != v
        for k, v in {
            "engagement_id": engagement_id,
            "flow_id": flow_id,
            "original_source_task_id": original_source_task_id,
            "source_task_id": source_task_id,
            "target_task_id": target_task_id,
            "flow_revision": flow_revision,
            "authorization_version": authorization_version,
            "replay_parent_task_id": replay_parent,
        }.items()
    ):
        raise FindingDecisionDenied(409, "Target proof ancestry differs")
    observation["replay_parent_task_id"] = replay_parent
    observation["observation_binding_sha256"] = hashlib.sha256(
        _OBS_DOMAIN
        + _canonical(
            {
                **observation,
                "engagement_id": engagement_id,
                "flow_id": flow_id,
                "original_source_task_id": original_source_task_id,
                "source_task_id": source_task_id,
                "target_task_id": target_task_id,
                "proof_sha256": proof_sha256,
                "audit_corroboration_sha256": audit_sha256,
                "report_source_evidence_sha256": report_source_evidence_sha256,
            }
        )
    ).hexdigest()
    return observation


async def append_candidate_review(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    original_source_task_id: str,
    source_task_id: str,
    target_task_id: str,
    proof_sha256: str,
    audit_sha256: str,
    authorization_version: int,
    flow_revision: int,
    report_source_evidence_sha256: str,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    expected_revision: int,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
    decision_status: str = "independent_verification_required",
) -> Dict[str, Any]:
    """Append ONE human-signed-context decision, fenced by a PG row lock + CAS.

    The caller must provide an authenticated senior role and compose the two
    trusted verifier callbacks under THIS db transaction. Reviewer token SHA
    and expiry are checked again on both sides of awaited verification work.
    Even a fully rechecked receipt is only a candidate; all promotion flags
    are unconditionally false.
    """
    _check_input(
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        original_source_task_id=original_source_task_id,
        source_task_id=source_task_id,
        target_task_id=target_task_id,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        report_source_evidence_sha256=report_source_evidence_sha256,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        expected_revision=expected_revision,
        decision_status=decision_status,
    )
    if not callable(trusted_current_verifier) or not callable(trusted_report_source_check):
        raise FindingDecisionDenied(503, "Trusted independent review sources required")
    signed = await _fence(
        db,
        engagement_id=engagement_id,
        reviewer_sub=reviewer_sub,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        authorization_version=authorization_version,
        writing=True,
    )
    previous = (
        (await db.execute(_CURRENT, {"eng": engagement_id, "flow": flow_id, "finding": finding_id}))
        .mappings()
        .one_or_none()
    )
    if previous is not None and (
        previous.get("engagement_id") != engagement_id
        or previous.get("flow_id") != flow_id
        or previous.get("finding_id") != finding_id
        or not _record_integrity(dict(previous))
        or type(previous.get("review_revision")) is not int
        or previous["review_revision"] <= 0
        or previous.get("reviewer_sub") != reviewer_sub
    ):
        raise FindingDecisionDenied(409, "Existing review chain corrupt or foreign")
    actual_revision = previous["review_revision"] if previous else 0
    if actual_revision != expected_revision:
        raise FindingDecisionDenied(409, "Finding review revision changed")
    verified = await inspect_target_finding_evidence(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        original_source_task_id=original_source_task_id,
        source_task_id=source_task_id,
        target_task_id=target_task_id,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        trusted_current_verifier=trusted_current_verifier,
    )
    if verified.get("status") != "candidate_only" or any(
        verified.get(k) is not False
        for k in (
            "finding_verified",
            "report_release_approved",
            "finding_release_eligible",
        )
    ):
        raise FindingDecisionDenied(409, "Current target source candidate unavailable")
    observation = await _observation(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        original_source_task_id=original_source_task_id,
        source_task_id=source_task_id,
        target_task_id=target_task_id,
        proof_sha256=proof_sha256,
        audit_sha256=audit_sha256,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        report_source_evidence_sha256=report_source_evidence_sha256,
    )
    try:
        report_checked = await trusted_report_source_check(
            finding_id, report_source_evidence_sha256
        )
    except Exception as exc:
        raise FindingDecisionDenied(503, "Signed report evidence check unavailable") from exc
    if report_checked is not True or await trusted_current_verifier() is not True:
        raise FindingDecisionDenied(409, "Current signed report/source provenance unavailable")
    try:
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        refreshed = await guard_sql(db, engagement_id, expected_version=authorization_version)
    except Exception as exc:
        raise FindingDecisionDenied(
            403, "Current signed reviewer/ROE revalidation unavailable"
        ) from exc
    if (
        refreshed.authorization_id != signed.authorization_id
        or refreshed.policy_sha256 != signed.policy_sha256
        or refreshed.version != signed.version
    ):
        raise FindingDecisionDenied(409, "Signed review authority changed")
    row = {
        "id": "vfdec-" + uuid.uuid4().hex,
        "engagement_id": engagement_id,
        "flow_id": flow_id,
        "finding_id": finding_id,
        "review_revision": actual_revision + 1,
        "previous_decision_id": previous["id"] if previous else None,
        "previous_decision_sha256": previous["decision_sha256"] if previous else None,
        "decision_status": decision_status,
        "reviewer_sub": reviewer_sub,
        "original_source_task_id": original_source_task_id,
        "source_task_id": source_task_id,
        "target_task_id": target_task_id,
        "proof_sha256": proof_sha256,
        "audit_corroboration_sha256": audit_sha256,
        "authorization_id": signed.authorization_id,
        "authorization_version": signed.version,
        "authorization_sha256": signed.policy_sha256,
        "flow_revision": flow_revision,
        "report_source_evidence_sha256": report_source_evidence_sha256,
        **observation,
    }
    row["decision_sha256"] = hashlib.sha256(_DOMAIN + _canonical(row)).hexdigest()
    try:
        inserted = (await db.execute(_INSERT, row)).scalar_one_or_none()
    except Exception as exc:
        raise FindingDecisionDenied(503, "Immutable candidate review insert failed") from exc
    if inserted != row["id"]:
        raise FindingDecisionDenied(409, "Concurrent candidate review conflict")
    return _safe(row)


async def read_latest_candidate_review(
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
    """Read only current, owner-authorized reviewed metadata; stale => UNKNOWN."""
    unknown = _safe(None)
    if not (
        _valid(_ENG, engagement_id)
        and _valid(_FLOW, flow_id)
        and _valid(_FINDING, finding_id)
        and _valid(_SUB, reviewer_sub)
        and reviewer_role == "senior_operator"
        and _sha(reviewer_token_sha256)
        and type(reviewer_expires_at) is int
        and reviewer_expires_at > 0
        and type(authorization_version) is int
        and authorization_version > 0
        and callable(trusted_current_verifier)
        and callable(trusted_report_source_check)
    ):
        return unknown
    try:
        signed = await _fence(
            db,
            engagement_id=engagement_id,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
            authorization_version=authorization_version,
            writing=False,
        )
        row = (
            (
                await db.execute(
                    _CURRENT, {"eng": engagement_id, "flow": flow_id, "finding": finding_id}
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            row is None
            or row.get("engagement_id") != engagement_id
            or row.get("flow_id") != flow_id
            or row.get("finding_id") != finding_id
            or row.get("reviewer_sub") != reviewer_sub
            or row.get("authorization_sha256") != signed.policy_sha256
            or row.get("authorization_version") != signed.version
            or row.get("decision_status") not in _ALLOWED
            or not _record_integrity(dict(row))
            or not _sha(row.get("report_source_evidence_sha256"))
            or type(row.get("review_revision")) is not int
            or row["review_revision"] < 1
        ):
            return unknown
        expected = await inspect_target_finding_evidence(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            original_source_task_id=row["original_source_task_id"],
            source_task_id=row["source_task_id"],
            target_task_id=row["target_task_id"],
            proof_sha256=row["proof_sha256"],
            audit_sha256=row["audit_corroboration_sha256"],
            authorization_version=authorization_version,
            flow_revision=row["flow_revision"],
            trusted_current_verifier=trusted_current_verifier,
        )
        if (
            expected.get("status") != "candidate_only"
            or any(
                expected.get(k) is not False
                for k in (
                    "finding_verified",
                    "report_release_approved",
                    "finding_release_eligible",
                )
            )
            or await trusted_report_source_check(finding_id, row["report_source_evidence_sha256"])
            is not True
            or await trusted_current_verifier() is not True
        ):
            return unknown
        current_observation = await _observation(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            original_source_task_id=row["original_source_task_id"],
            source_task_id=row["source_task_id"],
            target_task_id=row["target_task_id"],
            proof_sha256=row["proof_sha256"],
            audit_sha256=row["audit_corroboration_sha256"],
            authorization_version=authorization_version,
            flow_revision=row["flow_revision"],
            report_source_evidence_sha256=row["report_source_evidence_sha256"],
        )
        if any(row.get(key) != value for key, value in current_observation.items()):
            return unknown
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        return _safe(dict(row))
    except Exception:
        return unknown
