"""Finding-scoped independent effect admission, distinct from UNKNOWN-only 0021.

Requires a caller-owned PostgreSQL transaction, the signed candidate source,
the latest senior review and latest immutable UNKNOWN qualification. A real
production observer independently signs a LIVE owner-of-record/access effect
with TWO separate, out-of-band pinned external keys. The observer verifier is
imported at invocation (fail closed when absent), never constructed from an
LLM, MCP, provider response, bool or user-supplied verdict mapping.

The signed finding evidence, authorized senior, Task/Flow/ROE and report source
are refreshed inside the SAME transaction that inserts the immutable row.
THIS IS NOT REPORT RELEASE. No report-release mechanism reads this table until
the distinct senior final-release gate explicitly integrates it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import uuid
import time
from urllib.parse import urlsplit
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy import text

from ai_osop.core.models import FlowRecord, Task
from ai_osop.core.target_authority_proof import _canonical, _strict_json
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.target_verified_promotions import (
    TargetEffectQualificationDenied,
    _CURRENT_ATTEMPT,
    _CURRENT_REVIEW,
    _PROOF,
    _integrity as _unknown_integrity,
    _live_fence,
    _resource_candidate,
    _review_matches,
    read_target_effect_qualification,
)
from ai_osop.memory.verified_finding_decisions import read_latest_candidate_review
from ai_osop.safety.approval_binding import matches_pinned_payload

_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_FIND = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SUB = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}\Z")
_REVIEW = re.compile(r"vfdec-[0-9a-f]{32}\Z")
_QUAL = re.compile(r"teqa-[0-9a-f]{32}\Z")
_EVENT = re.compile(r"evt-[A-Za-z0-9._-]{1,78}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_OBSERVER_DOMAIN = b"AI-OSOP-INDEPENDENT-LIVE-EFFECT-VERDICT-LEDGER-V1\x00"

_FINDING_ALREADY_PROMOTED = text(
    "SELECT id FROM independent_target_effect_verifications "
    "WHERE engagement_id=:eng AND flow_id=:flow AND finding_id=:finding FOR SHARE"
)
_EFFECT_NONCE_USED = text(
    "SELECT id FROM independent_target_effect_verifications "
    "WHERE verifier_nonce_sha256=:nonce OR verdict_sha256=:digest FOR SHARE"
)
_FLOW_NOW = text("SELECT * FROM execution_flows " "WHERE id=:flow AND engagement_id=:eng FOR SHARE")
_THREE_TASKS = text(
    "SELECT * FROM tasks WHERE engagement_id=:eng AND flow_id=:flow "
    "AND id IN (:original,:source,:target) FOR SHARE"
)
_ANONYMOUS_TASK = text(
    "SELECT * FROM tasks WHERE engagement_id=:eng AND flow_id=:flow " "AND id=:anon FOR SHARE"
)
_ANONYMOUS_APPROVAL = text(
    "SELECT id,evidence,status FROM approval_requests WHERE engagement_id=:eng "
    "AND task_id=:anon AND id=:approval AND status='approved' FOR SHARE"
)
_CURRENT_PROMOTION = text(
    "SELECT * FROM independent_target_effect_verifications "
    "WHERE engagement_id=:eng AND flow_id=:flow AND finding_id=:finding FOR SHARE"
)
_CHALLENGE = text(
    "SELECT * FROM independent_target_effect_challenges "
    "WHERE id=:challenge AND engagement_id=:eng AND flow_id=:flow "
    "AND finding_id=:finding AND qualification_id=:qual FOR SHARE"
)
_CREATE_CHALLENGE = text(
    "INSERT INTO independent_target_effect_challenges "
    "(id,engagement_id,flow_id,finding_id,qualification_id,"
    "qualification_sha256,nonce_sha256,issued_at,expires_at) VALUES "
    "(:id,:eng,:flow,:finding,:qual,:sha,:nonce,:issued,:expires) "
    "ON CONFLICT DO NOTHING RETURNING id"
)
_COLUMNS = (
    "id",
    "engagement_id",
    "flow_id",
    "finding_id",
    "review_decision_id",
    "review_decision_sha256",
    "review_revision",
    "qualification_id",
    "qualification_sha256",
    "qualification_revision",
    "challenge_id",
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
    "senior_reviewer_sub",
    "resource_id",
    "resource_owner_identity_sha256",
    "resource_visibility",
    "source_http_status",
    "target_http_status",
    "anonymous_http_status",
    "private_content_sha256",
    "verifier_key_id",
    "verifier_origin",
    "verifier_public_key_sha256",
    "verifier_registry_sha256",
    "verifier_nonce_sha256",
    "verdict_sha256",
    "signed_verdict_json",
    "verdict_signature_b64url",
    "verdict_issued_at",
    "verdict_expires_at",
    "status",
    "independent_effect_verified",
    "finding_verified",
    "report_release_approved",
)
_INSERT = text(
    "INSERT INTO independent_target_effect_verifications ("
    + ",".join(_COLUMNS)
    + ") VALUES ("
    + ",".join(":" + name for name in _COLUMNS)
    + ") ON CONFLICT DO NOTHING RETURNING id"
)


class IndependentTargetEffectDenied(PermissionError):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status


def _exact(pattern: re.Pattern[str], value: Any) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _deny(condition: bool, status: int, reason: str) -> None:
    if not condition:
        raise IndependentTargetEffectDenied(status, reason)


def _unknown() -> Dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "finding_verified": False,
        "independent_effect_verified": False,
        "authorization_violation_verified": False,
        "report_release_approved": False,
        "finding_release_eligible": False,
        "verification_id": None,
        "verification_sha256": None,
    }


def _input(
    *,
    engagement_id: Any,
    flow_id: Any,
    finding_id: Any,
    review_decision_id: Any,
    review_decision_sha256: Any,
    qualification_id: Any,
    qualification_sha256: Any,
    expected_qualification_revision: Any,
    authorization_version: Any,
    flow_revision: Any,
    reviewer_sub: Any,
    reviewer_role: Any,
    reviewer_token_sha256: Any,
    reviewer_expires_at: Any,
    observer_claims_json: Any,
    observer_signature_b64url: Any,
    trusted_current_verifier: Any,
    trusted_report_source_check: Any,
) -> None:
    _deny(
        _exact(_ENG, engagement_id)
        and _exact(_FLOW, flow_id)
        and _exact(_FIND, finding_id)
        and _exact(_REVIEW, review_decision_id)
        and _exact(_QUAL, qualification_id)
        and all(
            _exact(_SHA, digest)
            for digest in (review_decision_sha256, qualification_sha256, reviewer_token_sha256)
        )
        and type(expected_qualification_revision) is int
        and expected_qualification_revision >= 1
        and type(authorization_version) is int
        and authorization_version > 0
        and type(flow_revision) is int
        and flow_revision >= 0
        and _exact(_SUB, reviewer_sub)
        and reviewer_role == "senior_operator"
        and type(reviewer_expires_at) is int
        and reviewer_expires_at > 0
        and type(observer_claims_json) is bytes
        and 1 <= len(observer_claims_json) <= 16384
        and type(observer_signature_b64url) is str
        and re.fullmatch(r"[A-Za-z0-9_-]{86}", observer_signature_b64url) is not None
        and callable(trusted_current_verifier)
        and callable(trusted_report_source_check),
        422,
        "Exact signed independent effect source and senior authority required",
    )


async def _current(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    qualification_id: str,
    qualification_sha256: str,
    expected_qualification_revision: int,
    authorization_version: int,
    flow_revision: int,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
    writing: bool,
) -> tuple[Any, Dict[str, Any], Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    # _live_fence checks a caller-owned transaction, locks current owner, and
    # re-verifies the senior token and signed current ROE, not a stale JWT.
    try:
        signed = await _live_fence(
            db,
            engagement_id=engagement_id,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
            authorization_version=authorization_version,
            read_only=not writing,
        )
    except TargetEffectQualificationDenied as exc:
        raise IndependentTargetEffectDenied(
            exc.status, "Current senior signed review/ROE unavailable"
        ) from exc
    params = {"eng": engagement_id, "flow": flow_id, "finding": finding_id}
    flow = (await db.execute(_FLOW_NOW, params)).mappings().one_or_none()
    _deny(
        flow is not None
        and flow.get("engagement_id") == engagement_id
        and flow.get("id") == flow_id
        and flow.get("status") == "running"
        and type(flow.get("revision")) is int
        and flow["revision"] == flow_revision,
        409,
        "Current signed Flow is missing, suspended or revised",
    )
    review = (await db.execute(_CURRENT_REVIEW, params)).mappings().one_or_none()
    _deny(
        _review_matches(
            review,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            review_decision_id=review_decision_id,
            review_decision_sha256=review_decision_sha256,
            proof_sha256=review.get("proof_sha256") if review else None,
            audit_sha256=review.get("audit_corroboration_sha256") if review else None,
            authorization_version=authorization_version,
            flow_revision=flow_revision,
            reviewer_sub=reviewer_sub,
            signed=signed,
        ),
        409,
        "Latest immutable senior candidate review is missing or changed",
    )
    checked = await read_latest_candidate_review(
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
    _deny(
        checked.get("decision_id") == review_decision_id
        and checked.get("decision_sha256") == review_decision_sha256
        and checked.get("status")
        in ("candidate_only", "UNKNOWN", "independent_verification_required")
        and checked.get("finding_verified") is False
        and checked.get("report_release_approved") is False,
        409,
        "Current cryptographically checked review not approved as candidate",
    )
    previous = (await db.execute(_CURRENT_ATTEMPT, params)).mappings().one_or_none()
    _deny(
        previous is not None
        and _unknown_integrity(dict(previous))
        and previous.get("id") == qualification_id
        and previous.get("attempt_sha256") == qualification_sha256
        and type(previous.get("revision")) is int
        and previous["revision"] == expected_qualification_revision
        and previous.get("review_decision_id") == review_decision_id
        and previous.get("review_decision_sha256") == review_decision_sha256
        and previous.get("review_revision") == review.get("review_revision")
        and previous.get("status") == "UNKNOWN"
        and previous.get("reason_code") == "independent_target_effect_service_missing"
        and all(
            previous.get(flag) is False
            for flag in (
                "independent_effect_verified",
                "finding_verified",
                "report_release_approved",
            )
        )
        and all(
            previous.get(k) == review.get(k)
            for k in (
                "engagement_id",
                "flow_id",
                "finding_id",
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
            )
        ),
        409,
        "Immutable UNKNOWN revision CAS changed or unqualified",
    )
    historical = await read_target_effect_qualification(
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
    _deny(
        historical.get("status") == "UNKNOWN"
        and historical.get("qualification_id") == qualification_id
        and historical.get("qualification_sha256") == qualification_sha256
        and historical.get("revision") == expected_qualification_revision
        and historical.get("finding_verified") is False
        and historical.get("report_release_approved") is False,
        409,
        "Latest independently rechecked UNKNOWN source unavailable",
    )
    proof = (
        (
            await db.execute(
                _PROOF,
                {"eng": engagement_id, "flow": flow_id, "proof": previous["proof_sha256"]},
            )
        )
        .mappings()
        .one_or_none()
    )
    _deny(
        proof is not None
        and all(
            proof.get(key) == value
            for key, value in (
                ("engagement_id", engagement_id),
                ("flow_id", flow_id),
                ("proof_sha256", previous["proof_sha256"]),
                ("audit_corroboration_sha256", previous["audit_corroboration_sha256"]),
                ("original_source_task_id", previous["original_source_task_id"]),
                ("source_task_id", previous["source_task_id"]),
                ("target_task_id", previous["target_task_id"]),
                ("authorization_version", authorization_version),
                ("flow_revision", flow_revision),
            )
        ),
        409,
        "Original signed proof/Task lineage missing",
    )
    try:
        claims = _strict_json(proof["target_claims_json"], max_bytes=4096)
        _deny(
            proof["target_claims_json"] == _canonical(claims)
            and claims.get("engagement_id") == engagement_id
            and claims.get("flow_id") == flow_id
            and claims.get("source_identity") != claims.get("target_identity")
            and claims.get("resource_owner_identity") == claims.get("source_identity")
            and claims.get("source_response_sha256") == claims.get("target_response_sha256")
            and all(
                _exact(_SHA, claims.get(name))
                for name in (
                    "source_request_sha256",
                    "target_request_sha256",
                    "source_session_sha256",
                    "target_session_sha256",
                    "source_response_sha256",
                    "target_response_sha256",
                )
            )
            and claims.get("source_session_sha256") != claims.get("target_session_sha256")
            and claims.get("resource_visibility") == "private"
            and claims.get("source_http_status") == 200
            and claims.get("target_http_status") == 200
            and claims.get("anonymous_http_status") in (401, 403, 404)
            and claims.get("redirected") is False
            and claims.get("public_access") is False,
            409,
            "Current immutable source lacks three-identity private effect",
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise IndependentTargetEffectDenied(409, "Original signed source malformed") from exc
    candidate = await _resource_candidate(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        review=dict(review),
        proof_sha256=previous["proof_sha256"],
        audit_sha256=previous["audit_corroboration_sha256"],
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        signed=signed,
    )
    _deny(
        all(previous.get(k) == v for k, v in candidate.items())
        and candidate.get("resource_visibility") == "private"
        and candidate.get("source_http_status") == 200
        and candidate.get("target_http_status") == 200
        and candidate.get("anonymous_http_status") in (401, 403, 404),
        409,
        "Independent owner-of-record candidate contradicts signed archive",
    )
    return signed, dict(review), dict(previous), claims, candidate


async def _fresh(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    reviewer_sub: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    authorization_version: int,
    signed: Any,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
    report_sha256: str,
) -> None:
    # EVERY truth is a current state assertion from the trusted production
    # source callbacks, not the observer's claims or cached client context.
    try:
        _deny(
            await trusted_current_verifier() is True
            and await trusted_report_source_check(finding_id, report_sha256) is True,
            409,
            "Current signed Task/source/report authority revoked",
        )
        await FlowArtifactReviewStore._reviewer_fence(
            db,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
        )
        refreshed = await guard_sql(db, engagement_id, expected_version=authorization_version)
        _deny(
            refreshed.authorization_id == signed.authorization_id
            and refreshed.version == signed.version
            and hmac.compare_digest(refreshed.policy_sha256, signed.policy_sha256),
            409,
            "Signed ROE/reviewer authority rotated during admission",
        )
    except IndependentTargetEffectDenied:
        raise
    except Exception as exc:
        raise IndependentTargetEffectDenied(403, "Current signed reviewer/ROE unavailable") from exc


def _row_digest(row: Dict[str, Any]) -> str:
    # Signed bytes and signature are retained, never request bodies/tokens.
    return hashlib.sha256(
        _OBSERVER_DOMAIN
        + _canonical(
            {
                k: row[k]
                for k in _COLUMNS
                if k not in ("signed_verdict_json", "verdict_signature_b64url", "verdict_sha256")
            }
        )
    ).hexdigest()


def _current_witness_trust(
    *,
    engagement_id: str,
    flow_id: str,
    signed_claims: bytes,
    signed_signature: str,
    challenge_issued_at: int,
) -> tuple[Dict[str, Any], str, str]:
    """Bind both signatures to the registry that is current at this instant.

    The core witness verifier rechecks its own registry across awaits. A key
    can still rotate after that verifier returns but before the ledger takes
    its pinned key fingerprint or commits a promotion. Never label a signature
    verified with an earlier key as evidence signed by a replacement key.
    """
    from ai_osop.core.independent_target_effect_observer import (
        _EFFECT_DOMAIN,
        _OWNER_DOMAIN,
        _check_detached,
        _load_trust,
        _b64raw,
    )

    config, access_key, owner_key, registry_sha = _load_trust(engagement_id, flow_id)
    claims = _strict_json(signed_claims, max_bytes=8192)
    _deny(_canonical(claims) == signed_claims, 409, "Canonical live witness required")
    owner_raw = _b64raw(claims["owner_claims_b64url"], max_len=11500)
    owner_claims = _strict_json(owner_raw, max_bytes=4096)
    _deny(
        _canonical(owner_claims) == owner_raw
        and type(claims.get("issued_at")) is int
        and type(owner_claims.get("observed_at")) is int
        and type(challenge_issued_at) is int
        # The nonce must bind observations made after its issuance. Allow
        # bounded clock skew between independent operators and the API.
        and challenge_issued_at - 5 <= claims["issued_at"]
        and challenge_issued_at - 5 <= owner_claims["observed_at"]
        and claims.get("key_id") == config["observer_key_id"]
        and claims.get("operator_id") == config["observer_operator_id"]
        and owner_claims.get("key_id") == config["owner_key_id"]
        and owner_claims.get("operator_id") == config["owner_operator_id"],
        409,
        "Current independent operators or signing keys changed",
    )
    _check_detached(signed_claims, signed_signature, access_key, _EFFECT_DOMAIN)
    _check_detached(owner_raw, claims["owner_signature_b64url"], owner_key, _OWNER_DOMAIN)
    raw_key = base64.b64decode(config["observer_public_key_b64"], validate=True)
    return config, hashlib.sha256(raw_key).hexdigest(), registry_sha


def _typed_task(row: Any) -> Task:
    _deny(row is not None, 409, "Signed Task row missing")
    try:
        return Task(
            **{
                field: row[field]
                for field in Task.model_fields
                if field != "trace_context" and field in row
            }
        )
    except (TypeError, KeyError, ValueError) as exc:
        raise IndependentTargetEffectDenied(409, "Signed Task cannot be reconstructed") from exc


def _typed_flow(row: Dict[str, Any]) -> FlowRecord:
    try:
        return FlowRecord(**{field: row[field] for field in FlowRecord.model_fields})
    except (TypeError, KeyError, ValueError) as exc:
        raise IndependentTargetEffectDenied(
            409, "Current signed Flow cannot be reconstructed"
        ) from exc


async def _read_original_tasks(
    db: Any, engagement_id: str, flow_id: str, previous: Dict[str, Any]
) -> tuple[FlowRecord, Task, Task, Task]:
    params = {
        "eng": engagement_id,
        "flow": flow_id,
        "original": previous["original_source_task_id"],
        "source": previous["source_task_id"],
        "target": previous["target_task_id"],
    }
    flow_row = (await db.execute(_FLOW_NOW, params)).mappings().one_or_none()
    _deny(
        flow_row is not None
        and flow_row["status"] == "running"
        and flow_row["revision"] == previous["flow_revision"],
        409,
        "Live Flow source revised",
    )
    current = (await db.execute(_THREE_TASKS, params)).mappings().all()
    _deny(
        len(current) == 3
        and {row["id"] for row in current}
        == {params["original"], params["source"], params["target"]}
        and all(
            row["engagement_id"] == engagement_id
            and row["flow_id"] == flow_id
            and row["payload"].get("_authorization_version") == previous["authorization_version"]
            for row in current
        ),
        409,
        "Original/current signed Task source missing or changed",
    )
    by_id = {row["id"]: _typed_task(row) for row in current}
    return (
        _typed_flow(dict(flow_row)),
        by_id[params["original"]],
        by_id[params["source"]],
        by_id[params["target"]],
    )


async def issue_independent_target_effect_challenge(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    qualification_id: str,
    qualification_sha256: str,
    expected_qualification_revision: int,
    authorization_version: int,
    flow_revision: int,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
) -> Dict[str, Any]:
    """Mint exactly one server-generated nonce under current senior/ROE and 0021.

    The trusted controller MUST keep the returned challenge/nonce server-side,
    pass it only to the separately authenticated production observer audit GET,
    and never retry a failed/UNKNOWN effect on an existing challenge.
    """
    _input(
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        expected_qualification_revision=expected_qualification_revision,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        observer_claims_json=b"pending",
        observer_signature_b64url="x" * 86,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
    )
    signed, review, previous, _, _ = await _current(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        expected_qualification_revision=expected_qualification_revision,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
        writing=True,
    )
    params = {"eng": engagement_id, "flow": flow_id, "finding": finding_id}
    _deny(
        (await db.execute(_FINDING_ALREADY_PROMOTED, params)).scalar_one_or_none() is None,
        409,
        "Finding already has an independent promotion",
    )
    await _fresh(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        reviewer_sub=reviewer_sub,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        authorization_version=authorization_version,
        signed=signed,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
        report_sha256=review["report_source_evidence_sha256"],
    )
    nonce = secrets.token_hex(16)
    challenge_id = "itefc-" + uuid.uuid4().hex
    issued = int(time.time())
    args = {
        "id": challenge_id,
        **params,
        "qual": qualification_id,
        "sha": qualification_sha256,
        "nonce": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        "issued": issued,
        "expires": issued + 60,
    }
    try:
        inserted = (await db.execute(_CREATE_CHALLENGE, args)).scalar_one_or_none()
    except Exception as exc:
        raise IndependentTargetEffectDenied(503, "Durable independent challenge UNKNOWN") from exc
    _deny(inserted == challenge_id, 409, "Concurrent independent challenge rejected")
    return {"challenge_id": challenge_id, "expected_nonce": nonce, "expires_at": issued + 60}


async def _require_challenge(
    db: Any,
    *,
    challenge_id: str,
    expected_nonce: str,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    qualification_id: str,
    qualification_sha256: str,
) -> Dict[str, Any]:
    _deny(
        type(challenge_id) is str
        and re.fullmatch(r"itefc-[0-9a-f]{32}", challenge_id) is not None
        and type(expected_nonce) is str
        and re.fullmatch(r"[0-9a-f]{32}", expected_nonce) is not None,
        422,
        "Server-issued independent challenge required",
    )
    params = {
        "challenge": challenge_id,
        "eng": engagement_id,
        "flow": flow_id,
        "finding": finding_id,
        "qual": qualification_id,
    }
    challenge = (await db.execute(_CHALLENGE, params)).mappings().one_or_none()
    now = int(time.time())
    _deny(
        challenge is not None
        and challenge.get("qualification_sha256") == qualification_sha256
        and challenge.get("nonce_sha256")
        == hashlib.sha256(expected_nonce.encode("ascii")).hexdigest()
        and type(challenge.get("issued_at")) is int
        and type(challenge.get("expires_at")) is int
        and challenge["issued_at"] <= now < challenge["expires_at"]
        and challenge["expires_at"] <= challenge["issued_at"] + 60,
        409,
        "Missing, stale, substituted or exhausted server-issued challenge",
    )
    return dict(challenge)


async def _anonymous_one_shot(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    anonymous_task_id: str,
    expected_nonce: str,
    expected_version: int,
    expected_revision: int,
    observer_claims: Dict[str, Any],
    challenge_id: str,
    source: Task,
    target: Task,
    trusted_anonymous_signed_dispatch_check: Callable[[str, str, str, str, int], Awaitable[bool]],
) -> bool:
    """Match an ALREADY approved and executed third anonymous Task; never run it."""
    if not (
        type(anonymous_task_id) is str
        and re.fullmatch(r"task-[A-Za-z0-9._-]{1,58}", anonymous_task_id)
        and type(expected_nonce) is str
        and re.fullmatch(r"[0-9a-f]{32}", expected_nonce)
        and observer_claims.get("nonce") == expected_nonce
        and observer_claims.get("finding_id") == finding_id
    ):
        return False
    request = observer_claims.get("observations", {}).get("anonymous", {})
    if type(request) is not dict:
        return False
    row = (
        (
            await db.execute(
                _ANONYMOUS_TASK,
                {"eng": engagement_id, "flow": flow_id, "anon": anonymous_task_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row.get("id") != anonymous_task_id:
        return False
    payload, result = row.get("payload"), row.get("result")
    if (
        type(payload) is not dict
        or type(result) is not dict
        or not callable(trusted_anonymous_signed_dispatch_check)
    ):
        return False
    provider_receipt = result.get("provider_evidence")
    if not (
        row.get("status") == "completed"
        and row.get("type") == "navigate"
        and row.get("approval_required") is True
        and row.get("assigned_agent_id")
        and row.get("engagement_id") == engagement_id
        and row.get("flow_id") == flow_id
        and type(source.parent_task_id) is str
        and source.parent_task_id == target.parent_task_id
        and row.get("parent_task_id") == source.parent_task_id
        and source.parent_task_id
        not in {
            source.id,
            target.id,
            anonymous_task_id,
        }
        and payload.get("_authorization_version") == expected_version
        and payload.get("_flow_revision", payload.get("planner_flow_revision")) == expected_revision
        and payload.get("identity") == "anonymous"
        and payload.get("role") == "anonymous"
        and payload.get("method") == "GET"
        and payload.get("url") == source.payload.get("url")
        and payload.get("url") == target.payload.get("url")
        and request.get("endpoint_url") == payload.get("url")
        and type(payload.get("approval_id")) is str
        and request.get("task_id") == anonymous_task_id
        and request.get("identity") is None
        and request.get("session_sha256") is None
        and request.get("http_status") in (401, 403, 404)
        and request.get("redirected") is False
        and result.get("identity") == "anonymous"
        and result.get("redirected") is False
        and result.get("http_status") == request.get("http_status")
        and result.get("request_sha256") == request.get("request_sha256")
        and result.get("response_sha256") == request.get("response_sha256")
        and type(provider_receipt) is dict
        and provider_receipt.get("source_authenticity_verified") is False
        and _exact(_EVENT, provider_receipt.get("provider_event_id"))
        and provider_receipt["provider_event_id"] == request.get("event_id")
        and _exact(_SHA, provider_receipt.get("provider_receipt_sha256"))
    ):
        return False
    approval = (
        (
            await db.execute(
                _ANONYMOUS_APPROVAL,
                {
                    "eng": engagement_id,
                    "anon": anonymous_task_id,
                    "approval": payload["approval_id"],
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        approval is None
        or approval.get("status") != "approved"
        or not matches_pinned_payload(approval.get("evidence"), payload)
    ):
        return False
    try:
        # A digest in a provider/agent-produced Task result is NOT an
        # authenticated execution receipt. Require original signed
        # supervision event verification, binding the anonymous witness
        # event ID and provider receipt to the persisted Task and ROE.
        return (
            await trusted_anonymous_signed_dispatch_check(
                engagement_id,
                anonymous_task_id,
                provider_receipt["provider_event_id"],
                provider_receipt["provider_receipt_sha256"],
                expected_version,
            )
        ) is True
    except Exception:
        return False


async def _verify_live_observer(
    db: Any,
    *,
    observer_claims_json: bytes,
    observer_signature_b64url: str,
    challenge_id: str,
    expected_nonce: str,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    qualification_id: str,
    qualification_sha256: str,
    expected_qualification_revision: int,
    review_decision_id: str,
    review_decision_sha256: str,
    flow_revision: int,
    authorization_version: int,
    signed: Any,
    review: Dict[str, Any],
    previous: Dict[str, Any],
    source_claims: Dict[str, Any],
    candidate: Dict[str, Any],
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
    trusted_anonymous_signed_dispatch_check: Callable[[str, str, str, str, int], Awaitable[bool]],
    read_existing_id: Optional[str] = None,
) -> Any:
    # The only trusted observer implementation is the independently witnessed,
    # TWO-signature production verifier. Type checks are supplemental: neither
    # a constructed dataclass nor source-supplied bool is a trust root.
    try:
        from ai_osop.core.independent_target_effect_observer import (
            LiveIndependentEffectEvidence,
            _load_trust,
            verify_independent_target_effect_claims,
        )
    except ImportError as exc:
        raise IndependentTargetEffectDenied(503, "Production LIVE verifier unavailable") from exc
    _deny(
        callable(trusted_anonymous_signed_dispatch_check),
        422,
        "Trusted signed anonymous Task dispatch verifier required",
    )

    challenge = await _require_challenge(
        db,
        challenge_id=challenge_id,
        expected_nonce=expected_nonce,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
    )
    flow, original, source, target = await _read_original_tasks(
        db,
        engagement_id,
        flow_id,
        previous,
    )
    _deny(
        flow.revision == flow_revision and flow.status == "running",
        409,
        "Current original signed Flow changed",
    )
    try:
        witness_claims = _strict_json(observer_claims_json, max_bytes=8192)
        _deny(
            _canonical(witness_claims) == observer_claims_json
            and witness_claims.get("schema") == "ai-osop.independent-target-effect.v1"
            and witness_claims.get("nonce") == expected_nonce
            and witness_claims.get("review_decision_id") == review_decision_id
            and witness_claims.get("review_decision_sha256") == review_decision_sha256
            and witness_claims.get("qualification_id") == qualification_id
            and witness_claims.get("qualification_sha256") == qualification_sha256
            and witness_claims.get("qualification_revision") == expected_qualification_revision
            and witness_claims.get("proof_sha256") == previous["proof_sha256"]
            and witness_claims.get("audit_sha256") == previous["audit_corroboration_sha256"]
            and witness_claims.get("finding_id") == finding_id
            and witness_claims.get("resource_id") == candidate["resource_id"],
            409,
            "Live witness signature source binding differs from current finding",
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise IndependentTargetEffectDenied(409, "Independent witness source malformed") from exc

    async def current_authority() -> bool:
        return await trusted_current_verifier() is True

    async def current_review(fid: str, digest: str) -> bool:
        return bool(
            fid == finding_id
            and digest == review_decision_sha256
            and await trusted_report_source_check(fid, review["report_source_evidence_sha256"])
            is True
        )

    async def current_qualification(fid: str, qid: str, qsha: str, revision: int) -> bool:
        if (fid, qid, qsha, revision) != (
            finding_id,
            qualification_id,
            qualification_sha256,
            expected_qualification_revision,
        ):
            return False
        row = (
            (
                await db.execute(
                    _CURRENT_ATTEMPT,
                    {"eng": engagement_id, "flow": flow_id, "finding": finding_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        return bool(
            row is not None
            and _unknown_integrity(dict(row))
            and row.get("id") == qualification_id
            and row.get("attempt_sha256") == qualification_sha256
            and row.get("revision") == expected_qualification_revision
            and row.get("status") == "UNKNOWN"
        )

    async def one_shot(fid: str, anonymous_task: str, nonce: str) -> bool:
        if fid != finding_id or nonce != expected_nonce:
            return False
        # Unique/append-only DB replay check, never a best-effort cache.
        args = {
            "nonce": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
            "digest": "0" * 64,
        }
        previous_nonce = (await db.execute(_EFFECT_NONCE_USED, args)).scalar_one_or_none()
        if previous_nonce is not None and previous_nonce != read_existing_id:
            return False
        previous_finding = (
            await db.execute(
                _FINDING_ALREADY_PROMOTED,
                {"eng": engagement_id, "flow": flow_id, "finding": finding_id},
            )
        ).scalar_one_or_none()
        if previous_finding is not None and previous_finding != read_existing_id:
            return False
        return await _anonymous_one_shot(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            anonymous_task_id=anonymous_task,
            expected_nonce=expected_nonce,
            expected_version=authorization_version,
            expected_revision=flow_revision,
            observer_claims=witness_claims,
            challenge_id=challenge_id,
            source=source,
            target=target,
            trusted_anonymous_signed_dispatch_check=trusted_anonymous_signed_dispatch_check,
        )

    try:
        verdict = await verify_independent_target_effect_claims(
            observer_claims_json=observer_claims_json,
            observer_signature_b64url=observer_signature_b64url,
            expected_nonce=expected_nonce,
            engagement_id=engagement_id,
            flow=flow,
            signed_authorization=signed,
            original_source_task=original,
            source_task=source,
            target_task=target,
            finding_id=finding_id,
            review_decision_id=review_decision_id,
            review_decision_sha256=review_decision_sha256,
            qualification_id=qualification_id,
            qualification_sha256=qualification_sha256,
            qualification_revision=expected_qualification_revision,
            proof_sha256=previous["proof_sha256"],
            audit_sha256=previous["audit_corroboration_sha256"],
            trusted_current_authority_check=current_authority,
            trusted_current_review_check=current_review,
            trusted_current_qualification_check=current_qualification,
            trusted_one_shot_admission_check=one_shot,
        )
        # No dictated result object from an LLM, MCP or client may stand in
        # for both independent cryptographic witness signatures.
        _deny(
            type(verdict) is LiveIndependentEffectEvidence, 409, "Signed LIVE verdict type required"
        )
        _deny(
            verdict.observer_claims_json == observer_claims_json
            and verdict.observer_signature_b64url == observer_signature_b64url
            and verdict.engagement_id == engagement_id
            and verdict.flow_id == flow_id
            and verdict.finding_id == finding_id
            and verdict.review_decision_id == review_decision_id
            and verdict.review_decision_sha256 == review_decision_sha256
            and verdict.qualification_id == qualification_id
            and verdict.qualification_sha256 == qualification_sha256
            and verdict.qualification_revision == expected_qualification_revision
            and verdict.proof_sha256 == previous["proof_sha256"]
            and verdict.audit_sha256 == previous["audit_corroboration_sha256"]
            and verdict.resource_id == candidate["resource_id"]
            and verdict.owner_identity == source_claims["source_identity"]
            and verdict.source_identity == source_claims["source_identity"]
            and verdict.target_identity == source_claims["target_identity"]
            and verdict.source_request_sha256 == source_claims["source_request_sha256"]
            and verdict.target_request_sha256 == source_claims["target_request_sha256"]
            and verdict.source_session_sha256 == source_claims["source_session_sha256"]
            and verdict.target_session_sha256 == source_claims["target_session_sha256"]
            and verdict.source_response_sha256 == source_claims["source_response_sha256"]
            and verdict.target_response_sha256 == source_claims["target_response_sha256"]
            and verdict.private_content_sha256 == source_claims["source_response_sha256"]
            and verdict.source_http_status == 200
            and verdict.target_http_status == 200
            and verdict.anonymous_http_status == candidate["anonymous_http_status"]
            and verdict.redirects_seen is False
            and verdict.public_resource is False
            and verdict.finding_verified is False
            and verdict.report_release_approved is False,
            409,
            "Independent verifier does not match immutable private effect",
        )
        config, pinned_key_sha, registry_sha256 = _current_witness_trust(
            engagement_id=engagement_id,
            flow_id=flow_id,
            signed_claims=observer_claims_json,
            signed_signature=observer_signature_b64url,
            challenge_issued_at=challenge["issued_at"],
        )
        pinned_key = base64.b64decode(config["observer_public_key_b64"], validate=True)
        owner_key = base64.b64decode(config["owner_public_key_b64"], validate=True)
        # A target assertion signer, or either earlier target audit signer,
        # must NEVER double as a purported independent LIVE witness. Reject
        # missing, rotated or indistinguishable out-of-band trust roots.
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from ai_osop.core.target_authority_proof import _keys as target_keys
        from ai_osop.core.target_authority_corroboration import _key_pair

        checked = [
            key.public_bytes(Encoding.Raw, PublicFormat.Raw) for _, key in target_keys().values()
        ]
        endpoint = urlsplit(source_claims["endpoint_url"])
        _deny(
            endpoint.scheme == "https" and endpoint.hostname is not None,
            409,
            "Signed target origin cannot bind LIVE effect",
        )
        old_audit = _key_pair(engagement_id, flow_id, "https://" + endpoint.hostname)
        checked.extend(
            key.public_bytes(Encoding.Raw, PublicFormat.Raw) for key in old_audit.values()
        )
        _deny(
            all(pinned_key != earlier and owner_key != earlier for earlier in checked)
            and pinned_key != owner_key,
            409,
            "LIVE independent verifier reuses original target/audit signing key",
        )
        _deny(
            verdict.observer_key_id == config["observer_key_id"]
            and verdict.owner_key_id == config["owner_key_id"],
            409,
            "Independent verifier changed operators",
        )
        return verdict, config, pinned_key_sha, registry_sha256
    except IndependentTargetEffectDenied:
        raise
    except Exception as exc:
        raise IndependentTargetEffectDenied(
            409, "Independent LIVE owner/access signature or one-shot attestation unavailable"
        ) from exc


async def admit_independent_target_effect_verification(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    review_decision_id: str,
    review_decision_sha256: str,
    qualification_id: str,
    qualification_sha256: str,
    expected_qualification_revision: int,
    authorization_version: int,
    flow_revision: int,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    challenge_id: str,
    expected_nonce: str,
    observer_claims_json: bytes,
    observer_signature_b64url: str,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
    trusted_anonymous_signed_dispatch_check: Callable[[str, str, str, str, int], Awaitable[bool]],
) -> Dict[str, Any]:
    """Sealed, one-shot VERIFIED finding CAS; NEVER senior report release.

    Must be called from the TRUSTED server path, in the SAME open PostgreSQL
    transaction as server-issued challenge, original signed source review,
    observer verification and INSERT. No remote provider or target access.
    The original 0021 UNKNOWN attempt remains unmodified forever.
    """
    _input(
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        expected_qualification_revision=expected_qualification_revision,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        observer_claims_json=observer_claims_json,
        observer_signature_b64url=observer_signature_b64url,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
    )
    _deny(
        callable(trusted_anonymous_signed_dispatch_check)
        and db is not None
        and callable(getattr(db, "execute", None))
        and callable(getattr(db, "in_transaction", None))
        and db.in_transaction() is True,
        503,
        "Caller-owned open PostgreSQL admission transaction required",
    )
    signed, review, previous, source_claims, candidate = await _current(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        expected_qualification_revision=expected_qualification_revision,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
        writing=True,
    )
    last_challenge = await _require_challenge(
        db,
        challenge_id=challenge_id,
        expected_nonce=expected_nonce,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
    )
    _deny(
        (
            await db.execute(
                _FINDING_ALREADY_PROMOTED,
                {"eng": engagement_id, "flow": flow_id, "finding": finding_id},
            )
        ).scalar_one_or_none()
        is None,
        409,
        "This finding was already independently verified",
    )
    verdict, config, pinned_key_sha, registry_sha = await _verify_live_observer(
        db,
        observer_claims_json=observer_claims_json,
        observer_signature_b64url=observer_signature_b64url,
        challenge_id=challenge_id,
        expected_nonce=expected_nonce,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        expected_qualification_revision=expected_qualification_revision,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        flow_revision=flow_revision,
        authorization_version=authorization_version,
        signed=signed,
        review=review,
        previous=previous,
        source_claims=source_claims,
        candidate=candidate,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
        trusted_anonymous_signed_dispatch_check=trusted_anonymous_signed_dispatch_check,
    )
    _deny(
        type(verdict.issued_at) is int
        and type(verdict.expires_at) is int
        and 0 < verdict.issued_at < verdict.expires_at <= verdict.issued_at + 60
        and int(time.time()) < verdict.expires_at
        and _exact(_SHA, verdict.observation_sha256)
        and verdict.nonce == expected_nonce,
        409,
        "Independent verified witness observation expired/UNKNOWN",
    )
    # Signed observer facts do not change the immutable candidate's original
    # unknown record. Refresh source/reviewer after awaited cryptographic
    # witness checks and before acquiring unique promotion/nonce indexes.
    again, review_again, previous_again, _, candidate_again = await _current(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        review_decision_id=review_decision_id,
        review_decision_sha256=review_decision_sha256,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
        expected_qualification_revision=expected_qualification_revision,
        authorization_version=authorization_version,
        flow_revision=flow_revision,
        reviewer_sub=reviewer_sub,
        reviewer_role=reviewer_role,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
        writing=True,
    )
    _deny(
        again.authorization_id == signed.authorization_id
        and again.policy_sha256 == signed.policy_sha256
        and again.version == signed.version
        and review_again["decision_sha256"] == review["decision_sha256"]
        and previous_again["attempt_sha256"] == previous["attempt_sha256"]
        and candidate_again == candidate,
        409,
        "Signed admission source changed after witness verification",
    )
    await _fresh(
        db,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        reviewer_sub=reviewer_sub,
        reviewer_token_sha256=reviewer_token_sha256,
        reviewer_expires_at=reviewer_expires_at,
        authorization_version=authorization_version,
        signed=signed,
        trusted_current_verifier=trusted_current_verifier,
        trusted_report_source_check=trusted_report_source_check,
        report_sha256=review["report_source_evidence_sha256"],
    )
    # Independent second signed dispatch attestation after awaited current
    # ROE/review/source checks. No untrusted provider response or digest alone
    # can survive into the immutable finding promotion.
    _, original_task, live_source_task, live_target_task = await _read_original_tasks(
        db, engagement_id, flow_id, previous
    )
    renewed_witness = _strict_json(observer_claims_json, max_bytes=8192)
    _deny(
        await _anonymous_one_shot(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            anonymous_task_id=verdict.anonymous_task_id,
            expected_nonce=expected_nonce,
            expected_version=authorization_version,
            expected_revision=flow_revision,
            observer_claims=renewed_witness,
            challenge_id=challenge_id,
            source=live_source_task,
            target=live_target_task,
            trusted_anonymous_signed_dispatch_check=trusted_anonymous_signed_dispatch_check,
        ),
        409,
        "Signed anonymous execution authority revoked after witness admission",
    )
    # The final signed-dispatch await may outlive the short-lived nonce or
    # permit either out-of-band signer to rotate/revoke. Both trusted roots
    # must still match the independently VERIFIED source at the INSERT point.
    await _require_challenge(
        db,
        challenge_id=challenge_id,
        expected_nonce=expected_nonce,
        engagement_id=engagement_id,
        flow_id=flow_id,
        finding_id=finding_id,
        qualification_id=qualification_id,
        qualification_sha256=qualification_sha256,
    )
    try:
        last_config, last_pinned_sha, last_registry_sha = _current_witness_trust(
            engagement_id=engagement_id,
            flow_id=flow_id,
            signed_claims=observer_claims_json,
            signed_signature=observer_signature_b64url,
            challenge_issued_at=last_challenge["issued_at"],
        )
        _deny(
            last_config == config
            and last_pinned_sha == pinned_key_sha
            and last_registry_sha == registry_sha
            and int(time.time()) < verdict.expires_at,
            409,
            "Independent LIVE witness expired or signer registry rotated before admission",
        )
    except IndependentTargetEffectDenied:
        raise
    except Exception as exc:
        raise IndependentTargetEffectDenied(
            409, "Independent LIVE witness trust revoked before admission"
        ) from exc
    nonce_sha = hashlib.sha256(expected_nonce.encode("ascii")).hexdigest()
    _deny(
        (
            await db.execute(
                _EFFECT_NONCE_USED,
                {"nonce": nonce_sha, "digest": verdict.observation_sha256},
            )
        ).scalar_one_or_none()
        is None,
        409,
        "Previously admitted independent witness nonce or verdict",
    )
    row = {
        "id": "itefv-" + uuid.uuid4().hex,
        "engagement_id": engagement_id,
        "flow_id": flow_id,
        "finding_id": finding_id,
        "review_decision_id": review_decision_id,
        "review_decision_sha256": review_decision_sha256,
        "review_revision": review["review_revision"],
        "qualification_id": qualification_id,
        "qualification_sha256": qualification_sha256,
        "qualification_revision": expected_qualification_revision,
        "challenge_id": challenge_id,
        "original_source_task_id": previous["original_source_task_id"],
        "source_task_id": previous["source_task_id"],
        "target_task_id": previous["target_task_id"],
        "proof_sha256": previous["proof_sha256"],
        "audit_corroboration_sha256": previous["audit_corroboration_sha256"],
        "observation_binding_sha256": previous["observation_binding_sha256"],
        "report_source_evidence_sha256": previous["report_source_evidence_sha256"],
        "authorization_id": signed.authorization_id,
        "authorization_version": signed.version,
        "authorization_sha256": signed.policy_sha256,
        "flow_revision": flow_revision,
        "senior_reviewer_sub": reviewer_sub,
        "resource_id": candidate["resource_id"],
        "resource_owner_identity_sha256": candidate["resource_owner_identity_sha256"],
        "resource_visibility": "private",
        "source_http_status": 200,
        "target_http_status": 200,
        "anonymous_http_status": verdict.anonymous_http_status,
        "private_content_sha256": verdict.private_content_sha256,
        "verifier_key_id": verdict.observer_key_id,
        "verifier_origin": config["origin"],
        "verifier_public_key_sha256": pinned_key_sha,
        "verifier_registry_sha256": registry_sha,
        "verifier_nonce_sha256": nonce_sha,
        "verdict_sha256": verdict.observation_sha256,
        "signed_verdict_json": observer_claims_json,
        "verdict_signature_b64url": observer_signature_b64url,
        "verdict_issued_at": verdict.issued_at,
        "verdict_expires_at": verdict.expires_at,
        "status": "VERIFIED",
        "independent_effect_verified": True,
        "finding_verified": True,
        "report_release_approved": False,
    }
    try:
        inserted = (await db.execute(_INSERT, row)).scalar_one_or_none()
    except Exception as exc:
        # Ambiguous commit acknowledgement must NEVER be retried by reissuing
        # live target activity. The outer transaction must fail and be audited.
        raise IndependentTargetEffectDenied(
            503, "Independent LIVE effect PostgreSQL admission status UNKNOWN"
        ) from exc
    _deny(inserted == row["id"], 409, "Finding/nonce immutable CAS collision")
    return {
        "status": "VERIFIED",
        "finding_verified": True,
        "independent_effect_verified": True,
        "authorization_violation_verified": True,
        "report_release_approved": False,
        "finding_release_eligible": False,
        "verification_id": row["id"],
        "verification_sha256": row["verdict_sha256"],
        "original_unknown_qualification_id": qualification_id,
        "original_unknown_qualification_sha256": qualification_sha256,
    }


async def read_independent_target_effect_verification(
    db: Any,
    *,
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    evidence_sha256: str,
    authorization_version: int,
    reviewer_sub: str,
    reviewer_role: str,
    reviewer_token_sha256: str,
    reviewer_expires_at: int,
    trusted_current_verifier: Callable[[], Awaitable[bool]],
    trusted_report_source_check: Callable[[str, str], Awaitable[bool]],
    trusted_anonymous_signed_dispatch_check: Callable[[str, str, str, str, int], Awaitable[bool]],
) -> Dict[str, Any]:
    """Readback under live signature/reviewer/source revocation checks.

    A database VERIFIED flag or copied digest does NOT authorize report
    release. The exact original signed outer and nested owner witness claims
    must reverify against CURRENT out-of-band keys, same immutable approved
    Task/Flow/ROE and one-shot anonymous admission. Stale/expired sources
    return UNKNOWN, never a cached VERIFIED or release permission.
    """
    unknown = _unknown()
    if not (
        _exact(_ENG, engagement_id)
        and _exact(_FLOW, flow_id)
        and _exact(_FIND, finding_id)
        and _exact(_SHA, evidence_sha256)
        and type(authorization_version) is int
        and authorization_version > 0
        and _exact(_SUB, reviewer_sub)
        and reviewer_role == "senior_operator"
        and _exact(_SHA, reviewer_token_sha256)
        and type(reviewer_expires_at) is int
        and reviewer_expires_at > 0
        and callable(trusted_current_verifier)
        and callable(trusted_report_source_check)
        and callable(trusted_anonymous_signed_dispatch_check)
        and db is not None
        and callable(getattr(db, "execute", None))
        and callable(getattr(db, "in_transaction", None))
        and db.in_transaction() is True
    ):
        return unknown
    try:
        params = {"eng": engagement_id, "flow": flow_id, "finding": finding_id}
        result = (await db.execute(_CURRENT_PROMOTION, params)).mappings().one_or_none()
        if result is None:
            return unknown
        row = dict(result)
        if not (
            row.get("engagement_id") == engagement_id
            and row.get("flow_id") == flow_id
            and row.get("finding_id") == finding_id
            and row.get("status") == "VERIFIED"
            and row.get("finding_verified") is True
            and row.get("independent_effect_verified") is True
            and row.get("report_release_approved") is False
            and row.get("verdict_sha256") == evidence_sha256
            and _exact(_REVIEW, row.get("review_decision_id"))
            and _exact(_QUAL, row.get("qualification_id"))
            and _exact(_SHA, row.get("review_decision_sha256"))
            and _exact(_SHA, row.get("qualification_sha256"))
            and row.get("authorization_version") == authorization_version
            and row.get("senior_reviewer_sub") == reviewer_sub
            and type(row.get("qualification_revision")) is int
            and type(row.get("flow_revision")) is int
            and type(row.get("signed_verdict_json")) is bytes
            and type(row.get("verdict_signature_b64url")) is str
        ):
            return unknown
        witness_claims = _strict_json(row["signed_verdict_json"], max_bytes=8192)
        if (
            _canonical(witness_claims) != row["signed_verdict_json"]
            or type(witness_claims.get("nonce")) is not str
        ):
            return unknown
        expected_nonce = witness_claims["nonce"]
        if hashlib.sha256(expected_nonce.encode("ascii")).hexdigest() != row.get(
            "verifier_nonce_sha256"
        ):
            return unknown
        signed, review, previous, source_claims, candidate = await _current(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            review_decision_id=row["review_decision_id"],
            review_decision_sha256=row["review_decision_sha256"],
            qualification_id=row["qualification_id"],
            qualification_sha256=row["qualification_sha256"],
            expected_qualification_revision=row["qualification_revision"],
            authorization_version=authorization_version,
            flow_revision=row["flow_revision"],
            reviewer_sub=reviewer_sub,
            reviewer_role=reviewer_role,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
            trusted_current_verifier=trusted_current_verifier,
            trusted_report_source_check=trusted_report_source_check,
            writing=False,
        )
        verdict, config, pinned_sha, registry_sha = await _verify_live_observer(
            db,
            observer_claims_json=row["signed_verdict_json"],
            observer_signature_b64url=row["verdict_signature_b64url"],
            challenge_id=row["challenge_id"],
            expected_nonce=expected_nonce,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            qualification_id=row["qualification_id"],
            qualification_sha256=row["qualification_sha256"],
            expected_qualification_revision=row["qualification_revision"],
            review_decision_id=row["review_decision_id"],
            review_decision_sha256=row["review_decision_sha256"],
            flow_revision=row["flow_revision"],
            authorization_version=authorization_version,
            signed=signed,
            review=review,
            previous=previous,
            source_claims=source_claims,
            candidate=candidate,
            trusted_current_verifier=trusted_current_verifier,
            trusted_report_source_check=trusted_report_source_check,
            trusted_anonymous_signed_dispatch_check=trusted_anonymous_signed_dispatch_check,
            read_existing_id=row["id"],
        )
        if not (
            verdict.observation_sha256 == evidence_sha256
            and verdict.private_content_sha256 == row["private_content_sha256"]
            and verdict.observer_key_id == row["verifier_key_id"]
            and config["origin"] == row["verifier_origin"]
            and pinned_sha == row["verifier_public_key_sha256"]
            and registry_sha == row["verifier_registry_sha256"]
            and candidate["resource_id"] == row["resource_id"]
            and candidate["resource_owner_identity_sha256"] == row["resource_owner_identity_sha256"]
            and row["resource_visibility"] == "private"
            and row["source_http_status"] == verdict.source_http_status == 200
            and row["target_http_status"] == verdict.target_http_status == 200
            and row["anonymous_http_status"] == verdict.anonymous_http_status
            and row["anonymous_http_status"] in (401, 403, 404)
            and review["report_source_evidence_sha256"] == row["report_source_evidence_sha256"]
            and review["review_revision"] == row["review_revision"]
            and previous["revision"] == row["qualification_revision"]
            and previous["original_source_task_id"] == row["original_source_task_id"]
            and previous["source_task_id"] == row["source_task_id"]
            and previous["target_task_id"] == row["target_task_id"]
            and previous["attempt_sha256"] == row["qualification_sha256"]
            and previous["proof_sha256"] == row["proof_sha256"]
            and previous["audit_corroboration_sha256"] == row["audit_corroboration_sha256"]
            and previous["observation_binding_sha256"] == row["observation_binding_sha256"]
            and signed.authorization_id == row["authorization_id"]
            and signed.policy_sha256 == row["authorization_sha256"]
            and type(row["verdict_issued_at"]) is int
            and type(row["verdict_expires_at"]) is int
            and verdict.issued_at == row["verdict_issued_at"]
            and verdict.expires_at == row["verdict_expires_at"]
        ):
            return unknown
        await _fresh(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            reviewer_sub=reviewer_sub,
            reviewer_token_sha256=reviewer_token_sha256,
            reviewer_expires_at=reviewer_expires_at,
            authorization_version=authorization_version,
            signed=signed,
            trusted_current_verifier=trusted_current_verifier,
            trusted_report_source_check=trusted_report_source_check,
            report_sha256=row["report_source_evidence_sha256"],
        )
        # Reading is also an authority decision: the final awaited reviewer/
        # ROE check can race with independent witness key revocation. Re-read
        # the short-lived challenge and prove both signatures against the
        # currently deployed registry immediately before returning VERIFIED.
        last_challenge = await _require_challenge(
            db,
            challenge_id=row["challenge_id"],
            expected_nonce=expected_nonce,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            qualification_id=row["qualification_id"],
            qualification_sha256=row["qualification_sha256"],
        )
        current_config, current_pinned_sha, current_registry_sha = _current_witness_trust(
            engagement_id=engagement_id,
            flow_id=flow_id,
            signed_claims=row["signed_verdict_json"],
            signed_signature=row["verdict_signature_b64url"],
            challenge_issued_at=last_challenge["issued_at"],
        )
        if not (
            current_config == config
            and current_pinned_sha == pinned_sha
            and current_registry_sha == registry_sha
            and int(time.time()) < verdict.expires_at
        ):
            return unknown
        return {
            "status": "VERIFIED",
            "finding_verified": True,
            "independent_effect_verified": True,
            "authorization_violation_verified": True,
            "report_release_approved": False,
            "finding_release_eligible": False,
            "verification_id": row["id"],
            "verification_sha256": evidence_sha256,
            "report_source_evidence_sha256": row["report_source_evidence_sha256"],
        }
    except Exception:
        # A stale key, changed trust generation, signer revocation, expired
        # observation, historical-only UNKNOWN, malformed signature, or
        # broken PG check is never a release permission.
        return unknown
