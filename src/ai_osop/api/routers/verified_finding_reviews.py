"""Senior-reviewed signed *candidate* finding provenance; not vulnerability release."""

from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr
from sqlalchemy import select, text

from ai_osop.api.deps import assert_engagement_access, state
from ai_osop.api.routers.flow_artifact_reviews import _senior_reviewer
from ai_osop.api.routers.report_attestations import (
    _SOURCE_BINDING_FIELDS,
    _graph_evidence,
    _refuse_unsupported_target_promotion,
    _verify_generation_release,
)
from ai_osop.api.routers.target_authority import _verify_signed_replay_dispatches
from ai_osop.auth.session_store import UserSessionORM
from ai_osop.core.authority_session_binding import reverify_replay_fingerprints
from ai_osop.core.independent_target_effect_observer import (
    IndependentEffectUnavailable,
    fetch_independent_target_effect_signed_receipt,
)
from ai_osop.core.models import Task
from ai_osop.orchestrator.context_compaction import task_assignment_sha256
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)
from ai_osop.memory.session_memory import ExecutionFlowORM, SessionMemory, TaskORM
from ai_osop.memory.verified_finding_decisions import (
    FindingDecisionDenied,
    append_candidate_review,
    read_latest_candidate_review,
)
from ai_osop.memory.target_verified_promotions import (
    TargetEffectQualificationDenied,
    read_target_effect_qualification,
    record_unknown_effect_qualification,
)
from ai_osop.memory.independent_target_effect_verifications import (
    IndependentTargetEffectDenied,
    admit_independent_target_effect_verification,
    issue_independent_target_effect_challenge,
    read_independent_target_effect_verification,
)
from ai_osop.reporting.attestation import _unique_object_pairs
from ai_osop.reporting.attested_storage import (
    load_attested_bundle,
    validated_report_id,
    verify_loaded_bundle,
)

router = APIRouter(prefix="/engagements", tags=["candidate-finding-reviews"])
_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_FINDING = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SOURCE_EVENT = re.compile(r"evt-[A-Za-z0-9._-]{1,78}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class CandidateReviewSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: StrictStr = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    report_id: StrictStr = Field(min_length=1, max_length=128)
    original_source_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,58}$")
    source_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,58}$")
    target_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,58}$")
    proof_sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
    audit_sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
    report_source_evidence_sha256: StrictStr = Field(pattern=r"^[a-f0-9]{64}$")
    expected_authorization_version: StrictInt = Field(ge=1)
    expected_flow_revision: StrictInt = Field(ge=0)
    expected_review_revision: StrictInt = Field(ge=0)
    decision_status: Literal["candidate_only", "UNKNOWN", "independent_verification_required"] = (
        "independent_verification_required"
    )


class TargetEffectQualificationSubmission(CandidateReviewSubmission):
    """Explicit UNKNOWN-only durable qualification, never finding promotion."""

    review_decision_id: StrictStr = Field(pattern=r"^vfdec-[0-9a-f]{32}$")
    review_decision_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    expected_qualification_revision: StrictInt = Field(ge=0, lt=1000000)


class IndependentEffectVerificationSubmission(TargetEffectQualificationSubmission):
    """Identify an existing immutable UNKNOWN before server-side witness retrieval.

    No client-provided signature, nonce, observation, 'verified' flag, or
    target destination is accepted. The server issues the challenge and reads
    the separately administered witness's existing signed audit records.
    """

    qualification_id: StrictStr = Field(pattern=r"^teqa-[0-9a-f]{32}$")
    qualification_sha256: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    expected_qualification_revision: StrictInt = Field(ge=1, lt=1000000)


def _empty_effect() -> Dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "reason_code": "independent_target_effect_service_missing",
        "revision": 0,
        "qualification_id": None,
        "qualification_sha256": None,
        "finding_verified": False,
        "independent_target_effect_verified": False,
        "authorization_violation_verified": False,
        "finding_release_eligible": False,
        "report_release_approved": False,
    }


def _source_tuple_valid(value: CandidateReviewSubmission) -> bool:
    return len({value.original_source_task_id, value.source_task_id, value.target_task_id}) == 3


async def _independent_report_source_check(
    db: Any,
    orch: Any,
    memory: SessionMemory,
    *,
    engagement_id: str,
    flow_id: str,
    flow_revision: int,
    report_id: str,
    signed: Any,
    finding_id: str,
    evidence_sha256: str,
) -> bool:
    """Recheck the signed report bytes, PG generation and original graph source.

    A graph validation flag can locate a report source, but cannot authenticate
    the source itself. Require its signed source_binding tuple to equal a
    completed same-tenant PostgreSQL task and its verified signed event.
    """
    try:
        if not _FINDING.fullmatch(finding_id) or not _SHA.fullmatch(evidence_sha256):
            return False
        bundle = await asyncio.to_thread(load_attested_bundle, engagement_id, report_id)
        source_rows: Dict[str, Dict[str, Any]] = {}
        evidence = await _graph_evidence(
            getattr(orch, "graph_memory", None),
            engagement_id,
            bundle,
            source_records=source_rows,
        )
        verdict = verify_loaded_bundle(
            bundle,
            session_id=engagement_id,
            report_id=report_id,
            evidence_by_finding=evidence,
        )
        _refuse_unsupported_target_promotion(bundle)
        if verdict.get("release_status") != "generation_binding_pending_verification":
            return False
        await _verify_generation_release(
            db,
            session_id=engagement_id,
            report_id=report_id,
            loaded=bundle,
            current_authorization=signed,
        )
        provenance = bundle["attestation"]["attestation"]["evidence_provenance"]
        if not isinstance(provenance, list):
            return False
        matches = [
            row
            for row in provenance
            if isinstance(row, dict)
            and row.get("finding_id") == finding_id
            and row.get("evidence_sha256") == evidence_sha256
        ]
        if len(matches) != 1:
            return False
        graph_binding = source_rows.get(finding_id)
        if not isinstance(graph_binding, dict):
            return False
        report = json.loads(
            bundle["artifacts"]["json"].decode("utf-8"),
            object_pairs_hook=_unique_object_pairs,
        )
        signed_findings = report.get("findings")
        if not isinstance(signed_findings, list) or len(signed_findings) > 200:
            return False
        signed_matches = [
            item
            for item in signed_findings
            if isinstance(item, dict)
            and item.get("id") == finding_id
            and item.get("evidence_hash") == evidence_sha256
        ]
        if len(signed_matches) != 1 or signed_matches[0].get("source_binding") != {
            k: graph_binding.get(k) for k in _SOURCE_BINDING_FIELDS
        }:
            return False
        source_id = graph_binding.get("source_task_id")
        event = graph_binding.get("source_event_id")
        receipt = graph_binding.get("provider_receipt_sha256")
        version = graph_binding.get("authorization_version")
        if (
            not isinstance(source_id, str)
            or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,78}", source_id)
            or not isinstance(event, str)
            or not _SOURCE_EVENT.fullmatch(event)
            or not isinstance(receipt, str)
            or not _SHA.fullmatch(receipt)
            or type(version) is not int
            or version != signed.version
            or graph_binding.get("authorization_sha256") != signed.policy_sha256
            or graph_binding.get("flow_id") != flow_id
            or type(graph_binding.get("flow_revision")) is not int
            or graph_binding["flow_revision"] != flow_revision
        ):
            return False
        current_flow = (
            await db.execute(
                select(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow_id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                )
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        if (
            current_flow is None
            or current_flow.engagement_id != engagement_id
            or current_flow.status not in {"pending", "running"}
            or type(current_flow.revision) is not int
            or current_flow.revision != flow_revision
        ):
            return False
        source = (
            await db.execute(
                select(TaskORM)
                .where(
                    TaskORM.id == source_id,
                    TaskORM.engagement_id == engagement_id,
                    TaskORM.flow_id == graph_binding.get("flow_id"),
                )
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        if source is None:
            return False
        current = Task(
            **{
                field: getattr(source, field)
                for field in Task.model_fields
                if field != "trace_context"
            }
        )
        if (
            current.engagement_id != engagement_id
            or current.status != "completed"
            or not isinstance(current.result, dict)
            or current.result.get("evidence_sha256") != evidence_sha256
            or current.payload.get("_authorization_version") != version
            or graph_binding.get("source_task_sha256") != task_assignment_sha256(current)
            or not callable(getattr(memory, "verify_signed_graph_action", None))
        ):
            return False
        return (
            await memory.verify_signed_graph_action(
                engagement_id, source_id, event, receipt, version
            )
        ) is True
    except Exception:
        return False


async def _process_review(
    engagement_id: str,
    flow_id: str,
    payload: Optional[CandidateReviewSubmission],
    response: Response,
    operator: Dict[str, Any],
    *,
    read_only: bool = False,
    finding_id: Optional[str] = None,
    report_id: Optional[str] = None,
    expected_authorization_version: Optional[int] = None,
    qualification_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Commit a source-bound senior candidate review, never a verified finding.

    Every callback below derives from the original signed bundle, immutable
    PostgreSQL observations and *currently locked* authenticated browser
    sessions. Client, graph or provider flags cannot construct a trusted check.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if (
        qualification_mode not in {None, "write", "read", "verify", "read_verified"}
        or (
            qualification_mode == "write"
            and not isinstance(payload, TargetEffectQualificationSubmission)
        )
        or (
            qualification_mode == "verify"
            and not isinstance(payload, IndependentEffectVerificationSubmission)
        )
        or (qualification_mode in {"read", "read_verified"} and not read_only)
    ):
        raise HTTPException(status_code=422, detail="Exact target qualification mode required")
    if (
        not _ENG.fullmatch(engagement_id)
        or not _FLOW.fullmatch(flow_id)
        or (payload is not None and not _source_tuple_valid(payload))
    ):
        raise HTTPException(status_code=422, detail="Exact signed finding source identity required")
    if read_only:
        if (
            payload is not None
            or finding_id is None
            or not _FINDING.fullmatch(finding_id)
            or report_id is None
            or type(expected_authorization_version) is not int
            or expected_authorization_version < 1
        ):
            raise HTTPException(status_code=422, detail="Exact candidate review identity required")
    elif payload is None:
        raise HTTPException(status_code=422, detail="Candidate review payload required")
    report_name = report_id if read_only else payload.report_id
    if not validated_report_id(engagement_id, report_name):
        raise HTTPException(status_code=422, detail="Exact signed report identity required")
    await assert_engagement_access(operator, engagement_id)
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if not isinstance(memory, SessionMemory) or memory._async_session is None:
        raise HTTPException(status_code=503, detail="Durable candidate review unavailable")
    token_sha = operator.get("_reviewer_token_sha256")
    token_exp = operator.get("_reviewer_expires_at")
    if (
        operator.get("role") != "senior_operator"
        or type(operator.get("sub")) is not str
        or type(token_sha) is not str
        or not _SHA.fullmatch(token_sha)
        or type(token_exp) is not int
        or token_exp <= int(time.time())
    ):
        raise HTTPException(status_code=403, detail="Current verified senior credentials required")
    try:
        async with asyncio.timeout(12.0):
            async with memory._async_session() as db:
                async with db.begin():
                    # Only the authenticated engagement owner may see even
                    # candidate existence. Hold the session row until return.
                    owner = (
                        await db.execute(
                            text(
                                "SELECT created_by FROM session_states "
                                "WHERE session_id=:sid "
                                + ("FOR SHARE" if read_only else "FOR UPDATE")
                            ),
                            {"sid": engagement_id},
                        )
                    ).scalar_one_or_none()
                    if type(owner) is not str or owner != operator.get("sub"):
                        raise HTTPException(status_code=403, detail="Engagement owner required")
                    await FlowArtifactReviewStore._reviewer_fence(
                        db,
                        reviewer_sub=owner,
                        reviewer_token_sha256=token_sha,
                        reviewer_expires_at=token_exp,
                    )
                    signed = await guard_sql(
                        db,
                        engagement_id,
                        expected_version=(
                            expected_authorization_version
                            if read_only
                            else payload.expected_authorization_version
                        ),
                    )
                    if signed.version != (
                        expected_authorization_version
                        if read_only
                        else payload.expected_authorization_version
                    ):
                        raise HTTPException(status_code=409, detail="Signed authorization changed")

                    if read_only:
                        archived = (
                            (
                                await db.execute(
                                    text(
                                        "SELECT original_source_task_id,source_task_id,target_task_id,"
                                        "proof_sha256,audit_corroboration_sha256,flow_revision,"
                                        "report_source_evidence_sha256 "
                                        "FROM verified_target_finding_decisions "
                                        "WHERE engagement_id=:sid AND flow_id=:fid "
                                        "AND finding_id=:finding "
                                        "ORDER BY review_revision DESC LIMIT 1 FOR SHARE"
                                    ),
                                    {"sid": engagement_id, "fid": flow_id, "finding": finding_id},
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if archived is None:
                            if qualification_mode in {"read", "read_verified"}:
                                return _empty_effect()
                            return {
                                "status": "UNKNOWN",
                                "review_revision": 0,
                                "decision_id": None,
                                "decision_sha256": None,
                                "finding_verified": False,
                                "authorization_violation_verified": False,
                                "independent_target_effect_verified": False,
                                "report_release_approved": False,
                                "finding_release_eligible": False,
                            }
                        payload = CandidateReviewSubmission(
                            finding_id=finding_id,
                            report_id=report_name,
                            original_source_task_id=archived["original_source_task_id"],
                            source_task_id=archived["source_task_id"],
                            target_task_id=archived["target_task_id"],
                            proof_sha256=archived["proof_sha256"],
                            audit_sha256=archived["audit_corroboration_sha256"],
                            report_source_evidence_sha256=archived["report_source_evidence_sha256"],
                            expected_authorization_version=expected_authorization_version,
                            expected_flow_revision=archived["flow_revision"],
                            expected_review_revision=0,
                        )

                    async def current_dispatch_session_verifier() -> bool:
                        try:
                            current = await guard_sql(
                                db,
                                engagement_id,
                                expected_version=payload.expected_authorization_version,
                            )
                            if (
                                current.authorization_id != signed.authorization_id
                                or current.policy_sha256 != signed.policy_sha256
                            ):
                                return False
                            observed = (
                                (
                                    await db.execute(
                                        select(TaskORM)
                                        .where(
                                            TaskORM.engagement_id == engagement_id,
                                            TaskORM.flow_id == flow_id,
                                            TaskORM.id.in_(
                                                (payload.source_task_id, payload.target_task_id)
                                            ),
                                        )
                                        .with_for_update(read=True)
                                    )
                                )
                                .scalars()
                                .all()
                            )
                            if len(observed) != 2:
                                return False
                            tasks = {
                                row.id: Task(
                                    **{
                                        name: getattr(row, name)
                                        for name in Task.model_fields
                                        if name != "trace_context"
                                    }
                                )
                                for row in observed
                            }
                            source = tasks.get(payload.source_task_id)
                            target = tasks.get(payload.target_task_id)
                            if (
                                source is None
                                or target is None
                                or any(
                                    task.engagement_id != engagement_id
                                    or task.flow_id != flow_id
                                    or task.type != "navigate"
                                    or task.status != "completed"
                                    or task.approval_required is not True
                                    or task.max_retries != 0
                                    or not isinstance(task.payload, dict)
                                    or task.payload.get("_flow_revision")
                                    != payload.expected_flow_revision
                                    or task.payload.get("_authorization_version") != signed.version
                                    for task in (source, target)
                                )
                                or not isinstance(source.parent_task_id, str)
                                or source.parent_task_id != target.parent_task_id
                                or source.parent_task_id in {source.id, target.id}
                                or source.payload.get("_comparison_role") != "source"
                                or target.payload.get("_comparison_role") != "target"
                                or source.payload.get("user_label")
                                == target.payload.get("user_label")
                                or not await _verify_signed_replay_dispatches(
                                    memory, engagement_id, signed.version, source, target
                                )
                            ):
                                return False
                            session_store = getattr(orch, "session_store", None)
                            if getattr(session_store, "sm", None) is not memory:
                                return False
                            for task in (source, target):
                                label = (
                                    task.payload.get("user_label")
                                    if isinstance(task.payload, dict)
                                    else None
                                )
                                if not isinstance(label, str):
                                    return False
                                row = (
                                    await db.execute(
                                        select(UserSessionORM)
                                        .where(
                                            UserSessionORM.pk == f"{engagement_id}:{label}",
                                            UserSessionORM.engagement_id == engagement_id,
                                            UserSessionORM.user_label == label,
                                        )
                                        .with_for_update(read=True)
                                    )
                                ).scalar_one_or_none()
                                if row is None:
                                    return False
                                imported = session_store._orm_to_dto(row, session_store._encryption)
                                reverify_replay_fingerprints(
                                    task.payload,
                                    imported,
                                    engagement_id=engagement_id,
                                    user_label=label,
                                    method="GET",
                                    url=task.payload["url"],
                                    task_id=task.id,
                                    parent_task_id=task.parent_task_id,
                                )
                            return True
                        except Exception:
                            return False

                    async def current_signed_report_source_check(
                        finding_id: str, evidence_sha: str
                    ) -> bool:
                        if finding_id != payload.finding_id or not hmac.compare_digest(
                            evidence_sha, payload.report_source_evidence_sha256
                        ):
                            return False
                        return await _independent_report_source_check(
                            db,
                            orch,
                            memory,
                            engagement_id=engagement_id,
                            flow_id=flow_id,
                            flow_revision=payload.expected_flow_revision,
                            report_id=report_name,
                            signed=signed,
                            finding_id=finding_id,
                            evidence_sha256=evidence_sha,
                        )

                    if not await current_dispatch_session_verifier():
                        if read_only:
                            if qualification_mode in {"read", "read_verified"}:
                                return _empty_effect()
                            return {
                                "status": "UNKNOWN",
                                "review_revision": 0,
                                "decision_id": None,
                                "decision_sha256": None,
                                "finding_verified": False,
                                "authorization_violation_verified": False,
                                "independent_target_effect_verified": False,
                                "report_release_approved": False,
                                "finding_release_eligible": False,
                            }
                        raise HTTPException(
                            status_code=409,
                            detail="Current signed dual-identity session/dispatch unavailable",
                        )
                    if not await current_signed_report_source_check(
                        payload.finding_id, payload.report_source_evidence_sha256
                    ):
                        if read_only:
                            if qualification_mode in {"read", "read_verified"}:
                                return _empty_effect()
                            return {
                                "status": "UNKNOWN",
                                "review_revision": 0,
                                "decision_id": None,
                                "decision_sha256": None,
                                "finding_verified": False,
                                "authorization_violation_verified": False,
                                "independent_target_effect_verified": False,
                                "report_release_approved": False,
                                "finding_release_eligible": False,
                            }
                        raise HTTPException(
                            status_code=409, detail="Signed report source unverified"
                        )
                    shared = dict(
                        engagement_id=engagement_id,
                        flow_id=flow_id,
                        finding_id=payload.finding_id,
                        reviewer_sub=operator["sub"],
                        reviewer_role=operator["role"],
                        reviewer_token_sha256=token_sha,
                        reviewer_expires_at=token_exp,
                        trusted_current_verifier=current_dispatch_session_verifier,
                        trusted_report_source_check=current_signed_report_source_check,
                    )
                    if qualification_mode == "read_verified":
                        # Locate ONLY the immutable digest. It is not trusted
                        # as a verified verdict: the ledger rechecks current
                        # ROE, human review, private owner keys, source Task
                        # and signed anonymous-denial receipts independently.
                        existing = (
                            await db.execute(
                                text(
                                    "SELECT verdict_sha256 FROM independent_target_effect_verifications "
                                    "WHERE engagement_id=:sid AND flow_id=:fid AND finding_id=:finding FOR SHARE"
                                ),
                                {
                                    "sid": engagement_id,
                                    "fid": flow_id,
                                    "finding": payload.finding_id,
                                },
                            )
                        ).scalar_one_or_none()
                        if not isinstance(existing, str) or not _SHA.fullmatch(existing):
                            result = _empty_effect()
                        else:

                            async def anonymous_signed_dispatch(
                                observed_engagement: str,
                                anonymous_task_id: str,
                                event_id: str,
                                receipt_sha256: str,
                                authorization_version: int,
                            ) -> bool:
                                if (
                                    observed_engagement != engagement_id
                                    or authorization_version != signed.version
                                    or not callable(
                                        getattr(memory, "verify_signed_graph_action", None)
                                    )
                                ):
                                    return False
                                try:
                                    return (
                                        await memory.verify_signed_graph_action(
                                            engagement_id,
                                            anonymous_task_id,
                                            event_id,
                                            receipt_sha256,
                                            authorization_version,
                                        )
                                    ) is True
                                except Exception:
                                    return False

                            result = await read_independent_target_effect_verification(
                                db,
                                engagement_id=engagement_id,
                                flow_id=flow_id,
                                finding_id=payload.finding_id,
                                evidence_sha256=existing,
                                authorization_version=payload.expected_authorization_version,
                                reviewer_sub=operator["sub"],
                                reviewer_role=operator["role"],
                                reviewer_token_sha256=token_sha,
                                reviewer_expires_at=token_exp,
                                trusted_current_verifier=current_dispatch_session_verifier,
                                trusted_report_source_check=current_signed_report_source_check,
                                trusted_anonymous_signed_dispatch_check=anonymous_signed_dispatch,
                            )
                            # An independently verified ledger result is still
                            # an internal trust boundary. Never forward extra
                            # witness/private content or an unbound VERIFIED
                            # claim through this senior API. Only a strict
                            # public allowlist crosses the HTTP boundary.
                            if not isinstance(result, dict):
                                result = _empty_effect()
                            elif result.get("status") == "VERIFIED":
                                if (
                                    set(result)
                                    != {
                                        "status",
                                        "finding_verified",
                                        "independent_effect_verified",
                                        "authorization_violation_verified",
                                        "report_release_approved",
                                        "finding_release_eligible",
                                        "verification_id",
                                        "verification_sha256",
                                        "report_source_evidence_sha256",
                                    }
                                    or result.get("finding_verified") is not True
                                    or result.get("independent_effect_verified") is not True
                                    or result.get("authorization_violation_verified") is not True
                                    or result.get("report_release_approved") is not False
                                    or result.get("finding_release_eligible") is not False
                                    or not isinstance(result.get("verification_id"), str)
                                    or not re.fullmatch(
                                        r"itefv-[0-9a-f]{32}", result["verification_id"]
                                    )
                                    or result.get("verification_sha256") != existing
                                    or result.get("report_source_evidence_sha256")
                                    != payload.report_source_evidence_sha256
                                ):
                                    result = _empty_effect()
                            else:
                                result = _empty_effect()
                    elif qualification_mode == "read":
                        result = await read_target_effect_qualification(
                            db,
                            engagement_id=engagement_id,
                            flow_id=flow_id,
                            finding_id=payload.finding_id,
                            reviewer_sub=operator["sub"],
                            reviewer_role=operator["role"],
                            reviewer_token_sha256=token_sha,
                            reviewer_expires_at=token_exp,
                            authorization_version=payload.expected_authorization_version,
                            trusted_current_verifier=current_dispatch_session_verifier,
                            trusted_report_source_check=current_signed_report_source_check,
                        )
                    elif qualification_mode == "write":
                        result = await record_unknown_effect_qualification(
                            db,
                            engagement_id=engagement_id,
                            flow_id=flow_id,
                            finding_id=payload.finding_id,
                            review_decision_id=payload.review_decision_id,
                            review_decision_sha256=payload.review_decision_sha256,
                            proof_sha256=payload.proof_sha256,
                            audit_sha256=payload.audit_sha256,
                            authorization_version=payload.expected_authorization_version,
                            flow_revision=payload.expected_flow_revision,
                            reviewer_sub=operator["sub"],
                            reviewer_role=operator["role"],
                            reviewer_token_sha256=token_sha,
                            reviewer_expires_at=token_exp,
                            expected_revision=payload.expected_qualification_revision,
                            trusted_current_verifier=current_dispatch_session_verifier,
                            trusted_report_source_check=current_signed_report_source_check,
                        )
                    elif qualification_mode == "verify":
                        # Only the trusted API can mint the fresh challenge.
                        # The witness read does NOT request any new target
                        # source/target/anonymous effect. Original immutable
                        # UNKNOWN and approved signed Task ancestry remain
                        # mandatory in the same PostgreSQL transaction.
                        effect_args = dict(
                            engagement_id=engagement_id,
                            flow_id=flow_id,
                            finding_id=payload.finding_id,
                            review_decision_id=payload.review_decision_id,
                            review_decision_sha256=payload.review_decision_sha256,
                            qualification_id=payload.qualification_id,
                            qualification_sha256=payload.qualification_sha256,
                            expected_qualification_revision=payload.expected_qualification_revision,
                            authorization_version=payload.expected_authorization_version,
                            flow_revision=payload.expected_flow_revision,
                            reviewer_sub=operator["sub"],
                            reviewer_role=operator["role"],
                            reviewer_token_sha256=token_sha,
                            reviewer_expires_at=token_exp,
                            trusted_current_verifier=current_dispatch_session_verifier,
                            trusted_report_source_check=current_signed_report_source_check,
                        )
                        challenge = await issue_independent_target_effect_challenge(
                            db,
                            **effect_args,
                        )
                        flow_row = (
                            await db.execute(
                                select(ExecutionFlowORM)
                                .where(
                                    ExecutionFlowORM.id == flow_id,
                                    ExecutionFlowORM.engagement_id == engagement_id,
                                )
                                .with_for_update(read=True)
                            )
                        ).scalar_one_or_none()
                        if (
                            flow_row is None
                            or flow_row.status != "running"
                            or flow_row.revision != payload.expected_flow_revision
                        ):
                            raise HTTPException(
                                status_code=409,
                                detail="Current signed Flow changed",
                            )
                        from ai_osop.core.models import FlowRecord

                        flow = FlowRecord(
                            **{field: getattr(flow_row, field) for field in FlowRecord.model_fields}
                        )
                        claims_json, signature = (
                            await fetch_independent_target_effect_signed_receipt(
                                engagement_id=engagement_id,
                                flow=flow,
                                expected_nonce=challenge["expected_nonce"],
                            )
                        )

                        async def current_anonymous_signed_dispatch(
                            observed_engagement: str,
                            anonymous_task_id: str,
                            event_id: str,
                            receipt_sha256: str,
                            authorization_version: int,
                        ) -> bool:
                            # A well-formed Task.result hash or observer
                            # signature cannot replace a PostgreSQL-authoritative
                            # *signed* dispatch+completion receipt for the
                            # separately approved anonymous Task.
                            if (
                                observed_engagement != engagement_id
                                or authorization_version != signed.version
                                or not callable(getattr(memory, "verify_signed_graph_action", None))
                            ):
                                return False
                            try:
                                return (
                                    await memory.verify_signed_graph_action(
                                        engagement_id,
                                        anonymous_task_id,
                                        event_id,
                                        receipt_sha256,
                                        authorization_version,
                                    )
                                ) is True
                            except Exception:
                                return False

                        result = await admit_independent_target_effect_verification(
                            db,
                            **effect_args,
                            challenge_id=challenge["challenge_id"],
                            expected_nonce=challenge["expected_nonce"],
                            observer_claims_json=claims_json,
                            observer_signature_b64url=signature,
                            trusted_anonymous_signed_dispatch_check=current_anonymous_signed_dispatch,
                        )
                    elif read_only:
                        result = await read_latest_candidate_review(
                            db,
                            authorization_version=payload.expected_authorization_version,
                            **shared,
                        )
                    else:
                        result = await append_candidate_review(
                            db,
                            original_source_task_id=payload.original_source_task_id,
                            source_task_id=payload.source_task_id,
                            target_task_id=payload.target_task_id,
                            proof_sha256=payload.proof_sha256,
                            audit_sha256=payload.audit_sha256,
                            authorization_version=payload.expected_authorization_version,
                            flow_revision=payload.expected_flow_revision,
                            report_source_evidence_sha256=payload.report_source_evidence_sha256,
                            expected_revision=payload.expected_review_revision,
                            decision_status=payload.decision_status,
                            **shared,
                        )
                    await FlowArtifactReviewStore._reviewer_fence(
                        db,
                        reviewer_sub=owner,
                        reviewer_token_sha256=token_sha,
                        reviewer_expires_at=token_exp,
                    )
                    # The store and trusted source callbacks await multiple
                    # independent services. Re-fence the *same* signed ROE
                    # after the last await, not just the human reviewer: a
                    # revoked or rotated authorization cannot be returned as
                    # a current candidate/UNKNOWN qualification receipt.
                    refreshed = await guard_sql(
                        db,
                        engagement_id,
                        expected_version=payload.expected_authorization_version,
                    )
                    if (
                        refreshed.session_id != engagement_id
                        or refreshed.version != signed.version
                        or refreshed.authorization_id != signed.authorization_id
                        or refreshed.policy_sha256 != signed.policy_sha256
                    ):
                        raise HTTPException(
                            status_code=409, detail="Current signed review authorization changed"
                        )
                    return result
    except HTTPException:
        raise
    except FindingDecisionDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    except TargetEffectQualificationDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    except IndependentTargetEffectDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    except IndependentEffectUnavailable as exc:
        raise HTTPException(
            status_code=503, detail="Independent live target-effect witness unavailable"
        ) from exc
    except ArtifactReviewDenied as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Signed candidate review unavailable") from exc


@router.post("/{engagement_id}/flows/{flow_id}/target-authority/finding-candidate-reviews")
async def review_signed_finding_candidate(
    engagement_id: str,
    flow_id: str,
    payload: CandidateReviewSubmission,
    response: Response,
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    return await _process_review(engagement_id, flow_id, payload, response, operator)


@router.get(
    "/{engagement_id}/flows/{flow_id}/target-authority/finding-candidate-reviews/{finding_id}"
)
async def get_signed_finding_candidate_review(
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    response: Response,
    report_id: str = Query(min_length=1, max_length=140),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    return await _process_review(
        engagement_id,
        flow_id,
        None,
        response,
        operator,
        read_only=True,
        finding_id=finding_id,
        report_id=report_id,
        expected_authorization_version=expected_authorization_version,
    )


@router.post("/{engagement_id}/flows/{flow_id}/target-authority/finding-effect-qualifications")
async def record_unverified_finding_effect_qualification(
    engagement_id: str,
    flow_id: str,
    payload: TargetEffectQualificationSubmission,
    response: Response,
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """Persist immutable UNKNOWN based on the latest existing candidate review.

    All signed-source/Task/session/owner/Flow verification is rerun inside the
    same PostgreSQL transaction; this never performs remote target requests.
    """
    return await _process_review(
        engagement_id,
        flow_id,
        payload,
        response,
        operator,
        qualification_mode="write",
    )


@router.post("/{engagement_id}/flows/{flow_id}/target-authority/finding-effect-verifications")
async def verify_independently_observed_finding_effect(
    engagement_id: str,
    flow_id: str,
    payload: IndependentEffectVerificationSubmission,
    response: Response,
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """One-shot live witness verification; never itself authorizes final release.

    No target requests are dispatched. Unavailable independently operated
    witnesses, signed ROE, human approval, exact private resource ownership or
    completed anonymous Task keep the finding UNKNOWN and unreleasable.
    """
    return await _process_review(
        engagement_id,
        flow_id,
        payload,
        response,
        operator,
        qualification_mode="verify",
    )


@router.get(
    "/{engagement_id}/flows/{flow_id}/target-authority/finding-effect-verifications/{finding_id}"
)
async def read_current_independent_finding_effect(
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    response: Response,
    report_id: str = Query(min_length=1, max_length=128),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """Current signed 0022 readback, never a cached verification or release."""
    return await _process_review(
        engagement_id,
        flow_id,
        None,
        response,
        operator,
        read_only=True,
        finding_id=finding_id,
        report_id=report_id,
        expected_authorization_version=expected_authorization_version,
        qualification_mode="read_verified",
    )


@router.get(
    "/{engagement_id}/flows/{flow_id}/target-authority/finding-effect-qualifications/{finding_id}"
)
async def read_unverified_finding_effect_qualification(
    engagement_id: str,
    flow_id: str,
    finding_id: str,
    response: Response,
    report_id: str = Query(min_length=1, max_length=140),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """Read only a currently reverified UNKNOWN, never stale verified effect."""
    return await _process_review(
        engagement_id,
        flow_id,
        None,
        response,
        operator,
        read_only=True,
        finding_id=finding_id,
        report_id=report_id,
        expected_authorization_version=expected_authorization_version,
        qualification_mode="read",
    )
