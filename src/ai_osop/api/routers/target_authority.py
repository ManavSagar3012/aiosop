"""Senior-only signed target-authority assertion intake.

No execution, finding promotion or final report release occurs here.
"""

from __future__ import annotations

import asyncio
import hmac
import re
from dataclasses import asdict
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy import select, text

from ai_osop.api.deps import assert_engagement_access, state
from ai_osop.api.routers.flow_artifact_reviews import _senior_reviewer
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_artifact_reviews import (
    ArtifactReviewDenied,
    FlowArtifactReviewStore,
)
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    ExecutionFlowORM,
    SessionMemory,
    TaskORM,
)
from ai_osop.memory.target_authority_receipts import TargetAuthorityReplayGuard
from ai_osop.safety.approval_binding import matches_pinned_payload

router = APIRouter(prefix="/engagements", tags=["target-authority"])
_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_EVENT = re.compile(r"evt-[A-Za-z0-9._-]{1,78}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class TargetAssertionSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    original_source_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,58}$")
    source_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,58}$")
    target_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,58}$")
    claims_json: StrictStr = Field(min_length=2, max_length=4096)
    signature_b64url: StrictStr = Field(pattern=r"^[A-Za-z0-9_-]{86}$")
    ownership_audit_json: Optional[StrictStr] = Field(default=None, min_length=2, max_length=4096)
    ownership_audit_signature: Optional[StrictStr] = Field(
        default=None, pattern=r"^[A-Za-z0-9_-]{86}$"
    )
    access_audit_json: Optional[StrictStr] = Field(default=None, min_length=2, max_length=4096)
    access_audit_signature: Optional[StrictStr] = Field(
        default=None, pattern=r"^[A-Za-z0-9_-]{86}$"
    )


def _task(row: Any) -> Task:
    return Task(**{field: getattr(row, field) for field in Task.model_fields})


async def _verify_signed_replay_dispatches(
    memory: Any,
    engagement_id: str,
    authorization_version: int,
    source: Task,
    target: Task,
) -> bool:
    """Require independent PostgreSQL signed dispatch+receipt for BOTH identities.

    Human approval, provider testimony, and even independently signed target
    claims cannot replace the original MCP execution-event ancestry.
    """
    if not callable(getattr(memory, "verify_signed_graph_action", None)):
        return False
    identifiers = set()
    receipts = set()
    for task in (source, target):
        result = task.result
        testimony = result.get("provider_evidence") if isinstance(result, dict) else None
        if not isinstance(testimony, dict):
            return False
        event_id = testimony.get("provider_event_id")
        receipt_sha = testimony.get("provider_receipt_sha256")
        if (
            type(event_id) is not str
            or _EVENT.fullmatch(event_id) is None
            or type(receipt_sha) is not str
            or _SHA.fullmatch(receipt_sha) is None
            or event_id in identifiers
            or receipt_sha in receipts
        ):
            return False
        identifiers.add(event_id)
        receipts.add(receipt_sha)
        try:
            if not await memory.verify_signed_graph_action(
                engagement_id,
                task.id,
                event_id,
                receipt_sha,
                authorization_version,
            ):
                return False
        except Exception:
            return False
    return True


@router.post("/{engagement_id}/flows/{flow_id}/target-authority/attestations")
async def admit_target_authority_assertion(
    engagement_id: str,
    flow_id: str,
    payload: TargetAssertionSubmission,
    response: Response,
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """Admit an immutable independent signature receipt, candidate only."""
    return await _process_target_authority_assertion(
        engagement_id,
        flow_id,
        payload,
        response,
        operator,
        existing_proof_sha256=None,
    )


@router.post(
    "/{engagement_id}/flows/{flow_id}/target-authority/attestations/{proof_sha256}/reverify"
)
async def reverify_target_authority_assertion(
    engagement_id: str,
    flow_id: str,
    proof_sha256: str,
    payload: TargetAssertionSubmission,
    response: Response,
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """Recheck a previously committed immutable signed receipt, read-only.

    Unlike first admission, no nonce is claimed and no assertion is inserted.
    Independent verification is repeated against original source bytes and
    current signed Flow, Task and human grant authority. Candidate only.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", proof_sha256):
        raise HTTPException(status_code=422, detail="Original immutable proof digest required")
    return await _process_target_authority_assertion(
        engagement_id,
        flow_id,
        payload,
        response,
        operator,
        existing_proof_sha256=proof_sha256,
    )


@router.get(
    "/{engagement_id}/flows/{flow_id}/target-authority/attestations/{proof_sha256}/reverify"
)
async def reverify_stored_target_authority_assertion(
    engagement_id: str,
    flow_id: str,
    proof_sha256: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_senior_reviewer),
) -> Dict[str, Any]:
    """Independently reverify the original immutable receipt without a resubmitted body.

    The initial read is solely for recovering existing bounded signed bytes;
    the shared full signed Task/Flow/ROE/session/reviewer gate is executed
    AGAIN under its own PostgreSQL transaction after this read. No new nonce,
    approval, remote request, vulnerability or report is produced.
    """
    if (
        not _ENG.fullmatch(engagement_id)
        or not _FLOW.fullmatch(flow_id)
        or not _SHA.fullmatch(proof_sha256)
    ):
        raise HTTPException(status_code=422, detail="Bounded existing target evidence required")
    await assert_engagement_access(operator, engagement_id)
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if (
        not isinstance(SessionMemory, type)
        or not isinstance(memory, SessionMemory)
        or memory._async_session is None
    ):
        raise HTTPException(status_code=503, detail="Durable target authority unavailable")
    try:
        async with asyncio.timeout(10.0):
            async with memory._async_session() as db:
                async with db.begin():
                    owner = (
                        await db.execute(
                            text(
                                "SELECT created_by FROM session_states WHERE session_id=:eng FOR SHARE"
                            ),
                            {"eng": engagement_id},
                        )
                    ).scalar_one_or_none()
                    if not isinstance(owner, str) or owner != operator.get("sub"):
                        raise HTTPException(status_code=403, detail="Engagement owner required")
                    source = (
                        (
                            await db.execute(
                                text(
                                    "SELECT original_source_task_id,source_task_id,target_task_id,"
                                    "target_claims_json,target_signature_b64url,"
                                    "ownership_audit_json,ownership_audit_signature,"
                                    "access_audit_json,access_audit_signature "
                                    "FROM target_authority_assertions WHERE engagement_id=:eng "
                                    "AND flow_id=:flow AND proof_sha256=:proof FOR SHARE"
                                ),
                                {"eng": engagement_id, "flow": flow_id, "proof": proof_sha256},
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if source is None:
                        raise HTTPException(status_code=404, detail="Existing proof unavailable")
                    if (
                        type(source["target_claims_json"]) is not bytes
                        or not 1 <= len(source["target_claims_json"]) <= 4096
                    ):
                        raise HTTPException(
                            status_code=409, detail="Original signed source unavailable"
                        )
                    payload = TargetAssertionSubmission(
                        original_source_task_id=source["original_source_task_id"],
                        source_task_id=source["source_task_id"],
                        target_task_id=source["target_task_id"],
                        claims_json=source["target_claims_json"].decode("utf-8"),
                        signature_b64url=source["target_signature_b64url"],
                        ownership_audit_json=(
                            source["ownership_audit_json"].decode("utf-8")
                            if type(source["ownership_audit_json"]) is bytes
                            else None
                        ),
                        ownership_audit_signature=source["ownership_audit_signature"],
                        access_audit_json=(
                            source["access_audit_json"].decode("utf-8")
                            if type(source["access_audit_json"]) is bytes
                            else None
                        ),
                        access_audit_signature=source["access_audit_signature"],
                    )
        return await _process_target_authority_assertion(
            engagement_id,
            flow_id,
            payload,
            response,
            operator,
            existing_proof_sha256=proof_sha256,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Archived target evidence unavailable") from exc


async def _process_target_authority_assertion(
    engagement_id: str,
    flow_id: str,
    payload: TargetAssertionSubmission,
    response: Response,
    operator: Dict[str, Any],
    *,
    existing_proof_sha256: Optional[str],
) -> Dict[str, Any]:
    """Shared signed-source/Task/ROE gate for first admission and review."""
    if not _ENG.fullmatch(engagement_id) or not _FLOW.fullmatch(flow_id):
        raise HTTPException(status_code=422, detail="Bounded signed engagement/Flow required")
    await assert_engagement_access(operator, engagement_id)
    from ai_osop.core.target_authority_proof import (
        TargetAuthorityDenied,
        verify_target_authority_proof,
    )

    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if (
        not isinstance(SessionMemory, type)
        or not isinstance(memory, SessionMemory)
        or memory._async_session is None
    ):
        raise HTTPException(status_code=503, detail="Durable target authority unavailable")
    try:
        async with asyncio.timeout(10.0):
            async with memory._async_session() as db:
                async with db.begin():
                    owner = (
                        await db.execute(
                            text(
                                "SELECT created_by FROM session_states WHERE session_id=:sid FOR SHARE"
                            ),
                            {"sid": engagement_id},
                        )
                    ).scalar_one_or_none()
                    if owner != operator.get("sub") or not isinstance(owner, str):
                        raise HTTPException(status_code=403, detail="Engagement owner required")

                    async def current_senior_check() -> None:
                        try:
                            await FlowArtifactReviewStore._reviewer_fence(
                                db,
                                reviewer_sub=owner,
                                reviewer_token_sha256=operator.get("_reviewer_token_sha256"),
                                reviewer_expires_at=operator.get("_reviewer_expires_at"),
                            )
                        except ArtifactReviewDenied as exc:
                            raise HTTPException(
                                status_code=exc.status,
                                detail="Signed senior review revoked or expired",
                            ) from exc

                    await current_senior_check()
                    signed = await guard_sql(db, engagement_id)
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
                    if flow_row is None or flow_row.status not in {"pending", "running"}:
                        raise HTTPException(status_code=409, detail="Current signed Flow required")
                    flow = FlowRecord(
                        **{field: getattr(flow_row, field) for field in FlowRecord.model_fields}
                    )
                    ids = {
                        payload.original_source_task_id,
                        payload.source_task_id,
                        payload.target_task_id,
                    }
                    if len(ids) != 3:
                        raise HTTPException(
                            status_code=409, detail="Distinct source tasks required"
                        )
                    records = (
                        (
                            await db.execute(
                                select(TaskORM)
                                .where(
                                    TaskORM.id.in_(ids),
                                    TaskORM.engagement_id == engagement_id,
                                )
                                .with_for_update(read=True)
                            )
                        )
                        .scalars()
                        .all()
                    )
                    if len(records) != 3:
                        raise HTTPException(
                            status_code=409, detail="Signed source Task unavailable"
                        )
                    tasks = {row.id: _task(row) for row in records}
                    original = tasks[payload.original_source_task_id]
                    source = tasks[payload.source_task_id]
                    target = tasks[payload.target_task_id]
                    if (
                        original.type != "map_workflow"
                        or original.status != "completed"
                        or original.flow_id not in {None, flow_id}
                        or source.type != "navigate"
                        or target.type != "navigate"
                        or source.status != "completed"
                        or target.status != "completed"
                        or source.flow_id != flow_id
                        or target.flow_id != flow_id
                        or not source.parent_task_id
                        or source.parent_task_id != target.parent_task_id
                        or not source.approval_required
                        or not target.approval_required
                    ):
                        raise HTTPException(status_code=409, detail="Source lineage unverified")
                    parent_row = (
                        await db.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.id == source.parent_task_id,
                                TaskORM.engagement_id == engagement_id,
                            )
                            .with_for_update(read=True)
                        )
                    ).scalar_one_or_none()
                    if (
                        parent_row is None
                        or parent_row.type != "replay_for_diff_auth"
                        or parent_row.parent_task_id != original.id
                        or parent_row.flow_id != flow_id
                        or parent_row.status != "completed"
                        or not parent_row.approval_required
                    ):
                        raise HTTPException(
                            status_code=409, detail="Approved replay ancestry unavailable"
                        )

                    # Prevent a simultaneous human approval revocation from
                    # passing a nonlocking read while this independent proof
                    # is committed. The signed ROE/Flow and all grant rows
                    # remain locked until the nonce + receipt transaction ends.
                    for approved in (source, target, _task(parent_row)):
                        approval_id = (
                            approved.payload.get("approval_id")
                            if isinstance(approved.payload, dict)
                            else None
                        )
                        if not isinstance(approval_id, str):
                            raise HTTPException(
                                status_code=409, detail="Human execution grant unavailable"
                            )
                        grant = (
                            await db.execute(
                                select(ApprovalRequestORM)
                                .where(
                                    ApprovalRequestORM.id == approval_id,
                                    ApprovalRequestORM.engagement_id == engagement_id,
                                    ApprovalRequestORM.task_id == approved.id,
                                    ApprovalRequestORM.status == "approved",
                                )
                                .with_for_update(read=True)
                            )
                        ).scalar_one_or_none()
                        if grant is None or not matches_pinned_payload(
                            grant.evidence, approved.payload
                        ):
                            raise HTTPException(
                                status_code=409, detail="Pinned human execution grant changed"
                            )

                    if not await _verify_signed_replay_dispatches(
                        memory,
                        engagement_id,
                        signed.version,
                        source,
                        target,
                    ):
                        raise HTTPException(
                            status_code=409,
                            detail="Original signed dual-identity dispatch receipts unavailable",
                        )

                    async def current_authority_check() -> bool:
                        try:
                            current = await guard_sql(db, engagement_id)
                            if (
                                current.version != signed.version
                                or current.authorization_id != signed.authorization_id
                                or current.policy_sha256 != signed.policy_sha256
                            ):
                                return False
                            for approved in (source, target, _task(parent_row)):
                                approval_id = (
                                    approved.payload.get("approval_id")
                                    if isinstance(approved.payload, dict)
                                    else None
                                )
                                if not isinstance(
                                    approval_id, str
                                ) or not await memory.is_task_approved(
                                    approved.id, engagement_id, approval_id
                                ):
                                    return False
                            persisted = await memory.assert_signed_authorization(
                                engagement_id, expected_version=signed.version
                            )
                            if (
                                persisted.version != signed.version
                                or persisted.authorization_id != signed.authorization_id
                            ):
                                return False

                            # Lock the exact PostgreSQL imported source and
                            # target sessions in THIS transaction. Browser
                            # token/cookie rotation uses UPDATE/UPSERT and
                            # cannot cross this signed-receipt commit fence.
                            # Redis/browser cache or a second unlocked DB
                            # lookup cannot authorize historical evidence.
                            from ai_osop.auth.session_store import UserSessionORM
                            from ai_osop.core.authority_session_binding import (
                                reverify_replay_fingerprints,
                            )

                            session_store = getattr(orch, "session_store", None)
                            if getattr(session_store, "sm", None) is not memory or not callable(
                                getattr(session_store, "_orm_to_dto", None)
                            ):
                                return False
                            for observed in (source, target):
                                user_label = observed.payload.get("user_label")
                                if not isinstance(user_label, str):
                                    return False
                                row = (
                                    await db.execute(
                                        select(UserSessionORM)
                                        .where(
                                            UserSessionORM.pk == f"{engagement_id}:{user_label}",
                                            UserSessionORM.engagement_id == engagement_id,
                                            UserSessionORM.user_label == user_label,
                                        )
                                        .with_for_update(read=True)
                                    )
                                ).scalar_one_or_none()
                                if row is None:
                                    return False
                                imported = session_store._orm_to_dto(row, session_store._encryption)
                                reverify_replay_fingerprints(
                                    observed.payload,
                                    imported,
                                    engagement_id=engagement_id,
                                    user_label=user_label,
                                    method="GET",
                                    url=observed.payload["url"],
                                    task_id=observed.id,
                                    parent_task_id=observed.parent_task_id,
                                )
                            return True
                        except Exception:
                            return False

                    stored = None
                    if existing_proof_sha256 is not None:
                        from ai_osop.memory.target_authority_receipts import (
                            PersistedTargetAuthorityReceiptGuard,
                        )

                        stored = (
                            (
                                await db.execute(
                                    text(
                                        "SELECT engagement_id,flow_id,original_source_task_id,"
                                        "source_task_id,target_task_id,key_id,authorization_version,"
                                        "flow_revision,proof_sha256,audit_corroboration_sha256,"
                                        "target_claims_json,target_signature_b64url,"
                                        "ownership_audit_json,ownership_audit_signature,"
                                        "access_audit_json,access_audit_signature,"
                                        "proof_received_at_epoch FROM target_authority_assertions "
                                        "WHERE engagement_id=:eng AND flow_id=:fid AND proof_sha256=:sha "
                                        "FOR SHARE"
                                    ),
                                    {
                                        "eng": engagement_id,
                                        "fid": flow_id,
                                        "sha": existing_proof_sha256,
                                    },
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if (
                            stored is None
                            or stored["original_source_task_id"] != original.id
                            or stored["source_task_id"] != source.id
                            or stored["target_task_id"] != target.id
                            or stored["authorization_version"] != signed.version
                            or stored["flow_revision"] != flow.revision
                            or type(stored["target_claims_json"]) is not bytes
                            or not hmac.compare_digest(
                                stored["target_claims_json"], payload.claims_json.encode("utf-8")
                            )
                            or stored["target_signature_b64url"] != payload.signature_b64url
                        ):
                            raise HTTPException(
                                status_code=409,
                                detail="Original immutable signed source unavailable",
                            )
                        guard = PersistedTargetAuthorityReceiptGuard(
                            db,
                            existing_proof_sha256,
                            proof_received_at_epoch=stored["proof_received_at_epoch"],
                        )
                    else:
                        guard = TargetAuthorityReplayGuard(db)

                    verdict = await verify_target_authority_proof(
                        claims_json=payload.claims_json.encode("utf-8"),
                        signature_b64url=payload.signature_b64url,
                        engagement_id=engagement_id,
                        flow=flow,
                        signed_authorization=signed,
                        original_source_task=original,
                        source_task=source,
                        target_task=target,
                        owner_sub=owner,
                        replay_guard=guard,
                        current_authority_check=current_authority_check,
                    )
                    audit_parts = (
                        payload.ownership_audit_json,
                        payload.ownership_audit_signature,
                        payload.access_audit_json,
                        payload.access_audit_signature,
                    )
                    if any(value is not None for value in audit_parts) and not all(
                        value is not None for value in audit_parts
                    ):
                        raise HTTPException(
                            status_code=409, detail="Complete independent audit pair required"
                        )
                    audit_sha256 = None
                    if all(value is not None for value in audit_parts):
                        from ai_osop.core.target_authority_corroboration import (
                            TargetAuditUnverified,
                            corroborate_target_audits,
                        )

                        try:
                            audit = corroborate_target_audits(
                                target_claims_json=payload.claims_json.encode("utf-8"),
                                target_proof_sha256=verdict.proof_sha256,
                                ownership_json=payload.ownership_audit_json.encode("utf-8"),
                                ownership_signature=payload.ownership_audit_signature,
                                access_json=payload.access_audit_json.encode("utf-8"),
                                access_signature=payload.access_audit_signature,
                                trusted_receipt_epoch=(
                                    stored["proof_received_at_epoch"]
                                    if stored is not None
                                    else None
                                ),
                            )
                        except TargetAuditUnverified as exc:
                            raise HTTPException(
                                status_code=409, detail="Independent target audit unverified"
                            ) from exc
                        audit_sha256 = audit.audit_sha256
                    if stored is not None:
                        if (
                            stored["proof_sha256"] != verdict.proof_sha256
                            or stored["key_id"] != verdict.key_id
                            or stored["audit_corroboration_sha256"] != audit_sha256
                            or stored["ownership_audit_json"]
                            != (
                                payload.ownership_audit_json.encode("utf-8")
                                if payload.ownership_audit_json is not None
                                else None
                            )
                            or stored["ownership_audit_signature"]
                            != payload.ownership_audit_signature
                            or stored["access_audit_json"]
                            != (
                                payload.access_audit_json.encode("utf-8")
                                if payload.access_audit_json is not None
                                else None
                            )
                            or stored["access_audit_signature"] != payload.access_audit_signature
                        ):
                            raise HTTPException(
                                status_code=409, detail="Immutable independent audit record changed"
                            )
                        await current_senior_check()
                        # Read-back review uses an independent PostgreSQL
                        # source inspector under the same signed-authority
                        # transaction, never a graph/provider review flag.
                        from ai_osop.memory.target_finding_evidence import (
                            inspect_target_finding_evidence,
                        )

                        async def trusted_source_recheck() -> bool:
                            return bool(
                                await current_authority_check()
                                and await _verify_signed_replay_dispatches(
                                    memory, engagement_id, signed.version, source, target
                                )
                            )

                        inspection = await inspect_target_finding_evidence(
                            db,
                            engagement_id=engagement_id,
                            flow_id=flow_id,
                            original_source_task_id=original.id,
                            source_task_id=source.id,
                            target_task_id=target.id,
                            proof_sha256=verdict.proof_sha256,
                            audit_sha256=audit_sha256 or "",
                            authorization_version=signed.version,
                            flow_revision=flow.revision,
                            trusted_current_verifier=trusted_source_recheck,
                        )
                        # The inspector may await multiple signed-source and
                        # nonce reads. Keep the human release reviewer current
                        # after the final awaited verification, too.
                        await current_senior_check()
                        response.headers["Cache-Control"] = "private, no-store"
                        response.headers["X-Content-Type-Options"] = "nosniff"
                        return {
                            "status": "target_assertion_reverified_candidate_only",
                            **asdict(verdict),
                            "independent_audit_records_correlated": audit_sha256 is not None,
                            "finding_verified": False,
                            "report_release_approved": False,
                            "durable_source_review_status": inspection["status"],
                        }
                    # Authenticated audit corroboration is still candidate
                    # evidence, never an automatic vulnerability promotion.
                    await current_senior_check()
                    await db.execute(
                        text(
                            "INSERT INTO target_authority_assertions "
                            "(id,engagement_id,flow_id,original_source_task_id,source_task_id,"
                            "target_task_id,key_id,authorization_version,flow_revision,proof_sha256,"
                            "audit_corroboration_sha256,target_claims_json,target_signature_b64url,"
                            "ownership_audit_json,ownership_audit_signature,access_audit_json,"
                            "access_audit_signature,proof_received_at_epoch) "
                            "VALUES (:id,:eng,:fid,:original,:source,:target,:key,:ver,:rev,:sha,"
                            ":audit_sha,:claims,:signature,:ownership,:ownership_sig,:access,:access_sig,"
                            "CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT))"
                        ),
                        {
                            "id": "tproof-" + verdict.proof_sha256[:32],
                            "eng": engagement_id,
                            "fid": flow.id,
                            "original": original.id,
                            "source": source.id,
                            "target": target.id,
                            "key": verdict.key_id,
                            "ver": signed.version,
                            "rev": flow.revision,
                            "sha": verdict.proof_sha256,
                            "audit_sha": audit_sha256,
                            "claims": payload.claims_json.encode("utf-8"),
                            "signature": payload.signature_b64url,
                            "ownership": (
                                payload.ownership_audit_json.encode("utf-8")
                                if payload.ownership_audit_json is not None
                                else None
                            ),
                            "ownership_sig": payload.ownership_audit_signature,
                            "access": (
                                payload.access_audit_json.encode("utf-8")
                                if payload.access_audit_json is not None
                                else None
                            ),
                            "access_sig": payload.access_audit_signature,
                        },
                    )
        response.headers["Cache-Control"] = "private, no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return {
            "status": "target_assertion_admitted_candidate_only",
            **asdict(verdict),
            "independent_audit_records_correlated": audit_sha256 is not None,
            "finding_verified": False,
            "report_release_approved": False,
        }
    except HTTPException:
        raise
    except TargetAuthorityDenied as exc:
        raise HTTPException(status_code=409, detail="Target authority evidence unverified") from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Target authority admission unavailable"
        ) from exc
