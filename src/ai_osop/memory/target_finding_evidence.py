"""Read-only PostgreSQL inspection of archived target-signed *candidate* evidence.

This is deliberately not a finding verifier or report-release authority. The
caller owns an open PostgreSQL transaction, an authenticated tenant/owner
decision, and a trusted current-state verifier that independently checks live
approvals, signed dispatch receipts and imported identity/session provenance.
Do not construct that verifier from a model or an HTTP/provider response.
"""

from __future__ import annotations

import hmac
import re
from typing import Any, Awaitable, Callable, Dict, Optional

from sqlalchemy import select, text

from ai_osop.core.models import FlowRecord, Task
from ai_osop.core.target_authority_corroboration import corroborate_target_audits
from ai_osop.core.target_authority_proof import verify_target_authority_proof
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    ExecutionFlowORM,
    TaskORM,
)
from ai_osop.memory.target_authority_receipts import PersistedTargetAuthorityReceiptGuard
from ai_osop.safety.approval_binding import matches_pinned_payload

_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,59}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._-]{1,58}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SIG = re.compile(r"[A-Za-z0-9_-]{86}\Z")

_READ_ASSERTION = text(
    "SELECT id, engagement_id, flow_id, original_source_task_id, "
    "source_task_id, target_task_id, key_id, authorization_version, "
    "flow_revision, proof_sha256, audit_corroboration_sha256, "
    "target_claims_json, target_signature_b64url, "
    "ownership_audit_json, ownership_audit_signature, "
    "access_audit_json, access_audit_signature, proof_received_at_epoch "
    "FROM target_authority_assertions "
    "WHERE engagement_id=:eng AND flow_id=:flow AND "
    "original_source_task_id=:original AND source_task_id=:source "
    "AND target_task_id=:target AND proof_sha256=:proof FOR SHARE"
)
_READ_OWNER = text("SELECT created_by FROM session_states WHERE session_id=:eng FOR SHARE")


def _verdict(
    status: str,
    engagement_id: str,
    flow_id: str,
    proof_sha256: str,
    audit_sha256: str,
    authorization_version: int,
    flow_revision: int,
) -> Dict[str, Any]:
    """Return metadata alone; never return signed bytes, body, or a true finding flag."""
    return {
        "status": status,
        "engagement_id": (
            engagement_id if type(engagement_id) is str and _ENG.fullmatch(engagement_id) else None
        ),
        "flow_id": (flow_id if type(flow_id) is str and _FLOW.fullmatch(flow_id) else None),
        "proof_sha256": (
            proof_sha256 if type(proof_sha256) is str and _SHA.fullmatch(proof_sha256) else None
        ),
        "audit_corroboration_sha256": (
            audit_sha256 if type(audit_sha256) is str and _SHA.fullmatch(audit_sha256) else None
        ),
        "authorization_version": (
            authorization_version
            if type(authorization_version) is int and authorization_version > 0
            else None
        ),
        "flow_revision": (
            flow_revision if type(flow_revision) is int and flow_revision >= 0 else None
        ),
        "finding_verified": False,
        "authorization_violation_verified": False,
        "report_release_approved": False,
        "finding_release_eligible": False,
    }


def _valid_inputs(
    engagement_id: Any,
    flow_id: Any,
    original_source_task_id: Any,
    source_task_id: Any,
    target_task_id: Any,
    proof_sha256: Any,
    audit_sha256: Any,
    authorization_version: Any,
    flow_revision: Any,
) -> bool:
    return (
        type(engagement_id) is str
        and _ENG.fullmatch(engagement_id) is not None
        and type(flow_id) is str
        and _FLOW.fullmatch(flow_id) is not None
        and all(
            type(value) is str and _TASK.fullmatch(value) is not None
            for value in (original_source_task_id, source_task_id, target_task_id)
        )
        and len({original_source_task_id, source_task_id, target_task_id}) == 3
        and type(proof_sha256) is str
        and _SHA.fullmatch(proof_sha256) is not None
        and type(audit_sha256) is str
        and _SHA.fullmatch(audit_sha256) is not None
        and type(authorization_version) is int
        and authorization_version > 0
        and type(flow_revision) is int
        and flow_revision >= 0
    )


async def inspect_target_finding_evidence(
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
    trusted_current_verifier: Optional[Callable[[], Awaitable[bool]]] = None,
) -> Dict[str, Any]:
    """Inspect an EXACT immutable signed receipt inside a caller-owned PG transaction.

    Holds PostgreSQL SHARE locks on ROE, Flow, source Tasks, grants and the
    assertion until the caller commits/rolls back. The trusted callback MUST
    recheck signed dispatch receipts, approval revocation and imported identity
    fingerprints against current PostgreSQL records in this transaction. Without
    it (or when any archived source is incomplete) the answer is UNKNOWN.
    Successful detached Ed25519 re-verification only yields `candidate_only`.

    The caller must authenticate and authorize the human before using this
    service. No transaction is created, no target request is made, no write is
    issued, and no raw signed/body material enters the return value.
    """
    unknown = _verdict(
        "UNKNOWN",
        engagement_id,
        flow_id,
        proof_sha256,
        audit_sha256,
        authorization_version,
        flow_revision,
    )
    if not _valid_inputs(
        engagement_id,
        flow_id,
        original_source_task_id,
        source_task_id,
        target_task_id,
        proof_sha256,
        audit_sha256,
        authorization_version,
        flow_revision,
    ):
        return unknown
    # Refuse execution outside a transaction: FOR SHARE only fences concurrent
    # revocation while the same PostgreSQL transaction remains open.
    if (
        db is None
        or not callable(getattr(db, "execute", None))
        or not callable(getattr(db, "in_transaction", None))
        or db.in_transaction() is not True
    ):
        return unknown

    try:
        signed = await guard_sql(db, engagement_id, expected_version=authorization_version)
        owner = (await db.execute(_READ_OWNER, {"eng": engagement_id})).scalar_one_or_none()
        if (
            type(owner) is not str
            or not owner
            or signed.session_id != engagement_id
            or signed.version != authorization_version
            or signed.policy.get("created_by") != owner
        ):
            return unknown

        args = {
            "eng": engagement_id,
            "flow": flow_id,
            "original": original_source_task_id,
            "source": source_task_id,
            "target": target_task_id,
            "proof": proof_sha256,
        }
        stored = (await db.execute(_READ_ASSERTION, args)).mappings().one_or_none()
        if stored is None or any(
            stored.get(field) != value
            for field, value in {
                "id": "tproof-" + proof_sha256[:32],
                "engagement_id": engagement_id,
                "flow_id": flow_id,
                "original_source_task_id": original_source_task_id,
                "source_task_id": source_task_id,
                "target_task_id": target_task_id,
                "proof_sha256": proof_sha256,
                "audit_corroboration_sha256": audit_sha256,
                "authorization_version": authorization_version,
                "flow_revision": flow_revision,
            }.items()
        ):
            return unknown
        if (
            type(stored.get("key_id")) is not str
            or not stored["key_id"]
            or type(stored.get("proof_received_at_epoch")) is not int
            or stored["proof_received_at_epoch"] < 1
            or type(stored.get("target_claims_json")) is not bytes
            or not 1 <= len(stored["target_claims_json"]) <= 4096
            or type(stored.get("target_signature_b64url")) is not str
            or _SIG.fullmatch(stored["target_signature_b64url"]) is None
            or any(
                type(stored.get(k)) is not bytes or not 1 <= len(stored[k]) <= 4096
                for k in ("ownership_audit_json", "access_audit_json")
            )
            or any(
                type(stored.get(k)) is not str or _SIG.fullmatch(stored[k]) is None
                for k in ("ownership_audit_signature", "access_audit_signature")
            )
        ):
            return unknown

        flow_row = (
            await db.execute(
                select(ExecutionFlowORM)
                .where(
                    ExecutionFlowORM.id == flow_id, ExecutionFlowORM.engagement_id == engagement_id
                )
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        if (
            flow_row is None
            or flow_row.status not in {"pending", "running"}
            or type(flow_row.revision) is not int
            or flow_row.revision != flow_revision
        ):
            return unknown
        flow = FlowRecord(**{key: getattr(flow_row, key) for key in FlowRecord.model_fields})
        selected = (
            (
                await db.execute(
                    select(TaskORM)
                    .where(
                        TaskORM.id.in_((original_source_task_id, source_task_id, target_task_id)),
                        TaskORM.engagement_id == engagement_id,
                    )
                    .with_for_update(read=True)
                )
            )
            .scalars()
            .all()
        )
        if len(selected) != 3 or {t.id for t in selected} != {
            original_source_task_id,
            source_task_id,
            target_task_id,
        }:
            return unknown
        tasks = {
            row.id: Task(
                **{key: getattr(row, key) for key in Task.model_fields if key != "trace_context"}
            )
            for row in selected
        }
        original, source, target = (
            tasks[original_source_task_id],
            tasks[source_task_id],
            tasks[target_task_id],
        )
        if (
            source.parent_task_id is None
            or source.parent_task_id != target.parent_task_id
            or source.parent_task_id == original.id
            or source.parent_task_id in {source.id, target.id}
        ):
            return unknown
        parent_row = (
            await db.execute(
                select(TaskORM)
                .where(TaskORM.id == source.parent_task_id, TaskORM.engagement_id == engagement_id)
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        if (
            parent_row is None
            or parent_row.type != "replay_for_diff_auth"
            or parent_row.parent_task_id != original.id
            or parent_row.flow_id != flow_id
            or parent_row.status != "completed"
            or parent_row.approval_required is not True
        ):
            return unknown
        parent = Task(
            **{key: getattr(parent_row, key) for key in Task.model_fields if key != "trace_context"}
        )
        for task in (source, target, parent):
            approval_id = task.payload.get("approval_id") if type(task.payload) is dict else None
            if type(approval_id) is not str or not approval_id:
                return unknown
            grant = (
                await db.execute(
                    select(ApprovalRequestORM)
                    .where(
                        ApprovalRequestORM.id == approval_id,
                        ApprovalRequestORM.engagement_id == engagement_id,
                        ApprovalRequestORM.task_id == task.id,
                        ApprovalRequestORM.status == "approved",
                    )
                    .with_for_update(read=True)
                )
            ).scalar_one_or_none()
            if grant is None or not matches_pinned_payload(grant.evidence, task.payload):
                return unknown

        # Existing trusted verifier is deliberately optional; no callback
        # means no credible current session/dispatch recheck, hence UNKNOWN.
        if not callable(trusted_current_verifier):
            return unknown
        receipt = PersistedTargetAuthorityReceiptGuard(
            db,
            proof_sha256,
            proof_received_at_epoch=stored["proof_received_at_epoch"],
        )
        proof = await verify_target_authority_proof(
            claims_json=stored["target_claims_json"],
            signature_b64url=stored["target_signature_b64url"],
            engagement_id=engagement_id,
            flow=flow,
            signed_authorization=signed,
            original_source_task=original,
            source_task=source,
            target_task=target,
            owner_sub=owner,
            replay_guard=receipt,
            current_authority_check=trusted_current_verifier,
        )
        if (
            proof.proof_sha256 != proof_sha256
            or proof.key_id != stored["key_id"]
            or proof.engagement_id != engagement_id
            or proof.flow_id != flow_id
            or proof.source_task_id != source_task_id
            or proof.target_task_id != target_task_id
        ):
            return unknown
        audit = corroborate_target_audits(
            target_claims_json=stored["target_claims_json"],
            target_proof_sha256=proof_sha256,
            ownership_json=stored["ownership_audit_json"],
            ownership_signature=stored["ownership_audit_signature"],
            access_json=stored["access_audit_json"],
            access_signature=stored["access_audit_signature"],
            trusted_receipt_epoch=stored["proof_received_at_epoch"],
        )
        if (
            not hmac.compare_digest(audit.audit_sha256, audit_sha256)
            or audit.proof_sha256 != proof_sha256
            or audit.engagement_id != engagement_id
            or audit.flow_id != flow_id
            or audit.source_task_id != source_task_id
            or audit.target_task_id != target_task_id
        ):
            return unknown
        candidate = _verdict(
            "candidate_only",
            engagement_id,
            flow_id,
            proof_sha256,
            audit_sha256,
            authorization_version,
            flow_revision,
        )
        candidate.update(
            {
                "original_source_task_id": original_source_task_id,
                "source_task_id": source_task_id,
                "target_task_id": target_task_id,
            }
        )
        return candidate
    except Exception:
        # Missing schema, revoked ROE, bad signature, broken trust store, DB
        # outage or inconsistent sources all produce the same closed result.
        return unknown
