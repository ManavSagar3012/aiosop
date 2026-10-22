"""Read-only, durable owner-scoped access to signed report attestations.

NOT the unsigned /engagements/{id}/report endpoint. Report contents and raw
evidence are never returned. Clients receive a verifiable Ed25519 envelope,
signed artifact hashes and an explicit accounting of verification boundaries.
"""

import asyncio
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from sqlalchemy import select, text

from ai_osop.api.deps import _oidc_config, state, verify_token
from ai_osop.core.config import settings
from ai_osop.core.models import Task
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql
from ai_osop.orchestrator.context_compaction import (
    source_sha256,
    task_assignment_sha256,
)
from ai_osop.reporting.attestation import (
    ARTIFACT_ALLOWLIST,
    ReportAttestationError,
    SCHEMA_V3,
    _unique_object_pairs,
)
from ai_osop.safety.approval_binding import task_payload_sha256
from ai_osop.reporting.attested_storage import (
    AttestedStorageUnavailable,
    load_attested_bundle,
    validated_report_id,
    verify_loaded_bundle,
)
from ai_osop.memory.supervision_store import (
    SupervisionConflict,
    SupervisionEventORM,
    SupervisionStore,
    _safe_payload,
)

router = APIRouter(prefix="/engagements", tags=["signed-report-attestations"])
_FINDING_ID = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")
_SOURCE_ID = re.compile(r"task-[A-Za-z0-9._-]{1,78}\Z")
_EVENT_ID = re.compile(r"evt-[A-Za-z0-9._-]{1,60}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_BINDING_FIELDS = (
    "source_task_id",
    "source_task_sha256",
    "flow_id",
    "flow_revision",
    "authorization_version",
    "authorization_sha256",
    "source_event_id",
    "provider_receipt_sha256",
)
_REPORT_TIMEOUT_SECONDS = 5.0
_UNSUPPORTED_TARGET_AUTHORITY_CLAIMS = frozenset(
    {
        "independent_target_authority_verified",
        "target_authority_verified",
        "target_effect_verified",
        "independent_target_effect_verified",
        "authorization_violation_verified",
        "exploit_success_verified",
        "source_authenticity_verified",
        "vulnerability_verified",
        "comparison_verified",
        "independently_validated",
        "certified",
        "validated",
    }
)
_COMPARISON_SOURCE_TYPES = frozenset(
    {
        "replay_for_diff_auth",
        "signed_diff_auth_compare",
        "signed_diff_comparison",
        "diff_auth_compare",
        "navigate",
    }
)
_COMPARISON_OUTCOMES = frozenset(
    {
        "candidate_review",
        "candidate_needs_independent_review",
        "expected_denial",
        "expected_denial_observed",
        "inconclusive",
        "unknown",
        "UNKNOWN",
        "unconfirmed",
    }
)


def _refuse_unsupported_target_promotion(loaded: Dict[str, Any]) -> None:
    """Check signed artifact claims without interpreting legacy enums as proof.

    Historical verified_findings_only describes a graph flag, not an
    independent target-verification verdict. It cannot authorize release.
    """
    try:
        artifacts = loaded["artifacts"]
        report = json.loads(
            artifacts["json"].decode("utf-8"),
            object_pairs_hook=_unique_object_pairs,
        )
        if not isinstance(report, dict):
            raise ValueError()
        findings = report["findings"]
        if not isinstance(findings, list) or len(findings) > 200:
            raise ValueError()
        # Follow nested claims as well: a signed report may embed a summary
        # inside findings, such as details.independent_target_effect_verified.
        # A top-level check alone can be bypassed with an additional dict.
        nodes = [(report, 0)]
        visited = 0
        while nodes:
            item, depth = nodes.pop()
            visited += 1
            if visited > 8192 or depth > 12:
                raise ValueError()
            if isinstance(item, dict):
                if (
                    len(item) > 256
                    or any(item.get(name) is True for name in _UNSUPPORTED_TARGET_AUTHORITY_CLAIMS)
                    or item.get("source_provenance_status")
                    not in {
                        None,
                        "UNKNOWN_graph_flag_only",
                        "UNKNOWN_signed_comparison_candidate",
                    }
                ):
                    raise ValueError()
                nodes.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                if len(item) > 512:
                    raise ValueError()
                nodes.extend((value, depth + 1) for value in item)
        for extension in ("md", "html"):
            body = artifacts[extension]
            if not isinstance(body, bytes) or len(body) > 4 * 1024 * 1024:
                raise ValueError()
            if findings and (
                b"## Verified Vulnerabilities" in body
                or b"<h2>Verified Vulnerabilities</h2>" in body
            ):
                raise ValueError()
    except Exception as exc:
        raise AttestedStorageUnavailable(
            "Report asserts target verification without independent evidence"
        ) from exc


def _independent_target_authority_available(
    memory: Any,
    engagement_id: str,
    source: Task,
    finding_id: str,
    evidence_sha256: str,
) -> bool:
    """Fail closed until an independent target-authority verifier exists.

    No such verifier is currently implemented in SessionMemory. Source Task
    result flags, Neo4j validation and signed MCP events all originate in the
    same provider trust boundary and cannot supply independent target proof.
    """
    return False


async def _live_independent_target_authority_for_release(
    db: Any,
    orch: Any,
    *,
    engagement_id: str,
    report_id: str,
    flow_id: str,
    flow_revision: int,
    finding_id: str,
    evidence_sha256: str,
    signed: Any,
    operator: Dict[str, Any],
) -> bool:
    """Reverify 0022's original owner/access signatures, never its DB flag.

    An independently stored VERIFIED row is a *locator*, not a trust root.
    The signed report's original finding evidence and exact Flow binding must
    match the immutable row, and the separately configured LIVE owner/access
    signer, approved source/target/anonymous Tasks, original MCP signatures,
    human reviewer, ROE and report bytes are freshly rechecked under this
    caller-owned release transaction. If any mechanism is unavailable, deny.
    """
    try:
        from ai_osop.api.routers.target_authority import _verify_signed_replay_dispatches
        from ai_osop.api.routers.verified_finding_reviews import (
            _independent_report_source_check,
        )
        from ai_osop.auth.session_store import UserSessionORM
        from ai_osop.core.authority_session_binding import reverify_replay_fingerprints
        from ai_osop.memory.independent_target_effect_verifications import (
            read_independent_target_effect_verification,
        )
        from ai_osop.memory.session_memory import TaskORM

        memory = getattr(orch, "session_memory", None)
        session_store = getattr(orch, "session_store", None)
        reviewer = operator.get("sub")
        token_sha = operator.get("_reviewer_token_sha256")
        token_expiry = operator.get("_reviewer_expires_at")
        if (
            operator.get("role") != "senior_operator"
            or not isinstance(reviewer, str)
            or not isinstance(token_sha, str)
            or _SHA.fullmatch(token_sha) is None
            or type(token_expiry) is not int
            or token_expiry <= int(datetime.now(timezone.utc).timestamp())
            or getattr(session_store, "sm", None) is not memory
            or not callable(getattr(memory, "verify_signed_graph_action", None))
            or not callable(getattr(session_store, "_orm_to_dto", None))
            or not callable(getattr(db, "in_transaction", None))
            or db.in_transaction() is not True
            or not isinstance(flow_id, str)
            or re.fullmatch(r"flow-[A-Za-z0-9._-]{1,59}", flow_id) is None
            or type(flow_revision) is not int
            or not isinstance(evidence_sha256, str)
            or _SHA.fullmatch(evidence_sha256) is None
        ):
            return False

        row = (
            (
                await db.execute(
                    text(
                        "SELECT * FROM independent_target_effect_verifications "
                        "WHERE engagement_id=:eng AND flow_id=:flow "
                        "AND finding_id=:finding FOR SHARE"
                    ),
                    {"eng": engagement_id, "flow": flow_id, "finding": finding_id},
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
            or row.get("report_source_evidence_sha256") != evidence_sha256
            or row.get("authorization_version") != signed.version
            or row.get("authorization_sha256") != signed.policy_sha256
            or row.get("authorization_id") != signed.authorization_id
            or row.get("flow_revision") != flow_revision
            or row.get("senior_reviewer_sub") != reviewer
            or row.get("report_release_approved") is not False
            or row.get("independent_effect_verified") is not True
            or row.get("finding_verified") is not True
            or row.get("status") != "VERIFIED"
            or not isinstance(row.get("verdict_sha256"), str)
            or _SHA.fullmatch(row["verdict_sha256"]) is None
        ):
            return False

        task_ids = (row.get("source_task_id"), row.get("target_task_id"))
        if (
            any(
                not isinstance(task_id, str) or _SOURCE_ID.fullmatch(task_id) is None
                for task_id in task_ids
            )
            or task_ids[0] == task_ids[1]
        ):
            return False

        async def current_dispatch_and_session() -> bool:
            try:
                current = await guard_sql(
                    db,
                    engagement_id,
                    expected_version=signed.version,
                )
                if (
                    current.authorization_id != signed.authorization_id
                    or current.policy_sha256 != signed.policy_sha256
                ):
                    return False
                rows = (
                    (
                        await db.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.engagement_id == engagement_id,
                                TaskORM.flow_id == flow_id,
                                TaskORM.id.in_(task_ids),
                            )
                            .with_for_update(read=True)
                        )
                    )
                    .scalars()
                    .all()
                )
                if len(rows) != 2:
                    return False
                tasks = {
                    entry.id: Task(
                        **{
                            field: getattr(entry, field)
                            for field in Task.model_fields
                            if field != "trace_context"
                        }
                    )
                    for entry in rows
                }
                source, target = tasks.get(task_ids[0]), tasks.get(task_ids[1])
                if (
                    not isinstance(source, Task)
                    or not isinstance(target, Task)
                    or any(
                        task.engagement_id != engagement_id
                        or task.flow_id != flow_id
                        or task.type != "navigate"
                        or task.status != "completed"
                        or task.approval_required is not True
                        or task.max_retries != 0
                        or not isinstance(task.payload, dict)
                        or task.payload.get("_flow_revision") != flow_revision
                        or task.payload.get("_authorization_version") != signed.version
                        for task in (source, target)
                    )
                    or not isinstance(source.parent_task_id, str)
                    or source.parent_task_id != target.parent_task_id
                    or source.parent_task_id in {source.id, target.id}
                    or source.payload.get("_comparison_role") != "source"
                    or target.payload.get("_comparison_role") != "target"
                    or source.payload.get("user_label") == target.payload.get("user_label")
                    or not await _verify_signed_replay_dispatches(
                        memory,
                        engagement_id,
                        signed.version,
                        source,
                        target,
                    )
                ):
                    return False
                for task in (source, target):
                    label = task.payload.get("user_label")
                    if not isinstance(label, str):
                        return False
                    imported_row = (
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
                    if imported_row is None:
                        return False
                    imported = session_store._orm_to_dto(
                        imported_row,
                        session_store._encryption,
                    )
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

        async def current_report_source(fid: str, digest: str) -> bool:
            return bool(
                fid == finding_id
                and digest == evidence_sha256
                and await _independent_report_source_check(
                    db,
                    orch,
                    memory,
                    engagement_id=engagement_id,
                    flow_id=flow_id,
                    flow_revision=flow_revision,
                    report_id=report_id,
                    signed=signed,
                    finding_id=fid,
                    evidence_sha256=digest,
                )
            )

        async def current_anonymous_signed_dispatch(
            observed_eng: str,
            task_id: str,
            event_id: str,
            receipt_sha: str,
            version: int,
        ) -> bool:
            if observed_eng != engagement_id or version != signed.version:
                return False
            try:
                return (
                    await memory.verify_signed_graph_action(
                        engagement_id,
                        task_id,
                        event_id,
                        receipt_sha,
                        version,
                    )
                ) is True
            except Exception:
                return False

        observed = await read_independent_target_effect_verification(
            db,
            engagement_id=engagement_id,
            flow_id=flow_id,
            finding_id=finding_id,
            evidence_sha256=row["verdict_sha256"],
            authorization_version=signed.version,
            reviewer_sub=reviewer,
            reviewer_role="senior_operator",
            reviewer_token_sha256=token_sha,
            reviewer_expires_at=token_expiry,
            trusted_current_verifier=current_dispatch_and_session,
            trusted_report_source_check=current_report_source,
            trusted_anonymous_signed_dispatch_check=current_anonymous_signed_dispatch,
        )
        return bool(
            observed.get("status") == "VERIFIED"
            and observed.get("finding_verified") is True
            and observed.get("independent_effect_verified") is True
            and observed.get("verification_sha256") == row["verdict_sha256"]
            and observed.get("report_source_evidence_sha256") == evidence_sha256
            and observed.get("report_release_approved") is False
            and observed.get("finding_release_eligible") is False
        )
    except Exception:
        # No module, expired witnesses, missing externally operated keys,
        # rotated session or malicious DB row can mint human release authority.
        return False


class FinalReportSignoff(BaseModel):
    """Human release decision, not a provider assertion or report signature."""

    model_config = ConfigDict(extra="forbid", strict=True)
    expected_authorization_version: StrictInt = Field(ge=1)
    expected_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=20, max_length=256)
    approval_statement: str = Field(
        pattern=r"^I approve releasing this exact signed report snapshot$"
    )


async def _verify_generation_release(
    db: Any,
    *,
    session_id: str,
    report_id: str,
    loaded: Dict[str, Any],
    current_authorization: Any,
) -> None:
    """Bind a verified v2 signature to its current signed ROE and terminal Task.

    The report is still a draft: this confirms only the report-generation
    task's durable successful outcome. No task or model result certifies final
    operator sign-off, remote exploitation, or engagement completeness.
    """
    envelope = loaded["attestation"]["attestation"]
    binding = envelope["generation_binding"]
    if (
        type(getattr(current_authorization, "version", None)) is not int
        or current_authorization.version != binding["authorization_version"]
        or not isinstance(getattr(current_authorization, "policy_sha256", None), str)
        or not hmac.compare_digest(
            current_authorization.policy_sha256, binding["authorization_sha256"]
        )
    ):
        raise AttestedStorageUnavailable("Report signed authorization version changed")

    # Lock this exact tenant-bound Task through bundle verification; a
    # competing replica's running/unknown/terminal transition cannot be
    # mistaken for a committed successful report generation.
    task_row = (
        (
            await db.execute(
                text(
                    "SELECT id, engagement_id, type, agent_type, status, payload, "
                    "result, started_at, completed_at, flow_id, subtask_id, "
                    "approval_required FROM tasks "
                    "WHERE id = :task AND engagement_id = :sid FOR SHARE"
                ),
                {"task": binding["task_id"], "sid": session_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        task_row is None
        or task_row["id"] != binding["task_id"]
        or task_row["engagement_id"] != session_id
        or task_row["type"] != "generate_report"
        or task_row["agent_type"] != "reporting"
        or task_row["status"] != "completed"
        or task_row.get("approval_required") is not True
        or task_row["started_at"] is None
        or task_row["completed_at"] is None
        or not isinstance(task_row["payload"], dict)
        or not isinstance(task_row["result"], dict)
    ):
        raise AttestedStorageUnavailable("Report generating task is unverified")
    payload = task_row["payload"]
    outcome = task_row["result"]
    if (
        type(payload.get("_authorization_version")) is not int
        or payload["_authorization_version"] != binding["authorization_version"]
        or payload.get("require_attestation") is not True
        or payload.get("signer_key_id") != envelope["signer_key_id"]
        or not isinstance(payload.get("version"), str)
        or report_id != f"report-{session_id}-{payload['version']}"
        or outcome.get("status") != "success"
        or outcome.get("signature_status") != "ed25519_signed"
        or outcome.get("report_id") != report_id
        or outcome.get("requires_approval") is not True
    ):
        raise AttestedStorageUnavailable("Report generating task binding mismatch")
    try:
        payload_digest = task_payload_sha256(payload)
    except ValueError as exc:
        raise AttestedStorageUnavailable("Report task payload cannot be verified") from exc
    if not hmac.compare_digest(payload_digest, binding["task_payload_sha256"]):
        raise AttestedStorageUnavailable("Report task payload binding changed")

    # Flow-backed generation must bind its original Flow and exact revision in
    # the detached signature. A legacy v2 report for a Flow Task cannot gain
    # a senior release merely because its Task later completed successfully.
    flow_id = task_row.get("flow_id")
    if flow_id is not None:
        if (
            envelope["schema"] != SCHEMA_V3
            or flow_id != binding.get("flow_id")
            or not isinstance(flow_id, str)
        ):
            raise AttestedStorageUnavailable("Report Task Flow binding is absent")
        flow = (
            (
                await db.execute(
                    text(
                        "SELECT id, engagement_id, status, revision "
                        "FROM execution_flows WHERE id=:flow AND engagement_id=:sid FOR SHARE"
                    ),
                    {"flow": flow_id, "sid": session_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            flow is None
            or flow["id"] != flow_id
            or flow["engagement_id"] != session_id
            or flow["status"] not in {"pending", "running"}
            or type(flow["revision"]) is not int
            or flow["revision"] != binding["flow_revision"]
        ):
            raise AttestedStorageUnavailable("Report Flow revoked, changed, or unavailable")
        subtask_id = task_row.get("subtask_id")
        if subtask_id is not None:
            step = (
                (
                    await db.execute(
                        text(
                            "SELECT id, engagement_id, flow_id, execution_task_id, status "
                            "FROM execution_subtasks "
                            "WHERE id=:step AND flow_id=:flow AND engagement_id=:sid FOR SHARE"
                        ),
                        {"step": subtask_id, "flow": flow_id, "sid": session_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if (
                step is None
                or step["id"] != subtask_id
                or step["flow_id"] != flow_id
                or step["engagement_id"] != session_id
                or step["execution_task_id"] != binding["task_id"]
                or step["status"] != "completed"
            ):
                raise AttestedStorageUnavailable("Report Flow subtask lineage changed")
    elif "flow_id" in binding:
        raise AttestedStorageUnavailable("Standalone report contains false Flow binding")

    result_hashes = outcome.get("artifact_sha256")
    expected_hashes = {
        **envelope["artifacts"],
        "attestation": loaded["attestation_sha256"],
        "manifest": loaded.get("manifest_sha256"),
    }
    if (
        not isinstance(result_hashes, dict)
        or set(result_hashes) != ARTIFACT_ALLOWLIST | {"attestation", "manifest"}
        or not all(
            isinstance(result_hashes[name], str)
            and isinstance(digest, str)
            and hmac.compare_digest(result_hashes[name], digest)
            for name, digest in expected_hashes.items()
        )
    ):
        raise AttestedStorageUnavailable("Report task artifact receipt is unverified")


async def _report_operator(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    if request.query_params or credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=403, detail="Authorization bearer header required")
    # A legacy shared API token cannot identify a human. Accept independently
    # signed, expiring operator identities from EITHER trusted local JWT
    # configuration or the fully pinned external OIDC issuer.
    if not settings.jwt_secret and _oidc_config() is None:
        raise HTTPException(status_code=503, detail="Operator JWT verification unavailable")
    operator = await verify_token(credentials=credentials, token=None)
    if operator.get("role") not in {"operator", "senior_operator"}:
        raise HTTPException(status_code=403, detail="Operator role required")
    if not isinstance(operator.get("sub"), str) or not operator["sub"].strip():
        raise HTTPException(status_code=403, detail="Verified operator identity required")
    claims = operator.get("claims")
    expiry = claims.get("exp") if isinstance(claims, dict) else None
    if type(expiry) is not int or expiry <= datetime.now(timezone.utc).timestamp():
        raise HTTPException(status_code=401, detail="Valid operator JWT expiry required")
    # Use the *same* current-session fingerprint as the separate senior
    # candidate-review endpoint. Never persist or expose raw bearer bytes.
    return {
        **operator,
        "_reviewer_token_sha256": hashlib.sha256(
            credentials.credentials.encode("utf-8")
        ).hexdigest(),
        "_reviewer_expires_at": expiry,
    }


async def _graph_evidence(
    graph: Any,
    engagement_id: str,
    loaded: Dict[str, Any],
    *,
    source_records: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    try:
        envelope = loaded["attestation"]
        source = envelope["attestation"]["evidence_provenance"]
        if not isinstance(source, list) or len(source) > 200:
            raise ValueError()
        ids = []
        for entry in source:
            identifier = entry["finding_id"]
            if not isinstance(identifier, str) or not _FINDING_ID.fullmatch(identifier):
                raise ValueError()
            ids.append(identifier)
        if len(set(ids)) != len(ids):
            raise ValueError()
        if graph is None or getattr(graph, "_driver", None) is None:
            raise ValueError()

        # Requery restricted, persisted evidence independently: report
        # fingerprints never authorize or supply raw evidence themselves.
        evidence = {}
        async with graph._driver.session() as db_session:
            result = await db_session.run(
                "MATCH (v:Vulnerability {engagement_id: $sid}) "
                "WHERE v.validated = true AND v.id IN $finding_ids "
                "RETURN v.id AS finding_id, v.evidence AS evidence, "
                "v.validated AS validated, v.source_task_id AS source_task_id, "
                "v.source_task_sha256 AS source_task_sha256, "
                "v.flow_id AS flow_id, v.flow_revision AS flow_revision, "
                "v.authorization_version AS authorization_version, "
                "v.authorization_sha256 AS authorization_sha256, "
                "v.source_event_id AS source_event_id, "
                "v.provider_receipt_sha256 AS provider_receipt_sha256 "
                "LIMIT $limit",
                sid=engagement_id,
                finding_ids=ids,
                limit=len(ids) + 1,
            )
            rows = await result.data()
        if not isinstance(rows, list) or len(rows) > len(ids):
            raise ValueError()
        for row in rows:
            if not isinstance(row, dict) or row.get("validated") is not True:
                raise ValueError()
            identifier = row.get("finding_id")
            if identifier not in ids or identifier in evidence:
                raise ValueError()
            value = row.get("evidence")
            if isinstance(value, str):
                # A nested duplicate field may be interpreted differently by
                # another verifier even though both hash a parsed JSON list.
                # Reject ambiguous raw graph evidence at release time.
                value = json.loads(value, object_pairs_hook=_unique_object_pairs)
            evidence[identifier] = value
            if source_records is not None:
                source_records[identifier] = {
                    name: row.get(name)
                    for name in (
                        "source_task_id",
                        "source_task_sha256",
                        "flow_id",
                        "flow_revision",
                        "authorization_version",
                        "authorization_sha256",
                        "source_event_id",
                        "provider_receipt_sha256",
                    )
                }
        if set(evidence) != set(ids):
            raise ValueError()
        return evidence
    except (KeyError, TypeError, ValueError, AttributeError, json.JSONDecodeError) as exc:
        raise AttestedStorageUnavailable("Independent report evidence unavailable") from exc


async def _verify_signed_finding_sources(
    orch: Any,
    engagement_id: str,
    loaded: Dict[str, Any],
    sources: Dict[str, Dict[str, Any]],
    signed: Any,
    *,
    db: Any = None,
    report_id: Optional[str] = None,
    operator: Optional[Dict[str, Any]] = None,
) -> None:
    """Gate *release*, not draft signing, on independently durable tool lineage.

    Neo4j's validated flag, an evidence digest and a human signoff do not
    authenticate a vulnerability source. An eligible release must also bind
    EVERY finding to a completed same-tenant PostgreSQL source Task whose
    result records the exact evidence snapshot hash, an active signed Flow,
    and a verified signed MCP completion event + dispatch. This attests only
    to the origin of a durable assertion, NOT to its target-side correctness.
    Historic/manual graph findings remain viewable as NON-CERTIFIED drafts.
    """
    try:
        provenance = loaded["attestation"]["attestation"]["evidence_provenance"]
        if not isinstance(provenance, list) or len(provenance) > 200:
            raise ValueError()
        if not provenance:
            return
        memory = getattr(orch, "session_memory", None)
        if not all(
            callable(getattr(memory, name, None))
            for name in (
                "load_task_authoritative",
                "load_flow",
                "verify_signed_graph_action",
            )
        ):
            raise ValueError()
        digest = getattr(signed, "policy_sha256", None)
        version = getattr(signed, "version", None)
        if (
            not isinstance(digest, str)
            or not _SHA.fullmatch(digest)
            or type(version) is not int
            or version < 1
        ):
            raise ValueError()
        if set(sources) != {p["finding_id"] for p in provenance}:
            raise ValueError()
        # Detached signature covers report JSON. Bind the *claimed* source
        # tuple to those signed bytes before independently proving it from
        # PostgreSQL, rather than trusting Neo4j fields added after signing.
        report_json = json.loads(
            loaded["artifacts"]["json"].decode("utf-8"),
            object_pairs_hook=_unique_object_pairs,
        )
        signed_findings = report_json["findings"]
        if (
            not isinstance(signed_findings, list)
            or len(signed_findings) != len(provenance)
            or any(not isinstance(f, dict) for f in signed_findings)
        ):
            raise ValueError()
        binding_by_id = {f.get("id"): f.get("source_binding") for f in signed_findings}
        if set(binding_by_id) != set(sources):
            raise ValueError()
        for item in provenance:
            ref = sources[item["finding_id"]]
            if binding_by_id[item["finding_id"]] != {
                key: ref.get(key) for key in _SOURCE_BINDING_FIELDS
            }:
                raise ValueError()
            task_id = ref.get("source_task_id")
            event_id = ref.get("source_event_id")
            receipt = ref.get("provider_receipt_sha256")
            flow_id = ref.get("flow_id")
            if (
                not isinstance(task_id, str)
                or not _SOURCE_ID.fullmatch(task_id)
                or not isinstance(event_id, str)
                or not _EVENT_ID.fullmatch(event_id)
                or not isinstance(receipt, str)
                or not _SHA.fullmatch(receipt)
                or not isinstance(flow_id, str)
                or not re.fullmatch(r"flow-[A-Za-z0-9._-]{1,78}", flow_id)
                or type(ref.get("flow_revision")) is not int
                or ref["flow_revision"] < 0
                or type(ref.get("authorization_version")) is not int
                or ref["authorization_version"] != version
                or ref.get("authorization_sha256") != digest
                or not isinstance(ref.get("source_task_sha256"), str)
                or not _SHA.fullmatch(ref["source_task_sha256"])
            ):
                raise ValueError()
            source = await memory.load_task_authoritative(task_id)
            flow = await memory.load_flow(flow_id)
            if (
                not isinstance(source, Task)
                or source.id != task_id
                or source.engagement_id != engagement_id
                or source.flow_id != flow_id
                or source.status != "completed"
                or not isinstance(source.payload, dict)
                or type(source.payload.get("_authorization_version")) is not int
                or source.payload["_authorization_version"] != version
                or not isinstance(source.result, dict)
                or source.result.get("status") not in {"success", "succeeded"}
                or source.result.get("evidence_sha256") != item["evidence_sha256"]
                or getattr(flow, "id", None) != flow_id
                or getattr(flow, "engagement_id", None) != engagement_id
                or getattr(flow, "status", None) not in {"pending", "running"}
                or type(getattr(flow, "revision", None)) is not int
                or flow.revision != ref["flow_revision"]
                or not hmac.compare_digest(
                    task_assignment_sha256(source),
                    ref["source_task_sha256"],
                )
            ):
                raise ValueError()
            if (
                source.type in _COMPARISON_SOURCE_TYPES
                or source.result.get("comparison_status") in _COMPARISON_OUTCOMES
                or source.result.get("comparison_outcome") in _COMPARISON_OUTCOMES
                or source.result.get("outcome") in _COMPARISON_OUTCOMES
                or source.result.get("candidate_needs_independent_review") is True
            ):
                raise ValueError()
            original_source_sha256 = source_sha256(source.model_dump(mode="json"))
            if not await memory.verify_signed_graph_action(
                engagement_id,
                task_id,
                event_id,
                receipt,
                version,
            ):
                raise ValueError()
            # Preserve outcome/status if durable results are modified while the
            # independently verified dispatch/event is being retrieved.
            fresh = await memory.load_task_authoritative(task_id)
            if (
                not isinstance(fresh, Task)
                or source_sha256(fresh.model_dump(mode="json")) != original_source_sha256
            ):
                raise ValueError()
            final_flow = await memory.load_flow(flow_id)
            if (
                getattr(final_flow, "engagement_id", None) != engagement_id
                or getattr(final_flow, "id", None) != flow_id
                or getattr(final_flow, "status", None) not in {"pending", "running"}
                or getattr(final_flow, "revision", None) != ref["flow_revision"]
            ):
                raise ValueError()
            # Legacy Graph/Task/source evidence cannot establish target-side
            # authorization effects. Only exact CURRENT dual-live-signature
            # owner/access evidence admitted in 0022, then independently
            # rechecked under THIS release transaction, may qualify.
            if (
                db is None
                or not isinstance(report_id, str)
                or not isinstance(operator, dict)
                or not await _live_independent_target_authority_for_release(
                    db,
                    orch,
                    engagement_id=engagement_id,
                    report_id=report_id,
                    flow_id=flow_id,
                    flow_revision=ref["flow_revision"],
                    finding_id=item["finding_id"],
                    evidence_sha256=item["evidence_sha256"],
                    signed=signed,
                    operator=operator,
                )
            ):
                raise ValueError()
    except Exception as exc:
        raise AttestedStorageUnavailable(
            "Report finding source provenance unverified; manual draft only"
        ) from exc


def _release_key(session_id: str, report_id: str, version: int, digest: str) -> str:
    material = f"{session_id}:{report_id}:{version}:{digest}".encode("utf-8")
    return "report-release:" + hashlib.sha256(material).hexdigest()


def _attested_nonempty_findings(loaded: Dict[str, Any]) -> bool:
    """Count only explicitly listed signed provenance, never provider claims.

    The real release pipeline validates this list independently; a missing
    optional legacy field has no authority to assert verified target effects.
    """
    outer = loaded.get("attestation")
    envelope = outer.get("attestation") if isinstance(outer, dict) else None
    records = envelope.get("evidence_provenance") if isinstance(envelope, dict) else None
    return isinstance(records, list) and bool(records)


async def _verified_final_release_candidate(
    db: Any,
    orch: Any,
    session_id: str,
    report_id: str,
    operator: Dict[str, Any],
    *,
    require_owner: bool = True,
) -> tuple[Dict[str, Any], Dict[str, Any], Any]:
    """Perform complete independent verification under one PostgreSQL lock.

    A senior's JWT is not itself a release. Revalidate the signed engagement,
    original completed report-generation Task, detached Ed25519 bytes and
    independently fetched graph evidence before committing a human signoff.
    """
    durable = (
        (
            await db.execute(
                text(
                    "SELECT session_id, created_by FROM session_states "
                    "WHERE session_id=:sid FOR SHARE"
                ),
                {"sid": session_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if durable is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if operator.get("role") != "senior_operator":
        raise HTTPException(status_code=403, detail="Senior operator signoff required")
    if require_owner and operator.get("sub") != durable["created_by"]:
        # Senior visibility of reports does not grant authority to approve
        # another human owner's engagement for external release.
        raise HTTPException(status_code=403, detail="Engagement owner signoff required")
    try:
        signed = await guard_sql(db, session_id)
    except AuthorizationDenied as exc:
        raise HTTPException(
            status_code=403, detail="Current signed authorization required"
        ) from exc
    loaded = await asyncio.to_thread(load_attested_bundle, session_id, report_id)
    source_records: Dict[str, Dict[str, Any]] = {}
    evidence = await _graph_evidence(
        getattr(orch, "graph_memory", None),
        session_id,
        loaded,
        source_records=source_records,
    )
    verified = verify_loaded_bundle(
        loaded,
        session_id=session_id,
        report_id=report_id,
        evidence_by_finding=evidence,
    )
    _refuse_unsupported_target_promotion(loaded)
    if verified.get("release_status") != "generation_binding_pending_verification":
        raise HTTPException(
            status_code=409, detail="Legacy report cannot receive verified final signoff"
        )
    await _verify_generation_release(
        db,
        session_id=session_id,
        report_id=report_id,
        loaded=loaded,
        current_authorization=signed,
    )
    await _verify_signed_finding_sources(
        orch,
        session_id,
        loaded,
        source_records,
        signed,
        db=db,
        report_id=report_id,
        operator=operator,
    )
    # Graph lookups, independent owner/key validation and Task receipt checks
    # all await other services. The ROE can be revoked or rotated during any
    # of those awaits. A signed source verdict under yesterday's authority
    # cannot authorize POST release or a current GET release representation.
    try:
        current_signed = await guard_sql(db, session_id, expected_version=signed.version)
    except AuthorizationDenied as exc:
        raise HTTPException(
            status_code=403, detail="Signed report release authorization revoked"
        ) from exc
    if (
        current_signed.session_id != session_id
        or current_signed.version != signed.version
        or current_signed.authorization_id != signed.authorization_id
        or current_signed.policy_sha256 != signed.policy_sha256
    ):
        raise HTTPException(status_code=409, detail="Signed report release authorization changed")
    return verified, loaded, signed


@router.post("/{session_id}/attestations/{report_id}/release")
async def approve_signed_report_release(
    session_id: str,
    report_id: str,
    payload: FinalReportSignoff,
    response: Response,
    operator: Dict[str, Any] = Depends(_report_operator),
) -> Dict[str, Any]:
    """Immutable human approval event for one independently verified snapshot.

    The signed report's cryptographic envelope is never mutated. Approval
    releases an exact snapshot for review/distribution and does not certify
    vulnerability findings, production readiness, or any remote exploit effect.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not validated_report_id(session_id, report_id):
        raise HTTPException(status_code=404, detail="Signed report not found")
    if operator.get("role") != "senior_operator":
        raise HTTPException(status_code=403, detail="Senior operator required")
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if not callable(getattr(memory, "_async_session", None)):
        raise HTTPException(status_code=503, detail="Durable report release unavailable")

    async def commit() -> Dict[str, Any]:
        async with memory._async_session() as db:
            async with db.begin():
                _, loaded, signed = await _verified_final_release_candidate(
                    db,
                    orch,
                    session_id,
                    report_id,
                    operator,
                )
                digest = loaded["attestation_sha256"]
                verified_effects = _attested_nonempty_findings(loaded)
                if (
                    signed.version != payload.expected_authorization_version
                    or not hmac.compare_digest(digest, payload.expected_attestation_sha256)
                ):
                    raise HTTPException(
                        status_code=409, detail="Signed report snapshot or ROE changed"
                    )
                key = _release_key(session_id, report_id, signed.version, digest)
                event_payload = {
                    "status": "human_release_approved",
                    "report_id": report_id,
                    "attestation_sha256": digest,
                    "authorization_version": signed.version,
                    "external_effect_verified": verified_effects,
                    "reason": _safe_payload({"reason": payload.reason.strip()})["reason"],
                }
                event = await SupervisionStore(memory)._append_event(
                    db,
                    session_id,
                    None,
                    "report.human_release_approved",
                    str(operator["sub"]),
                    event_payload,
                    idempotency_key=key,
                )
                if verified_effects:
                    # Appending an event can await another transaction's
                    # advisory lock. During that wait, externally managed
                    # witness keys, a short-lived owner observation or the
                    # senior's session can expire or rotate. PostgreSQL row
                    # locks alone cannot protect those external trust roots.
                    # Revalidate *after* the awaited append, inside the same
                    # transaction: failure rolls back both event and outbox.
                    _, current_bundle, current_signed = await _verified_final_release_candidate(
                        db,
                        orch,
                        session_id,
                        report_id,
                        operator,
                    )
                    if (
                        not _attested_nonempty_findings(current_bundle)
                        or current_bundle["attestation_sha256"] != digest
                        or current_signed.version != signed.version
                        or current_signed.authorization_id != signed.authorization_id
                        or current_signed.policy_sha256 != signed.policy_sha256
                    ):
                        raise HTTPException(
                            status_code=409,
                            detail="Signed report or independent authority changed during release",
                        )
                return {
                    "status": "human_release_approved",
                    "report_id": report_id,
                    "attestation_sha256": digest,
                    "authorization_version": signed.version,
                    "release_event_id": event.id,
                    "operator_approval_recorded": True,
                    "external_effect_verified": verified_effects,
                    "report_completeness_certified": False,
                }

    try:
        return await asyncio.wait_for(commit(), timeout=10.0)
    except HTTPException:
        raise
    except SupervisionConflict as exc:
        raise HTTPException(
            status_code=409, detail="Signed report release decision conflicts"
        ) from exc
    except (AttestedStorageUnavailable, ReportAttestationError) as exc:
        raise HTTPException(
            status_code=503, detail="Independent report release verification unavailable"
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Durable signed report release unavailable"
        ) from exc


@router.get("/{session_id}/attestations/{report_id}/release")
async def get_signed_report_release_status(
    session_id: str,
    report_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_report_operator),
) -> Dict[str, Any]:
    """Independent current-state lookup; a previous release can be invalidated."""
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not validated_report_id(session_id, report_id):
        raise HTTPException(status_code=404, detail="Signed report not found")
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if not callable(getattr(memory, "_async_session", None)):
        raise HTTPException(status_code=503, detail="Durable report release unavailable")
    try:

        async def lookup() -> Dict[str, Any]:
            async with memory._async_session() as db:
                async with db.begin():
                    _, loaded, signed = await _verified_final_release_candidate(
                        db,
                        orch,
                        session_id,
                        report_id,
                        operator,
                        require_owner=False,
                    )
                    key = _release_key(
                        session_id,
                        report_id,
                        signed.version,
                        loaded["attestation_sha256"],
                    )
                    event = (
                        await db.execute(
                            select(SupervisionEventORM).where(
                                SupervisionEventORM.engagement_id == session_id,
                                SupervisionEventORM.idempotency_key == key,
                                SupervisionEventORM.kind == "report.human_release_approved",
                            )
                        )
                    ).scalar_one_or_none()
                    if event is not None:
                        owner_row = (
                            (
                                await db.execute(
                                    text(
                                        "SELECT created_by FROM session_states "
                                        "WHERE session_id=:sid FOR SHARE"
                                    ),
                                    {"sid": session_id},
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if (
                            owner_row is None
                            or not isinstance(owner_row["created_by"], str)
                            or not hmac.compare_digest(str(event.actor_id), owner_row["created_by"])
                        ):
                            raise AttestedStorageUnavailable(
                                "Human report signoff owner no longer matches"
                            )
                    if event is not None and (
                        not isinstance(event.payload, dict)
                        or event.payload.get("attestation_sha256") != loaded["attestation_sha256"]
                        or event.payload.get("authorization_version") != signed.version
                        or event.payload.get("report_id") != report_id
                        or event.payload.get("status") != "human_release_approved"
                        or event.payload.get("external_effect_verified", False)
                        is not _attested_nonempty_findings(loaded)
                    ):
                        raise AttestedStorageUnavailable(
                            "Human release event integrity unavailable"
                        )
                    return {
                        "status": (
                            "human_release_approved"
                            if event is not None
                            else "awaiting_human_release"
                        ),
                        "report_id": report_id,
                        "authorization_version": signed.version,
                        "attestation_sha256": loaded["attestation_sha256"],
                        "release_event_id": event.id if event is not None else None,
                        "operator_approval_recorded": event is not None,
                        "external_effect_verified": _attested_nonempty_findings(loaded),
                        "report_completeness_certified": False,
                    }

        return await asyncio.wait_for(lookup(), timeout=10.0)
    except HTTPException:
        raise
    except (AttestedStorageUnavailable, ReportAttestationError) as exc:
        raise HTTPException(
            status_code=503, detail="Independent report release verification unavailable"
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Durable signed report release unavailable"
        ) from exc


@router.get("/{session_id}/attestations/{report_id}/artifacts/{artifact_kind}")
async def download_verified_signed_report_artifact(
    session_id: str,
    report_id: str,
    artifact_kind: str,
    operator: Dict[str, Any] = Depends(_report_operator),
) -> Response:
    """Authenticated download of the exact bytes verified by signed Task.

    The original signature/manifest are checked *before* returning content.
    Never serve untrusted HTML inline, never expose host paths or use caller
    filenames, and never infer human signoff from artifact retrieval.
    """
    if artifact_kind not in ARTIFACT_ALLOWLIST or not validated_report_id(session_id, report_id):
        raise HTTPException(status_code=404, detail="Signed report artifact not found")
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if not callable(getattr(memory, "_async_session", None)):
        raise HTTPException(status_code=503, detail="Signed report storage unavailable")

    async def verify_and_read() -> tuple[bytes, str]:
        async with memory._async_session() as db:
            async with db.begin():
                _, loaded, _ = await _verified_final_release_candidate(
                    db,
                    orch,
                    session_id,
                    report_id,
                    operator,
                    require_owner=False,
                )
                blob = loaded["artifacts"].get(artifact_kind)
                expected = loaded["attestation"]["attestation"]["artifacts"][artifact_kind]
                if (
                    not isinstance(blob, bytes)
                    or not 0 < len(blob) <= 4 * 1024 * 1024
                    or not isinstance(expected, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", expected)
                    or not hmac.compare_digest(hashlib.sha256(blob).hexdigest(), expected)
                ):
                    raise AttestedStorageUnavailable("Signed report artifact digest unavailable")
                return blob, expected

    try:
        blob, digest = await asyncio.wait_for(verify_and_read(), timeout=10.0)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Independently signed artifact unavailable"
        ) from exc
    return Response(
        content=blob,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Signed-Artifact-Sha256": digest,
            "Content-Disposition": f'attachment; filename="{report_id}.{artifact_kind}"',
            "Content-Security-Policy": "sandbox",
        },
    )


@router.get("/{session_id}/attestations/{report_id}")
async def get_signed_report_attestation(
    session_id: str,
    report_id: str,
    response: Response,
    operator: Dict[str, Any] = Depends(_report_operator),
) -> Dict[str, Any]:
    """Only real JWT owner/senior + active signed ROE + independently verified bundle.

    The PostgreSQL FOR SHARE lock is held through verification to prevent a
    concurrent signed policy revocation from racing the response decision.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not validated_report_id(session_id, report_id):
        raise HTTPException(status_code=404, detail="Signed report not found")
    orch = state.get("orchestrator")
    if orch is None or getattr(orch, "session_memory", None) is None:
        raise HTTPException(status_code=503, detail="Authoritative report services unavailable")

    async def read_and_verify() -> Dict[str, Any]:
        async with orch.session_memory._async_session() as db:
            async with db.begin():
                durable = (
                    (
                        await db.execute(
                            text(
                                "SELECT session_id, created_by FROM session_states "
                                "WHERE session_id = :sid FOR SHARE"
                            ),
                            {"sid": session_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if durable is None:
                    raise HTTPException(status_code=404, detail="Engagement not found")
                if operator["role"] != "senior_operator" and (
                    not durable["created_by"] or durable["created_by"] != operator["sub"]
                ):
                    raise HTTPException(status_code=403, detail="Engagement access denied")
                try:
                    current_authorization = await guard_sql(db, session_id)
                except AuthorizationDenied as exc:
                    raise HTTPException(
                        status_code=403, detail="Verified signed engagement authorization required"
                    ) from exc
                # The root is an administrator-configured absolute directory;
                # client-controlled filenames, symlinks and directory walks fail.
                loaded = await asyncio.to_thread(load_attested_bundle, session_id, report_id)
                evidence = await _graph_evidence(
                    getattr(orch, "graph_memory", None), session_id, loaded
                )
                verified = verify_loaded_bundle(
                    loaded,
                    session_id=session_id,
                    report_id=report_id,
                    evidence_by_finding=evidence,
                )
                _refuse_unsupported_target_promotion(loaded)
                if verified["release_status"] == "generation_binding_pending_verification":
                    await _verify_generation_release(
                        db,
                        session_id=session_id,
                        report_id=report_id,
                        loaded=loaded,
                        current_authorization=current_authorization,
                    )
                    verified["release_status"] = "signed_report_task_snapshot_verified"
                verified["independent_target_authority_verified"] = False
                verified["finding_release_eligible"] = False
                return verified

    try:
        return await asyncio.wait_for(read_and_verify(), timeout=_REPORT_TIMEOUT_SECONDS)
    except HTTPException:
        raise
    except (AttestedStorageUnavailable, ReportAttestationError) as exc:
        raise HTTPException(
            status_code=503, detail="Signed report verification unavailable"
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Authoritative report verification unavailable"
        ) from exc
