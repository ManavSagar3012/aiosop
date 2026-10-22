"""Read-only, redacted operator access to immutable *candidate* evidence.

The 0023/0024 artifact ledger records integrity and signed Task attribution,
not independently observed target access. This endpoint cannot turn provider
testimony, a digest, or a PostgreSQL row into a verified vulnerability.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from ai_osop.api.deps import assert_engagement_access, require_role, state
from ai_osop.memory.session_memory import SessionMemory

router = APIRouter(prefix="/engagements", tags=["candidate-evidence"])
_ENGAGEMENT = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FINDING = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,90}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._-]{1,90}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class SignedNavigationEvidenceRequest(BaseModel):
    """Only identity/version references; never client-provided HTTP testimony."""

    model_config = ConfigDict(extra="forbid", strict=True)
    flow_id: StrictStr = Field(pattern=r"^flow-[A-Za-z0-9._-]{1,90}$")
    source_task_id: StrictStr = Field(pattern=r"^task-[A-Za-z0-9._-]{1,90}$")
    expected_flow_revision: StrictInt = Field(ge=0)
    expected_authorization_version: StrictInt = Field(ge=1)


@router.post(
    "/{engagement_id}/findings/{finding_id}/candidate-evidence-artifacts/from-signed-navigation"
)
async def capture_signed_navigation_candidate_evidence(
    engagement_id: str,
    finding_id: str,
    body: SignedNavigationEvidenceRequest,
    response: Response,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Persist redacted candidate metadata from an already executed signed GET.

    Never navigates, replays, fetches private bytes or treats a successful
    provider receipt as proof of target-owned unauthorized access. A senior may
    *associate* a provider summary with an unverified candidate finding, not
    create an independently verified finding or an exploit approval.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not _ENGAGEMENT.fullmatch(engagement_id) or not _FINDING.fullmatch(finding_id):
        raise HTTPException(422, "Bounded evidence identity required")
    await assert_engagement_access(operator, engagement_id)
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    supervision = getattr(orch, "supervision_store", None)
    if not isinstance(memory, SessionMemory) or supervision is None:
        raise HTTPException(503, "Signed source and provider event ledger unavailable")
    try:
        from ai_osop.core.diff_auth_engine import DifferentialAuthEngine
        from ai_osop.memory.graph_research_projection import verify_signed_action_event
        from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

        signed = await memory.assert_signed_authorization(
            engagement_id, expected_version=body.expected_authorization_version
        )
        flow = await memory.load_flow(body.flow_id)
        session = await memory.load_session_state(engagement_id)
        source = await memory.load_task_authoritative(body.source_task_id)
        if (
            signed.version != body.expected_authorization_version
            or flow is None
            or flow.engagement_id != engagement_id
            or flow.status not in {"pending", "running"}
            or flow.revision != body.expected_flow_revision
            or session is None
            or session.phase in {"halted", "completed"}
            or source is None
            or source.id != body.source_task_id
            or source.engagement_id != engagement_id
            or source.flow_id != body.flow_id
            or source.type != "navigate"
            or source.status != "completed"
            or source.approval_required is not True
            or not isinstance(source.payload, dict)
            or source.payload.get("_authorization_version") != body.expected_authorization_version
            or source.payload.get("_flow_revision") != body.expected_flow_revision
            or source.payload.get("operator_approved") is not True
            or not isinstance(source.payload.get("approval_id"), str)
            or not isinstance(source.payload.get("url"), str)
            or source.payload.get("method", "GET") != "GET"
            or not isinstance(source.result, dict)
        ):
            raise ValueError("Current signed navigation authority unavailable")
        result = source.result
        event = result.get("provider_evidence")
        if (
            result.get("status") != "success"
            or result.get("verification_status") != "provider_testimony_only"
            or result.get("remote_effect_verified") is not False
            or result.get("authorization_violation_verified") is not False
            or result.get("findings_count") != 0
            or result.get("redirected") is not False
            or type(result.get("http_status_code")) is not int
            or not 200 <= result["http_status_code"] < 300
            or not isinstance(result.get("response_body_sha256"), str)
            or not _DIGEST.fullmatch(result["response_body_sha256"])
            or not isinstance(event, dict)
            or set(event)
            != {
                "provider_event_id",
                "provider_receipt_sha256",
                "source_authenticity_verified",
                "target_effect_verified",
                "finding_verified",
            }
            or event.get("source_authenticity_verified") is not False
            or event.get("target_effect_verified") is not False
            or event.get("finding_verified") is not False
            or not isinstance(event.get("provider_event_id"), str)
            or not isinstance(event.get("provider_receipt_sha256"), str)
            or not _DIGEST.fullmatch(event["provider_receipt_sha256"])
        ):
            raise ValueError("Independent provider summary provenance unavailable")

        scope = ScopeEnforcer(session.scope)
        scope.validate_time_window()
        validate_payload_targets(scope, {"url": source.payload["url"]}, require_target=True)
        if not await memory.is_task_approved(
            source.id, engagement_id, source.payload["approval_id"]
        ):
            raise ValueError("Signed Task approval has been revoked")
        if not await verify_signed_action_event(
            supervision=supervision,
            engagement_id=engagement_id,
            task_id=source.id,
            event_id=event["provider_event_id"],
            provider_receipt_sha256=event["provider_receipt_sha256"],
            authorization_version=body.expected_authorization_version,
        ):
            raise ValueError("Provider event trust is unavailable")
        await memory.assert_signed_authorization(
            engagement_id, expected_version=body.expected_authorization_version
        )
        current_flow = await memory.load_flow(body.flow_id)
        if (
            current_flow is None
            or current_flow.engagement_id != engagement_id
            or current_flow.revision != body.expected_flow_revision
            or current_flow.status not in {"pending", "running"}
        ):
            raise ValueError("Signed Flow changed before candidate admission")
        # These bytes represent a *provider metadata summary*, not the HTTP
        # body and not a target-authority proof. The original browser result's
        # domain-separated response digest remains a non-verifying reference.
        summary = {
            "schema": "ai-osop.signed-provider-summary.v1",
            "source_task_id": source.id,
            "provider_event_id": event["provider_event_id"],
            "provider_receipt_sha256": event["provider_receipt_sha256"],
            "browser_summary_body_sha256": result["response_body_sha256"],
            "verification_state": "candidate_unverified",
        }
        # Exactly one PostgreSQL primary-key identity for this signed event +
        # finding association, even when a lost HTTP ACK induces concurrent
        # retries. A duplicate insert fails closed: readers use GET to inspect
        # the already committed record; POST never performs any remote replay.
        artifact_id = (
            "ev-"
            + hashlib.sha256(
                json.dumps(
                    [
                        "ai-osop-signed-provider-candidate-v1",
                        engagement_id,
                        finding_id,
                        source.id,
                        event["provider_event_id"],
                        event["provider_receipt_sha256"],
                        result["response_body_sha256"],
                    ],
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()[:32]
        )
        artifact = await DifferentialAuthEngine(memory).create_and_persist_evidence_artifact(
            finding_id=finding_id,
            engagement_id=engagement_id,
            target_url=source.payload["url"],
            http_method="GET",
            request_headers={},
            request_body={},
            response_status=result["http_status_code"],
            response_headers={},
            response_body=summary,
            source_tool="signed_browser_provider_summary",
            approval_id=source.payload["approval_id"],
            source_task_id=source.id,
            artifact_id=artifact_id,
        )
        # The storage layer itself rechecks the signed source and enforces
        # durable PG readback. If the response is lost, query the GET endpoint
        # and do not blindly repeat a POST that may have committed.
        return {
            "status": "candidate_evidence_recorded_unverified",
            "artifact_id": artifact.id,
            "merkle_leaf_sha256": artifact.merkle_leaf_hash,
            "finding_verified": False,
            "independent_target_effect_verified": False,
            "safe_to_automatically_retry": False,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            503, "Signed candidate evidence admission unavailable; do not retry without readback"
        ) from exc


@router.get("/{engagement_id}/findings/{finding_id}/candidate-evidence-artifacts")
async def read_candidate_evidence_artifacts(
    engagement_id: str,
    finding_id: str,
    response: Response,
    flow_id: str = Query(..., min_length=6, max_length=96),
    expected_flow_revision: int = Query(..., ge=0),
    expected_authorization_version: int = Query(..., ge=1),
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Return bounded digest-only references under current signed ROE/Flow.

    No full EvidenceArtifact serialization: raw URL, query, response digests,
    replay_recipe and private provider observations remain server-side.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if (
        not _ENGAGEMENT.fullmatch(engagement_id)
        or not _FINDING.fullmatch(finding_id)
        or not _FLOW.fullmatch(flow_id)
    ):
        raise HTTPException(422, "Bounded signed candidate evidence identifiers required")

    await assert_engagement_access(operator, engagement_id)
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    if not isinstance(memory, SessionMemory):
        raise HTTPException(503, "Signed candidate evidence ledger unavailable")

    async def current_flow() -> Any:
        await memory.assert_signed_authorization(
            engagement_id, expected_version=expected_authorization_version
        )
        flow = await memory.load_flow(flow_id)
        if (
            flow is None
            or flow.id != flow_id
            or flow.engagement_id != engagement_id
            or flow.status not in {"pending", "running"}
            or flow.revision != expected_flow_revision
        ):
            raise HTTPException(409, "Signed Flow changed; refresh before evidence review")
        return flow

    try:
        await current_flow()
        rows = await memory.list_finding_evidence(engagement_id, finding_id)
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError("Candidate evidence list is unbounded")
        safe_rows = []
        for artifact in rows:
            recipe = getattr(artifact, "replay_recipe", None)
            source_id = recipe.get("source_task_id") if isinstance(recipe, dict) else None
            leaf = getattr(artifact, "merkle_leaf_hash", None)
            artifact_id = getattr(artifact, "id", None)
            if (
                artifact.engagement_id != engagement_id
                or artifact.finding_id != finding_id
                or not isinstance(artifact_id, str)
                or not re.fullmatch(r"ev-[A-Za-z0-9._-]{1,60}", artifact_id)
                or not isinstance(leaf, str)
                or not _DIGEST.fullmatch(leaf)
                or not isinstance(source_id, str)
                or not _TASK.fullmatch(source_id)
                or not isinstance(recipe, dict)
                or recipe.get("schema") != "ai-osop.redacted-evidence-reference.v1"
                or recipe.get("replayable") is not False
                or recipe.get("finding_verified") is not False
                or recipe.get("target_effect_verified") is not False
            ):
                raise ValueError("Candidate evidence provenance unavailable")
            producer = await memory.load_task_authoritative(source_id)
            if (
                producer is None
                or producer.id != source_id
                or producer.engagement_id != engagement_id
                or producer.flow_id != flow_id
                or producer.status not in {"running", "completed"}
                or not isinstance(producer.payload, dict)
                or producer.payload.get("_authorization_version") != expected_authorization_version
                or producer.payload.get("_flow_revision") != expected_flow_revision
                or not isinstance(producer.payload.get("url"), str)
                or hashlib.sha256(producer.payload["url"].encode("utf-8")).hexdigest()
                != recipe.get("original_url_sha256")
            ):
                raise ValueError("Candidate evidence source is no longer current")
            safe_rows.append(
                {
                    "artifact_id": artifact_id,
                    "source_task_id": source_id,
                    "merkle_leaf_sha256": leaf,
                    "verification_state": "candidate_unverified",
                    "independent_target_effect_verified": False,
                }
            )
        # Recheck current signer and Flow after the awaited source/ledger reads;
        # concurrent revocation or pause must never return a stale authority view.
        await current_flow()
        return {
            "engagement_id": engagement_id,
            "finding_id": finding_id,
            "flow_id": flow_id,
            "flow_revision": expected_flow_revision,
            "authorization_version": expected_authorization_version,
            "verification_state": "candidate_unverified",
            "finding_verified": False,
            "independent_target_effect_verified": False,
            "artifacts": safe_rows,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Current signed candidate evidence unavailable") from exc
