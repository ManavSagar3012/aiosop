"""AI-OSOP Findings Router

Dashboard endpoints for vulnerability findings, diff-auth, evidence vault, and actions.
"""

import hashlib
import json
import re
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ai_osop.api.deps import assert_engagement_access, require_role, state, verify_token
from ai_osop.core.config import AgentType
from ai_osop.core.models import FindingStatus, Task

router = APIRouter(prefix="/engagements", tags=["findings"])


class ReplayWorkflowRequest(BaseModel):
    """Senior proposal only; a separate signed Task approval authorizes replay."""

    source_user_label: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    target_user_label: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    expected_authorization_version: int = Field(ge=1)
    flow_id: str = Field(min_length=6, max_length=96, pattern=r"^flow-[A-Za-z0-9._-]+$")
    source_task_id: str = Field(min_length=6, max_length=96, pattern=r"^task-[A-Za-z0-9._-]+$")
    expected_flow_revision: int = Field(ge=0)


@router.get("/{session_id}/workflows/replay-sources")
async def list_signed_replay_sources(
    session_id: str,
    flow_id: str = Query(..., min_length=6, max_length=96),
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Read eligible original replay provenance, never credentials or graph hints.

    A signed browser Source Task lives in PostgreSQL (often without Flow ID
    because authenticated discovery precedes the human Flow). The UI must not
    derive it from arbitrary Neo4j projection or guess IDs. This is an inert,
    owner-scoped discovery read; POST must recheck all conditions separately.
    """
    await assert_engagement_access(operator, session_id)
    from sqlalchemy import select

    from ai_osop.auth.session_store import SessionStore
    from ai_osop.memory.session_memory import SessionMemory, TaskORM
    from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

    orch = state.get("orchestrator")
    if not re.fullmatch(r"flow-[A-Za-z0-9._-]{1,90}", flow_id):
        raise HTTPException(status_code=422, detail="Valid Flow ID required")
    if orch is None or not isinstance(orch.session_memory, SessionMemory):
        raise HTTPException(status_code=503, detail="Signed source ledger unavailable")
    try:
        memory = orch.session_memory
        signed = await memory.assert_signed_authorization(session_id)
        flow = await memory.load_flow(flow_id)
        engagement = await memory.load_session_state(session_id)
        if (
            flow is None or flow.engagement_id != session_id
            or flow.status not in {"pending", "running"}
            or engagement is None or engagement.phase in {"halted", "completed"}
            or not engagement.scope.authorization_ref
            or not (engagement.scope.domains or engagement.scope.ips)
        ):
            raise HTTPException(status_code=409, detail="Signed Flow is not active")
        scope = ScopeEnforcer(engagement.scope)
        scope.validate_time_window()
        async with memory._async_session() as db:
            rows = (await db.execute(
                select(TaskORM).where(
                    TaskORM.engagement_id == session_id,
                    TaskORM.type == "map_workflow",
                    TaskORM.status == "completed",
                ).order_by(TaskORM.created_at.desc()).limit(100)
            )).scalars().all()
        sources = []
        seen = set()
        for row in rows:
            original = row.payload
            receipt = row.result
            if (
                row.flow_id not in {None, flow_id}
                or not isinstance(original, dict)
                or not isinstance(receipt, dict)
                or original.get("_authorization_version") != signed.version
                or receipt.get("status") not in {"success", "workflow_recorded"}
            ):
                continue
            label = original.get("user_label")
            workflow_id = receipt.get("workflow_id")
            if (
                not isinstance(label, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", label)
                or label in {"guest", "anonymous"}
                or not isinstance(workflow_id, str)
                or not re.fullmatch(r"wf-[A-Za-z0-9._-]{1,80}", workflow_id)
                or not isinstance(row.id, str)
                or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,78}", row.id)
            ):
                continue
            try:
                validate_payload_targets(
                    scope, {"url": original.get("url")}, require_target=True
                )
            except Exception:
                continue
            if row.id in seen:
                continue
            seen.add(row.id)
            sources.append({
                "source_task_id": row.id,
                "workflow_id": workflow_id,
                "source_user_label": label,
            })
            if len(sources) >= 50:
                break
        store = getattr(orch, "session_store", None)
        if not isinstance(store, SessionStore):
            store = SessionStore(memory)
        sessions = await store.list_sessions(session_id)
        identities = sorted({
            record.user_label for record in sessions
            if record.engagement_id == session_id
            and isinstance(record.user_label, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", record.user_label)
            and not record.is_expired(skew_seconds=0)
            and (record.cookies or record.local_storage)
        })[:50]
        await memory.assert_signed_authorization(
            session_id, expected_version=signed.version
        )
        return {
            "flow_id": flow.id,
            "flow_revision": flow.revision,
            "authorization_version": signed.version,
            "sources": [s for s in sources if s["source_user_label"] in identities],
            "identities": identities,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Verified replay sources unavailable"
        ) from exc


def _vuln_node_to_finding(v: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Neo4j Vulnerability node onto the UI Finding shape."""
    sev = (v.get("severity") or "low").lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "low"
    ev_raw = v.get("evidence")
    try:
        ev = json.loads(ev_raw) if isinstance(ev_raw, str) else (ev_raw or [])
        ev_count = len(ev) if isinstance(ev, list) else (1 if ev else 0)
    except Exception:
        ev_count = 1 if ev_raw else 0
    confidence = float(v.get("confidence") or 0.0)
    tool_source = v.get("tool_source") or ""
    return {
        "id": v.get("id"),
        "title": v.get("title") or v.get("vuln_type") or "Untitled finding",
        "category": v.get("vuln_type") or v.get("cwe") or "unknown",
        "severity": sev,
        # Graph validation is an analyst/model review flag. It cannot by
        # itself authenticate the source MCP receipt, independent target
        # effect, or vulnerability; release has a separate signed PG gate.
        # Neo4j validation is a review annotation, not independent target
        # evidence. Never expose that annotation as a verified UI finding.
        "status": "hypothesis",
        "graph_review_status": "reviewed" if v.get("validated") is True else "unreviewed",
        "source_authenticity_verified": False,
        "independent_target_effect_verified": False,
        "authorization_violation_verified": False,
        "verification_basis": "unattested_graph_review",
        "evScore": round(float(v.get("cvss_score") or 0.0) * 10),
        "confidence": confidence,
        "historicalConfidence": confidence,
        "evidenceCount": ev_count,
        "agentConsensus": [tool_source] if tool_source else [],
        "engagement_id": v.get("engagement_id"),
        "provenance": tool_source,
        "replayabilityScore": confidence,
    }


async def _finding_exists(session_id: str, finding_id: str) -> bool:
    cypher = "MATCH (v:Vulnerability {id: $fid}) WHERE v.engagement_id = $sid RETURN v.id LIMIT 1"
    async with state["orchestrator"].graph_memory._driver.session() as session:
        res = await session.run(cypher, {"fid": finding_id, "sid": session_id})
        return (await res.single()) is not None


@router.get("/{session_id}/findings")
async def get_findings(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """All Vulnerability nodes for an engagement, shaped for the UI."""
    await assert_engagement_access(operator, session_id)
    cypher = (
        "MATCH (v:Vulnerability) WHERE v.engagement_id = $sid RETURN v ORDER BY v.created_at DESC"
    )
    findings: List[Dict[str, Any]] = []
    async with state["orchestrator"].graph_memory._driver.session() as session:
        result = await session.run(cypher, {"sid": session_id})
        async for record in result:
            n = record["v"]
            if n:
                findings.append(_vuln_node_to_finding(dict(n)))
    return findings


@router.get("/{session_id}/diff-auth")
async def get_diff_auth_findings(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Differential-authorization findings for an engagement."""
    await assert_engagement_access(operator, session_id)
    cypher = (
        "MATCH (d:DiffAuthFinding) WHERE d.engagement_id = $sid RETURN d ORDER BY d.created_at DESC"
    )
    out: List[Dict[str, Any]] = []
    async with state["orchestrator"].graph_memory._driver.session() as session:
        result = await session.run(cypher, {"sid": session_id})
        async for record in result:
            d = record["d"]
            if not d:
                continue
            d = dict(d)
            diff_raw = d.get("evidence_diff")
            try:
                diff = json.loads(diff_raw) if isinstance(diff_raw, str) else (diff_raw or {})
            except Exception:
                diff = {}
            out.append(
                {
                    "id": d.get("id"),
                    "category": d.get("category"),
                    "resource_id": d.get("resource_id"),
                    "test_identity_id": d.get("test_identity_id"),
                    "expected_result": d.get("expected_result"),
                    "observed_result": d.get("observed_result"),
                    "evidence_diff": diff,
                    "confidence": float(d.get("confidence") or 0.0),
                    "source_authenticity_verified": False,
                    "authorization_violation_verified": False,
                    "remote_effect_outcome": "unknown",
                }
            )
    from ai_osop.core.triage import rank_findings

    return rank_findings(out)


@router.get("/{session_id}/uncertainty")
async def get_uncertainties(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Open uncertainties for an engagement."""
    await assert_engagement_access(operator, session_id)
    return []


@router.get("/{session_id}/invariants")
async def get_invariants(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Business-logic invariants discovered for an engagement."""
    await assert_engagement_access(operator, session_id)
    return await state["orchestrator"].graph_memory.get_invariants(session_id)


@router.get("/{session_id}/payouts")
async def get_payouts(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Predicted/realised bug-bounty payouts for an engagement."""
    await assert_engagement_access(operator, session_id)
    return []


@router.post("/{session_id}/discovery/trigger")
async def trigger_discovery(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Kick off authenticated discovery for the engagement."""
    await assert_engagement_access(operator, session_id)
    from ai_osop.api.routers.sessions import _trigger_authenticated_discovery

    await _trigger_authenticated_discovery(session_id)
    return {"status": "triggered", "session_id": session_id}


@router.post("/{session_id}/findings/{finding_id}/verify")
async def verify_finding(
    session_id: str,
    finding_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Record senior graph review, not an independently verified vulnerability."""
    await assert_engagement_access(operator, session_id)
    if not await _finding_exists(session_id, finding_id):
        raise HTTPException(status_code=404, detail="Finding not found for this engagement")
    await state["orchestrator"].graph_memory.validate_vulnerability(finding_id)
    return {
        "status": "graph_validated_unverified",
        "finding_id": finding_id,
        "session_id": session_id,
        "source_authenticity_verified": False,
        "independent_target_effect_verified": False,
        "authorization_violation_verified": False,
    }


@router.post("/{session_id}/findings/{finding_id}/replay")
async def replay_finding(
    session_id: str,
    finding_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Queue an exploit-validation (replay) task for a finding."""
    await assert_engagement_access(operator, session_id)
    if not await _finding_exists(session_id, finding_id):
        raise HTTPException(status_code=404, detail="Finding not found for this engagement")
    task = Task(
        type="validate_exploit",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        payload={"finding_id": finding_id, "mode": "replay"},
        engagement_id=session_id,
        approval_required=True,
    )
    await state["orchestrator"].schedule_task(task)
    return {"status": "queued", "task_id": task.id, "task_type": task.type}


@router.get("/{session_id}/findings/{finding_id}/evidence-diff")
async def get_finding_evidence_diff(
    session_id: str,
    finding_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Retrieve 3-way differential evidence diff (Owner vs Attacker vs Anonymous) for a finding."""
    await assert_engagement_access(operator, session_id)
    orch = state.get("orchestrator")
    if not orch or not orch.session_memory:
        raise HTTPException(status_code=503, detail="Session memory unavailable")

    artifacts = await orch.session_memory.list_finding_evidence(session_id, finding_id)
    return {
        "finding_id": finding_id,
        "engagement_id": session_id,
        "artifact_count": len(artifacts),
        "artifacts": [a.model_dump() for a in artifacts],
    }


class FindingOverrideRequest(BaseModel):
    finding_status: FindingStatus
    override_reason: str = Field(..., min_length=5, description="Mandatory senior operator audit note")


@router.post("/{session_id}/findings/{finding_id}/override")
async def override_finding(
    session_id: str,
    finding_id: str,
    req: FindingOverrideRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Allows human senior operator to promote/reject a finding with mandatory audit note."""
    await assert_engagement_access(operator, session_id)
    if not await _finding_exists(session_id, finding_id):
        raise HTTPException(status_code=404, detail="Finding not found for this engagement")

    orch = state.get("orchestrator")
    if not orch or not orch.graph_memory:
        raise HTTPException(status_code=503, detail="Graph memory unavailable")

    operator_id = operator.get("sub") or operator.get("username") or "senior_operator"
    if hasattr(orch.graph_memory, "override_vulnerability_status"):
        await orch.graph_memory.override_vulnerability_status(
            vuln_id=finding_id,
            status=req.finding_status.value,
            reason=req.override_reason,
            operator_id=operator_id,
        )
    return {
        "status": "success",
        "finding_id": finding_id,
        "new_status": req.finding_status.value,
        "override_reason": req.override_reason,
        "operator_id": operator_id,
    }


@router.get("/{session_id}/findings/{finding_id}/vault")
async def get_finding_vault(
    session_id: str, finding_id: str, operator: Dict[str, Any] = Depends(verify_token)
):
    """Assemble the evidence package for a finding."""
    await assert_engagement_access(operator, session_id)
    ev_q = (
        "MATCH (ev:Evidence) WHERE ev.engagement_id = $sid "
        "RETURN ev ORDER BY ev.created_at DESC LIMIT 100"
    )
    raw_requests: List[str] = []
    raw_responses: List[str] = []
    screenshots: List[str] = []
    workflow_trace: List[Dict[str, Any]] = []

    async with state["orchestrator"].graph_memory._driver.session() as session:
        vres = await session.run(vuln_q, {"fid": finding_id, "sid": session_id})
        vrec = await vres.single()
        if not vrec:
            raise HTTPException(status_code=404, detail="Finding not found for this engagement")
        v = dict(vrec["v"])
        ev_raw = v.get("evidence")
        try:
            items = json.loads(ev_raw) if isinstance(ev_raw, str) else (ev_raw or [])
        except Exception:
            items = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict):
                if it.get("request"):
                    raw_requests.append(str(it["request"]))
                if it.get("response"):
                    raw_responses.append(str(it["response"]))
                if not it.get("request") and not it.get("response"):
                    raw_requests.append(json.dumps(it, default=str))
            else:
                raw_requests.append(str(it))

        eres = await session.run(ev_q, {"sid": session_id})
        async for record in eres:
            ev = dict(record["ev"])
            etype = (ev.get("type") or "").lower()
            path = ev.get("path") or ""
            if any(k in etype or k in path.lower() for k in ("screenshot", "png", "jpg", "dom")):
                screenshots.append(path)
            workflow_trace.append({"type": ev.get("type"), "path": path, "id": ev.get("id")})

    integrity_hash = hashlib.sha256(
        json.dumps(
            {"f": finding_id, "rq": raw_requests, "rs": raw_responses, "sc": screenshots},
            sort_keys=True,
            default=str,
        ).encode()
    ).hexdigest()

    return {
        "id": f"vault-{finding_id}",
        "finding_id": finding_id,
        "raw_requests": raw_requests,
        "raw_responses": raw_responses,
        "screenshots": screenshots,
        "workflow_trace": workflow_trace,
        "replay_script": None,
        "integrity_hash": integrity_hash,
    }


@router.post("/{session_id}/poc/generate")
async def generate_poc(
    session_id: str,
    finding_id: str = Query(...),
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Queue a PoC-generation task for the ExploitAgent."""
    await assert_engagement_access(operator, session_id)
    task = Task(
        type="exploit_validation",
        agent_type=AgentType.EXPLOIT_VALIDATION,
        payload={"finding_id": finding_id, "generate_poc": True},
        engagement_id=session_id,
        approval_required=True,
    )
    await state["orchestrator"].schedule_task(task)
    return {"status": "queued", "task_id": task.id, "finding_id": finding_id}


@router.post("/{session_id}/workflows/{workflow_id}/replay")
async def replay_workflow(
    session_id: str,
    workflow_id: str,
    request: ReplayWorkflowRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Stage an owned, ROE-pinned cross-identity replay for distinct approval.

    This route must never infer a second identity or permit missing target_user_label
    (the WorkflowAgent explicitly needs it). A senior request is NOT the human
    execution approval; the signed Task is parked for that separate decision.
    """
    await assert_engagement_access(operator, session_id)
    from ai_osop.memory.session_memory import SessionMemory
    from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

    orch = state["orchestrator"]
    if (
        not re.fullmatch(r"wf-[A-Za-z0-9._-]{1,80}", workflow_id)
        or request.source_user_label == request.target_user_label
    ):
        raise HTTPException(status_code=422, detail="Two distinct bounded identities and workflow are required")
    if not isinstance(orch.session_memory, SessionMemory):
        raise HTTPException(status_code=503, detail="Durable signed replay admission unavailable")
    try:
        receipt = await orch.session_memory.assert_signed_authorization(
            session_id, expected_version=request.expected_authorization_version
        )
        engagement = await orch.session_memory.load_session_state(session_id)
        if engagement is None or engagement.phase in {"completed", "halted"}:
            raise HTTPException(status_code=409, detail="Engagement is no longer active")
        enforcer = ScopeEnforcer(engagement.scope)
        enforcer.validate_time_window()
        flow = await orch.session_memory.load_flow(request.flow_id)
        if (
            flow is None or flow.engagement_id != session_id
            or flow.status not in {"pending", "running"}
            or flow.revision != request.expected_flow_revision
        ):
            raise HTTPException(status_code=409, detail="Flow changed or was not confirmed")
        # The Flow must contain at least one durable human-created objective.
        # Do not mistake an empty planner-created Flow for human confirmation.
        objectives = await orch.session_memory.list_flow_tasks(flow.id)
        if len(objectives) >= 100 or not any(
            objective.type == "flow_objective"
            and objective.engagement_id == session_id
            and objective.flow_id == flow.id
            for objective in objectives
        ):
            raise HTTPException(status_code=409, detail="Flow requires a durable human objective")
        source = await orch.session_memory.load_task_authoritative(request.source_task_id)
        if (
            source is None or source.id != request.source_task_id
            or source.engagement_id != session_id
            or source.type != "map_workflow" or source.status != "completed"
            or source.flow_id not in {None, flow.id}
            or not isinstance(source.payload, dict)
            or source.payload.get("_authorization_version") != receipt.version
            or source.payload.get("user_label") != request.source_user_label
            or not isinstance(source.result, dict)
            or source.result.get("workflow_id") != workflow_id
        ):
            raise HTTPException(status_code=409, detail="Original signed workflow source unavailable")
        validate_payload_targets(enforcer, {"url": source.payload.get("url")}, require_target=True)
        for label in (request.source_user_label, request.target_user_label):
            identity = await orch.session_store.get_session_authoritative(session_id, label)
            if (
                identity is None
                or identity.engagement_id != session_id
                or identity.user_label != label
                or identity.is_expired(skew_seconds=0)
                or not (identity.cookies or identity.local_storage)
            ):
                raise HTTPException(status_code=409, detail="Authenticated identity is unavailable")
        # A guessed workflow ID from another engagement must never become a
        # replay instruction. Graph identity is checked here, then again at
        # the independent per-step signed execution boundary.
        async with orch.graph_memory._driver.session() as graph_session:
            found = await graph_session.run(
                "MATCH (w:Workflow {id:$wid, engagement_id:$eid}) "
                "RETURN w.id AS id LIMIT 1",
                {"wid": workflow_id, "eid": session_id},
            )
            if await found.single() is None:
                raise HTTPException(status_code=404, detail="Workflow not found for engagement")
        # Keep the grant exactly pinned to the senior's reviewed version,
        # including a concurrent ROE replacement while graph/IdP is read.
        await orch.session_memory.assert_signed_authorization(
            session_id, expected_version=receipt.version
        )
        current_flow = await orch.session_memory.load_flow(flow.id)
        if (
            current_flow is None or current_flow.engagement_id != session_id
            or current_flow.status not in {"pending", "running"}
            or current_flow.revision != flow.revision
        ):
            raise HTTPException(status_code=409, detail="Flow changed before replay admission")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Signed replay authority or evidence unavailable"
        ) from exc
    # A lost HTTP response must not mint a new consequential approval every
    # time the senior reloads the page. Exact same reviewed source, Flow
    # revision, signer and identity pair names one durable proposal TaskORM.
    # Separate Flow revisions permit a genuinely new operator review.
    replay_key = json.dumps(
        [
            "signed-diff-replay-proposal-v1", session_id, flow.id, flow.revision,
            receipt.version, source.id, workflow_id,
            request.source_user_label, request.target_user_label,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    replay_task_id = "task-" + hashlib.sha256(replay_key.encode("utf-8")).hexdigest()[:32]
    try:
        existing = await orch.session_memory.load_task_authoritative(replay_task_id)
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Signed replay deduplication ledger unavailable"
        ) from exc
    if existing is not None:
        # An existing request may be awaiting approval, executing or UNKNOWN;
        # none of those states justifies a duplicate POST or external replay.
        raise HTTPException(
            status_code=409,
            detail="An identical signed replay proposal already exists; review durable task status",
        )
    task = Task(
        id=replay_task_id,
        type="replay_for_diff_auth",
        agent_type=AgentType.WORKFLOW,
        payload={
            "workflow_id": workflow_id,
            "source_user_label": request.source_user_label,
            "target_user_label": request.target_user_label,
            "_authorization_version": receipt.version,
            "_flow_revision": request.expected_flow_revision,
        },
        engagement_id=session_id,
        flow_id=request.flow_id,
        parent_task_id=request.source_task_id,
        approval_required=True,
    )
    try:
        await orch.schedule_task(task)
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Signed replay admission was not confirmed") from exc
    return {
        "status": "awaiting_execution_approval",
        "task_id": task.id,
        "workflow_id": workflow_id,
        "execution_started": False,
    }


@router.get("/{session_id}/workflows/{workflow_id}/signed-comparisons")
async def read_signed_replay_comparison(
    session_id: str,
    workflow_id: str,
    flow_id: str = Query(..., min_length=6, max_length=96),
    replay_task_id: str = Query(..., min_length=6, max_length=96),
    step_id: str = Query(..., min_length=6, max_length=96),
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Compare two individually approved PG terminal observations, read-only.

    Only redacted provider-testimony classifications are returned. Graph nodes,
    HTTP success and response similarity do not establish a vulnerability.
    There is no nested browser call or report-promotion side effect.
    """
    await assert_engagement_access(operator, session_id)
    from ai_osop.core.signed_replay_comparison import (
        classify_signed_observation_pair, observation_task_id,
    )
    from ai_osop.memory.graph_research_projection import verify_signed_action_event
    from ai_osop.memory.session_memory import SessionMemory
    from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

    if (
        not re.fullmatch(r"wf-[A-Za-z0-9._-]{1,80}", workflow_id)
        or not re.fullmatch(r"flow-[A-Za-z0-9._-]{1,90}", flow_id)
        or not re.fullmatch(r"task-[A-Za-z0-9._-]{1,90}", replay_task_id)
        or not re.fullmatch(r"step-[A-Za-z0-9._-]{1,80}", step_id)
    ):
        raise HTTPException(status_code=422, detail="Bounded signed replay source required")
    orch = state.get("orchestrator")
    if (
        orch is None or not isinstance(getattr(orch, "session_memory", None), SessionMemory)
        or getattr(orch, "supervision_store", None) is None
    ):
        raise HTTPException(status_code=503, detail="Signed replay evidence ledger unavailable")
    memory = orch.session_memory
    try:
        signed = await memory.assert_signed_authorization(session_id)
        flow = await memory.load_flow(flow_id)
        parent = await memory.load_task_authoritative(replay_task_id)
        session = await memory.load_session_state(session_id)
        if (
            flow is None or flow.id != flow_id or flow.engagement_id != session_id
            or flow.status not in {"pending", "running"}
            or parent is None or parent.engagement_id != session_id
            or parent.flow_id != flow_id or parent.type != "replay_for_diff_auth"
            or parent.status != "completed" or not parent.approval_required
            or not isinstance(parent.payload, dict)
            or parent.payload.get("_authorization_version") != signed.version
            or parent.payload.get("_flow_revision") != flow.revision
            or parent.payload.get("workflow_id") != workflow_id
            or parent.payload.get("operator_approved") is not True
            or not isinstance(parent.payload.get("approval_id"), str)
            or not await memory.is_task_approved(
                parent.id, session_id, parent.payload["approval_id"]
            )
            or session is None or session.phase in {"completed", "halted"}
            or session.scope.engagement_id != session_id
        ):
            raise HTTPException(status_code=409, detail="Signed replay state is not current")
        source_label, target_label = (
            parent.payload.get("source_user_label"),
            parent.payload.get("target_user_label"),
        )
        if (
            not isinstance(source_label, str)
            or not isinstance(target_label, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", source_label)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", target_label)
            or source_label == target_label
        ):
            raise HTTPException(status_code=409, detail="Distinct signed identities unavailable")
        original = await memory.load_task_authoritative(parent.parent_task_id)
        if (
            original is None or original.engagement_id != session_id
            or original.type != "map_workflow" or original.status != "completed"
            or original.flow_id not in {None, flow_id}
            or not isinstance(original.payload, dict)
            or original.payload.get("_authorization_version") != signed.version
            or original.payload.get("user_label") != source_label
            or not isinstance(original.result, dict)
            or original.result.get("workflow_id") != workflow_id
        ):
            raise HTTPException(status_code=409, detail="Original signed map source unavailable")
        enforcer = ScopeEnforcer(session.scope)
        enforcer.validate_time_window()
        validate_payload_targets(
            enforcer, {"url": original.payload.get("url")}, require_target=True
        )
        identities = getattr(orch, "session_store", None)
        if identities is None:
            raise HTTPException(status_code=503, detail="Authenticated identity store unavailable")
        for label in (source_label, target_label):
            identity = await identities.get_session_authoritative(session_id, label)
            if (
                identity is None or identity.engagement_id != session_id
                or identity.user_label != label or identity.is_expired(skew_seconds=0)
                or not (identity.cookies or identity.local_storage)
            ):
                raise HTTPException(status_code=409, detail="Replay identity expired or unavailable")
        # PostgreSQL TaskORM is the source of role, target and comparison
        # results. Neo4j is cross-checked solely for immutable tenant scope.
        async with orch.graph_memory._driver.session() as graph:
            records = await graph.run(
                "MATCH (w:Workflow {id:$wid,engagement_id:$eid})-[:HAS_STEP]->"
                "(s:Step {id:$sid,engagement_id:$eid,workflow_id:$wid})"
                "-[:TARGETS_ENDPOINT]->(e:Endpoint {engagement_id:$eid}) "
                "WHERE s.endpoint_id=e.id "
                "RETURN w.role AS role,e.url AS url,e.method AS method LIMIT 2",
                {"wid": workflow_id, "eid": session_id, "sid": step_id},
            )
            rows = [dict(row) async for row in records]
        if (
            len(rows) != 1 or rows[0].get("role") != source_label
            or rows[0].get("method") != "GET"
        ):
            raise HTTPException(status_code=409, detail="Tenant-bound graph step unavailable")
        url = rows[0].get("url")
        validate_payload_targets(enforcer, {"url": url}, require_target=True)
        ids = [
            observation_task_id(
                session_id, parent.id, flow_id, workflow_id,
                step_id, label, signed.version,
            )
            for label in (source_label, target_label)
        ]
        source = await memory.load_task_authoritative(ids[0])
        target = await memory.load_task_authoritative(ids[1])
        if source is not None and target is not None:
            for task in (source, target):
                if not isinstance(task.payload, dict) or task.payload.get("url") != url:
                    raise HTTPException(status_code=409, detail="Signed target mismatch")
                result = task.result if isinstance(task.result, dict) else {}
                proof = result.get("provider_evidence")
                if not isinstance(proof, dict) or not await verify_signed_action_event(
                    supervision=orch.supervision_store,
                    engagement_id=session_id,
                    task_id=task.id,
                    event_id=proof.get("provider_event_id"),
                    provider_receipt_sha256=proof.get("provider_receipt_sha256"),
                    authorization_version=signed.version,
                ):
                    raise HTTPException(status_code=409, detail="Signed provider origin unavailable")
                approval_id = task.payload.get("approval_id")
                if (
                    not isinstance(approval_id, str)
                    or not await memory.is_task_approved(task.id, session_id, approval_id)
                ):
                    raise HTTPException(status_code=409, detail="Signed step approval unavailable")
        await memory.assert_signed_authorization(
            session_id, expected_version=signed.version
        )
        latest_flow = await memory.load_flow(flow_id)
        if (
            latest_flow is None or latest_flow.revision != flow.revision
            or latest_flow.status not in {"pending", "running"}
        ):
            raise HTTPException(status_code=409, detail="Flow changed during observation read")
        verdict = classify_signed_observation_pair(
            source, target, engagement_id=session_id, parent_id=parent.id,
            flow_id=flow_id, workflow_id=workflow_id, step_id=step_id,
            source_identity=source_label, target_identity=target_label,
            version=signed.version, flow_revision=flow.revision,
            original_source_task_id=original.id,
        )
        return {"flow_id": flow_id, "replay_task_id": parent.id, **verdict}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Signed differential evidence unavailable"
        ) from exc
