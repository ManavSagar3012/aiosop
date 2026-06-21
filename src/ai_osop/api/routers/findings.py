"""AI-OSOP Findings Router

Dashboard endpoints for vulnerability findings, diff-auth, evidence vault, and actions.
"""

import hashlib
import json
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import assert_engagement_access, require_role, state, verify_token
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

router = APIRouter(prefix="/engagements", tags=["findings"])


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
        "status": "verified" if v.get("validated") else "hypothesis",
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
    """Operator force-verify: mark the vulnerability validated in the graph."""
    await assert_engagement_access(operator, session_id)
    if not await _finding_exists(session_id, finding_id):
        raise HTTPException(status_code=404, detail="Finding not found for this engagement")
    await state["orchestrator"].graph_memory.validate_vulnerability(finding_id)
    return {"status": "verified", "finding_id": finding_id, "session_id": session_id}


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
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Queue a workflow replay (differential-auth re-run) for the WorkflowAgent."""
    await assert_engagement_access(operator, session_id)
    task = Task(
        type="replay_for_diff_auth",
        agent_type=AgentType.WORKFLOW,
        payload={"workflow_id": workflow_id},
        engagement_id=session_id,
    )
    await state["orchestrator"].schedule_task(task)
    return {"status": "queued", "task_id": task.id, "workflow_id": workflow_id}
