"""AI-OSOP Findings Router

Dashboard endpoints for vulnerability findings, diff-auth, evidence vault, and actions.
"""

import hashlib
import json
from typing import Any, Dict, List

import structlog
from fastapi import APIRouter, Body, Depends, HTTPException, Query

from ai_osop.api.deps import assert_engagement_access, require_role, state, verify_token
from ai_osop.core.findings_quality import FindingConversionEngine

logger = structlog.get_logger("ai_osop.findings")

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

router = APIRouter(prefix="/engagements", tags=["findings"])


_SEVERITY_EV_SCORE = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 10}


def _vuln_node_to_finding(v: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Neo4j Vulnerability node onto the UI Finding shape."""
    sev = (v.get("severity") or "low").lower()
    if sev not in {"low", "medium", "high", "critical"}:
        sev = "low"
    ev_raw = v.get("evidence")
    try:
        ev = json.loads(ev_raw) if isinstance(ev_raw, str) else (ev_raw or [])
    except Exception as e:
        logger.warning("failed_to_parse_evidence", finding_id=v.get("id"), error=str(e))
        ev = []
    if not isinstance(ev, list):
        ev = [ev] if ev else []
    ev_count = len(ev)
    # Surface the location/evidence the scanner actually recorded. nuclei stores
    # template / matched_at / url inside evidence[0]; without lifting these into the
    # DTO the dashboard and bounty reports cannot show WHERE a finding was matched.
    # (AIOSOP-FINDINGS-EVIDENCE-2026-06-30)
    first = next((e for e in ev if isinstance(e, dict)), {})
    matched_at = first.get("matched_at") or first.get("url")
    confidence = float(v.get("confidence") or 0.0)
    tool_source = v.get("tool_source") or ""
    # evScore prefers real CVSS; nuclei findings carry none, so fall back to a
    # severity-derived score instead of collapsing every finding to 0.
    cvss = float(v.get("cvss_score") or 0.0)
    ev_score = round(cvss * 10) if cvss > 0 else _SEVERITY_EV_SCORE.get(sev, 10)
    return {
        "id": v.get("id"),
        "title": v.get("title") or v.get("vuln_type") or "Untitled finding",
        "category": v.get("vuln_type") or v.get("cwe") or "unknown",
        "severity": sev,
        "status": "verified" if v.get("validated") else "hypothesis",
        "evScore": ev_score,
        "confidence": confidence,
        "historicalConfidence": confidence,
        "evidenceCount": ev_count,
        "agentConsensus": [tool_source] if tool_source else [],
        "engagement_id": v.get("engagement_id"),
        "provenance": tool_source,
        "replayabilityScore": confidence,
        # --- evidence/location surfaced for the UI + reports (additive) ---
        "description": v.get("description") or "",
        "cwe": v.get("cwe"),
        "matchedAt": matched_at,
        "templateId": first.get("template"),
        "url": first.get("url") or matched_at,
    }


async def _finding_exists(session_id: str, finding_id: str, id_forms: List[str] | None = None) -> bool:
    forms = id_forms or [session_id]
    records = await state["orchestrator"].graph_memory.run_read_query(
        "MATCH (v:Vulnerability {id: $fid}) WHERE v.engagement_id IN $ids RETURN v.id LIMIT 1",
        {"fid": finding_id, "ids": forms},
    )
    return bool(records)


def _engagement_id_forms(session: Any, session_id: str) -> List[str]:
    """Return every id form an engagement's nodes may be keyed under.

    The URL carries either the FULL session_id (eng-{ts}-{eid}) or the SHORT
    operator engagement_id; writers persist under one or the other. Match both so
    a read never misses findings due to an id-form mismatch (AIOSOP-FINDINGS-KEY).
    """
    forms = [session_id]
    scope_eid = getattr(getattr(session, "scope", None), "engagement_id", None)
    if scope_eid:
        forms.append(scope_eid)
    sess_id = getattr(session, "session_id", None)
    if sess_id:
        forms.append(sess_id)
    return list(dict.fromkeys(f for f in forms if f))


@router.get("/{session_id}/findings")
async def get_findings(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """All Vulnerability nodes for an engagement, shaped for the UI."""
    session = await assert_engagement_access(operator, session_id)
    forms = _engagement_id_forms(session, session_id)
    vuln_nodes = await state["orchestrator"].graph_memory.get_vulnerabilities_by_engagement(
        *forms
    )
    return [_vuln_node_to_finding(n) for n in vuln_nodes]


@router.get("/{session_id}/report")
async def get_report(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Serve the persisted assessment report for an engagement.

    AIOSOP-REPORT-API-001 (2026-07-03): the dashboard's Mission Report page and the
    PRINT REPORT button both GET /engagements/{id}/report, but NO route existed — the
    call 404'd, so reporting-through-the-dashboard was broken. The ReportingAgent
    already generates real reports during the REPORTING phase and persists them to
    reports/{engagement_id}/report-*.{md,html}; this endpoint serves those ACTUAL
    artifacts (never a fabricated/mock report). If the engagement has not reached
    reporting yet, it 404s honestly (the UI renders REPORT_NOT_FOUND).

    Shape matches ui MissionReport.tsx: {report_id, markdown, html, body_html}.
    """
    await assert_engagement_access(operator, session_id)

    import glob
    import os

    # Path-traversal guard: session_id is used in a filesystem path. Reject any
    # separator/traversal so a crafted id cannot escape the reports/ directory.
    if os.sep in session_id or "/" in session_id or "\\" in session_id or ".." in session_id:
        raise HTTPException(status_code=400, detail="invalid engagement id")

    reports_dir = os.path.join("reports", session_id)
    # Main report body is report-*.html; exclude the report-*.graph.html companion.
    html_matches = [
        p
        for p in sorted(glob.glob(os.path.join(reports_dir, "report-*.html")))
        if not p.endswith(".graph.html")
    ]
    md_matches = sorted(glob.glob(os.path.join(reports_dir, "report-*.md")))
    if not html_matches and not md_matches:
        raise HTTPException(
            status_code=404, detail="No report has been generated for this engagement yet"
        )

    def _read(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return ""

    html_path = html_matches[-1] if html_matches else ""
    md_path = md_matches[-1] if md_matches else ""
    report_id = os.path.splitext(os.path.basename(html_path or md_path))[0]
    body_html = _read(html_path)
    markdown = _read(md_path)
    return {
        "report_id": report_id,
        "markdown": markdown,
        "html": body_html,
        "body_html": body_html,
    }


@router.get("/{session_id}/diff-auth")
async def get_diff_auth_findings(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Differential-authorization findings for an engagement."""
    session = await assert_engagement_access(operator, session_id)
    forms = _engagement_id_forms(session, session_id)
    cypher = (
        "MATCH (d:DiffAuthFinding) WHERE d.engagement_id IN $ids RETURN d ORDER BY d.created_at DESC"
    )
    diff_records = await state["orchestrator"].graph_memory.run_read_query(
        cypher, {"ids": forms}
    )
    out: List[Dict[str, Any]] = []
    for record in diff_records:
        d = record.get("d")
        if not d:
            continue
        d = dict(d)
        diff_raw = d.get("evidence_diff")
        try:
            diff = json.loads(diff_raw) if isinstance(diff_raw, str) else (diff_raw or {})
        except (json.JSONDecodeError, TypeError):
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
    session = await assert_engagement_access(operator, session_id)
    forms = _engagement_id_forms(session, session_id)
    if not await _finding_exists(session_id, finding_id, forms):
        raise HTTPException(status_code=404, detail="Finding not found for this engagement")
    await state["orchestrator"].graph_memory.validate_vulnerability(finding_id)
    return {"status": "verified", "finding_id": finding_id, "session_id": session_id}


@router.post("/{session_id}/findings/{finding_id}/resolve")
async def resolve_finding(
    session_id: str,
    finding_id: str,
    status: str = Body(...),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Operator resolves a finding's outcome."""
    await assert_engagement_access(operator, session_id)
    return await FindingConversionEngine.resolve_finding(
        finding_id, status, state["session_memory"], state["graph_memory"]
    )


@router.post("/{session_id}/findings/{finding_id}/replay")
async def replay_finding(
    session_id: str,
    finding_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Queue an exploit-validation (replay) task for a finding."""
    session = await assert_engagement_access(operator, session_id)
    forms = _engagement_id_forms(session, session_id)
    if not await _finding_exists(session_id, finding_id, forms):
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
    session = await assert_engagement_access(operator, session_id)
    forms = _engagement_id_forms(session, session_id)
    vuln_q = "MATCH (v:Vulnerability) WHERE v.id = $fid AND v.engagement_id IN $ids RETURN v LIMIT 1"
    ev_q = (
        "MATCH (ev:Evidence) WHERE ev.engagement_id IN $ids "
        "RETURN ev ORDER BY ev.created_at DESC LIMIT 100"
    )
    raw_requests: List[str] = []
    raw_responses: List[str] = []
    screenshots: List[str] = []
    workflow_trace: List[Dict[str, Any]] = []

    vrecs = await state["orchestrator"].graph_memory.run_read_query(
        vuln_q, {"fid": finding_id, "ids": forms}
    )
    if not vrecs:
        raise HTTPException(status_code=404, detail="Finding not found for this engagement")
    v = dict(vrecs[0].get("v", {}))
    ev_raw = v.get("evidence")
    try:
        items = json.loads(ev_raw) if isinstance(ev_raw, str) else (ev_raw or [])
    except (json.JSONDecodeError, TypeError):
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

    ev_records = await state["orchestrator"].graph_memory.run_read_query(ev_q, {"ids": forms})
    for record in ev_records:
        ev = dict(record.get("ev", {}))
        etype = (ev.get("type") or "").lower()
        path = ev.get("path") or ""
        if any(k in etype or k in path.lower() for k in ("screenshot", "png", "jpg", "dom")):
            screenshots.append(path)
        workflow_trace.append({"type": ev.get("type"), "path": path, "id": ev.get("id")})

    integrity_hash = hashlib.sha256(
        json.dumps(
            {
                "f": finding_id,
                "rq": raw_requests,
                "rs": raw_responses,
                "sc": screenshots,
            },
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
