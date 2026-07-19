"""AI-OSOP Engagement Router

All engagement lifecycle endpoints: create, list, get, transition, halt.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import (
    CreateEngagementRequest,
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)
from ai_osop.core.exceptions import WorkflowException, WorkflowTransitionError
from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.orchestrator.orchestrator import EngagementPhase

router = APIRouter(prefix="/engagements", tags=["engagements"])


@router.post("", response_model=SessionState)
async def create_engagement(
    request: CreateEngagementRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Create new penetration testing engagement."""
    cleaned_domains = []
    for d in request.domains:
        d = d.replace("https://", "").replace("http://", "")
        if "/" in d:
            d = d.split("/")[0]
        cleaned_domains.append(d)

    scope = ScopeDefinition(
        engagement_id=request.engagement_id,
        domains=cleaned_domains,
        ips=request.ips,
        exclusions=request.exclusions,
        allowed_techniques=request.allowed_techniques,
        restrictions=request.restrictions,
        approval_required_for=request.approval_required_for,
        testing_window_start=request.testing_window_start,
        testing_window_end=request.testing_window_end,
        authorization_ref=request.authorization_ref,
    )

    import traceback as _tb

    _orch = state.get("orchestrator")
    if _orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    try:
        session = await _orch.create_engagement(scope, request.roe, created_by=operator.get("sub"))
        return session
    except Exception:
        _tb_content = _tb.format_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Engagement creation failed: {_tb_content[:2000]}",
        )


@router.get("")
async def list_engagements(operator: Dict[str, Any] = Depends(verify_token)):
    """List all active engagements sorted by creation time (latest last)."""
    try:
        orch = state.get("orchestrator")
        if orch is None:
            return {"error": "Orchestrator not initialized", "engagements": []}
        sessions = list(orch._sessions.values())
        sessions.sort(key=lambda x: x.created_at, reverse=True)
        # Ownership filter: operators see only their own engagements;
        # senior_operator sees all.
        if operator.get("role") != "senior_operator":
            sessions = [s for s in sessions if s.created_by == operator.get("sub")]
        return [s.model_dump(mode="json") for s in sessions]
    except Exception as e:
        import traceback

        tb = traceback.format_exc()
        import logging

        logging.getLogger("ai_osop.api.engagements").error("list_engagements_failed: %s\n%s", e, tb)
        from starlette.responses import JSONResponse

        return JSONResponse(
            status_code=500,
            content={
                "detail": f"Failed to list engagements: {str(e)}",
                "error_type": type(e).__name__,
            },
        )


@router.get("/{session_id}")
async def get_engagement(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get engagement details."""
    session = await assert_engagement_access(operator, session_id)
    return session


@router.get("/{session_id}/audit-log")
async def get_audit_log(
    session_id: str,
    limit: int = 1000,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Return the audit trail for an engagement.

    The dashboard (ui/src/services/network.ts) fetches this by session_id, but
    audit events are persisted keyed by scope.engagement_id, so resolve the
    session first and query by that id.
    """
    session = await assert_engagement_access(operator, session_id)
    engagement_id = session.scope.engagement_id

    # Fetch events under both IDs (scope engagement_id and session_id) to resolve split-brain logging.
    events_by_scope = await state["orchestrator"].session_memory.query_audit_log(
        engagement_id=engagement_id, limit=limit
    )
    events_by_session = await state["orchestrator"].session_memory.query_audit_log(
        engagement_id=session_id, limit=limit
    )

    # Deduplicate by event_id and sort chronologically (earliest first, matching audit-trail UI expectation)
    all_events = {e.event_id: e for e in (events_by_scope + events_by_session)}
    sorted_events = sorted(all_events.values(), key=lambda e: e.timestamp)

    return [e.model_dump(mode="json") for e in sorted_events[:limit]]


@router.post("/{session_id}/scan/deterministic")
async def deterministic_scan(
    session_id: str,
    target: str = "",
    mode: str = "suite",
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Run the deterministic detection backbone against the engagement target and
    persist validated findings (SQLi, IDOR, JWT forgery, mass-assignment, ...).

    This bypasses the LLM/agent/MCP task lifecycle that strands findings on the
    300s timeout, so a scan is hang-proof and completes in seconds. Target is the
    engagement scope's first domain unless an explicit ``target`` is supplied.
    """
    session = await assert_engagement_access(operator, session_id)
    engagement_id = session.scope.engagement_id

    base = target
    if not base:
        domains = session.scope.domains or []
        if not domains:
            raise HTTPException(
                status_code=400,
                detail="no target: engagement scope has no domains and no 'target' was provided",
            )
        d = domains[0]
        base = d if d.startswith("http") else f"http://{d}"

    from ai_osop.core.deterministic_scan import run_deterministic_scan, run_generalized_sqli

    gm = state["orchestrator"].graph_memory
    persisted: list = []
    validated: list = []
    expected = 0
    # suite   = benchmark-proven checks (juice-shop-tuned, recall-scored)
    # discovered = general oracles driven off recon-discovered endpoints (any target)
    if mode in ("suite", "both"):
        p, validated, expected = await run_deterministic_scan(base, engagement_id, gm)
        persisted += p
    if mode in ("discovered", "both"):
        gp, _examined = await run_generalized_sqli(engagement_id, gm)
        persisted += gp
    return {
        "status": "success",
        "mode": mode,
        "target": base,
        "engagement_id": engagement_id,
        "suite_validated": len(validated),
        "suite_expected": expected,
        "recall": round(len(validated) / expected, 3) if expected else None,
        "persisted": len(persisted),
        "findings": [v.model_dump(mode="json") for v in persisted],
    }


@router.get("/{session_id}/report/bounty")
async def bounty_report(
    session_id: str,
    target: str = "",
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Render a submittable markdown bounty report from the engagement's validated
    findings (severity-ranked, with CWE/OWASP, evidence, and reproduction steps)."""
    session = await assert_engagement_access(operator, session_id)
    engagement_id = session.scope.engagement_id
    from ai_osop.core.report_generator import generate_bounty_report

    gm = state["orchestrator"].graph_memory
    tgt = target or (session.scope.domains[0] if session.scope.domains else "")
    md = await generate_bounty_report(engagement_id, gm, target=tgt)
    return {"engagement_id": engagement_id, "format": "markdown", "report": md}


@router.post("/{session_id}/transition")
async def transition_phase(
    session_id: str,
    new_phase: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Transition engagement to new phase."""
    await assert_engagement_access(operator, session_id)
    try:
        phase = EngagementPhase(new_phase)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid phase: {new_phase}")

    try:
        session = await state["orchestrator"].transition_phase(session_id, phase)
        return session
    except WorkflowTransitionError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except WorkflowException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        import logging

        logging.getLogger("ai_osop.api.engagements").exception("transition_phase_failed")
        raise HTTPException(status_code=400, detail="Phase transition failed")


@router.post("/{session_id}/halt")
async def halt_engagement(
    session_id: str,
    reason: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Emergency halt engagement."""
    await assert_engagement_access(operator, session_id)
    await state["orchestrator"].halt_engagement(session_id, reason)
    return {"status": "halted", "session_id": session_id, "reason": reason}
