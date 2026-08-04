"""AI-OSOP Engagement Router

All engagement lifecycle endpoints: create, list, get, transition, halt.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

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


@router.post(
    "",
    response_model=SessionState,
    summary="Create a new engagement",
    description="Initialize a penetration testing engagement with target scope, rules of engagement, and operator context.",
)
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

    _orch = state.get("orchestrator")
    if _orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    try:
        session = await _orch.create_engagement(scope, request.roe, created_by=operator.get("sub"))
        return session
    except Exception:
        # AIOSOP-ERROR-DISCLOSURE (2026-08-03): the previous handler returned up
        # to 2000 chars of the traceback in the HTTP response — internal paths,
        # hostnames, and stack content leaked to the caller. Log the traceback
        # server-side; return a generic message. The caller can inspect logs.
        import logging

        logger = logging.getLogger("ai_osop.api.engagements")
        logger.exception("engagement_creation_failed")
        raise HTTPException(
            status_code=500,
            detail="Engagement creation failed — see server logs",
        )


@router.get(
    "",
    summary="List engagements",
    description="Return all engagements visible to the caller, ordered newest-first. Operators see only their own engagements; senior operators see all. Bounded by limit/offset.",
)
async def list_engagements(
    operator: Dict[str, Any] = Depends(verify_token),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """List engagements, newest first. Bounded by limit/offset.

    AIOSOP-SCALE-003 (2026-08-01): previously returned every in-memory session
    unbounded (same class of issue as list_tasks before AIOSOP-SCALE-002). Apply
    a server-side default cap; clients that need more can page with limit/offset.
    """
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
        sessions = sessions[offset : offset + limit]
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


@router.get(
    "/{session_id}",
    summary="Get engagement details",
    description="Retrieve the full session state for an engagement by its session ID.",
)
async def get_engagement(session_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get engagement details."""
    session = await assert_engagement_access(operator, session_id)
    return session


@router.get(
    "/{session_id}/audit-log",
    summary="Get engagement audit log",
    description="Return the chronological audit trail for an engagement, including all state-changing events.",
)
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


@router.post(
    "/{session_id}/scan/deterministic",
    summary="Run deterministic vulnerability scan",
    description="Execute the deterministic detection backbone (SQLi, IDOR, JWT forgery, mass-assignment) against the engagement target and persist validated findings. Supports suite, discovered, or both modes.",
)
async def deterministic_scan(
    session_id: str,
    target: str = "",
    mode: str = "suite",
    discover: bool = False,
    auth_user: str = "",
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Run the deterministic detection backbone against the engagement target and
    persist validated findings (SQLi, IDOR, JWT forgery, mass-assignment, ...).

    This bypasses the LLM/agent/MCP task lifecycle that strands findings on the
    300s timeout, so a scan is hang-proof and completes in seconds. Target is the
    engagement scope's first domain unless an explicit ``target`` is supplied.

    ``auth_user`` (only meaningful for ``mode`` = discovered/both) names a captured
    UserSession label for this engagement. When set, the generalized surface
    oracles (SQLi / mass-assignment / injection) run through that authenticated
    session, so injection points that only exist behind login become reachable.
    Unknown label or no stored session -> the scan runs unauthenticated (the
    historical behavior), never an error.
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

    from ai_osop.core.deterministic_scan import (
        bootstrap_discovery,
        run_deterministic_scan,
        run_generalized_scan,
    )

    gm = state["orchestrator"].graph_memory

    # M1 governed egress: build ONE governance hook for this engagement and thread
    # it through every target-traffic path (discovery, suite, generalized — authed
    # and unauthenticated). The hook scope-checks each request (out-of-scope host
    # raises before egress), throttles it via a dedicated bounty-safe rate limiter
    # (B2 — politer than the orchestrator's task-admission limiter), and stamps the
    # program research header. This is the single chokepoint that makes the whole
    # scan defensibly in-policy.
    from ai_osop.core.config import settings
    from ai_osop.safety.governed_client import governance_hook, research_header_from_settings
    from ai_osop.safety.rate_limiter import RateLimiter
    from ai_osop.safety.scope import ScopeEnforcer

    ghook = governance_hook(
        scope=ScopeEnforcer(session.scope),
        rate_limiter=RateLimiter(
            target_rate=settings.scan_target_rate_per_second,
            target_capacity=settings.scan_target_burst,
        ),
        research_header=research_header_from_settings(),
    )

    seeded = 0
    if discover:
        seeded = await bootstrap_discovery(base, engagement_id, gm, governance_hook=ghook)
    persisted: list = []
    validated: list = []
    expected = 0
    # suite   = benchmark-proven checks (juice-shop-tuned, recall-scored)
    # discovered = general oracles driven off recon-discovered endpoints (any target)
    if mode in ("suite", "both"):
        p, validated, expected = await run_deterministic_scan(
            base, engagement_id, gm, governance_hook=ghook
        )
        persisted += p
    authenticated_as = None
    if mode in ("discovered", "both"):
        # Auth passthrough: if an auth_user label is supplied and a session was
        # captured for it, drive the generalized surface oracles through that
        # authenticated SessionClient (which carries the SAME governance hook, so
        # authed probes are governed too). Any resolution failure degrades to an
        # unauthenticated scan rather than erroring.
        store = state.get("session_store")
        sess_client = None
        if auth_user and store is not None:
            try:
                usersession = await store.get_session_or_none(engagement_id, auth_user)
                if usersession is not None:
                    sess_client = store.as_user(
                        engagement_id, auth_user, base_url=base, governance_hook=ghook
                    )
            except Exception:
                sess_client = None
        if sess_client is not None:
            async with sess_client as client:
                authenticated_as = auth_user
                gp, _examined = await run_generalized_scan(
                    engagement_id, gm, client=client, governance_hook=ghook
                )
        else:
            gp, _examined = await run_generalized_scan(engagement_id, gm, governance_hook=ghook)
        persisted += gp
    return {
        "status": "success",
        "mode": mode,
        "discovered_seeded": seeded,
        "target": base,
        "engagement_id": engagement_id,
        "authenticated_as": authenticated_as,
        "suite_validated": len(validated),
        "suite_expected": expected,
        "recall": round(len(validated) / expected, 3) if expected else None,
        "persisted": len(persisted),
        "findings": [v.model_dump(mode="json") for v in persisted],
    }


# DUPLICATE ROUTE REMOVED (audit 2026-08-01): GET /{session_id}/report/bounty was
# defined both here (engagements, registering FIRST in main.py so it won) and in
# routers/findings.py:171. This handler called core.report_generator.generate_bounty_report
# directly, bypassing the reporting-mcp; the findings handler is the canonical,
# reporting-mcp-backed implementation that the working tests + fixtures target.
# The engagements copy shadowed it. Exactly one bounty-report route remains:
# findings.py. core/report_generator.py stays available for other callers.


@router.post(
    "/{session_id}/transition",
    summary="Transition engagement phase",
    description="Advance an engagement to the next lifecycle phase (e.g. reconnaissance, exploitation, reporting).",
)
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


@router.post(
    "/{session_id}/halt",
    summary="Halt engagement",
    description="Emergency halt of an engagement. Stops all running tasks and transitions the session to a halted state.",
)
async def halt_engagement(
    session_id: str,
    reason: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Emergency halt engagement."""
    await assert_engagement_access(operator, session_id)
    await state["orchestrator"].halt_engagement(session_id, reason)
    return {"status": "halted", "session_id": session_id, "reason": reason}
