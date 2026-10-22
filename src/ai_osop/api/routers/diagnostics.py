"""Authenticated, engagement-scoped execution diagnostics."""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import assert_engagement_access, state, verify_token
from ai_osop.observability.engagement_diagnostics import build_engagement_diagnostics

logger = logging.getLogger("ai_osop.api.diagnostics")
router = APIRouter(prefix="/engagements", tags=["diagnostics"])


@router.get("/{engagement_id}/diagnostics")
async def engagement_diagnostics(
    engagement_id: str,
    limit: int = Query(50, ge=1, le=200),
    operator: Dict[str, Any] = Depends(verify_token),
) -> Dict[str, Any]:
    """Inspect task health and recent audit provenance for an owned engagement.

    Audit action, result and context payloads are never returned. The response
    degrades to live task diagnostics if the audit database is unavailable.
    """
    session = await assert_engagement_access(operator, engagement_id)
    orchestrator = state.get("orchestrator")
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")

    audit_available = True
    events = []
    try:
        events = await orchestrator.session_memory.query_audit_log(engagement_id, limit=limit)
    except Exception:
        audit_available = False
        logger.exception("engagement_audit_query_failed", extra={"engagement_id": engagement_id})

    return build_engagement_diagnostics(
        engagement_id=engagement_id,
        phase=session.phase,
        tasks=list(orchestrator._tasks.values()),
        events=events,
        event_limit=limit,
        audit_available=audit_available,
    )
