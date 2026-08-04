"""AI-OSOP Approval Router

Approval workflow endpoints for human-in-the-loop gates.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import (
    ApprovalDecisionRequest,
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)

router = APIRouter(prefix="/approvals", tags=["approvals"])

# AIOSOP-SCALE-005 (2026-08-03): bound the pending-approvals dump. The router
# previously returned every pending request with no limit — a fleet of parked
# exploit tasks or a long-lived engagement can leave hundreds. Server-side
# default cap + offset like list_tasks/findings.
_DEFAULT_APPROVALS_LIMIT = 200
_MAX_APPROVALS_LIMIT = 2000


@router.get(
    "/pending",
    summary="List pending approvals",
    description="Return all pending human-in-the-loop approval requests visible to the caller. Bounded by limit/offset.",
)
async def list_pending_approvals(
    limit: int = Query(_DEFAULT_APPROVALS_LIMIT, ge=1),
    offset: int = Query(0, ge=0),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """List all pending approval requests visible to the operator.

    Bounded by ``limit``/``offset`` (default 200, max 2000).
    """
    pending = [
        req.model_dump()
        for req in state["orchestrator"]._approval_requests.values()
        if req.status == "pending"
    ]
    # Filter by engagement access: operators see only approvals for engagements they own
    if operator.get("role") != "senior_operator":
        accessible = set()
        for sid, sess in state["orchestrator"]._sessions.items():
            if sess.created_by == operator.get("sub"):
                accessible.add(sid)
        pending = [p for p in pending if p.get("engagement_id") in accessible]
    effective = min(limit, _MAX_APPROVALS_LIMIT)
    return pending[offset : offset + effective]


@router.get(
    "/{request_id}",
    summary="Get approval request",
    description="Retrieve the details of a specific approval request by its ID.",
)
async def get_approval(request_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get approval request details."""
    request = state["orchestrator"]._approval_requests.get(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    await assert_engagement_access(operator, request.engagement_id)
    return request


@router.post(
    "/{request_id}/resolve",
    summary="Resolve approval request",
    description="Approve or reject a pending approval request. Only senior operators may resolve approvals.",
)
async def resolve_approval(
    request_id: str,
    decision: ApprovalDecisionRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Resolve an approval request."""
    request = state["orchestrator"]._approval_requests.get(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    # Engagement binding check: senior operator must have access to the engagement
    await assert_engagement_access(operator, request.engagement_id)
    try:
        result = await state["orchestrator"].resolve_approval(
            request_id=request_id,
            decision=decision.decision,
            operator_id=decision.operator_id,
            notes=decision.notes,
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
