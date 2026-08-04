"""AI-OSOP DLQ Router

Dead Letter Queue endpoints for operator review and management.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ai_osop.api.deps import assert_engagement_access, require_role, state
from ai_osop.core.models import AuditEvent
from ai_osop.core.tracing import trace_span
from ai_osop.reliability.dlq import DLQEntry

router = APIRouter(prefix="/dlq", tags=["dlq"])


class DLQListResponse(BaseModel):
    entries: List[DLQEntry]
    total: int


class DLQActionResponse(BaseModel):
    success: bool
    message: str
    entry_id: Optional[str] = None


@router.get(
    "",
    response_model=DLQListResponse,
    summary="List DLQ entries",
    description="List Dead Letter Queue entries with optional filtering by engagement ID and status. Non-senior operators must provide an engagement_id.",
)
async def list_dlq_entries(
    engagement_id: Optional[str] = None,
    status: Optional[str] = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """List DLQ entries with optional filtering by engagement and status."""
    with trace_span("api.dlq.list", attributes={"engagement_id": engagement_id or "all"}):
        orchestrator = state.get("orchestrator")
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not available")

        # Ownership check: if user is not senior_operator, restrict to their engagement.
        # AIOSOP-DLQ-AUTHZ-001 (2026-08-03): the old check compared against
        # ``operator.get("engagement_id")`` — a claim that exists on NO identity
        # (JWT claims are sub/role/tenant_id; the static-token identity is
        # sub/role/tenant_id too), so every non-senior operator was rejected 403
        # and the DLQ audit endpoints were dead for the operators who need them.
        # The operator's engagement is "one they created"; resolve it through the
        # same assert_engagement_access tenant + ownership rules.
        if operator.get("role") != "senior_operator":
            if not engagement_id:
                raise HTTPException(
                    status_code=403, detail="engagement_id required for non-senior operators"
                )
            await assert_engagement_access(operator, engagement_id)

        entries = await orchestrator.session_memory.list_dlq_entries(engagement_id, status)
        return DLQListResponse(entries=entries, total=len(entries))


@router.get(
    "/{entry_id}",
    response_model=DLQEntry,
    summary="Get DLQ entry details",
    description="Retrieve the full details of a single DLQ entry by its ID, including the original error and task context.",
)
async def get_dlq_entry(
    entry_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Get a single DLQ entry by ID."""
    with trace_span("api.dlq.get", attributes={"dlq_entry_id": entry_id}):
        orchestrator = state.get("orchestrator")
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not available")

        entry = await orchestrator.session_memory.get_dlq_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail="DLQ entry not found")

        # Ownership check. AIOSOP-DLQ-AUTHZ-001: same dead-claim bug as the list
        # endpoint — ``operator.get("engagement_id")`` never exists. Route the
        # entry's engagement through assert_engagement_access (tenant + ownership).
        if operator.get("role") != "senior_operator":
            await assert_engagement_access(operator, entry.engagement_id)

        return entry


@router.post(
    "/{entry_id}/requeue",
    response_model=DLQActionResponse,
    summary="Requeue DLQ entry",
    description="Move a DLQ entry back into the normal task queue for retry. Only senior operators may requeue.",
)
async def requeue_dlq_entry(
    entry_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Requeue a DLQ entry for retry."""
    with trace_span("api.dlq.requeue", attributes={"dlq_entry_id": entry_id}):
        orchestrator = state.get("orchestrator")
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not available")

        entry = await orchestrator.session_memory.get_dlq_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail="DLQ entry not found")

        await orchestrator.dlq.requeue(entry_id)

        # Audit log
        await orchestrator._audit_log(
            AuditEvent(
                event_type="dlq_requeued",
                severity="info",
                actor_type="operator",
                actor_id=operator.get("id", "unknown"),
                action={"dlq_entry_id": entry_id, "task_id": entry.task_id},
                result={"success": True},
                context={},
                engagement_id=entry.engagement_id,
            )
        )

        return DLQActionResponse(
            success=True,
            message="Entry requeued successfully",
            entry_id=entry_id,
        )


@router.post(
    "/{entry_id}/discard",
    response_model=DLQActionResponse,
    summary="Discard DLQ entry",
    description="Permanently discard a DLQ entry. Only senior operators may discard entries.",
)
async def discard_dlq_entry(
    entry_id: str,
    notes: Optional[str] = None,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Permanently discard a DLQ entry."""
    with trace_span("api.dlq.discard", attributes={"dlq_entry_id": entry_id}):
        orchestrator = state.get("orchestrator")
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not available")

        entry = await orchestrator.session_memory.get_dlq_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail="DLQ entry not found")

        await orchestrator.dlq.discard(entry_id, operator_notes=notes)

        # Audit log
        await orchestrator._audit_log(
            AuditEvent(
                event_type="dlq_discarded",
                severity="warning",
                actor_type="operator",
                actor_id=operator.get("id", "unknown"),
                action={"dlq_entry_id": entry_id, "task_id": entry.task_id, "notes": notes},
                result={"success": True},
                context={},
                engagement_id=entry.engagement_id,
            )
        )

        return DLQActionResponse(
            success=True,
            message="Entry discarded successfully",
            entry_id=entry_id,
        )


@router.post(
    "/{entry_id}/retry",
    response_model=DLQActionResponse,
    summary="Retry DLQ entry",
    description="Retry a DLQ entry (alias for requeue). Moves the entry back into the normal task queue.",
)
async def retry_dlq_entry(
    entry_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Retry a DLQ entry (alias for requeue)."""
    with trace_span("api.dlq.retry", attributes={"dlq_entry_id": entry_id}):
        orchestrator = state.get("orchestrator")
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not available")

        entry = await orchestrator.session_memory.get_dlq_entry(entry_id)
        if not entry:
            raise HTTPException(status_code=404, detail="DLQ entry not found")

        await orchestrator.dlq.requeue(entry_id)

        # Audit log
        await orchestrator._audit_log(
            AuditEvent(
                event_type="dlq_retried",
                severity="info",
                actor_type="operator",
                actor_id=operator.get("id", "unknown"),
                action={"dlq_entry_id": entry_id, "task_id": entry.task_id},
                result={"success": True},
                context={},
                engagement_id=entry.engagement_id,
            )
        )

        return DLQActionResponse(
            success=True,
            message="Entry retried successfully",
            entry_id=entry_id,
        )
