"""ApprovalCoordinator — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all approval request lifecycle: registration, raising, resolution, and timeout handling.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Dict, Optional

from ai_osop.core.config import settings
from ai_osop.core.models import ApprovalRequest, AuditEvent
from ai_osop.core.tracing import trace_span
from ai_osop.core.observability import record_approval_requested, record_approval_resolved
from ai_osop.core.exceptions import WorkflowException

import structlog

logger = structlog.get_logger("ai_osop.orchestrator.approval_coordinator")


class ApprovalCoordinator:
    """Manage approval requests and operator decisions."""

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        """Submit approval request and BLOCK until the operator decides (or timeout)."""
        await self._register_approval(request)
        try:
            await asyncio.wait_for(
                self._wait_for_approval(request.id), timeout=settings.approval_timeout_seconds
            )
        except asyncio.TimeoutError:
            request.status = "timeout"
            request.operator_notes = "Auto-rejected due to timeout"
        return request

    async def _register_approval(self, request: ApprovalRequest) -> None:
        """Register an approval request and fan it out to operator-notification callbacks."""
        self._orch._approval_requests[request.id] = request
        await self._orch.session_memory.store_approval_request(request)
        for callback in self._orch._approval_callbacks:
            try:
                await callback(request)
            except Exception:
                pass

    async def _raise_approval(self, request: ApprovalRequest) -> None:
        """Non-blocking approval used by the scheduler. Registers + notifies, then spawns
        a background watcher so a denial/timeout fails the parked task WITHOUT stalling
        the scheduler."""
        await self._register_approval(request)
        asyncio.create_task(self._await_approval_outcome(request.id))

    async def _await_approval_outcome(self, request_id: str) -> None:
        """Background: wait out the approval timeout; on timeout/denial fail the parked task."""
        try:
            await asyncio.wait_for(
                self._wait_for_approval(request_id), timeout=settings.approval_timeout_seconds
            )
        except asyncio.TimeoutError:
            request = self._orch._approval_requests.get(request_id)
            if request and request.status not in ("approved", "rejected", "modified"):
                request.status = "timeout"
                request.operator_notes = "Auto-rejected due to timeout"
                await self._orch.session_memory.store_approval_request(request)
        request = self._orch._approval_requests.get(request_id)
        if not request or request.status == "approved":
            return
        task = self._orch._tasks.get(request.task_id)
        if task and task.status == "awaiting_approval":
            await self._orch.task_scheduler._on_task_failure(
                task, {"error": f"Approval denied: {request.status}"}
            )

    async def _wait_for_approval(self, request_id: str) -> None:
        """Wait for approval request to be resolved."""
        while True:
            request = self._orch._approval_requests.get(request_id)
            if request and request.status in ["approved", "rejected", "modified"]:
                return
            await asyncio.sleep(1)

    async def resolve_approval(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Resolve an approval request with operator decision."""
        with trace_span(
            "orchestrator.resolve_approval",
            attributes={
                "request_id": request_id,
                "decision": decision,
                "operator_id": operator_id,
            },
        ):
            request = self._orch._approval_requests.get(request_id)
            if not request:
                raise WorkflowException(f"Approval request {request_id} not found")

            request.status = decision
            request.operator_id = operator_id
            request.operator_notes = notes
            request.responded_at = datetime.utcnow()

            # Sprint 6B: Record approval resolution metrics
            wait_seconds = None
            if request.requested_at:
                wait_seconds = (request.responded_at - request.requested_at).total_seconds()
            record_approval_resolved(decision, wait_seconds)

            await self._orch.session_memory.store_approval_request(request)

            # Update task payload if approved
            if decision == "approved":
                task = self._orch._tasks.get(request.task_id)
                if task:
                    task.payload["operator_approved"] = True
                    task.payload["approval_id"] = request.id
                    await self._orch.task_scheduler._assign_task(task)
                    await self._orch.session_memory.store_task(task)

            # Audit log
            await self._orch._audit_log(
                AuditEvent(
                    event_type="approval_resolved",
                    severity="info" if decision == "approved" else "warning",
                    actor_type="operator",
                    actor_id=operator_id,
                    action={
                        "request_id": request_id,
                        "task_id": request.task_id,
                        "decision": decision,
                    },
                    result={"status": decision, "notes": notes},
                    context={"engagement_id": request.engagement_id},
                    engagement_id=request.engagement_id,
                )
            )

            return request

    @staticmethod
    def _strip_stale_approval(task) -> None:
        """Drop persisted approval grant so gate re-fires."""
        if task.approval_required and isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)
