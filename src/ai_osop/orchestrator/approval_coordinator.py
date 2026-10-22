"""ApprovalCoordinator — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all approval request lifecycle: registration, raising, resolution, and timeout handling.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ai_osop.core.config import settings
from ai_osop.core.models import ApprovalRequest, AuditEvent
from ai_osop.core.tracing import trace_span
from ai_osop.core.observability import record_approval_requested, record_approval_resolved
from ai_osop.core.exceptions import WorkflowException

import structlog

logger = structlog.get_logger("ai_osop.orchestrator.approval_coordinator")


def remaining_durable_approval_seconds(request: Optional[ApprovalRequest], timeout_seconds: float) -> float:
    """Remaining lifetime of a parked human review across process restarts.

    Restarting a watcher must not give an already-expired approval a fresh
    full timeout. Unknown/invalid timestamps fail toward immediate expiry,
    not an indefinite or extended approval window.
    """
    if request is None or not isinstance(request.requested_at, datetime):
        return 0.0
    start = request.requested_at
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    else:
        start = start.astimezone(timezone.utc)
    remaining = float(timeout_seconds) - (
        datetime.now(timezone.utc) - start
    ).total_seconds()
    return max(0.0, min(max(0.0, float(timeout_seconds)), remaining))


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
            request, _ = await self._orch._expire_pending_approval(request.id)
        return request

    async def _register_approval(self, request: ApprovalRequest) -> None:
        """Register an approval request and fan it out to operator-notification callbacks."""
        await self._orch.session_memory.store_approval_request(request)
        self._orch._approval_requests[request.id] = request
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
            pending = self._orch._approval_requests.get(request_id)
            remaining = remaining_durable_approval_seconds(
                pending, settings.approval_timeout_seconds,
            )
            await asyncio.wait_for(
                self._wait_for_approval(request_id), timeout=remaining
            )
        except asyncio.TimeoutError:
            try:
                await self._orch._expire_pending_approval(request_id)
            except Exception as exc:
                logger.warning("approval_timeout_persistence_unavailable", error_type=type(exc).__name__)
                return
        request = self._orch._approval_requests.get(request_id)
        if not request or request.status == "approved":
            return
        from ai_osop.memory.session_memory import SessionMemory
        if isinstance(self._orch.session_memory, SessionMemory):
            return  # PostgreSQL already settled the terminal task/outbox.
        task = self._orch._tasks.get(request.task_id)
        if task and task.status == "awaiting_approval":
            await self._orch.task_scheduler._on_task_failure(
                task, {"error": f"Approval denied: {request.status}"}
            )

    async def _wait_for_approval(self, request_id: str) -> None:
        """Wait for approval request to be resolved."""
        while True:
            request = self._orch._approval_requests.get(request_id)
            if request and request.status in ["approved", "rejected", "modified", "timeout"]:
                return
            await asyncio.sleep(1)

    async def resolve_approval(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Serialize approvals with the orchestrator's legacy decision path."""
        from ai_osop.memory.session_memory import SessionMemory
        if isinstance(self._orch.session_memory, SessionMemory):
            # There is exactly one production decision path. It signs and
            # fences an approval and its task grant atomically in PostgreSQL.
            return await self._orch.resolve_approval(
                request_id, decision, operator_id, notes
            )
        async with self._orch._approval_decision_locks.setdefault(request_id, asyncio.Lock()):
            return await self._resolve_approval_locked(request_id, decision, operator_id, notes)

    async def _resolve_approval_locked(
        self, request_id: str, decision: str, operator_id: str, notes: Optional[str] = None
    ) -> ApprovalRequest:
        """Keep pending state visible until the decision write succeeds."""
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
            if request.status != "pending":
                return request

            task = self._orch._tasks.get(request.task_id)
            if task and task.engagement_id != request.engagement_id:
                raise WorkflowException("Approval and task engagement do not match")
            session = self._orch._sessions.get(request.engagement_id)
            if session is None or session.phase in {"halted", "completed"}:
                raise WorkflowException("Approval engagement is inactive")
            if task is None or task.status in {"completed", "failed", "cancelled"}:
                raise WorkflowException("Approval task is no longer actionable")
            if decision not in {"approved", "rejected"}:
                raise WorkflowException("Invalid approval decision")
            if decision == "approved" and task.status != "awaiting_approval":
                raise WorkflowException("Approval task is not awaiting a decision")
            if task.type == "planner_inference":
                # The internal planner is never dispatched via an external
                # agent when a generic approval request is resolved.
                raise WorkflowException("Internal planner approval cannot dispatch an agent task")

            resolved = request.model_copy(update={
                "status": decision, "operator_id": operator_id,
                "operator_notes": notes, "responded_at": datetime.utcnow(),
            })
            await self._orch.session_memory.store_approval_request(resolved)
            request.status = resolved.status
            request.operator_id = resolved.operator_id
            request.operator_notes = resolved.operator_notes
            request.responded_at = resolved.responded_at

            # Sprint 6B: Record approval resolution metrics
            wait_seconds = None
            if request.requested_at:
                wait_seconds = (request.responded_at - request.requested_at).total_seconds()
            record_approval_resolved(decision, wait_seconds)

            # Update task payload if approved
            if decision == "approved":
                if task:
                    task.payload["operator_approved"] = True
                    task.payload["approval_id"] = request.id
                    await self._orch.session_memory.store_task(task)
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
