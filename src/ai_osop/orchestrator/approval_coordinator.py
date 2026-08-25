"""ApprovalCoordinator — extracted from Orchestrator for Sprint 9 Architecture Excellence.

Handles all approval request lifecycle: registration, raising, resolution, and timeout handling.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Optional

import structlog

from ai_osop.core.config import settings
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ApprovalRequest, AuditEvent
from ai_osop.core.observability import record_approval_resolved
from ai_osop.core.tracing import trace_span

logger = structlog.get_logger("ai_osop.orchestrator.approval_coordinator")


class ApprovalCoordinator:
    """Manage approval requests and operator decisions."""

    def __init__(self, orchestrator: Any) -> None:
        self._orch = orchestrator

    async def request_approval(self, request: ApprovalRequest) -> ApprovalRequest:
        """Submit approval request and BLOCK until the operator decides (or timeout)."""
        # Get engagement session to verify scope signature
        session = await self._orch.session_memory.get_session_by_engagement_id(
            request.engagement_id
        )
        if not session:
            raise WorkflowException(f"Engagement {request.engagement_id} not found")

        # Verify scope signature with the SINGLE shared signing key (OSOP-P0-03), so
        # verification can never diverge from how engagement_manager signed it. This
        # fail-closes in production when OSOP_AUDIT_SECRET_KEY is unset.
        from ai_osop.core.config import scope_signing_key

        if not session.scope.verify_signature(scope_signing_key()):
            raise WorkflowException("Scope signature verification failed")

        # Audit log approval_requested
        await self._orch._audit_log(
            AuditEvent(
                event_type="approval_requested",
                severity="info",
                actor_type="system",
                actor_id="system",
                action={
                    "request_id": request.id,
                    "task_id": request.task_id,
                },
                result={"status": "pending"},
                context={"engagement_id": request.engagement_id},
                engagement_id=request.engagement_id,
            )
        )

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
            except Exception as e:
                logger.warning("broad_exception_caught", error=str(e))
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

    async def _wait_for_approval(
        self, request_id: str, max_wait_seconds: Optional[int] = None
    ) -> None:
        """Wait for approval request to be resolved.

        Args:
            request_id: The approval request ID to wait for.
            max_wait_seconds: DEPRECATED. Timeout is handled by the caller via
                asyncio.wait_for() so that the full approval_timeout_seconds
                (default 1800s) is honoured.
        """
        start = asyncio.get_event_loop().time()
        while True:
            request = self._orch._approval_requests.get(request_id)
            if request and request.status in ["approved", "rejected", "modified"]:
                return
            if (
                max_wait_seconds is not None
                and asyncio.get_event_loop().time() - start > max_wait_seconds
            ):
                logger.warning(
                    "approval_wait_timeout",
                    request_id=request_id,
                    max_wait_seconds=max_wait_seconds,
                )
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

            # AIOSOP-APPROVAL-VOCAB-001: normalize the operator decision to the
            # canonical status set (approved/rejected/modified). Callers (the API,
            # ops scripts) have historically sent "denied"/"deny"/"reject" — none of
            # which the approval waiters recognize (_wait_for_approval only matches
            # approved/rejected/modified), so a "denied" decision left the gated task
            # parked in `awaiting_approval` until the 1800s timeout and stalled the
            # whole exploitation phase.
            decision = self._canonical_decision(decision)
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

            if decision == "approved":
                # Grant: inject the operator-resolved approval_id and re-dispatch.
                task = self._orch._tasks.get(request.task_id)
                if task:
                    task.payload["operator_approved"] = True
                    task.payload["approval_id"] = request.id
                    await self._orch.task_scheduler._assign_task(task)
                    await self._orch.session_memory.store_task(task)
            elif decision in ("rejected", "modified"):
                # Deny: fail the parked task NOW. Previously a non-approval decision
                # did nothing here — the only denial path was a background timeout
                # watcher that (a) exists only for scheduler-raised approvals and
                # (b) waited out the full approval_timeout_seconds — so a rejected
                # exploit left the engagement stuck in `exploitation` for up to 30 min.
                # _on_task_failure sets a terminal "failed" status (no retry), which
                # lets _is_phase_complete advance the phase.
                task = self._orch._tasks.get(request.task_id)
                if task and task.status == "awaiting_approval":
                    await self._orch.task_scheduler._on_task_failure(
                        task,
                        {
                            "status": "failed",
                            "error": f"Approval {decision}: {notes or 'operator decision'}",
                            "error_type": "ApprovalDenied",
                        },
                    )

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

    def is_task_approved(self, task_id: str) -> bool:
        """Single source of authority for whether a task may run.

        Returns True ONLY if an ApprovalRequest for this task was resolved
        "approved" by a named operator. This deliberately does NOT consult
        ``task.payload["operator_approved"]`` — that field is agent-writable and
        persisted to Neo4j/Redis, so trusting it is the GAP-2-1/GAP-2-2 bypass.
        Approval lives in the (operator-resolved) ApprovalRequest record only.
        """
        for req in self._orch._approval_requests.values():
            if req.task_id == task_id and req.status == "approved" and req.operator_id:
                return True
        return False

    def approved_request_id(self, task_id: str) -> Optional[str]:
        """Return the id of the operator-approved ApprovalRequest for this task, if any.

        The trusted source of an approval token. The scheduler uses this to re-inject
        payload["approval_id"] just-in-time before executing a genuinely-approved task,
        because the payload token is deliberately stripped on retry/ingress (GAP-2-1/2-3)
        while the ApprovalRequest record remains the durable authority. Without this a
        retried-but-approved exploit runs with a stripped id and fails
        "requires an approval_id".
        """
        for req in self._orch._approval_requests.values():
            if req.task_id == task_id and req.status == "approved" and req.operator_id:
                return req.id
        return None

    def has_pending_approval(self, task_id: str) -> bool:
        """True if an unresolved approval request already exists for this task.

        AIOSOP-APPROVAL-DEDUPE-001: the scheduler consults this before raising a
        new ApprovalRequest so that concurrent/re-entrant _assign_task calls for the
        same task (e.g. the in-memory Task plus a copy reloaded from durable state,
        both still "pending") cannot each raise a duplicate approval and flood the
        operator. Authority remains the ApprovalRequest record, never task.payload.
        """
        for req in self._orch._approval_requests.values():
            if req.task_id == task_id and req.status == "pending":
                return True
        return False

    @staticmethod
    def _canonical_decision(decision: str) -> str:
        """Map operator-decision synonyms onto the canonical status vocabulary
        (approved / rejected / modified) used by the approval waiters and gate."""
        d = str(decision or "").strip().lower()
        if d in (
            "approved",
            "approve",
            "accept",
            "accepted",
            "allow",
            "allowed",
            "grant",
            "granted",
        ):
            return "approved"
        if d in (
            "rejected",
            "reject",
            "denied",
            "deny",
            "decline",
            "declined",
            "refused",
            "refuse",
        ):
            return "rejected"
        if d in ("modified", "modify", "amend", "amended", "changed"):
            return "modified"
        return d

    @staticmethod
    def _strip_stale_approval(task) -> None:
        """Drop persisted approval grant so gate re-fires."""
        if task.approval_required and isinstance(task.payload, dict):
            task.payload.pop("operator_approved", None)
            task.payload.pop("approval_id", None)
