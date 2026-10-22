"""Durable, single-use execution identity for calls to the paid model planner.

The Flow objective is planned, and the strategic planner's parent is completed.
Neither can be used as a model-usage execution identity. A planner task is
claimed separately under the engagement lock and the Flow revision CAS.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterator, Optional

from structlog.contextvars import bound_contextvars
from sqlalchemy import select, update

from ai_osop.core.config import AgentType
from ai_osop.core.models import ApprovalRequest, FlowRecord, ScopeDefinition, Task
from ai_osop.core.telemetry import (
    ENGAGEMENT_ID_CTX_VAR,
    FLOW_ID_CTX_VAR,
    SUBTASK_ID_CTX_VAR,
    TASK_ID_CTX_VAR,
)
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.memory.session_memory import (
    ApprovalRequestORM,
    ExecutionFlowORM,
    ExecutionSubtaskORM,
    TaskORM,
)
from ai_osop.memory.supervision_store import (
    SupervisionConflict,
    SupervisionControlORM,
    SupervisionStore,
)
from ai_osop.safety.scope import action_requires_approval


class PlannerApprovalPending(RuntimeError):
    """An internal provider call is parked until an operator explicitly approves."""

    def __init__(self, approval_id: str, task_id: str, revision: int):
        super().__init__("Planner inference awaits a signed human decision")
        self.approval_id = approval_id
        self.task_id = task_id
        self.revision = revision

    def response(self) -> dict[str, Any]:
        return {
            "status": "awaiting_planner_approval",
            "approval_id": self.approval_id,
            "task_id": self.task_id,
            "flow_revision": self.revision,
        }


@dataclass(frozen=True)
class PlannerAdmission:
    task_id: str
    engagement_id: str
    flow_id: str
    revision: int
    subtask_id: Optional[str]

    @contextmanager
    def bind_context(self) -> Iterator[None]:
        """Restore the previous task after the nested provider invocation."""
        bindings = (
            (ENGAGEMENT_ID_CTX_VAR, self.engagement_id),
            (TASK_ID_CTX_VAR, self.task_id),
            (FLOW_ID_CTX_VAR, self.flow_id),
            (SUBTASK_ID_CTX_VAR, self.subtask_id or ""),
        )
        tokens = [(var, var.set(value)) for var, value in bindings]
        try:
            with bound_contextvars(
                engagement_id=self.engagement_id,
                task_id=self.task_id,
                flow_id=self.flow_id,
                subtask_id=self.subtask_id or "",
            ):
                yield
        finally:
            for var, token in reversed(tokens):
                var.reset(token)


class PlannerExecutionStore(SupervisionStore):
    """One irrevocable claim per planner input, across all process replicas.

    A stranded `running` planner task is deliberately never retried: after
    provider submission its remote outcome and charge may be unknown.
    """

    @staticmethod
    def task_id(
        flow_id: str, parent_id: str, purpose: str, source_id: str = "", pass_number: int = 0
    ) -> str:
        seed = f"{flow_id}:{parent_id}:{purpose}:{source_id}:{pass_number}"
        return "task-planner-" + hashlib.sha256(seed.encode()).hexdigest()[:32]

    @staticmethod
    def approval_id(task_id: str) -> str:
        return "apr-planner-" + task_id.removeprefix("task-planner-")

    async def resolve_internal_approval(
        self,
        request_id: str,
        engagement_id: str,
        task_id: str,
        decision: str,
        operator_id: str,
        *,
        actor_role: str,
        expected_authorization_version: int,
        expected_flow_revision: int,
        notes: Optional[str] = None,
    ) -> tuple[ApprovalRequest, bool]:
        """Signed, operator-verified internal decision; never dispatch an agent.

        The caller must supply `operator_id` and `actor_role` from a verified
        JWT, not HTTP request body fields. A committed approval leaves the task
        parked as `awaiting_approval`. An explicit planner retry later claims
        it under the same signed version and a new Flow CAS transaction.
        """
        if (
            actor_role != "senior_operator"
            or any(
                not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}", value) is None
                for value in (request_id, engagement_id, task_id, operator_id)
            )
            or request_id != self.approval_id(task_id)
            or decision not in {"approved", "rejected"}
            or type(expected_authorization_version) is not int
            or expected_authorization_version < 1
            or type(expected_flow_revision) is not int
            or expected_flow_revision < 0
            or (notes is not None and (not isinstance(notes, str) or len(notes) > 2048))
        ):
            raise PermissionError("Invalid or unauthorized internal planner decision")

        try:
            async with self._sessions() as db:
                async with db.begin():
                    engagement, _ = await self._guard(db, engagement_id, require_window=True)
                    signed = await guard_sql(
                        db,
                        engagement_id,
                        expected_version=expected_authorization_version,
                    )
                    scope = ScopeDefinition.model_validate(engagement.scope)
                    if not action_requires_approval("planner_inference", scope):
                        raise PermissionError(
                            "Current signed ROE does not require planner approval"
                        )
                    request = (
                        await db.execute(
                            select(ApprovalRequestORM)
                            .where(
                                ApprovalRequestORM.id == request_id,
                                ApprovalRequestORM.engagement_id == engagement_id,
                                ApprovalRequestORM.task_id == task_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        request is None
                        or request.action_type != "planner_inference"
                        or request.agent_id != "planner-runtime"
                    ):
                        raise PermissionError("No matching internal planner approval exists")
                    task = (
                        await db.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.id == task_id,
                                TaskORM.engagement_id == engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    payload = (
                        task.payload if task is not None and isinstance(task.payload, dict) else {}
                    )
                    if (
                        task is None
                        or task.type != "planner_inference"
                        or not task.approval_required
                        or not task.flow_id
                        or request.target != task.flow_id
                        or task.assigned_agent_id != "planner-runtime"
                        or type(payload.get("_authorization_version")) is not int
                        or payload["_authorization_version"] != signed.version
                        or payload.get("planner_flow_revision") != expected_flow_revision
                    ):
                        raise PermissionError("Internal planner authorization binding is stale")
                    flow = (
                        await db.execute(
                            select(ExecutionFlowORM)
                            .where(
                                ExecutionFlowORM.id == task.flow_id,
                                ExecutionFlowORM.engagement_id == engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        flow is None
                        or flow.status not in {"pending", "running"}
                        or flow.revision != expected_flow_revision
                    ):
                        raise PermissionError("Planner approval Flow revision changed")
                    if request.status == "pending":
                        if task.status != "awaiting_approval":
                            raise PermissionError(
                                "Planner task is no longer awaiting human approval"
                            )
                        if payload.get("approval_id") is not None:
                            raise PermissionError(
                                "Planner task already carries an unexpected grant"
                            )
                        request.status = decision
                        request.operator_id = operator_id
                        request.operator_notes = notes
                        request.responded_at = datetime.utcnow()
                        if decision == "approved":
                            # No task scheduling occurs here. The later
                            # PlannerExecutionStore.admit re-checks all fences.
                            task.payload = {
                                **task.payload,
                                "approval_id": request_id,
                                "operator_approved": True,
                            }
                        else:
                            task.status = "failed"
                            task.result = {"status": "failed", "reason": "operator_rejected"}
                            task.completed_at = datetime.utcnow()
                        await self._append_event(
                            db,
                            engagement_id,
                            task_id,
                            "planner.approval_resolved",
                            operator_id,
                            {"status": decision, "revision": expected_flow_revision},
                            idempotency_key="planner-approval-resolved:" + request_id,
                        )
                        await db.flush()
                        changed = True
                    else:
                        if request.status not in {"approved", "rejected"}:
                            raise PermissionError("Planner approval is no longer actionable")
                        changed = False
                    result = ApprovalRequest(
                        id=request.id,
                        task_id=request.task_id,
                        agent_id=request.agent_id,
                        action_type=request.action_type,
                        target=request.target,
                        payload_summary=request.payload_summary,
                        risk_assessment=request.risk_assessment,
                        evidence=request.evidence or [],
                        status=request.status,
                        operator_id=request.operator_id,
                        operator_notes=request.operator_notes,
                        requested_at=request.requested_at,
                        responded_at=request.responded_at,
                        engagement_id=request.engagement_id,
                    )
            return result, changed
        except (PermissionError, SupervisionConflict):
            raise PermissionError("Internal planner decision not authorized") from None
        except Exception as exc:
            raise RuntimeError("Durable planner approval is unavailable") from exc

    async def admit(
        self,
        flow: FlowRecord,
        parent: Task,
        *,
        purpose: str,
        source_id: Optional[str] = None,
        pass_number: int = 0,
    ) -> PlannerAdmission:
        if (
            purpose not in {"flow_generation", "flow_refinement", "adaptive_planning"}
            or parent.engagement_id != flow.engagement_id
            or flow.status not in {"pending", "running"}
            or parent.status != ("completed" if purpose == "adaptive_planning" else "planned")
            or (purpose != "adaptive_planning" and parent.flow_id != flow.id)
            or (purpose == "flow_refinement" and not source_id)
            or (purpose != "flow_refinement" and source_id is not None)
            or type(pass_number) is not int
            or pass_number < 0
            or pass_number > 3
        ):
            raise ModelBudgetExceeded("Planner task source is not authorized")
        identifier = self.task_id(flow.id, parent.id, purpose, source_id or "", pass_number)
        approval_id = self.approval_id(identifier)
        awaiting: Optional[PlannerApprovalPending] = None
        admitted_revision: Optional[int] = None
        try:
            async with self._sessions() as db:
                async with db.begin():
                    engagement, _ = await self._guard(db, flow.engagement_id, require_window=True)
                    signed = await guard_sql(db, flow.engagement_id)
                    scope = ScopeDefinition.model_validate(engagement.scope)
                    requires_approval = action_requires_approval("planner_inference", scope)
                    if purpose == "adaptive_planning" and not engagement.roe.get(
                        "adaptive_planning_enabled", False
                    ):
                        raise ModelBudgetExceeded("Autonomous planning is disabled by ROE")
                    durable_parent = (
                        await db.execute(
                            select(TaskORM)
                            .where(
                                TaskORM.id == parent.id,
                                TaskORM.engagement_id == flow.engagement_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    if (
                        durable_parent is None
                        or durable_parent.status != parent.status
                        or durable_parent.type != parent.type
                        or (purpose != "adaptive_planning" and durable_parent.flow_id != flow.id)
                    ):
                        raise ModelBudgetExceeded(
                            "Planner source is not in its durable required state"
                        )
                    if purpose == "flow_refinement":
                        row = (
                            await db.execute(
                                select(ExecutionSubtaskORM)
                                .where(
                                    ExecutionSubtaskORM.id == source_id,
                                    ExecutionSubtaskORM.flow_id == flow.id,
                                    ExecutionSubtaskORM.engagement_id == flow.engagement_id,
                                    ExecutionSubtaskORM.task_id == parent.id,
                                )
                                .with_for_update()
                            )
                        ).scalar_one_or_none()
                        if (
                            row is None
                            or row.status != "completed"
                            or row.refinement_count != pass_number
                            or not row.execution_task_id
                        ):
                            raise ModelBudgetExceeded("Planner refinement source is stale")
                        executed = (
                            await db.execute(
                                select(TaskORM.id)
                                .where(
                                    TaskORM.id == row.execution_task_id,
                                    TaskORM.engagement_id == flow.engagement_id,
                                    TaskORM.status == "completed",
                                )
                                .with_for_update()
                            )
                        ).scalar_one_or_none()
                        if executed is None:
                            raise ModelBudgetExceeded("Refinement execution is not confirmed")
                    # An existing claim, including a failed, unknown or stale
                    # running claim, cannot be replayed for the same input.
                    existing = (
                        await db.execute(select(TaskORM).where(TaskORM.id == identifier))
                    ).scalar_one_or_none()
                    if existing is not None:
                        payload = existing.payload if isinstance(existing.payload, dict) else {}
                        if (
                            not requires_approval
                            or existing.type != "planner_inference"
                            or existing.status != "awaiting_approval"
                            or existing.engagement_id != flow.engagement_id
                            or existing.flow_id != flow.id
                            or existing.parent_task_id != parent.id
                            or existing.subtask_id != source_id
                            or not existing.approval_required
                            or type(payload.get("_authorization_version")) is not int
                            or payload["_authorization_version"] != signed.version
                            or payload.get("planner_purpose") != purpose
                            or payload.get("planner_flow_revision") != flow.revision
                        ):
                            raise ModelBudgetExceeded("Planner execution cannot be replayed")
                        approval = (
                            await db.execute(
                                select(ApprovalRequestORM).where(
                                    ApprovalRequestORM.id == approval_id,
                                    ApprovalRequestORM.engagement_id == flow.engagement_id,
                                    ApprovalRequestORM.task_id == identifier,
                                )
                            )
                        ).scalar_one_or_none()
                        if (
                            approval is None
                            or approval.action_type != "planner_inference"
                            or approval.target != flow.id
                            or approval.agent_id != "planner-runtime"
                        ):
                            raise ModelBudgetExceeded("Planner approval identity is missing")
                        if approval.status == "pending":
                            awaiting = PlannerApprovalPending(
                                approval_id, identifier, flow.revision
                            )
                        elif (
                            approval.status != "approved"
                            or not approval.operator_id
                            or approval.responded_at is None
                            or payload.get("approval_id") != approval_id
                        ):
                            raise ModelBudgetExceeded("Planner approval was not granted")
                    latest_control = (
                        await db.execute(
                            select(SupervisionControlORM)
                            .where(
                                SupervisionControlORM.engagement_id == flow.engagement_id,
                                SupervisionControlORM.task_id.in_([parent.id, identifier]),
                                SupervisionControlORM.action.in_(
                                    ["pause", "resume", "cancel", "stop"]
                                ),
                            )
                            .order_by(
                                SupervisionControlORM.created_at.desc(),
                                SupervisionControlORM.request_id.desc(),
                            )
                            .limit(1)
                        )
                    ).scalar_one_or_none()
                    if latest_control is not None and latest_control.action in {
                        "pause",
                        "cancel",
                        "stop",
                    }:
                        raise ModelBudgetExceeded("Operator control blocks planner execution")
                    if awaiting is not None:
                        # Repeated polls do not change the review snapshot.
                        # A concurrent pause/revision invalidates it instead.
                        current_flow = (
                            await db.execute(
                                select(ExecutionFlowORM)
                                .where(
                                    ExecutionFlowORM.id == flow.id,
                                    ExecutionFlowORM.engagement_id == flow.engagement_id,
                                )
                                .with_for_update()
                            )
                        ).scalar_one_or_none()
                        if (
                            current_flow is None
                            or current_flow.revision != flow.revision
                            or current_flow.status != flow.status
                        ):
                            raise ModelBudgetExceeded(
                                "Planner Flow changed while awaiting approval"
                            )
                        revised = flow.revision
                    else:
                        revised = (
                            await db.execute(
                                update(ExecutionFlowORM)
                                .where(
                                    ExecutionFlowORM.id == flow.id,
                                    ExecutionFlowORM.engagement_id == flow.engagement_id,
                                    ExecutionFlowORM.revision == flow.revision,
                                    ExecutionFlowORM.status == flow.status,
                                    ExecutionFlowORM.status.in_(["pending", "running"]),
                                )
                                .values(
                                    revision=ExecutionFlowORM.revision + 1,
                                    updated_at=datetime.utcnow(),
                                )
                                .returning(ExecutionFlowORM.revision)
                            )
                        ).scalar_one_or_none()
                        if revised is None:
                            raise ModelBudgetExceeded("Flow changed before planner admission")
                    if existing is None:
                        status = "awaiting_approval" if requires_approval else "running"
                        db.add(
                            TaskORM(
                                id=identifier,
                                type="planner_inference",
                                priority=parent.priority,
                                agent_type=AgentType.CONTEXT_MANAGER.value,
                                payload={
                                    "_authorization_version": signed.version,
                                    "planner_purpose": purpose,
                                    **(
                                        {"planner_flow_revision": revised}
                                        if requires_approval
                                        else {}
                                    ),
                                },
                                dependencies=[],
                                max_retries=0,
                                timeout_seconds=parent.timeout_seconds,
                                scope_check=True,
                                approval_required=requires_approval,
                                status=status,
                                result=None,
                                retry_count=0,
                                created_at=datetime.utcnow(),
                                started_at=datetime.utcnow() if not requires_approval else None,
                                completed_at=None,
                                engagement_id=flow.engagement_id,
                                assigned_agent_id="planner-runtime",
                                flow_id=flow.id,
                                subtask_id=source_id,
                                parent_task_id=parent.id,
                            )
                        )
                        if requires_approval:
                            db.add(
                                ApprovalRequestORM(
                                    id=approval_id,
                                    task_id=identifier,
                                    agent_id="planner-runtime",
                                    action_type="planner_inference",
                                    target=flow.id,
                                    payload_summary="Internal model planning request for operator review",
                                    risk_assessment="Signed model budget and Flow revision required",
                                    evidence=[],
                                    status="pending",
                                    operator_id=None,
                                    operator_notes=None,
                                    requested_at=datetime.utcnow(),
                                    responded_at=None,
                                    engagement_id=flow.engagement_id,
                                )
                            )
                            awaiting = PlannerApprovalPending(approval_id, identifier, revised)
                    elif awaiting is None:
                        # A human-approved internal task remains parked until
                        # this explicit retry; generic approval never dispatches it.
                        existing.status = "running"
                        existing.started_at = datetime.utcnow()
                        existing.payload = {
                            **existing.payload,
                            "planner_flow_revision": revised,
                        }
                    if existing is None or awaiting is None:
                        await db.flush()
                        await self._append_event(
                            db,
                            flow.engagement_id,
                            identifier,
                            "planner.approval_requested" if awaiting else "planner.admitted",
                            "planner-runtime",
                            {
                                "status": "awaiting_approval" if awaiting else "running",
                                "revision": revised,
                                "source": purpose,
                            },
                            idempotency_key=(
                                "planner-request:" if awaiting else "planner-admitted:"
                            )
                            + identifier,
                        )
                    admitted_revision = revised
            if awaiting is not None:
                raise awaiting
            return PlannerAdmission(
                identifier, flow.engagement_id, flow.id, admitted_revision, source_id
            )
        except PlannerApprovalPending:
            raise
        except (ModelBudgetExceeded, SupervisionConflict):
            raise ModelBudgetExceeded("Durable planner admission denied") from None
        except Exception as exc:
            raise ModelBudgetExceeded("Durable planner admission unavailable") from exc

    async def finish(self, admission: PlannerAdmission, outcome: str) -> None:
        """Persist final local state and outbox. Unknown means remote unknown."""
        if outcome not in {"completed", "failed", "dispatch_unknown"}:
            raise ValueError("Invalid planner outcome")
        async with self._sessions() as db:
            async with db.begin():
                # Serialization with engagement control/revocation transactions;
                # finishing an already-admitted call remains possible if revoked.
                await self._guard(db, admission.engagement_id)
                updated = (
                    await db.execute(
                        update(TaskORM)
                        .where(
                            TaskORM.id == admission.task_id,
                            TaskORM.engagement_id == admission.engagement_id,
                            TaskORM.status == "running",
                            TaskORM.type == "planner_inference",
                        )
                        .values(
                            status=outcome,
                            result={"status": outcome},
                            completed_at=datetime.utcnow(),
                        )
                        .returning(TaskORM.id)
                    )
                ).scalar_one_or_none()
                if updated is None:
                    raise RuntimeError("Planner task settlement CAS was rejected")
                await self._append_event(
                    db,
                    admission.engagement_id,
                    admission.task_id,
                    "planner.finished",
                    "planner-runtime",
                    {"status": outcome, "revision": admission.revision},
                    idempotency_key="planner-finished:" + admission.task_id,
                )


async def run_planner_completion(
    store: PlannerExecutionStore,
    admission: PlannerAdmission,
    complete: Callable[..., Any],
    *args: Any,
    finalize: Optional[Callable[[Any], Any]] = None,
    **kwargs: Any,
) -> Any:
    """Never downgrade ambiguous provider/settlement outcomes to heuristics.

    Opt-in finalize runs *after* the one permitted provider call and owns the
    atomic PostgreSQL completion/validated-proposal transaction. It must not
    invoke a provider. The legacy path still settles just the receipt.
    """
    try:
        with admission.bind_context():
            result = await complete(*args, **kwargs)
    except ModelBudgetExceeded:
        try:
            await store.finish(admission, "failed")
        except Exception as exc:
            raise ModelOutcomeUncertain("Planner failure receipt was not persisted") from exc
        raise
    except BaseException as exc:
        try:
            await store.finish(admission, "dispatch_unknown")
        except Exception as exc:
            raise ModelOutcomeUncertain("Planner provider outcome could not be persisted") from exc
        if isinstance(exc, Exception) and not isinstance(exc, ModelOutcomeUncertain):
            raise ModelOutcomeUncertain("Planner provider execution is unverified") from exc
        raise
    try:
        if finalize is not None:
            return await finalize(result)
        await store.finish(admission, "completed")
        return result
    except asyncio.CancelledError:
        # The paid request has already returned. A cancellation during the
        # proposal transaction must never make its single-use admission appear
        # retryable. Try to persist UNKNOWN without suppressing shutdown; if a
        # completed proposal won the race, finish's running-only CAS denies
        # the downgrade. A failed receipt leaves the original running claim
        # quarantined and equally non-replayable.
        try:
            await asyncio.shield(store.finish(admission, "dispatch_unknown"))
        except BaseException:
            pass
        raise
    except Exception as exc:
        # A model may have been charged even if this local persistence failed.
        # Keep the original running/UNKNOWN Task (and the single-use claim)
        # rather than retry, marking a receipt complete without its content,
        # or running a deterministic replacement on ambiguous settlement.
        raise ModelOutcomeUncertain("Planner completion receipt was not persisted") from exc
