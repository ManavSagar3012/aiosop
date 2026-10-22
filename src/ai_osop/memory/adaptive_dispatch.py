"""Signed, operator-confirmed adaptive proposal -> pending Flow plan.

Only commits a planned Flow objective and a pending, approval-gated subtask.
It NEVER calls a task scheduler, Temporal activity, agent or external target.
The later explicit Flow subtask dispatch remains a separate authorization step.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Any

from sqlalchemy import select, update

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord, Task
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql
from ai_osop.memory.session_memory import (
    ApprovalRequestORM, ExecutionFlowORM, ExecutionSubtaskORM, TaskORM,
)
from ai_osop.memory.supervision_store import SupervisionConflict, SupervisionStore
from ai_osop.orchestrator.planner_execution import PlannerExecutionStore
from ai_osop.safety.scope import ScopeEnforcer, action_requires_approval


class AdaptiveDispatchDenied(PermissionError):
    """Signed authorization, policy, Flow or consent no longer permits admission."""


class AdaptiveDispatchUnavailable(RuntimeError):
    """Could not establish a durable, single-use pending Flow plan."""


_DOMAIN = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z"
)
_ALLOWED_RECON = frozenset({
    "recon", "reconnaissance", "full_recon", "sub_recon", "request_sub_recon",
})


def _bounded_target(value: Any, scope: ScopeDefinition) -> str:
    if not isinstance(value, str) or value != value.strip() or len(value) > 253:
        raise AdaptiveDispatchDenied("Invalid confirmed target")
    target = value.lower()
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not _DOMAIN.fullmatch(target):
            raise AdaptiveDispatchDenied("Only explicit domain or IP targets are permitted")
    enforcer = ScopeEnforcer(scope)
    enforcer.validate_time_window()
    try:
        if not enforcer.validate_target(target):
            raise AdaptiveDispatchDenied("Target not in signed scope")
    except AdaptiveDispatchDenied:
        raise
    except Exception as exc:
        raise AdaptiveDispatchDenied("Target not in signed scope") from exc
    return target


def is_adaptive_staged_subtask(subtask: SubtaskRecord) -> bool:
    """Identify the exact reserved namespace for signed adaptive follow-ups.

    This is only a routing hint, NOT authorization: the claim verifies all
    durable planner/approval/Flow/parent/step associations under PostgreSQL
    locks before admitting any provider or task scheduler work.
    """
    return (
        subtask.task_id.startswith("task-adaptive-")
        or subtask.id.startswith("subtask-adaptive-")
    )


def build_adaptive_execution_task(
    *, flow: FlowRecord, subtask: SubtaskRecord,
    target: str, priority: int = 5,
) -> Task:
    """Construct a deterministic *pending, unapproved* execution reservation.

    This is not authority: all stored lineage/target/signer versions are
    reloaded and verified inside claim_confirmed_adaptive_subtask's PG txn.
    """
    task_id = "task-adaptive-exec-" + hashlib.sha256(
        subtask.id.encode("utf-8")
    ).hexdigest()[:24]
    return Task(
        id=task_id, type="full_recon", agent_type=AgentType.RECON,
        engagement_id=flow.engagement_id, flow_id=flow.id,
        subtask_id=subtask.id, parent_task_id=subtask.task_id,
        payload={"target": target}, priority=priority,
        dependencies=[], scope_check=True, approval_required=True,
        max_retries=0, status="pending",
    )


async def claim_confirmed_adaptive_subtask(
    session_memory: Any,
    *,
    flow: FlowRecord,
    engagement: SessionState,
    subtask: SubtaskRecord,
    payload: dict[str, Any],
    expected_revision: int,
    actor_id: str,
    actor_role: str,
    execution_task: Task,
) -> dict[str, Any]:
    """Claim a signed human-confirmed target and Flow revision *atomically*.

    The reserved adaptive ID namespace cannot use the legacy claim_subtask,
    whose general scope guard alone would admit a DIFFERENT in-scope target.
    The only acceptable payload is the exact original confirmed target string;
    secondary URLs, hosts, command args and arbitrary agent options are denied.

    The pending TaskORM, step claim, Flow revision and dispatch-intent outbox
    are committed together. No queue/Temporal/agent call occurs in this helper.
    A separate scheduler hydration path must submit the durable pending task
    through the ordinary human approval gate before any target access.
    """
    if (
        actor_role != "senior_operator"
        or not isinstance(actor_id, str) or not actor_id or len(actor_id) > 64
        or type(expected_revision) is not int or expected_revision < 0
        or flow.engagement_id != engagement.session_id
        or subtask.engagement_id != engagement.session_id
        or subtask.flow_id != flow.id
        or not is_adaptive_staged_subtask(subtask)
        or not isinstance(payload, dict)
        or set(payload) != {"target"}
        or not isinstance(payload.get("target"), str)
        or flow.revision != expected_revision
        or flow.status not in {"pending", "running"}
        or subtask.status != "pending"
        or not isinstance(execution_task, Task)
        or execution_task.id != build_adaptive_execution_task(
            flow=flow, subtask=subtask, target=payload["target"],
            priority=execution_task.priority,
        ).id
        or execution_task.type != "full_recon"
        or execution_task.agent_type != AgentType.RECON
        or execution_task.status != "pending"
        or execution_task.engagement_id != engagement.session_id
        or execution_task.flow_id != flow.id
        or execution_task.subtask_id != subtask.id
        or execution_task.parent_task_id != subtask.task_id
        or execution_task.dependencies != []
        or execution_task.payload != payload
        or execution_task.approval_required is not True
        or execution_task.scope_check is not True
        or execution_task.max_retries != 0
        or execution_task.assigned_agent_id is not None
    ):
        raise AdaptiveDispatchDenied("Adaptive dispatch requires senior identity, exact target and Flow revision")

    store = PlannerExecutionStore(session_memory)
    try:
        async with store._sessions() as db:
            async with db.begin():
                durable, _ = await store._guard(
                    db, engagement.session_id,
                    actor_id=actor_id, actor_role=actor_role, require_window=True,
                )
                scope = ScopeDefinition.model_validate(durable.scope)
                if (
                    not isinstance(durable.roe, dict)
                    or durable.roe.get("adaptive_planning_enabled") is not True
                    or durable.phase not in {"reconnaissance", "vulnerability_discovery"}
                    or "no_active_scanning" in scope.restrictions
                    or "no_reconnaissance" in scope.restrictions
                    or not action_requires_approval("planner_inference", scope)
                    or not {str(t).strip().lower() for t in scope.allowed_techniques}.intersection(_ALLOWED_RECON)
                ):
                    raise AdaptiveDispatchDenied("Signed ROE no longer permits adaptive reconnaissance")
                current_flow = (await db.execute(select(ExecutionFlowORM).where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == engagement.session_id,
                ).with_for_update())).scalar_one_or_none()
                if (
                    current_flow is None
                    or current_flow.status != flow.status
                    or current_flow.status not in {"running", "pending"}
                    or current_flow.revision != expected_revision
                ):
                    raise AdaptiveDispatchDenied("Adaptive Flow changed before dispatch")

                parent = (await db.execute(select(TaskORM).where(
                    TaskORM.id == subtask.task_id,
                    TaskORM.engagement_id == engagement.session_id,
                    TaskORM.flow_id == flow.id,
                ).with_for_update())).scalar_one_or_none()
                parent_payload = parent.payload if parent is not None and isinstance(parent.payload, dict) else {}
                request_id = parent_payload.get("adaptive_source_approval_id")
                confirmed_target = parent_payload.get("planned_target")
                signer_version = parent_payload.get("_authorization_version")
                if (
                    parent is None or parent.type != "flow_objective"
                    or parent.status != "planned" or parent.agent_type != AgentType.RECON.value
                    or parent.parent_task_id is not None or parent.subtask_id is not None
                    or not parent.approval_required
                    or not isinstance(request_id, str) or not request_id
                    or type(signer_version) is not int or signer_version < 1
                    or not isinstance(confirmed_target, str)
                    or payload["target"] != confirmed_target
                ):
                    raise AdaptiveDispatchDenied("Confirmed adaptive parent or exact target binding is missing")

                # Bind the entire provenance to deterministic names assigned
                # in the human-confirmation transaction, not editable titles.
                digest = hashlib.sha256(
                    f"{engagement.session_id}:{request_id}:adaptive-recon".encode()
                ).hexdigest()[:24]
                if (
                    parent.id != f"task-adaptive-{digest}"
                    or subtask.id != f"subtask-adaptive-{digest}"
                ):
                    raise AdaptiveDispatchDenied("Adaptive objective/subtask identity is not authoritative")
                signing = await guard_sql(
                    db, engagement.session_id, expected_version=signer_version,
                )
                target = _bounded_target(confirmed_target, scope)
                if target != confirmed_target:
                    raise AdaptiveDispatchDenied("Confirmed adaptive target must be canonical")
                approval = (await db.execute(select(ApprovalRequestORM).where(
                    ApprovalRequestORM.id == request_id,
                    ApprovalRequestORM.engagement_id == engagement.session_id,
                ).with_for_update())).scalar_one_or_none()
                if (
                    approval is None or approval.status != "approved"
                    or approval.action_type != "planner_inference"
                    or approval.agent_id != "planner-runtime"
                    or not approval.operator_id or approval.responded_at is None
                    or approval.target != flow.id
                ):
                    raise AdaptiveDispatchDenied("Human planner approval is no longer valid")
                planner = (await db.execute(select(TaskORM).where(
                    TaskORM.id == approval.task_id,
                    TaskORM.engagement_id == engagement.session_id,
                    TaskORM.type == "planner_inference",
                ).with_for_update())).scalar_one_or_none()
                planner_payload = planner.payload if planner is not None and isinstance(planner.payload, dict) else {}
                planner_result = planner.result if planner is not None and isinstance(planner.result, dict) else {}
                confirmation = planner_result.get("adaptive_execution_admission")
                proposal = planner_result.get("adaptive_proposal")
                if (
                    planner is None or planner.status != "completed"
                    or not planner.approval_required
                    or planner.flow_id != flow.id or planner.assigned_agent_id != "planner-runtime"
                    or store.approval_id(planner.id) != request_id
                    or planner_payload.get("planner_purpose") != "adaptive_planning"
                    or planner_payload.get("approval_id") != request_id
                    or planner_payload.get("operator_approved") is not True
                    or planner_payload.get("_authorization_version") != signing.version
                    or planner_result.get("review_status") != "operator_review"
                    or not isinstance(confirmation, dict)
                    or confirmation.get("status") != "pending_dispatch_review"
                    or confirmation.get("objective_id") != parent.id
                    or confirmation.get("subtask_id") != subtask.id
                    or confirmation.get("flow_revision") != expected_revision
                    or confirmation.get("confirmed_by") != actor_id
                    or not isinstance(proposal, dict)
                    or proposal.get("action") != "request_sub_recon"
                    or not isinstance(proposal.get("parameters"), dict)
                    or proposal["parameters"].get("target") != target
                ):
                    raise AdaptiveDispatchDenied("Signed confirmation or original proposal binding changed")
                durable_step = (await db.execute(select(ExecutionSubtaskORM).where(
                    ExecutionSubtaskORM.id == subtask.id,
                    ExecutionSubtaskORM.engagement_id == engagement.session_id,
                    ExecutionSubtaskORM.flow_id == flow.id,
                    ExecutionSubtaskORM.task_id == parent.id,
                ).with_for_update())).scalar_one_or_none()
                if (
                    durable_step is None
                    or durable_step.status != "pending"
                    or durable_step.execution_task_id is not None
                    or durable_step.task_type != "full_recon"
                    or durable_step.agent_type != AgentType.RECON.value
                    or durable_step.approval_required is not True
                    or durable_step.dependencies != []
                    or durable_step.refinement_count != 0
                    or subtask.task_id != parent.id
                    or subtask.dependencies != []
                    or subtask.execution_task_id is not None
                    or subtask.refinement_count != 0
                    or durable_step.task_type != subtask.task_type
                    or durable_step.agent_type != subtask.agent_type.value
                    or durable_step.approval_required != subtask.approval_required
                ):
                    raise AdaptiveDispatchDenied("Adaptive subtask is not an untouched, approval-gated recon step")

                # Signer binding is not taken from the browser payload. It is
                # derived from the signed authoritative ledger while locks are
                # held. A newly created task can never assert its own approval.
                pinned_payload = {"target": target, "_authorization_version": signing.version}
                execution_task.payload = pinned_payload
                execution_task.status = "pending"
                execution_task.approval_required = True
                execution_task.created_at = datetime.utcnow()

                # Persistent task/step/Flow/event must be committed as ONE unit.
                # Do not rely on the later scheduler's store_task UPSERT to
                # create an execution task after a consumed Flow claim.
                db.add(TaskORM(
                    id=execution_task.id, type=execution_task.type,
                    priority=execution_task.priority,
                    agent_type=execution_task.agent_type.value,
                    payload=pinned_payload,
                    dependencies=[], max_retries=0,
                    timeout_seconds=execution_task.timeout_seconds,
                    scope_check=True, approval_required=True,
                    status="pending", result=None, retry_count=0,
                    created_at=execution_task.created_at,
                    started_at=None, completed_at=None,
                    engagement_id=engagement.session_id,
                    assigned_agent_id=None, flow_id=flow.id,
                    subtask_id=subtask.id, parent_task_id=parent.id,
                ))
                await db.flush()

                claim = (await db.execute(update(ExecutionSubtaskORM).where(
                    ExecutionSubtaskORM.id == subtask.id,
                    ExecutionSubtaskORM.engagement_id == engagement.session_id,
                    ExecutionSubtaskORM.flow_id == flow.id,
                    ExecutionSubtaskORM.task_id == parent.id,
                    ExecutionSubtaskORM.status == "pending",
                    ExecutionSubtaskORM.execution_task_id.is_(None),
                    ExecutionSubtaskORM.approval_required.is_(True),
                ).values(
                    status="dispatched",
                    execution_task_id=execution_task.id,
                    updated_at=datetime.utcnow(),
                )
                    .returning(ExecutionSubtaskORM.id))).scalar_one_or_none()
                if claim != subtask.id:
                    raise AdaptiveDispatchDenied("Adaptive subtask was already claimed")
                revision = (await db.execute(update(ExecutionFlowORM).where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == engagement.session_id,
                    ExecutionFlowORM.status == flow.status,
                    ExecutionFlowORM.revision == expected_revision,
                ).values(
                    revision=ExecutionFlowORM.revision + 1,
                    updated_at=datetime.utcnow(),
                ).returning(ExecutionFlowORM.revision))).scalar_one_or_none()
                if revision != expected_revision + 1:
                    raise AdaptiveDispatchDenied("Adaptive Flow CAS changed during dispatch")
                await SupervisionStore._append_event(
                    db, engagement.session_id, execution_task.id,
                    "planner.adaptive_dispatch_intent", actor_id,
                    {"status": "pending", "flow_id": flow.id,
                     "subtask_id": subtask.id, "task_id": execution_task.id,
                     "revision": revision, "signed_version": signing.version,
                     "approval_required": True},
                    idempotency_key="adaptive-dispatch-intent:" + subtask.id,
                )
        return {
            "status": "pending",
            "task_id": execution_task.id,
            "subtask_id": subtask.id,
            "flow_revision": revision,
            "approval_required": True,
            "execution_started": False,
        }
    except (AdaptiveDispatchDenied, SupervisionConflict, AuthorizationDenied) as exc:
        raise AdaptiveDispatchDenied("Adaptive target/authorization/Flow claim rejected") from exc
    except Exception as exc:
        raise AdaptiveDispatchUnavailable("Adaptive signed dispatch claim storage unavailable") from exc


async def confirm_adaptive_followup(
    session_memory: Any,
    *,
    request_id: str,
    engagement_id: str,
    actor_id: str,
    actor_role: str,
    expected_authorization_version: int,
    expected_flow_revision: int,
    confirmed_target: str,
    confirm_execution: bool,
) -> dict[str, Any]:
    """Atomic signed Flow CAS + planned objective/subtask + audit/outbox.

    Independent approval to run the model does not authorize running targets.
    A fresh senior operator must explicitly confirm this specific proposed
    target, and the resulting step *still* requires a separate dispatch/approval
    through the platform's normal execution workflow.
    """
    if (
        actor_role != "senior_operator"
        or not isinstance(actor_id, str) or not actor_id.strip() or len(actor_id) > 64
        or not isinstance(request_id, str) or not request_id
        or not isinstance(engagement_id, str) or not engagement_id
        or type(expected_authorization_version) is not int
        or expected_authorization_version < 1
        or type(expected_flow_revision) is not int or expected_flow_revision < 0
        or confirm_execution is not True
    ):
        raise AdaptiveDispatchDenied("Explicit senior confirmation and signed versions required")

    store = PlannerExecutionStore(session_memory)
    digest = hashlib.sha256(f"{engagement_id}:{request_id}:adaptive-recon".encode()).hexdigest()[:24]
    objective_id = f"task-adaptive-{digest}"
    subtask_id = f"subtask-adaptive-{digest}"
    try:
        async with store._sessions() as db:
            async with db.begin():
                engagement, _ = await store._guard(
                    db, engagement_id, actor_id=actor_id,
                    actor_role=actor_role, require_window=True,
                )
                signed = await guard_sql(
                    db, engagement_id,
                    expected_version=expected_authorization_version,
                )
                scope = ScopeDefinition.model_validate(engagement.scope)
                if (
                    engagement.phase not in {"reconnaissance", "vulnerability_discovery"}
                    or not isinstance(engagement.roe, dict)
                    or engagement.roe.get("adaptive_planning_enabled") is not True
                    or "no_active_scanning" in scope.restrictions
                    or "no_reconnaissance" in scope.restrictions
                    or not action_requires_approval("planner_inference", scope)
                ):
                    raise AdaptiveDispatchDenied("Adaptive reconnaissance is not allowed by signed ROE")
                techniques = {str(t).strip().lower() for t in scope.allowed_techniques}
                if not techniques.intersection(_ALLOWED_RECON):
                    raise AdaptiveDispatchDenied("Signed ROE does not explicitly permit reconnaissance")
                target = _bounded_target(confirmed_target, scope)
                approval = (await db.execute(select(ApprovalRequestORM).where(
                    ApprovalRequestORM.id == request_id,
                    ApprovalRequestORM.engagement_id == engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if (
                    approval is None or approval.status != "approved"
                    or approval.action_type != "planner_inference"
                    or approval.agent_id != "planner-runtime"
                    or not approval.operator_id or approval.responded_at is None
                ):
                    raise AdaptiveDispatchDenied("No approved, durable internal planner decision")
                planner = (await db.execute(select(TaskORM).where(
                    TaskORM.id == approval.task_id,
                    TaskORM.engagement_id == engagement_id,
                    TaskORM.type == "planner_inference",
                ).with_for_update())).scalar_one_or_none()
                payload = planner.payload if planner is not None and isinstance(planner.payload, dict) else {}
                result = planner.result if planner is not None and isinstance(planner.result, dict) else {}
                proposal = result.get("adaptive_proposal")
                if (
                    planner is None or planner.status != "completed"
                    or not planner.approval_required or planner.assigned_agent_id != "planner-runtime"
                    or not planner.flow_id or approval.target != planner.flow_id
                    or store.approval_id(planner.id) != request_id
                    or payload.get("planner_purpose") != "adaptive_planning"
                    or payload.get("approval_id") != request_id
                    or payload.get("operator_approved") is not True
                    or type(payload.get("_authorization_version")) is not int
                    or payload["_authorization_version"] != signed.version
                    or type(payload.get("planner_flow_revision")) is not int
                    or payload["planner_flow_revision"] != expected_flow_revision
                    or result.get("review_status") != "operator_review"
                    or not isinstance(proposal, dict)
                    or proposal.get("action") != "request_sub_recon"
                    or not isinstance(proposal.get("parameters"), dict)
                    or proposal["parameters"].get("target") != target
                    or result.get("adaptive_execution_admission") is not None
                ):
                    raise AdaptiveDispatchDenied("Adaptive proposal was changed, consumed, or is not actionable")
                flow = (await db.execute(select(ExecutionFlowORM).where(
                    ExecutionFlowORM.id == planner.flow_id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if (
                    flow is None or flow.status not in {"running", "pending"}
                    or flow.revision != expected_flow_revision
                ):
                    raise AdaptiveDispatchDenied("Flow revision or status changed")

                updated = (await db.execute(
                    update(ExecutionFlowORM)
                    .where(
                        ExecutionFlowORM.id == flow.id,
                        ExecutionFlowORM.engagement_id == engagement_id,
                        ExecutionFlowORM.revision == expected_flow_revision,
                        ExecutionFlowORM.status == flow.status,
                        ExecutionFlowORM.status.in_(["running", "pending"]),
                    )
                    .values(
                        revision=ExecutionFlowORM.revision + 1,
                        updated_at=datetime.utcnow(),
                    )
                    .returning(ExecutionFlowORM.revision)
                )).scalar_one_or_none()
                if updated != expected_flow_revision + 1:
                    raise AdaptiveDispatchDenied("Flow changed before adaptive plan admission")

                now = datetime.utcnow()
                db.add(TaskORM(
                    id=objective_id, type="flow_objective", priority=5,
                    agent_type=AgentType.RECON.value,
                    payload={
                        "title": f"Review authorized reconnaissance for {target}",
                        "adaptive_source_approval_id": request_id,
                        "planned_target": target,
                        "_authorization_version": signed.version,
                    },
                    dependencies=[], max_retries=0, timeout_seconds=300,
                    scope_check=True, approval_required=True, status="planned",
                    result=None, retry_count=0, created_at=now, started_at=None,
                    completed_at=None, engagement_id=engagement_id,
                    assigned_agent_id=None, flow_id=flow.id, subtask_id=None,
                    parent_task_id=None,
                ))
                db.add(ExecutionSubtaskORM(
                    id=subtask_id, engagement_id=engagement_id, flow_id=flow.id,
                    task_id=objective_id,
                    title=f"Review scoped follow-up: {target}",
                    description="Human-confirmed adaptive recon proposal. Requires explicit subtask dispatch and execution approval.",
                    task_type="full_recon", agent_type=AgentType.RECON.value,
                    approval_required=True, order=0, dependencies=[],
                    status="pending", refinement_count=0, result_summary=None,
                    execution_task_id=None, created_at=now, updated_at=now,
                ))
                planner.result = {
                    **result,
                    "adaptive_execution_admission": {
                        "status": "pending_dispatch_review",
                        "objective_id": objective_id,
                        "subtask_id": subtask_id,
                        "flow_revision": updated,
                        "confirmed_by": actor_id,
                    },
                }
                await db.flush()
                await SupervisionStore._append_event(
                    db, engagement_id, planner.id,
                    "planner.adaptive_followup_prepared", actor_id,
                    {
                        "status": "pending_dispatch_review", "flow_id": flow.id,
                        "revision": updated, "objective_id": objective_id,
                        "subtask_id": subtask_id, "signed_version": signed.version,
                    },
                    idempotency_key="adaptive-followup:" + planner.id,
                )
        return {
            "status": "pending_dispatch_review",
            "flow_id": flow.id,
            "flow_revision": updated,
            "objective_task_id": objective_id,
            "subtask_id": subtask_id,
            "approval_required": True,
            "execution_started": False,
            "dispatch_required": True,
            "target": target,
        }
    except (AdaptiveDispatchDenied, SupervisionConflict, AuthorizationDenied) as exc:
        raise AdaptiveDispatchDenied("Signed or Flow admission rejected") from exc
    except Exception as exc:
        raise AdaptiveDispatchUnavailable("Durable adaptive follow-up admission unavailable") from exc
