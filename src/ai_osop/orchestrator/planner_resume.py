"""Signed, single-use HTTP continuation for human-approved adaptive planning.

This component intentionally produces *proposals*, never scheduled agent tasks.
The existing adaptive completion callback's `schedule_task` path is not atomic
with Flow pause/cancel or signer revocation, so it is not safe to invoke from
an HTTP approval continuation.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from ai_osop.core.config import AgentType
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import FlowRecord, ScopeDefinition
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.memory.session_memory import (
    ApprovalRequestORM, ExecutionFlowORM, TaskORM,
)
from ai_osop.orchestrator.planner_execution import PlannerExecutionStore
from ai_osop.safety.scope import ScopeEnforcer, action_requires_approval


class AdaptiveResumeDenied(PermissionError):
    """An approval is absent, stale, revoked, or already consumed."""


class AdaptiveResumeUnavailable(RuntimeError):
    """No safely usable model provider, durable storage, or receipt is available."""


def _safe_proposal(decision: dict[str, Any], scope: ScopeDefinition) -> dict[str, Any]:
    """A bounded, inert suggestion: never reinterpret it as agent authority."""
    action = decision.get("action")
    parameters = decision.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {}
    if action == "stop":
        return {"action": "stop", "parameters": {}}
    if action == "create_hypothesis":
        statement = parameters.get("statement")
        if isinstance(statement, str) and 0 < len(statement.strip()) <= 1000:
            return {"action": action, "parameters": {"statement": statement.strip()}}
    if action == "request_sub_recon":
        target = parameters.get("target")
        if (
            isinstance(target, str)
            and 0 < len(target.strip()) <= 253
            and "no_active_scanning" not in scope.restrictions
        ):
            target = target.strip()
            try:
                ScopeEnforcer(scope).validate_time_window()
                if ScopeEnforcer(scope).validate_target(target):
                    return {"action": action, "parameters": {"target": target}}
            except Exception:
                pass
    # Invalid, out-of-scope, or unexpected model suggestions are not transformed
    # into a different active action by heuristic fallback.
    return {"action": "blocked", "parameters": {}, "reason": "proposal_outside_authorized_bounds"}


async def resume_approved_adaptive_plan(
    orchestrator: Any,
    *,
    request_id: str,
    engagement_id: str,
    actor_id: str,
    actor_role: str,
    expected_authorization_version: int,
    expected_flow_revision: int,
) -> dict[str, Any]:
    """Resume only an approved parked planner identity under signed PG fences.

    The planner's own `admit` locks engagement state, rechecks signature,
    Flow CAS, parent completion, human approval, and consumes the deterministic
    planner task exactly once before any provider call. Provider failures stay
    unknown/terminal: no retry and no generic external-agent scheduling.
    """
    if (
        actor_role != "senior_operator" or not isinstance(actor_id, str)
        or not actor_id or not isinstance(request_id, str) or not request_id
        or not isinstance(engagement_id, str) or not engagement_id
        or type(expected_authorization_version) is not int
        or expected_authorization_version < 1
        or type(expected_flow_revision) is not int
        or expected_flow_revision < 0
    ):
        raise AdaptiveResumeDenied("Verified senior identity and explicit versions are required")

    controller = getattr(orchestrator, "adaptive_planner", None)
    memory = getattr(orchestrator, "session_memory", None)
    llm = getattr(orchestrator, "llm_client", None)
    if (
        controller is None or memory is None
        or not isinstance(llm, LiteLLMClient)
        or not callable(getattr(llm, "complete", None))
    ):
        raise AdaptiveResumeUnavailable("Durable adaptive model planner is unavailable")

    store = PlannerExecutionStore(memory)
    try:
        async with store._sessions() as db:
            async with db.begin():
                engagement, _ = await store._guard(db, engagement_id, require_window=True)
                signed = await guard_sql(
                    db, engagement_id, expected_version=expected_authorization_version,
                )
                scope = ScopeDefinition.model_validate(engagement.scope)
                if (
                    not action_requires_approval("planner_inference", scope)
                    or not engagement.roe.get("adaptive_planning_enabled", False)
                ):
                    raise AdaptiveResumeDenied("Signed adaptive planning is not approved")
                approval = (await db.execute(
                    select(ApprovalRequestORM).where(
                        ApprovalRequestORM.id == request_id,
                        ApprovalRequestORM.engagement_id == engagement_id,
                    ).with_for_update()
                )).scalar_one_or_none()
                if (
                    approval is None or approval.status != "approved"
                    or approval.action_type != "planner_inference"
                    or approval.agent_id != "planner-runtime"
                    or not approval.operator_id or approval.responded_at is None
                ):
                    raise AdaptiveResumeDenied("Internal planner has no signed human approval")
                parked = (await db.execute(
                    select(TaskORM).where(
                        TaskORM.id == approval.task_id,
                        TaskORM.engagement_id == engagement_id,
                    ).with_for_update()
                )).scalar_one_or_none()
                payload = parked.payload if parked is not None and isinstance(parked.payload, dict) else {}
                if (
                    parked is None or parked.type != "planner_inference"
                    or parked.status != "awaiting_approval" or not parked.approval_required
                    or parked.assigned_agent_id != "planner-runtime"
                    or not parked.flow_id or parked.flow_id != approval.target
                    or parked.flow_id != controller._flow_id(engagement_id)
                    or not parked.parent_task_id
                    or request_id != store.approval_id(parked.id)
                    or payload.get("planner_purpose") != "adaptive_planning"
                    or type(payload.get("_authorization_version")) is not int
                    or payload["_authorization_version"] != signed.version
                    or payload.get("planner_flow_revision") != expected_flow_revision
                    or payload.get("approval_id") != request_id
                    or payload.get("operator_approved") is not True
                ):
                    raise AdaptiveResumeDenied("Internal planner claim is stale or already consumed")
                flow_row = (await db.execute(
                    select(ExecutionFlowORM).where(
                        ExecutionFlowORM.id == parked.flow_id,
                        ExecutionFlowORM.engagement_id == engagement_id,
                    ).with_for_update()
                )).scalar_one_or_none()
                if (
                    flow_row is None or flow_row.status not in {"running", "pending"}
                    or flow_row.revision != expected_flow_revision
                ):
                    raise AdaptiveResumeDenied("Adaptive Flow changed during human review")
                parent_row = (await db.execute(
                    select(TaskORM).where(
                        TaskORM.id == parked.parent_task_id,
                        TaskORM.engagement_id == engagement_id,
                    ).with_for_update()
                )).scalar_one_or_none()
                if (
                    parent_row is None or parent_row.status != "completed"
                    or parent_row.type not in {"full_recon", "burp_scan", "nuclei_scan"}
                    or parent_row.agent_type not in {
                        AgentType.RECON.value, AgentType.VULN_ANALYSIS.value
                    }
                ):
                    raise AdaptiveResumeDenied("Adaptive source task is not completed")
                parent_id = parent_row.id
                planner_id = parked.id
                flow = FlowRecord(
                    id=flow_row.id,
                    engagement_id=engagement_id,
                    objective=flow_row.objective,
                    status=flow_row.status,
                    revision=flow_row.revision,
                    created_at=flow_row.created_at,
                    updated_at=flow_row.updated_at,
                )
        # The preflight is only a read: planner.admit independently enforces a
        # new signed-version / Flow CAS transaction when claiming provider work.
        parent = await memory.load_task_authoritative(parent_id)
        if parent is None or parent.status != "completed" or parent.engagement_id != engagement_id:
            raise AdaptiveResumeDenied("Adaptive parent is no longer completed")
        decision = await controller.evaluate_and_plan_next_step(
            engagement_id, parent_task=parent, flow=flow,
        )
        revision = decision.pop("_planner_flow_revision", None)
        if type(revision) is not int or revision != expected_flow_revision + 1:
            raise AdaptiveResumeUnavailable("Planner did not record an authorized admission")
        safe = _safe_proposal(decision, scope)
        provenance = decision.get("provenance")
        safe["provenance"] = provenance if isinstance(provenance, str) and provenance in {
            "LLM", "deterministic_planner"
        } else "unverified"

        # The provider is already settled. Persist the safe suggestion and
        # event/outbox together; never perform another model request on retry.
        async with store._sessions() as db:
            async with db.begin():
                await store._guard(db, engagement_id)
                task = (await db.execute(select(TaskORM).where(
                    TaskORM.id == planner_id,
                    TaskORM.engagement_id == engagement_id,
                    TaskORM.type == "planner_inference",
                ).with_for_update())).scalar_one_or_none()
                current_flow = (await db.execute(select(ExecutionFlowORM).where(
                    ExecutionFlowORM.id == flow.id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                ).with_for_update())).scalar_one_or_none()
                if task is None or task.status != "completed":
                    raise AdaptiveResumeUnavailable("Confirmed planner result was not persisted")
                valid_flow = bool(
                    current_flow is not None and current_flow.revision == revision
                    and current_flow.status in {"pending", "running"}
                )
                try:
                    await guard_sql(db, engagement_id, expected_version=expected_authorization_version)
                    signed_active = True
                except Exception:
                    signed_active = False
                usable = valid_flow and signed_active
                task.result = {
                    "status": "completed",
                    "adaptive_proposal": safe if usable else None,
                    "review_status": "operator_review" if usable else "invalidated",
                }
                await store._append_event(
                    db, engagement_id, planner_id,
                    "planner.adaptive_proposal" if usable else "planner.adaptive_invalidated",
                    actor_id,
                    {"status": "operator_review" if usable else "invalidated",
                     "revision": revision, "action": safe["action"] if usable else "blocked"},
                    idempotency_key="adaptive-proposal:" + planner_id,
                )
                await db.flush()
        if not usable:
            raise AdaptiveResumeDenied("Authorization or Flow changed during planning; proposal invalidated")
        return {
            "status": "proposal_ready",
            "approval_id": request_id,
            "flow_id": flow.id,
            "flow_revision": revision,
            "planner_task_id": planner_id,
            "review_required": True,
            "execution_started": False,
            "proposal": safe,
        }
    except AuthorizationDenied as exc:
        raise AdaptiveResumeDenied("Signed authorization was revoked or changed") from exc
    except (AdaptiveResumeDenied, AdaptiveResumeUnavailable, ModelBudgetExceeded, ModelOutcomeUncertain):
        raise
    except Exception as exc:
        raise AdaptiveResumeUnavailable("Signed adaptive continuation failed closed") from exc


async def read_approved_adaptive_proposal(
    orchestrator: Any, *, request_id: str, engagement_id: str,
) -> dict[str, Any]:
    """Load an already-settled human-review proposal; never request a model.

    Revoked signers and changed Flow revisions block *presentation as usable*.
    Historical audit events remain available through the audit subsystem.
    """
    memory = getattr(orchestrator, "session_memory", None)
    if memory is None or not isinstance(request_id, str) or not request_id:
        raise AdaptiveResumeDenied("Adaptive approval identity is unavailable")
    store = PlannerExecutionStore(memory)
    try:
        async with store._sessions() as db:
            async with db.begin():
                engagement, _ = await store._guard(db, engagement_id, require_window=True)
                scope = ScopeDefinition.model_validate(engagement.scope)
                approval = (await db.execute(select(ApprovalRequestORM).where(
                    ApprovalRequestORM.id == request_id,
                    ApprovalRequestORM.engagement_id == engagement_id,
                ))).scalar_one_or_none()
                if (
                    approval is None or approval.status != "approved"
                    or approval.action_type != "planner_inference"
                ):
                    raise AdaptiveResumeDenied("Adaptive approval is not approved")
                task = (await db.execute(select(TaskORM).where(
                    TaskORM.id == approval.task_id,
                    TaskORM.engagement_id == engagement_id,
                    TaskORM.type == "planner_inference",
                ))).scalar_one_or_none()
                payload = task.payload if task is not None and isinstance(task.payload, dict) else {}
                result = task.result if task is not None and isinstance(task.result, dict) else {}
                if (
                    task is None or task.status != "completed"
                    or not task.approval_required
                    or task.assigned_agent_id != "planner-runtime"
                    or request_id != store.approval_id(task.id)
                    or approval.target != task.flow_id
                    or payload.get("planner_purpose") != "adaptive_planning"
                    or payload.get("approval_id") != request_id
                    or payload.get("operator_approved") is not True
                    or type(payload.get("_authorization_version")) is not int
                    or type(payload.get("planner_flow_revision")) is not int
                    or result.get("review_status") != "operator_review"
                    or not isinstance(result.get("adaptive_proposal"), dict)
                ):
                    raise AdaptiveResumeDenied("No settled adaptive proposal is reviewable")
                await guard_sql(
                    db, engagement_id,
                    expected_version=payload["_authorization_version"],
                )
                flow = (await db.execute(select(ExecutionFlowORM).where(
                    ExecutionFlowORM.id == task.flow_id,
                    ExecutionFlowORM.engagement_id == engagement_id,
                ))).scalar_one_or_none()
                if (
                    flow is None or flow.status not in {"running", "pending"}
                    or flow.revision != payload["planner_flow_revision"]
                ):
                    raise AdaptiveResumeDenied("Adaptive proposal Flow revision is stale")
                recorded = result["adaptive_proposal"]
                safe = _safe_proposal(recorded, scope)
                provenance = recorded.get("provenance")
                safe["provenance"] = provenance if isinstance(provenance, str) and provenance in {
                    "LLM", "deterministic_planner"
                } else "unverified"
                return {
                    "status": "proposal_ready",
                    "approval_id": request_id,
                    "flow_id": flow.id,
                    "flow_revision": flow.revision,
                    "planner_task_id": task.id,
                    "review_required": True,
                    "execution_started": False,
                    "proposal": safe,
                }
    except AuthorizationDenied as exc:
        raise AdaptiveResumeDenied("Adaptive proposal signing authority is no longer active") from exc
    except (AdaptiveResumeDenied, AdaptiveResumeUnavailable):
        raise
    except Exception as exc:
        raise AdaptiveResumeUnavailable("Durable adaptive proposal unavailable") from exc
