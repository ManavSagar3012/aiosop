"""AI-OSOP Approval Router

Approval workflow endpoints for human-in-the-loop gates.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, StrictBool, StrictInt

from ai_osop.api.deps import (
    ApprovalDecisionRequest,
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)
from ai_osop.memory import session_memory as memory_module
from ai_osop.memory.supervision_store import SupervisionStore, SupervisionConflict
from ai_osop.orchestrator.planner_execution import PlannerExecutionStore
from ai_osop.orchestrator.planner_resume import (
    AdaptiveResumeDenied, AdaptiveResumeUnavailable,
    read_approved_adaptive_proposal, resume_approved_adaptive_plan,
)
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.memory.adaptive_dispatch import (
    AdaptiveDispatchDenied, AdaptiveDispatchUnavailable, confirm_adaptive_followup,
)
from ai_osop.memory.authorization_store import guard_sql
from ai_osop.core.exceptions import WorkflowException
from sqlalchemy import select

router = APIRouter(prefix="/approvals", tags=["approvals"])


class AdaptiveContinuationRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=64)
    expected_authorization_version: StrictInt = Field(ge=1)
    expected_flow_revision: StrictInt = Field(ge=0)


class AdaptiveFollowupRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=64)
    expected_authorization_version: StrictInt = Field(ge=1)
    expected_flow_revision: StrictInt = Field(ge=0)
    confirmed_target: str = Field(min_length=1, max_length=253)
    # This is a separate human decision from approval of the model call.
    # Even with true, target execution still requires subtask dispatch approval.
    confirm_execution: StrictBool


async def _adaptive_version_hint(memory: Any, engagement_id: str, proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Expose only a presently signed version, never policy or a bearer token."""
    async with memory._async_session() as db:
        planner = (await db.execute(select(memory_module.TaskORM).where(
            memory_module.TaskORM.id == proposal["planner_task_id"],
            memory_module.TaskORM.engagement_id == engagement_id,
            memory_module.TaskORM.type == "planner_inference",
        ))).scalar_one_or_none()
        payload = planner.payload if planner is not None and isinstance(planner.payload, dict) else {}
        version = payload.get("_authorization_version")
        if type(version) is not int or version < 1:
            raise AdaptiveResumeDenied("No signed proposal version available")
        await guard_sql(db, engagement_id, expected_version=version)
    return {**proposal, "authorization_version": version}


def _durable_memory(memory: Any) -> bool:
    # Resolve the live class at call-time: some isolated API startup tests
    # patch SessionMemory while importing the app, and a captured Mock class
    # must never be used as isinstance's authority.
    session_type = memory_module.SessionMemory
    return isinstance(session_type, type) and isinstance(memory, session_type)


async def _safe_approval_view(memory: Any, request: Any) -> Dict[str, Any]:
    """Expose bounded planner lineage and version hints; never grant authority.

    This read does not attest a valid signer or reserve provider execution.
    The separate resolution and planner admission transactions revalidate all
    authorization, testing-window and Flow fences before mutating anything.
    """
    data = request.model_dump()
    if not _durable_memory(memory) or request.action_type != "planner_inference":
        return data
    async with memory._async_session() as db:
        task = (
            await db.execute(select(memory_module.TaskORM).where(
                memory_module.TaskORM.id == request.task_id,
                memory_module.TaskORM.engagement_id == request.engagement_id,
                memory_module.TaskORM.type == "planner_inference",
            ))
        ).scalar_one_or_none()
        if (
            task is None or not isinstance(task.payload, dict)
            or task.status != "awaiting_approval"
            or not task.approval_required
            or task.assigned_agent_id != "planner-runtime"
            or request.agent_id != "planner-runtime"
            or request.target != task.flow_id
            or (
                request.status == "approved"
                and (
                    task.payload.get("approval_id") != request.id
                    or task.payload.get("operator_approved") is not True
                    or not request.operator_id
                    or request.responded_at is None
                )
            )
            or (
                request.status == "pending"
                and task.payload.get("approval_id") is not None
            )
        ):
            return data
        revision = task.payload.get("planner_flow_revision")
        version = task.payload.get("_authorization_version")
        if (
            isinstance(task.flow_id, str)
            and type(revision) is int and revision >= 0
            and type(version) is int and version >= 1
        ):
            data.update({
                "flow_id": task.flow_id,
                "flow_revision": revision,
                "authorization_version": version,
            })
            purpose = task.payload.get("planner_purpose")
            if purpose in {"flow_generation", "flow_refinement", "adaptive_planning"}:
                data["planner_purpose"] = purpose
                if isinstance(task.parent_task_id, str):
                    data["parent_task_id"] = task.parent_task_id
                if purpose == "flow_refinement" and isinstance(task.subtask_id, str):
                    data["source_subtask_id"] = task.subtask_id
            # A stale paused/cancelled/revised Flow must not be presented as
            # reviewable merely because a historical approval remains pending.
            flow = (
                await db.execute(select(memory_module.ExecutionFlowORM).where(
                    memory_module.ExecutionFlowORM.id == task.flow_id,
                    memory_module.ExecutionFlowORM.engagement_id == request.engagement_id,
                ))
            ).scalar_one_or_none()
            data["flow_revision_current"] = bool(
                flow is not None
                and flow.status in {"running", "pending"}
                and flow.revision == revision
            )
    return data


@router.get("/pending")
async def list_pending_approvals(operator: Dict[str, Any] = Depends(verify_token)):
    """List all pending approval requests visible to the operator."""
    orchestrator = state["orchestrator"]
    memory = getattr(orchestrator, "session_memory", None)
    if _durable_memory(memory):
        try:
            requests = await memory.list_pending_approvals()
            if operator.get("role") != "senior_operator":
                authorized = []
                for request in requests:
                    try:
                        await SupervisionStore(memory).assert_access(
                            request.engagement_id, operator.get("sub") or "",
                            operator.get("role") or "",
                        )
                        authorized.append(request)
                    except SupervisionConflict:
                        continue
                requests = authorized
            return [await _safe_approval_view(memory, request) for request in requests]
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Approval storage unavailable") from exc
    pending = [
        req.model_dump()
        for req in orchestrator._approval_requests.values()
        if req.status == "pending"
    ]
    # Filter by engagement access: operators see only approvals for engagements they own
    if operator.get("role") != "senior_operator":
        accessible = set()
        for sid, sess in state["orchestrator"]._sessions.items():
            if sess.created_by == operator.get("sub"):
                accessible.add(sid)
        pending = [p for p in pending if p.get("engagement_id") in accessible]
    return pending


@router.get("/planner-ready")
async def list_approved_internal_planners(
    engagement_id: str = Query(..., min_length=1, max_length=128),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Read approved, still-parked internal planner tasks for explicit reentry.

    This is *not* a dispatch endpoint or an authorization grant. The planner's
    original generate/refine route must claim the task under a fresh signed
    authorization check and Flow revision CAS before calling any provider.
    """
    await assert_engagement_access(operator, engagement_id)
    memory = getattr(state["orchestrator"], "session_memory", None)
    if not _durable_memory(memory):
        raise HTTPException(status_code=503, detail="Durable planner approvals unavailable")
    try:
        async with memory._async_session() as db:
            ids = (
                await db.execute(
                    select(memory_module.ApprovalRequestORM.id)
                    .join(
                        memory_module.TaskORM,
                        memory_module.TaskORM.id == memory_module.ApprovalRequestORM.task_id,
                    )
                    .where(
                        memory_module.ApprovalRequestORM.engagement_id == engagement_id,
                        memory_module.ApprovalRequestORM.action_type == "planner_inference",
                        memory_module.ApprovalRequestORM.status == "approved",
                        memory_module.TaskORM.engagement_id == engagement_id,
                        memory_module.TaskORM.type == "planner_inference",
                        memory_module.TaskORM.status == "awaiting_approval",
                        memory_module.TaskORM.approval_required.is_(True),
                    )
                    .order_by(memory_module.ApprovalRequestORM.responded_at.desc())
                    .limit(100)
                )
            ).scalars().all()
        ready = []
        for request_id in ids:
            request = await memory.load_approval_request(request_id)
            if request is None:
                raise RuntimeError("Approval ledger changed while listing")
            view = await _safe_approval_view(memory, request)
            if (
                view.get("planner_purpose") in {
                    "flow_generation", "flow_refinement", "adaptive_planning"
                }
                and type(view.get("authorization_version")) is int
                and type(view.get("flow_revision")) is int
            ):
                ready.append(view)
        return ready
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Planner approval storage unavailable") from exc


@router.get("/adaptive/proposals")
async def list_settled_adaptive_proposals(
    engagement_id: str = Query(..., min_length=1, max_length=128),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Read human-review proposals from durable PG, never replay a model."""
    await assert_engagement_access(operator, engagement_id)
    memory = getattr(state["orchestrator"], "session_memory", None)
    if not _durable_memory(memory):
        raise HTTPException(status_code=503, detail="Durable planner storage unavailable")
    try:
        async with memory._async_session() as db:
            approval_ids = (
                await db.execute(
                    select(memory_module.ApprovalRequestORM.id)
                    .join(memory_module.TaskORM,
                          memory_module.TaskORM.id == memory_module.ApprovalRequestORM.task_id)
                    .where(
                        memory_module.ApprovalRequestORM.engagement_id == engagement_id,
                        memory_module.ApprovalRequestORM.action_type == "planner_inference",
                        memory_module.ApprovalRequestORM.status == "approved",
                        memory_module.TaskORM.engagement_id == engagement_id,
                        memory_module.TaskORM.type == "planner_inference",
                        memory_module.TaskORM.status == "completed",
                        memory_module.TaskORM.payload["planner_purpose"].astext == "adaptive_planning",
                    )
                    .order_by(memory_module.ApprovalRequestORM.responded_at.desc())
                    .limit(20)
                )
            ).scalars().all()
        results = []
        for approval_id in approval_ids:
            try:
                proposal = await read_approved_adaptive_proposal(
                    state["orchestrator"],
                    request_id=approval_id, engagement_id=engagement_id,
                )
                proposal = await _adaptive_version_hint(memory, engagement_id, proposal)
            except AdaptiveResumeDenied:
                # Stale/revoked or non-adaptive completion cannot be presented
                # as a live proposal. No model call or fallback is attempted.
                continue
            results.append(proposal)
        return results
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Adaptive proposal storage unavailable") from exc


@router.post("/{request_id}/adaptive/continue")
async def continue_approved_adaptive_planner(
    request_id: str,
    body: AdaptiveContinuationRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Explicitly consume approved signed adaptive inference, proposal only.

    No generic approval dispatch, scan scheduling, or model replay is allowed.
    Approval grants are fenced independently by the planner's atomic admission.
    """
    if body.request_id != request_id:
        raise HTTPException(status_code=400, detail="Planner approval identity mismatch")
    subject = operator.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(status_code=403, detail="Verified senior operator required")
    memory = getattr(state["orchestrator"], "session_memory", None)
    if not _durable_memory(memory):
        raise HTTPException(status_code=503, detail="Durable planner storage unavailable")
    try:
        approval = await memory.load_approval_request(request_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Planner approval storage unavailable") from exc
    if approval is None:
        raise HTTPException(status_code=404, detail="Planner approval not found")
    await assert_engagement_access(operator, approval.engagement_id)
    if approval.action_type != "planner_inference" or approval.status != "approved":
        raise HTTPException(status_code=409, detail="No approved internal planner continuation")
    try:
        return await resume_approved_adaptive_plan(
            state["orchestrator"],
            request_id=request_id,
            engagement_id=approval.engagement_id,
            actor_id=subject,
            actor_role=operator["role"],
            expected_authorization_version=body.expected_authorization_version,
            expected_flow_revision=body.expected_flow_revision,
        )
    except (AdaptiveResumeDenied, ModelBudgetExceeded) as exc:
        raise HTTPException(
            status_code=409,
            detail="Planner approval is stale, revoked, or already consumed; refresh and review",
        ) from exc
    except ModelOutcomeUncertain as exc:
        raise HTTPException(
            status_code=503,
            detail="Planner model outcome unknown; do not retry this approval",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Durable adaptive continuation unavailable; inspect the planner receipt before retrying",
        ) from exc


@router.post("/{request_id}/adaptive/prepare-followup")
async def prepare_confirmed_adaptive_followup(
    request_id: str,
    body: AdaptiveFollowupRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Human confirmation -> atomic pending Flow plan, never direct execution.

    The later Flow subtask dispatch remains a *separate* human-approved,
    ROE-guarded action. This route never invokes Orchestrator.schedule_task.
    """
    if body.request_id != request_id:
        raise HTTPException(status_code=400, detail="Adaptive approval identity mismatch")
    if body.confirm_execution is not True:
        raise HTTPException(status_code=422, detail="Explicit human execution confirmation required")
    subject = operator.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(status_code=403, detail="Verified senior operator required")
    memory = getattr(state["orchestrator"], "session_memory", None)
    if not _durable_memory(memory):
        raise HTTPException(status_code=503, detail="Durable adaptive admission unavailable")
    try:
        approval = await memory.load_approval_request(request_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Planner approval storage unavailable") from exc
    if approval is None:
        raise HTTPException(status_code=404, detail="Planner approval not found")
    await assert_engagement_access(operator, approval.engagement_id)
    if approval.action_type != "planner_inference" or approval.status != "approved":
        raise HTTPException(status_code=409, detail="No approved adaptive proposal")
    try:
        return await confirm_adaptive_followup(
            memory, request_id=request_id, engagement_id=approval.engagement_id,
            actor_id=subject, actor_role=operator["role"],
            expected_authorization_version=body.expected_authorization_version,
            expected_flow_revision=body.expected_flow_revision,
            confirmed_target=body.confirmed_target,
            confirm_execution=body.confirm_execution,
        )
    except AdaptiveDispatchDenied as exc:
        raise HTTPException(
            status_code=409, detail="Adaptive follow-up denied by signed ROE, Flow, target or approval state",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Adaptive follow-up admission unavailable; no execution was started",
        ) from exc


@router.get("/{request_id}/adaptive/proposal")
async def get_settled_adaptive_proposal(
    request_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """View a persisted proposal after refresh; never replay provider calls."""
    memory = getattr(state["orchestrator"], "session_memory", None)
    if not _durable_memory(memory):
        raise HTTPException(status_code=503, detail="Durable planner storage unavailable")
    try:
        request = await memory.load_approval_request(request_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Planner approval storage unavailable") from exc
    if request is None:
        raise HTTPException(status_code=404, detail="Planner approval not found")
    await assert_engagement_access(operator, request.engagement_id)
    if request.action_type != "planner_inference" or request.status != "approved":
        raise HTTPException(status_code=409, detail="No approved adaptive planner proposal")
    try:
        proposal = await read_approved_adaptive_proposal(
            state["orchestrator"],
            request_id=request_id, engagement_id=request.engagement_id,
        )
        return await _adaptive_version_hint(memory, request.engagement_id, proposal)
    except AdaptiveResumeDenied as exc:
        raise HTTPException(
            status_code=409, detail="Adaptive proposal no longer authorized or reviewable",
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Adaptive proposal storage unavailable") from exc


@router.get("/{request_id}")
async def get_approval(request_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get approval request details."""
    orchestrator = state["orchestrator"]
    memory = getattr(orchestrator, "session_memory", None)
    try:
        request = (
            await memory.load_approval_request(request_id)
            if _durable_memory(memory)
            else orchestrator._approval_requests.get(request_id)
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Approval storage unavailable") from exc
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    await assert_engagement_access(operator, request.engagement_id)
    if _durable_memory(memory):
        try:
            return await _safe_approval_view(memory, request)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Approval storage unavailable") from exc
    return request


@router.post("/{request_id}/resolve")
async def resolve_approval(
    request_id: str,
    decision: ApprovalDecisionRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Resolve an approval request."""
    orchestrator = state["orchestrator"]
    memory = getattr(orchestrator, "session_memory", None)
    try:
        request = (
            await memory.load_approval_request(request_id)
            if _durable_memory(memory)
            else orchestrator._approval_requests.get(request_id)
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Approval storage unavailable") from exc
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    # Engagement binding check: senior operator must have access to the engagement
    await assert_engagement_access(operator, request.engagement_id)
    # A browser-supplied operator ID cannot attest who actually authorized an
    # execution. Keep old clients compatible only when they agree with the
    # cryptographically verified subject; all persisted evidence uses the JWT.
    authenticated_subject = operator.get("sub")
    if not isinstance(authenticated_subject, str) or not authenticated_subject.strip():
        raise HTTPException(status_code=403, detail="Verified operator identity required")
    if decision.request_id != request_id:
        raise HTTPException(status_code=400, detail="Approval request identity mismatch")
    if decision.operator_id is not None and decision.operator_id != authenticated_subject:
        raise HTTPException(status_code=403, detail="Approval operator identity mismatch")
    try:
        if request.action_type == "planner_inference":
            if not _durable_memory(memory):
                raise RuntimeError("Durable internal planner is unavailable")
            if (
                decision.expected_authorization_version is None
                or decision.expected_flow_revision is None
            ):
                raise HTTPException(
                    status_code=422,
                    detail="Planner approval requires explicit authorization and Flow revision",
                )
            resolved, _won = await PlannerExecutionStore(memory).resolve_internal_approval(
                request_id, request.engagement_id, request.task_id,
                decision.decision, authenticated_subject,
                actor_role=operator["role"],
                expected_authorization_version=decision.expected_authorization_version,
                expected_flow_revision=decision.expected_flow_revision,
                notes=decision.notes,
            )
            return resolved
        result = await orchestrator.resolve_approval(
            request_id=request_id,
            decision=decision.decision,
            operator_id=authenticated_subject,
            notes=decision.notes,
        )
        return result
    except HTTPException:
        raise
    except (WorkflowException, PermissionError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="Approval is no longer actionable") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Approval resolution unavailable") from exc
