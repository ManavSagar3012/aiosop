"""Authorized persistent flow planning and operator subtask controls."""

from datetime import datetime
import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ai_osop.api.deps import assert_engagement_access, require_role, state, verify_token
from ai_osop.core.config import AgentType
from ai_osop.core.models import AuditEvent, FlowRecord, SubtaskRecord, Task
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.safety.scope import (
    ScopeEnforcer,
    action_requires_approval,
    validate_payload_targets,
)
from ai_osop.memory.adaptive_dispatch import (
    AdaptiveDispatchDenied,
    AdaptiveDispatchUnavailable,
    build_adaptive_execution_task,
    claim_confirmed_adaptive_subtask,
    is_adaptive_staged_subtask,
)
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.memory.flow_model_analytics import (
    FlowModelAnalyticsUnavailable,
    read_flow_model_analytics,
)

router = APIRouter(prefix="/flows", tags=["flows"])
_CONSEQUENTIAL = {
    "exploit",
    "validate_exploit",
    "exploit_validation",
    "post_exploit",
    "post_exploitation",
    "credential_access",
    "modify_target",
}
_MUTABLE_FLOW_STATES = {"pending", "running"}
_TERMINAL_FLOW_STATES = {"cancelled", "completed", "failed", "halted"}
_TERMINAL_STEP_STATES = {"completed", "failed", "cancelled"}


class CreateFlowRequest(BaseModel):
    engagement_id: str
    objective: str = Field(min_length=1, max_length=2048)


class CreateObjectiveRequest(BaseModel):
    title: str = Field(min_length=1, max_length=256)
    expected_revision: Optional[int] = Field(None, ge=0)


class CreateSubtaskRequest(BaseModel):
    task_id: str
    title: str = Field(min_length=1, max_length=256)
    description: str = Field("", max_length=4096)
    task_type: str = Field("recon", max_length=128)
    agent_type: AgentType = AgentType.RECON
    dependencies: List[str] = Field(default_factory=list, max_length=15)
    approval_required: bool = False


class PatchSubtaskRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=4096)
    expected_revision: int = Field(ge=0)


class DispatchSubtaskRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(5, ge=1, le=10)
    expected_revision: Optional[int] = Field(None, ge=0)


class FlowControlRequest(BaseModel):
    expected_revision: Optional[int] = Field(None, ge=0)


def _check_expected_revision(flow: FlowRecord, expected: Optional[int]) -> None:
    if expected is not None and flow.revision != expected:
        raise HTTPException(status_code=409, detail="Flow changed; refresh before proceeding")


async def _cas_flow_status(
    flow: FlowRecord, expected_statuses: List[str], new_status: str
) -> FlowRecord:
    """Commit a flow control transition only if the durable revision matches.

    The memory layer performs one SQL UPDATE with engagement ownership, source
    state, and revision predicates. Never re-upsert a stale FlowRecord after a
    conflict; that would undo a concurrent operator's newer decision.
    """
    committed = await state["orchestrator"].session_memory.transition_flow_status(
        flow_id=flow.id,
        engagement_id=flow.engagement_id,
        expected_revision=flow.revision,
        allowed_statuses=expected_statuses,
        new_status=new_status,
    )
    if committed is None:
        raise HTTPException(
            status_code=409,
            detail="Flow changed concurrently; refresh before retrying",
        )
    return committed


def _require_mutable_flow(flow: FlowRecord, session: Any) -> None:
    """Never execute or revise a paused/closed flow or stopped engagement."""
    if session.phase in {"completed", "halted"}:
        raise HTTPException(status_code=409, detail="Engagement is not active")
    if flow.status not in _MUTABLE_FLOW_STATES:
        raise HTTPException(status_code=409, detail="Flow is paused or closed")


async def _check_no_active_subtasks(flow: FlowRecord) -> List[SubtaskRecord]:
    """Pause/cancel cannot safely stop already submitted external executions.

    Flow-scoped cancellation needs durable task/workflow cancellation in the
    orchestrator. Reject controls on in-flight work rather than advertise a
    pause that would leave external agents running.
    """
    sm = state["orchestrator"].session_memory
    steps = await sm.list_subtasks(flow.id)
    # SessionMemory.list_subtasks caps results at 100. Never treat an
    # incomplete view as proof that there is no active execution.
    if len(steps) >= 100:
        raise HTTPException(
            status_code=409,
            detail="Flow subtask history may be truncated; cannot safely stop this flow",
        )
    for step in steps:
        if step.engagement_id != flow.engagement_id:
            raise HTTPException(status_code=409, detail="Flow contains foreign subtask")
        if step.status not in ({"pending"} | _TERMINAL_STEP_STATES):
            raise HTTPException(
                status_code=409,
                detail="Flow has submitted work; use senior engagement halt to stop execution",
            )
        if step.execution_task_id:
            execution = await sm.load_task(step.execution_task_id)
            if execution is None or execution.status not in _TERMINAL_STEP_STATES:
                raise HTTPException(
                    status_code=409,
                    detail="Flow has unresolved execution; use senior engagement halt",
                )
    return steps


async def _audit_flow_control(
    flow: FlowRecord, operator: Dict[str, Any], action: str, old_status: str
) -> None:
    """Record operator identity and state change without untrusted payloads."""
    await state["orchestrator"]._audit_log(
        AuditEvent(
            event_type=f"flow_{action}",
            severity="warning" if action in {"cancelled", "halted"} else "info",
            actor_type="operator",
            actor_id=str(operator.get("sub") or "unknown")[:64],
            action={"flow_id": flow.id, "from": old_status, "to": flow.status},
            result={"success": True},
            context={"engagement_id": flow.engagement_id},
            engagement_id=flow.engagement_id,
        )
    )


async def _owned_flow(flow_id: str, operator: Dict[str, Any]) -> FlowRecord:
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator unavailable")
    flow = await orch.session_memory.load_flow(flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="Flow not found")
    await assert_engagement_access(operator, flow.engagement_id)
    return flow


async def _owned_subtask(flow: FlowRecord, subtask_id: str) -> SubtaskRecord:
    subtasks = await state["orchestrator"].session_memory.list_subtasks(flow.id)
    for subtask in subtasks:
        if subtask.id == subtask_id and subtask.engagement_id == flow.engagement_id:
            return subtask
    raise HTTPException(status_code=404, detail="Subtask not found")


@router.post("", response_model=FlowRecord)
async def create_flow(
    request: CreateFlowRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> FlowRecord:
    """Persist an objective in an explicitly scoped engagement."""
    session = await assert_engagement_access(operator, request.engagement_id)
    if session.phase in {"halted", "completed"}:
        raise HTTPException(status_code=409, detail="Engagement is not active")
    flow = FlowRecord(engagement_id=request.engagement_id, objective=request.objective)
    await state["orchestrator"].session_memory.store_flow(flow)
    return flow


@router.get("", response_model=List[FlowRecord])
async def list_flows(
    engagement_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
) -> List[FlowRecord]:
    await assert_engagement_access(operator, engagement_id)
    return await state["orchestrator"].session_memory.list_flows(engagement_id)


@router.get("/{flow_id}")
async def get_flow(
    flow_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
) -> Dict[str, Any]:
    flow = await _owned_flow(flow_id, operator)
    sm = state["orchestrator"].session_memory
    return {
        "flow": flow,
        "tasks": await sm.list_flow_tasks(flow.id),
        "subtasks": await sm.list_subtasks(flow.id),
    }


@router.get("/{flow_id}/model-analytics")
async def get_flow_model_analytics(
    flow_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """PentAGI-style per-model/agent Flow read, without fabricated billing."""
    flow = await _owned_flow(flow_id, operator)
    memory = state["orchestrator"].session_memory
    try:
        result = await asyncio.wait_for(
            read_flow_model_analytics(
                memory, engagement_id=flow.engagement_id, flow_id=flow.id,
            ),
            timeout=5.0,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Authoritative Flow model analytics unavailable",
        ) from exc
    return result


@router.post("/{flow_id}/tasks", response_model=Task)
async def create_flow_objective(
    flow_id: str,
    request: CreateObjectiveRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Task:
    """Create a durable task objective without executing it prematurely."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _require_mutable_flow(flow, session)
    _check_expected_revision(flow, request.expected_revision)
    task = Task(
        type="flow_objective",
        agent_type=AgentType.RECON,
        engagement_id=flow.engagement_id,
        flow_id=flow.id,
        status="planned",
        payload={"title": request.title},
    )
    orch = state["orchestrator"]
    committed = await orch.session_memory.create_flow_objective(flow, session, task)
    if committed is None:
        raise HTTPException(
            status_code=409, detail="Flow or engagement changed; refresh before creating objective"
        )
    orch._tasks[task.id] = task
    return task


@router.post("/{flow_id}/tasks/{task_id}/generate")
async def generate_flow_subtasks(
    flow_id: str,
    task_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Propose validated, pending subtasks for explicit operator review."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _require_mutable_flow(flow, session)
    sm = state["orchestrator"].session_memory
    objective = await sm.load_task(task_id)
    if (
        objective is None
        or objective.flow_id != flow.id
        or objective.engagement_id != flow.engagement_id
        or objective.type != "flow_objective"
    ):
        raise HTTPException(status_code=404, detail="Flow objective not found")
    orch = state["orchestrator"]
    if not hasattr(orch, "generate_flow_subtasks"):
        raise HTTPException(status_code=503, detail="Flow planner unavailable")
    return await orch.generate_flow_subtasks(flow.id, task_id)


@router.post("/{flow_id}/subtasks/{subtask_id}/refine")
async def refine_flow_subtask(
    flow_id: str,
    subtask_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Request a bounded revision from a verified completed subtask."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _require_mutable_flow(flow, session)
    await _owned_subtask(flow, subtask_id)
    orch = state["orchestrator"]
    if not hasattr(orch, "refine_flow_subtask"):
        raise HTTPException(status_code=503, detail="Flow refiner unavailable")
    return await orch.refine_flow_subtask(flow.id, subtask_id)


@router.post("/{flow_id}/subtasks", response_model=SubtaskRecord)
async def add_subtask(
    flow_id: str,
    request: CreateSubtaskRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> SubtaskRecord:
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _require_mutable_flow(flow, session)
    orch = state["orchestrator"]
    sm = orch.session_memory
    objective = await sm.load_task(request.task_id)
    if (
        objective is None
        or objective.flow_id != flow.id
        or objective.engagement_id != flow.engagement_id
        or objective.type != "flow_objective"
    ):
        raise HTTPException(status_code=400, detail="Task objective is outside this flow")
    all_steps = await sm.list_subtasks(flow.id)
    subtasks = [step for step in all_steps if step.task_id == request.task_id]
    if len(all_steps) >= 15:
        raise HTTPException(status_code=409, detail="Maximum 15 subtasks per flow")
    known = {step.id for step in subtasks}
    if (
        len(set(request.dependencies)) != len(request.dependencies)
        or not set(request.dependencies) <= known
    ):
        raise HTTPException(
            status_code=400, detail="Dependencies must be earlier subtasks in this objective"
        )
    subtask = SubtaskRecord(
        engagement_id=flow.engagement_id,
        flow_id=flow.id,
        task_id=objective.id,
        title=request.title,
        description=request.description,
        task_type=request.task_type,
        agent_type=request.agent_type,
        approval_required=(
            request.approval_required
            or request.task_type in _CONSEQUENTIAL
            or request.agent_type == AgentType.EXPLOIT_VALIDATION
            or action_requires_approval(request.task_type, session.scope)
        ),
        order=len(all_steps),
        dependencies=request.dependencies,
    )
    committed = await sm.commit_flow_refinement(
        flow=flow,
        engagement=session,
        expected_subtask_ids=[step.id for step in all_steps],
        additions=[subtask],
        activate_flow=False,
    )
    if committed is None:
        raise HTTPException(status_code=409, detail="Flow changed; refresh before editing")
    return subtask


@router.patch("/{flow_id}/subtasks/{subtask_id}", response_model=SubtaskRecord)
async def revise_subtask(
    flow_id: str,
    subtask_id: str,
    request: PatchSubtaskRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> SubtaskRecord:
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _require_mutable_flow(flow, session)
    subtask = (await _owned_subtask(flow, subtask_id)).model_copy(deep=True)
    if flow.revision != request.expected_revision:
        raise HTTPException(status_code=409, detail="Flow plan changed; refresh before editing")
    if subtask.status != "pending":
        raise HTTPException(status_code=409, detail="Only pending subtasks can be edited")
    if request.title is not None:
        subtask.title = request.title
    if request.description is not None:
        subtask.description = request.description
    subtask.updated_at = datetime.utcnow()
    sm = state["orchestrator"].session_memory
    committed = await sm.commit_flow_refinement(
        flow=flow,
        engagement=session,
        expected_subtask_ids=[step.id for step in await sm.list_subtasks(flow.id)],
        additions=[],
        revised_step=subtask,
        activate_flow=False,
    )
    if committed is None:
        raise HTTPException(status_code=409, detail="Flow changed; refresh before editing")
    return subtask


@router.post("/{flow_id}/subtasks/{subtask_id}/dispatch")
async def dispatch_subtask(
    flow_id: str,
    subtask_id: str,
    request: DispatchSubtaskRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Schedule only authorized, ready subtasks through the existing safety gates."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _require_mutable_flow(flow, session)
    _check_expected_revision(flow, request.expected_revision)
    if not session.scope.authorization_ref or not (session.scope.domains or session.scope.ips):
        raise HTTPException(
            status_code=403, detail="Engagement requires explicit scope and authorization reference"
        )
    subtask = await _owned_subtask(flow, subtask_id)
    # A catalog choice only persists an inert human-review marker. It is NOT
    # an execution recipe. A later operator (or a direct API client) must not
    # turn that marker into a Task with arbitrary attacker-supplied payload or
    # invoke any MCP tool through the ordinary dispatch endpoint.
    if subtask.task_type == "operator_mcp_capability_review":
        raise HTTPException(
            status_code=409,
            detail="MCP capability review is inert and cannot be dispatched; create a separate signed, scoped and explicitly approved execution Task",
        )
    if subtask.status != "pending":
        raise HTTPException(status_code=409, detail="Subtask already dispatched or finished")
    sm = state["orchestrator"].session_memory
    steps = await sm.list_subtasks(flow.id, task_id=subtask.task_id)
    by_id = {step.id: step for step in steps}
    if any(
        dependency not in by_id or by_id[dependency].status != "completed"
        for dependency in subtask.dependencies
    ):
        raise HTTPException(status_code=409, detail="Subtask dependencies are not complete")
    try:
        enforcer = ScopeEnforcer(session.scope)
        enforcer.validate_time_window()
        validate_payload_targets(
            enforcer,
            request.payload,
            require_target=subtask.agent_type
            in {
                AgentType.RECON,
                AgentType.VULN_ANALYSIS,
            },
        )
    except (ScopeValidationError, OutOfScopeError) as exc:
        raise HTTPException(
            status_code=403,
            detail="Subtask target or testing window is outside authorized scope",
        ) from exc
    adaptive_staged = is_adaptive_staged_subtask(subtask)
    # Production must reserve an immutable TaskORM + Flow/subtask claim +
    # outbox BEFORE attempting any queue or Temporal side effects. A missing
    # hydration/enqueue capability is a release blocker, not permission to
    # call the legacy nontransactional schedule_task fallback.
    durable_memory = isinstance(sm, SessionMemory)
    orchestrator = state["orchestrator"]
    if durable_memory and not callable(getattr(orchestrator, "enqueue_registered_task", None)):
        raise HTTPException(
            status_code=503,
            detail="Durable Flow task enqueue unavailable; no task claimed or scheduled",
        )
    if adaptive_staged:
        task = build_adaptive_execution_task(
            flow=flow, subtask=subtask,
            target=request.payload.get("target", ""),
            priority=request.priority,
        )
    else:
        task = Task(
            type=subtask.task_type,
            agent_type=subtask.agent_type,
            engagement_id=flow.engagement_id,
            flow_id=flow.id,
            subtask_id=subtask.id,
            parent_task_id=subtask.task_id,
            dependencies=[by_id[dep].execution_task_id for dep in subtask.dependencies],
            scope_check=True,
            approval_required=(
                subtask.approval_required
                or subtask.task_type in _CONSEQUENTIAL
                or subtask.agent_type == AgentType.EXPLOIT_VALIDATION
                or action_requires_approval(subtask.task_type, session.scope)
            ),
            payload=dict(request.payload),
            priority=request.priority,
        )
    if adaptive_staged:
        # A signed adaptive Flow step is fundamentally different from an
        # ordinary user-created step: its target, execution technique and
        # confirming human identity were immutably recorded in PostgreSQL.
        # The general scope-only claim permits a different in-scope target;
        # use the signed specialized claim INSTEAD, in its own single PG txn.
        actor = operator.get("sub")
        if (
            operator.get("role") != "senior_operator"
            or not isinstance(actor, str) or not actor.strip()
        ):
            raise HTTPException(
                status_code=403,
                detail="Adaptive follow-up dispatch requires its confirming senior operator",
            )
        if type(request.expected_revision) is not int:
            raise HTTPException(
                status_code=409,
                detail="Adaptive dispatch needs an explicit current Flow revision",
            )
        try:
            reserved = await claim_confirmed_adaptive_subtask(
                sm,
                flow=flow,
                engagement=session,
                subtask=subtask,
                payload=request.payload,
                expected_revision=request.expected_revision,
                actor_id=actor,
                actor_role=operator["role"],
                execution_task=task,
            )
        except AdaptiveDispatchDenied as exc:
            raise HTTPException(
                status_code=409,
                detail="Adaptive target, human confirmation, signed policy or Flow revision changed; refresh",
            ) from exc
        except AdaptiveDispatchUnavailable as exc:
            raise HTTPException(
                status_code=503,
                detail="Authoritative adaptive dispatch claim unavailable; no task scheduled",
            ) from exc
        claimed = (reserved is True and not durable_memory) or (
            isinstance(reserved, dict)
            and reserved.get("task_id") == task.id
            and reserved.get("status") == "pending"
            and reserved.get("approval_required") is True
            and reserved.get("execution_started") is False
            and reserved.get("flow_revision") == flow.revision + 1
        )
    else:
        # Preserve ordinary explicitly created manual Flow dispatch semantics.
        claim_kwargs = dict(
            flow=flow, engagement=session, subtask=subtask,
            payload=request.payload,
        )
        if durable_memory:
            claim_kwargs["execution_task"] = task
        claimed = await sm.claim_subtask(
            subtask.id, flow.engagement_id, **claim_kwargs,
        )
    if not claimed:
        raise HTTPException(
            status_code=409,
            detail="Flow, authorization or subtask changed before dispatch; refresh",
        )
    if durable_memory:
        # Only hydrate the exact immutable TaskORM committed with the Flow
        # claim. This method must recheck signed authority and route through
        # the existing task-level human approval gate before any target call.
        # Never call schedule_task (which UPSERTs/schedules a *new* task).
        try:
            admitted = await orchestrator.enqueue_registered_task(task.id)
            if admitted is False:
                raise RuntimeError("Durable task not enqueued")
        except Exception as exc:
            # Queue publishing could have succeeded before the transport error.
            # Reservation is durable; do not reset the claim or retry remote
            # effects. Outbox/hydration reconciliation owns the unknown state.
            raise HTTPException(
                status_code=503,
                detail="Durable task registered; enqueue outcome unknown. Do not retry dispatch",
            ) from exc
        return {
            "subtask_id": subtask.id,
            "task_id": task.id,
            "status": "registered",
            "approval_required": task.approval_required,
            "approval_state": "awaiting_scheduler_review" if task.approval_required else "not_required",
            "execution_started": False,
        }
    # Compatibility with explicitly isolated manual-flow unit stubs ONLY.
    # A control request may have paused/cancelled the flow while scope and
    # dependencies were being checked. This is a best-effort second guard;
    # cross-replica atomicity still requires transactional flow CAS.
    latest_flow = await sm.load_flow(flow.id)
    latest_session = await assert_engagement_access(operator, flow.engagement_id)
    if (
        latest_flow is None
        or latest_flow.status not in _MUTABLE_FLOW_STATES
        or latest_session.phase in {"halted", "completed"}
    ):
        subtask.status = "cancelled"
        subtask.updated_at = datetime.utcnow()
        await sm.store_subtask(subtask)
        raise HTTPException(status_code=409, detail="Flow or engagement stopped before scheduling")
    try:
        await state["orchestrator"].schedule_task(task)
    except Exception:
        # Scheduling can fail AFTER a queue/Temporal workflow has accepted the
        # task. Never reset the claimed step to 'pending': automatic retries
        # could execute the same consequential tool twice.
        current = next(
            (step for step in await sm.list_subtasks(flow.id) if step.id == subtask.id),
            subtask,
        )
        if current.status not in _TERMINAL_STEP_STATES:
            current.status = "dispatch_unknown"
            current.execution_task_id = task.id
            current.updated_at = datetime.utcnow()
            await sm.store_subtask(current)
        raise HTTPException(
            status_code=503,
            detail="Task dispatch outcome unknown; do not retry until reconciled",
        )
    # A fast worker may already have persisted a terminal result before this
    # endpoint returns. Do not overwrite that authoritative terminal state.
    current = next(
        (step for step in await sm.list_subtasks(flow.id) if step.id == subtask.id),
        subtask,
    )
    if current.status not in _TERMINAL_STEP_STATES:
        current.status = "dispatched"
        current.execution_task_id = task.id
        current.updated_at = datetime.utcnow()
        await sm.store_subtask(current)
    return {"subtask_id": subtask.id, "task_id": task.id, "status": task.status}


@router.get("/{flow_id}/actions")
async def get_flow_actions(
    flow_id: str,
    limit: int = Query(100, ge=1, le=100),
    operator: Dict[str, Any] = Depends(verify_token),
) -> Dict[str, Any]:
    flow = await _owned_flow(flow_id, operator)
    actions = await state["orchestrator"].session_memory.list_actions(
        flow.engagement_id, limit=limit, flow_id=flow.id
    )
    return {"flow_id": flow.id, "actions": actions}


@router.post("/{flow_id}/pause")
async def pause_flow(
    flow_id: str,
    request: Optional[FlowControlRequest] = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Pause operator dispatch only if there are no active execution tasks."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _check_expected_revision(flow, request.expected_revision if request else None)
    if flow.status == "paused":
        return {"flow_id": flow.id, "status": "paused", "execution_stopped": False}
    _require_mutable_flow(flow, session)
    await _check_no_active_subtasks(flow)
    old_status = flow.status
    committed = await _cas_flow_status(flow, ["pending", "running"], "paused")
    await _audit_flow_control(committed, operator, "paused", old_status)
    return {"flow_id": committed.id, "status": committed.status, "execution_stopped": False}


@router.post("/{flow_id}/resume")
async def resume_flow(
    flow_id: str,
    request: Optional[FlowControlRequest] = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Resume a paused plan without reviving a stopped engagement."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _check_expected_revision(flow, request.expected_revision if request else None)
    if flow.status in _MUTABLE_FLOW_STATES:
        _require_mutable_flow(flow, session)
        return {"flow_id": flow.id, "status": flow.status}
    if flow.status != "paused" or session.phase in {"halted", "completed"}:
        raise HTTPException(
            status_code=409, detail="Only paused flows in active engagements can resume"
        )
    if not session.scope.authorization_ref or not (session.scope.domains or session.scope.ips):
        raise HTTPException(status_code=403, detail="Engagement lacks authorized scope")
    try:
        ScopeEnforcer(session.scope).validate_time_window()
    except (OutOfScopeError, ScopeValidationError) as exc:
        raise HTTPException(status_code=403, detail="Engagement testing window is closed") from exc
    await _check_no_active_subtasks(flow)
    committed = await _cas_flow_status(flow, ["paused"], "pending")
    await _audit_flow_control(committed, operator, "resumed", "paused")
    return {"flow_id": committed.id, "status": committed.status}


@router.post("/{flow_id}/cancel")
async def cancel_flow(
    flow_id: str,
    request: Optional[FlowControlRequest] = None,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Cancel unsubmitted steps; active execution requires engagement halt."""
    flow = await _owned_flow(flow_id, operator)
    session = await assert_engagement_access(operator, flow.engagement_id)
    _check_expected_revision(flow, request.expected_revision if request else None)
    if flow.status == "cancelled":
        return {"flow_id": flow.id, "status": "cancelled", "execution_stopped": False}
    if flow.status in _TERMINAL_FLOW_STATES or session.phase in {"halted", "completed"}:
        raise HTTPException(status_code=409, detail="Flow or engagement is already terminal")
    steps = await _check_no_active_subtasks(flow)
    old_status = flow.status
    sm = state["orchestrator"].session_memory
    committed = await _cas_flow_status(flow, ["pending", "running", "paused"], "cancelled")
    for step in steps:
        if step.status == "pending":
            step.status = "cancelled"
            step.updated_at = datetime.utcnow()
            await sm.store_subtask(step)
    await _audit_flow_control(committed, operator, "cancelled", old_status)
    return {"flow_id": committed.id, "status": committed.status, "execution_stopped": False}


@router.post("/{flow_id}/halt")
async def halt_flow(
    flow_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Emergency stop uses the engagement-level halt, including active agents."""
    flow = await _owned_flow(flow_id, operator)
    orch = state["orchestrator"]
    session = await assert_engagement_access(operator, flow.engagement_id)
    if flow.status == "halted" and session.phase == "halted":
        return {"flow_id": flow.id, "status": "halted", "engagement_halted": True}
    # The existing orchestrator halt silently returns for unknown in-memory
    # sessions. Rehydrate an authorized persisted session after a restart.
    orch._sessions.setdefault(flow.engagement_id, session)
    await orch.halt_engagement(flow.engagement_id, "Operator stopped flow " + flow.id)
    if orch._sessions[flow.engagement_id].phase != "halted":
        raise HTTPException(status_code=503, detail="Engagement halt could not be confirmed")
    # Halting the engagement is irreversible. If another operator changed the
    # flow while the halt was underway, use a fresh durable revision and retry
    # a bounded number of times; never undo the emergency stop.
    for _ in range(3):
        latest = await orch.session_memory.load_flow(flow.id)
        if latest is None or latest.engagement_id != flow.engagement_id:
            raise HTTPException(status_code=503, detail="Halted engagement Flow record unavailable")
        if latest.status == "halted":
            return {"flow_id": latest.id, "status": "halted", "engagement_halted": True}
        committed = await orch.session_memory.transition_flow_status(
            flow_id=latest.id,
            engagement_id=latest.engagement_id,
            expected_revision=latest.revision,
            allowed_statuses=[latest.status],
            new_status="halted",
        )
        if committed is not None:
            await _audit_flow_control(committed, operator, "halted", latest.status)
            return {"flow_id": committed.id, "status": committed.status, "engagement_halted": True}
    raise HTTPException(
        status_code=503,
        detail="Engagement halted but Flow state is changing; reconcile before retrying",
    )
