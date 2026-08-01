"""AI-OSOP Task Router

Task creation, listing, and status retrieval.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_osop.api.deps import (
    CreateTaskRequest,
    assert_engagement_access,
    engagement_id_forms,
    require_role,
    state,
    verify_token,
)
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

router = APIRouter(prefix="/tasks", tags=["tasks"])


# AIOSOP-SCALE-002 (2026-08-01): bound the previously-unbounded in-memory dump.
# list_tasks returned every task in the orchestrator's _tasks dict — which lives
# for the whole process lifetime. On a long-lived engagement or after recovery of
# a large backlog this returned thousands of Task objects per call, wasting CPU +
# memory and leaking task details to any caller. Apply a sane server-side cap; a
# client that wants more can paginate with limit/offset.
_DEFAULT_TASK_LIST_LIMIT = 200
_MAX_TASK_LIST_LIMIT = 2000


@router.get("", response_model=List[Task])
async def list_tasks(
    engagement_id: Optional[str] = None,
    limit: Optional[int] = Query(None, ge=1),
    operator: Dict[str, Any] = Depends(verify_token),
):
    """List tasks, optionally filtered by engagement_id. Bounded by `limit`."""
    all_tasks = state["orchestrator"]._tasks
    if engagement_id:
        session = await assert_engagement_access(operator, engagement_id)
        # Tasks are scheduled under session.canonical_engagement_id (the SHORT
        # scope id), but callers naturally query with the session_id this same
        # engagement's create-response returned — match both forms, same fix
        # as findings.py's AIOSOP-FINDINGS-KEY. Confirmed live 2026-07-25: this
        # endpoint silently returned [] for engagements with real tasks.
        forms = set(engagement_id_forms(session, engagement_id))
        tasks = [t for t in all_tasks.values() if t.engagement_id in forms]
    else:
        tasks = list(all_tasks.values())
    # Bound the response. Sort newest-first so the cap returns the most relevant.
    tasks.sort(key=lambda t: t.created_at or "", reverse=True)
    effective = _DEFAULT_TASK_LIST_LIMIT if limit is None else min(limit, _MAX_TASK_LIST_LIMIT)
    return tasks[:effective]


from ai_osop.core.models import Task
from ai_osop.core.enums import AgentType

# AIOSOP-APPROVAL-FORCE-001: REMOVED. A duplicate hardcoded string set here would
# drift from TaskScheduler.DANGEROUS_TASK_MARKERS (substring-match on type +
# agent-type + scope-check). The single source of truth is
# TaskScheduler._is_dangerous_task. See AIOSOP-APPROVAL-SURFACE-001.


@router.post("", response_model=Task)
async def create_task(
    request: CreateTaskRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Create and schedule a new task."""
    # Ownership check: operator must own the engagement they're creating a task for
    # Returns the canonical (scope.engagement_id) form so the task is keyed
    # consistently with the rest of the platform (AIOSOP-FINDINGS-KEY, 2026-07-20).
    session = await assert_engagement_access(operator, request.engagement_id)
    canonical_eid = session.canonical_engagement_id

    try:
        agent_type = AgentType(request.agent_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid agent type: {request.agent_type}")

    task = Task(
        type=request.task_type,
        priority=request.priority,
        agent_type=agent_type,
        payload=request.payload,
        dependencies=request.dependencies,
        approval_required=request.approval_required,
        engagement_id=canonical_eid,
    )
    # AIOSOP-APPROVAL-GATE-FORCE-001: dangerous task types must ALWAYS land behind
    # the operator gate. Task.approval_required comes from the client (trusted path),
    # but a malicious or misconfigured producer could omit it. Delegate to the single
    # canonical dangerous-task classifier in TaskScheduler so the rule is defined
    # in exactly one place (matches schedule_task, ingest_queued_task, scope-tamper).
    if state["orchestrator"].task_scheduler._is_dangerous_task(task):
        task.approval_required = True

    await state["orchestrator"].schedule_task(task)
    # NOTE (W6/#8): the dead Celery path (execute_task_celery.delay(...)) was
    # removed here. It was a stub that returned {"status":"completed"} WITHOUT
    # executing anything — a fake-success no-op that would report the task done
    # while the real work ran (or didn't) through schedule_task above. There is
    # no Celery worker, no compose service, and no other importer, so this call
    # only enqueued a message that was never processed. schedule_task() is the
    # single real execution path.
    return task


@router.get("/{task_id}")
async def get_task(
    task_id: str,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """Get task status and results."""
    task = state["orchestrator"]._tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Ownership check: operator must own the engagement this task belongs to
    await assert_engagement_access(operator, task.engagement_id)
    return task
