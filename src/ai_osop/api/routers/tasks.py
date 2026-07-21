"""AI-OSOP Task Router

Task creation, listing, and status retrieval.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import (
    CreateTaskRequest,
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.get("", response_model=List[Task])
async def list_tasks(
    engagement_id: Optional[str] = None,
    operator: Dict[str, Any] = Depends(verify_token),
):
    """List tasks, optionally filtered by engagement_id."""
    all_tasks = state["orchestrator"]._tasks
    if engagement_id:
        await assert_engagement_access(operator, engagement_id)
        tasks = [t for t in all_tasks.values() if t.engagement_id == engagement_id]
    else:
        tasks = list(all_tasks.values())
    return tasks


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

    await state["orchestrator"].schedule_task(task)
    from ai_osop.celery_app import execute_task_celery
    execute_task_celery.delay(task.model_dump())
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
