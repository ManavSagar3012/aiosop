"""AI-OSOP Task Router

Task creation and status retrieval.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import CreateTaskRequest, require_role, state, verify_token
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.post("", response_model=Task)
async def create_task(
    request: CreateTaskRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Create and schedule a new task."""
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
        engagement_id=request.engagement_id,
    )

    await state["orchestrator"].schedule_task(task)
    return task


@router.get("/{task_id}")
async def get_task(task_id: str, operator: Dict[str, Any] = Depends(verify_token)):
    """Get task status and results."""
    task = state["orchestrator"]._tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task
