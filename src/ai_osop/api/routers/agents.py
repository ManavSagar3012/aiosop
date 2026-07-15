"""AI-OSOP Agent Router

Agent status and listing endpoints.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import (
    AgentStatusResponse,
    require_role,
    state,
    update_active_agents,
)

router = APIRouter(prefix="/agents", tags=["agents"])


@router.get("", response_model=List[AgentStatusResponse])
async def list_agents(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))
):
    """List all registered agents and their status."""
    agents = []
    for agent in state["orchestrator"]._agents.values():
        status = await agent.get_status()
        agents.append(AgentStatusResponse(**status))
    update_active_agents(len(agents))
    return agents


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Get specific agent status."""
    agent = state["orchestrator"]._agents.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return await agent.get_status()
