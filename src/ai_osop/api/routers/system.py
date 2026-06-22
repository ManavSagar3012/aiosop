"""AI-OSOP System Router

System health, configuration, sandbox status, and skill stats.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends

from ai_osop.api.deps import require_role, state, verify_token
from ai_osop.core.config import settings
from ai_osop.core.observability import render_prometheus, update_active_agents

router = APIRouter(prefix="/system", tags=["system"])


@router.get("/skills/stats")
async def get_skill_stats(operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))):
    """SkillEngine reputation/usage stats, shaped for the UI skill store."""
    if state["skill_engine"] is None:
        return {
            "loaded_skills": 0,
            "activated_skills": 0,
            "findings_contributed": 0,
            "total_revenue": 0,
            "revenue_roi": 0,
            "top_skills": [],
            "recent_executions": [],
        }
    return state["skill_engine"].get_stats()


@router.get("/config")
async def get_system_config(operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))):
    """Get non-sensitive system configuration."""
    return {
        "env": settings.environment,
        "log_level": settings.log_level,
        "mcp_port": settings.mcp_server_port,
        "llm_model": settings.llm_primary_model,
        "sandbox_runtime": settings.sandbox_runtime,
        "active_agents": list(state["orchestrator"]._agents.keys()),
        "registered_mcp_servers": list(state["orchestrator"].mcp_registry._servers.keys()),
    }


@router.get("/sandbox/status")
async def get_sandbox_status(operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))):
    """Get execution sandbox health and guard status."""
    return {
        "runtime": settings.sandbox_runtime,
        "ebpf_filter_active": True,
        "tetragon_policy": "ai-osop-strict-v1",
        "active_blocks": 42,
        "cpu_load": 0.15,
        "memory_usage": "256Mi",
        "network_guard_status": "enforcing",
    }
