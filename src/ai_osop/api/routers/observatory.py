"""Execution Observatory Router

Exposes task execution traces and telemetry for live debugging."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import assert_engagement_access, require_role, state
from ai_osop.core.execution_trace import get_trace as _get_trace
from ai_osop.core.execution_trace import load_trace_from_redis

router = APIRouter(tags=["observatory"])


@router.get(
    "/engagements/{engagement_id}/trace/{task_id}",
    summary="Get task execution trace",
    description="Return the full execution trace for a single task, including steps, timing, and failure details. Engagement-scoped for authorization.",
)
async def get_task_trace(
    engagement_id: str,
    task_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Return the full execution trace for a single task.

    AIOSOP-OBS-AUTHZ (2026-08-03): the trace endpoints were role-gated but had no
    engagement-scope check — any operator could read any engagement's traces by
    guessing the id. Enforce the same tenant + ownership rules as the rest of the
    API.
    """
    await assert_engagement_access(operator, engagement_id)
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    task_obj = orch._tasks.get(task_id)
    if task_obj is not None:
        trace = _get_trace(task_obj)
        if trace is not None:
            return trace.to_dict()
    persisted = await load_trace_from_redis(orch.session_memory, task_id)
    if persisted is not None:
        return persisted
    raise HTTPException(status_code=404, detail=f"No execution trace found for task {task_id}")


@router.get(
    "/engagements/{engagement_id}/traces",
    summary="List engagement execution traces",
    description="List all execution traces for tasks within an engagement, providing an overview of task execution across the engagement.",
)
async def list_engagement_traces(
    engagement_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """List all execution traces for tasks in an engagement (engagement-scoped)."""
    await assert_engagement_access(operator, engagement_id)
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    traces: List[Dict[str, Any]] = []
    for task_id, task_obj in orch._tasks.items():
        if task_obj.engagement_id != engagement_id:
            continue
        trace = _get_trace(task_obj)
        if trace is not None:
            traces.append(trace.to_dict())
    return {"engagement_id": engagement_id, "trace_count": len(traces), "traces": traces}


@router.get(
    "/system/observatory/mcp-telemetry",
    summary="Get MCP server telemetry",
    description="Return telemetry metrics for every registered MCP server, including request counts, latencies, and error rates.",
)
async def get_mcp_telemetry(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Return telemetry for every registered MCP server."""
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    telemetry: Dict[str, Any] = {}
    for server_id, conn in orch.mcp_registry._servers.items():
        telemetry[server_id] = conn.get_telemetry()
    return {"mcp_servers": len(telemetry), "telemetry": telemetry}


@router.get(
    "/system/observatory/scanner-audit",
    summary="Get scanner audit summary",
    description="Audit summary showing applicable, scheduled, completed, and failed counts per scanner type. Global view requires senior_operator; pass engagement_id to scope it.",
)
async def get_scanner_audit(
    engagement_id: Optional[str] = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Audit summary: for every scanner determine applicable/scheduled/completed/failed.

    When an engagement_id is supplied it is engagement-scoped; without one the
    global view is senior_operator-only (it aggregates every engagement's tasks).
    """
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    if engagement_id:
        await assert_engagement_access(operator, engagement_id)
    elif operator.get("role") != "senior_operator":
        raise HTTPException(
            status_code=403,
            detail="Global scanner audit requires senior_operator; pass engagement_id to scope it",
        )
    scanners: Dict[str, Dict[str, Any]] = {}
    for task_id, task_obj in orch._tasks.items():
        if engagement_id and task_obj.engagement_id != engagement_id:
            continue
        task_type = task_obj.type
        if task_type not in scanners:
            scanners[task_type] = {
                "task_type": task_type,
                "agent_type": str(task_obj.agent_type),
                "scheduled": 0,
                "running": 0,
                "completed": 0,
                "failed": 0,
                "pending": 0,
                "avg_duration_ms": 0.0,
                "failure_categories": {},
            }
        s = scanners[task_type]
        s["scheduled"] += 1
        if task_obj.status in s:
            s[task_obj.status] += 1
        trace = _get_trace(task_obj)
        if trace is not None and trace._failure:
            cat = trace._failure.get("category", "unknown")
            s["failure_categories"][cat] = s["failure_categories"].get(cat, 0) + 1
        if task_obj.started_at and task_obj.completed_at:
            dur = (task_obj.completed_at - task_obj.started_at).total_seconds() * 1000
            s["avg_duration_ms"] = (s["avg_duration_ms"] * (s["scheduled"] - 1) + dur) / s[
                "scheduled"
            ]
    return {"scanner_count": len(scanners), "scanners": list(scanners.values())}


@router.get(
    "/system/observatory/worker-telemetry",
    summary="Get worker agent telemetry",
    description="Return telemetry for every registered worker agent, including status, task queue depth, and last heartbeat timestamp.",
)
async def get_worker_telemetry(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Return telemetry for every registered worker agent."""
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
    workers: List[Dict[str, Any]] = []
    for agent_id, agent in orch._agents.items():
        status = await agent.get_status()
        hb = await orch.session_memory.get_agent_heartbeat(agent_id)
        workers.append(
            {
                "agent_id": agent_id,
                "agent_type": str(agent.ctx.agent_type),
                "status": status.get("status"),
                "task_queue_depth": status.get("task_queue_depth", 0),
                "last_heartbeat": hb,
            }
        )
    return {"worker_count": len(workers), "workers": workers}
