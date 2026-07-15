"""Execution Observatory Router

Exposes task execution traces and telemetry for live debugging."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from ai_osop.api.deps import require_role, state
from ai_osop.core.execution_trace import get_trace as _get_trace
from ai_osop.core.execution_trace import load_trace_from_redis

router = APIRouter(tags=["observatory"])


@router.get("/engagements/{engagement_id}/trace/{task_id}")
async def get_task_trace(
    engagement_id: str,
    task_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Return the full execution trace for a single task."""
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


@router.get("/engagements/{engagement_id}/traces")
async def list_engagement_traces(
    engagement_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """List all execution traces for tasks in an engagement."""
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


@router.get("/system/observatory/mcp-telemetry")
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


@router.get("/system/observatory/scanner-audit")
async def get_scanner_audit(
    engagement_id: Optional[str] = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Audit summary: for every scanner determine applicable/scheduled/completed/failed."""
    orch = state.get("orchestrator")
    if orch is None:
        raise HTTPException(status_code=503, detail="Orchestrator not initialized")
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


@router.get("/system/observatory/worker-telemetry")
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
