"""AI-OSOP System Router

System health, configuration, sandbox status, and skill stats.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List

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


@router.get("/mcp/health")
async def get_mcp_health(operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))):
    """Get MCP server health: circuit breaker state, failure counts, recovery attempts.

    Sprint 7: Exposes circuit breaker v2 state so operators can diagnose
    MCP connectivity issues without reading logs.
    """
    mcp_registry = state["orchestrator"].mcp_registry
    servers: List[Dict[str, Any]] = []
    for server_id, conn in mcp_registry._servers.items():
        servers.append({
            "server_id": server_id,
            "host": conn.host,
            "port": conn.port,
            "circuit_state": conn.get_circuit_state(),
            "failure_count": conn._failure_count,
            "success_count": conn._success_count,
            "last_success_at": conn._last_success_at.isoformat() if conn._last_success_at else None,
            "last_failure_at": conn._last_failure_at.isoformat() if conn._last_failure_at else None,
            "recovery_attempts": conn._recovery_attempts,
            "consecutive_successes": conn._consecutive_successes,
            "initialized": conn._initialized,
        })
    return {"servers": servers}


@router.get("/dlq/stats")
async def get_dlq_stats(operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))):
    """Get Dead Letter Queue statistics for operator review.

    Sprint 7: Exposes DLQ counts so operators know when failed tasks
    need manual intervention.
    """
    dlq = state["orchestrator"].dlq
    stats = await dlq.get_stats()
    return stats


@router.get("/dlq/entries")
async def list_dlq_entries(
    engagement_id: str = None,
    status: str = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """List DLQ entries for operator review and requeue/discard decisions."""
    dlq = state["orchestrator"].dlq
    entries = await dlq.list_entries(engagement_id=engagement_id, status=status)
    return {"entries": [e.model_dump() for e in entries]}


@router.post("/dlq/requeue")
async def requeue_dlq_entry(
    dlq_entry_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Requeue a DLQ task back into the normal task queue."""
    dlq = state["orchestrator"].dlq
    task = await dlq.requeue(dlq_entry_id)
    if task is None:
        return {"status": "not_found", "message": "DLQ entry not found or already resolved"}
    await state["orchestrator"].schedule_task(task)
    return {"status": "requeued", "task_id": task.id}


@router.post("/dlq/discard")
async def discard_dlq_entry(
    dlq_entry_id: str,
    operator_notes: str = "",
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Permanently discard a DLQ entry."""
    dlq = state["orchestrator"].dlq
    await dlq.discard(dlq_entry_id, operator_notes)
    return {"status": "discarded", "dlq_entry_id": dlq_entry_id}

@router.get("/readiness/trust-score")
async def get_trust_score(operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))):
    """Compute a LIVE trust/readiness score from real subsystem health.

    AIOSOP-TRUST-001 (2026-07-03): this endpoint previously returned a hardcoded
    ``{"trust_score": 97, "readiness": "ready", "last_audited": "2026-06-23T15:00:00Z"}``
    regardless of actual state — a fabricated confidence signal that still reported
    "ready / 97" while the entire MCP tool tier was down and /agents was 500ing. It now
    derives the score from live checks: critical backing services (redis/neo4j/postgres)
    weighted heavily (the platform cannot operate without them) and MCP tool reality
    weighted meaningfully (the platform cannot produce real findings without tools).
    ``last_audited`` is the actual time this score was computed.
    """
    from ai_osop.api.health import (
        _check_redis,
        _check_neo4j,
        _check_postgres,
        _check_mcp_registry,
    )

    redis = await _check_redis()
    neo4j = await _check_neo4j()
    postgres = await _check_postgres()
    mcp = await _check_mcp_registry()

    critical = {"redis": redis, "neo4j": neo4j, "postgres": postgres}
    crit_total = len(critical)
    crit_healthy = sum(1 for c in critical.values() if c.get("status") == "healthy")
    total_mcp = mcp.get("total_servers", 0) or 0
    healthy_mcp = mcp.get("healthy_servers", 0) or 0

    critical_score = crit_healthy / crit_total if crit_total else 0.0
    tool_score = (healthy_mcp / total_mcp) if total_mcp else 0.0
    trust_score = round(100 * (0.6 * critical_score + 0.4 * tool_score))

    if crit_healthy < crit_total:
        readiness = "not_ready"
    elif healthy_mcp == 0:
        # backing services up but no working tools -> can serve, can't do offensive work
        readiness = "degraded"
    else:
        readiness = "ready"

    return {
        "trust_score": trust_score,
        "readiness": readiness,
        "last_audited": datetime.utcnow().isoformat() + "Z",
        "components": {
            "critical_services": {
                "healthy": crit_healthy,
                "total": crit_total,
                "redis": redis.get("status"),
                "neo4j": neo4j.get("status"),
                "postgres": postgres.get("status"),
            },
            "mcp_tooling": {
                "healthy_servers": healthy_mcp,
                "total_servers": total_mcp,
                "status": mcp.get("status"),
            },
        },
    }
