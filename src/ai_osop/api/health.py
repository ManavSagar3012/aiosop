"""Health and readiness endpoints for AI-OSOP.

Provides:
- /health — Liveness probe (always returns 200 if process is up).
- /ready — Readiness probe (verifies all critical dependencies are reachable).

The /ready endpoint is what Kubernetes uses to determine if the pod can receive traffic.
It checks Redis, Neo4j, Postgres, and MCP registry connectivity.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status

from ai_osop.api.deps import state
from ai_osop.core.telemetry import RequestContext

router = APIRouter(tags=["health"])


async def _check_redis() -> Dict[str, Any]:
    """Check Redis connectivity via the orchestrator's session_memory."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.session_memory:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        redis = orch.session_memory._redis
        if not redis:
            return {"status": "unhealthy", "error": "redis client not connected"}
        start = time.monotonic()
        await redis.ping()
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_neo4j() -> Dict[str, Any]:
    """Check Neo4j connectivity via the orchestrator's graph_memory."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.graph_memory:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        driver = orch.graph_memory._driver
        if not driver:
            return {"status": "unhealthy", "error": "neo4j driver not connected"}
        start = time.monotonic()
        await driver.verify_connectivity()
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_postgres() -> Dict[str, Any]:
    """Check PostgreSQL connectivity via the orchestrator's session_memory."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.session_memory:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        engine = orch.session_memory._pg_engine
        if not engine:
            return {"status": "unhealthy", "error": "postgres engine not initialized"}
        start = time.monotonic()
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


async def _check_mcp_registry() -> Dict[str, Any]:
    """Check MCP registry health (how many servers are ready)."""
    try:
        orch = state.get("orchestrator")
        if not orch or not orch.mcp_registry:
            return {"status": "unknown", "error": "orchestrator not initialized"}
        registry = orch.mcp_registry
        servers = list(registry._servers.keys())
        healthy = 0
        errors = []
        for server_id in servers:
            conn = registry._servers.get(server_id)
            if conn and conn._session:
                healthy += 1
            else:
                errors.append(f"{server_id}: not connected")
        return {
            "status": "healthy" if healthy > 0 else "degraded",
            "total_servers": len(servers),
            "healthy_servers": healthy,
            "errors": errors,
        }
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


@router.get("/health", status_code=status.HTTP_200_OK)
async def health() -> Dict[str, Any]:
    """Liveness probe.

    Returns 200 if the process is alive. This is intentionally minimal — it
    does not verify dependencies. Kubernetes uses this to decide whether to
    restart the container.
    """
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@router.get("/ready", status_code=status.HTTP_200_OK)
async def ready() -> Dict[str, Any]:
    """Readiness probe.

    Verifies all critical dependencies are reachable before returning 200.
    If any dependency is unhealthy, returns 503 with detailed breakdown.
    Kubernetes uses this to decide whether to send traffic to the pod.
    """
    checks = {
        "redis": await _check_redis(),
        "neo4j": await _check_neo4j(),
        "postgres": await _check_postgres(),
        "mcp_registry": await _check_mcp_registry(),
    }

    all_healthy = all(
        c["status"] in ("healthy", "unknown") for c in checks.values()
    )
    # If any critical dependency is unhealthy, we are not ready
    critical_unhealthy = any(
        c["status"] == "unhealthy"
        for name, c in checks.items()
        if name in ("redis", "neo4j", "postgres")
    )

    if critical_unhealthy:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "timestamp": datetime.utcnow().isoformat(),
                "checks": checks,
            },
        )

    return {
        "status": "ready" if all_healthy else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }
