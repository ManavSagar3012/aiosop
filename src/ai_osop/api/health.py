"""Health and readiness endpoints for AI-OSOP.

Provides:
- /health — Liveness probe (always returns 200 if process is up).
- /ready — Readiness probe (verifies all critical dependencies are reachable).

The /ready endpoint is what Kubernetes uses to determine if the pod can receive traffic.
It checks Redis, Neo4j, Postgres, and MCP registry connectivity.

Sprint 8 enhancements:
- ai_osop_ready_status metric (1=ready, 0=not_ready, 0.5=degraded)
- Readiness history tracking (last 5 checks for flapping detection)
- Dependency-specific threshold reporting
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text

from ai_osop.api.deps import state
from ai_osop.api.mcp_fleet_readiness import _FLEET
from ai_osop.core.config import settings
from ai_osop.core.metrics import READY_STATUS
from ai_osop.core.telemetry import RequestContext

router = APIRouter(tags=["health"])

# Sprint 8: readiness history for flapping detection
_readiness_history: Deque[Dict[str, Any]] = deque(maxlen=5)
_DEPENDENCY_TIMEOUT_SECONDS = 3.0


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
        async with asyncio.timeout(_DEPENDENCY_TIMEOUT_SECONDS):
            await redis.ping()
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception:
        # Driver exceptions may contain connection strings and credentials.
        # A public readiness probe must not echo remote exception bodies.
        return {"status": "unhealthy", "error": "redis connectivity unavailable"}


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
        async with asyncio.timeout(_DEPENDENCY_TIMEOUT_SECONDS):
            await driver.verify_connectivity()
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception:
        return {"status": "unhealthy", "error": "neo4j connectivity unavailable"}


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
        async with asyncio.timeout(_DEPENDENCY_TIMEOUT_SECONDS):
            async with engine.connect() as conn:
                # SQLAlchemy 2.x rejects unwrapped SQL strings.  The previous
                # probe incorrectly reported a healthy database as unavailable.
                await conn.execute(text("SELECT 1"))
        return {"status": "healthy", "latency_ms": round((time.monotonic() - start) * 1000, 2)}
    except Exception:
        return {"status": "unhealthy", "error": "postgres connectivity unavailable"}


async def _check_mcp_registry() -> Dict[str, Any]:
    """Report trusted fleet initialization, not merely open HTTP sessions."""
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
                # Registry keys are operator-controlled and need not be
                # exposed on the unauthenticated readiness response.
                errors.append("MCP server not connected")
        bootstrap = state.get("mcp_bootstrap_readiness")
        if isinstance(bootstrap, dict) and bootstrap:
            expected = {server_id: role == "critical" for server_id, role in _FLEET}
            exact_roster = set(bootstrap) == set(expected) and all(
                type(bootstrap.get(server_id)) is dict
                and bootstrap[server_id].get("critical") is critical
                for server_id, critical in expected.items()
            )
            critical = [record for record in bootstrap.values() if record.get("critical") is True]
            initialized = sum(
                record.get("initialized") is True and record.get("status") == "initialized"
                for record in critical
            )
            runtime_verified = sum(
                record.get("runtime_health_verified") is True for record in critical
            )
            all_initialized = sum(
                record.get("initialized") is True and record.get("status") == "initialized"
                for record in bootstrap.values()
            )
            all_runtime_verified = sum(
                record.get("runtime_health_verified") is True for record in bootstrap.values()
            )
            return {
                "status": (
                    "healthy"
                    if exact_roster
                    and len(bootstrap) == 11
                    and len(critical) == 5
                    and initialized == runtime_verified == len(critical)
                    and all_initialized == all_runtime_verified == len(bootstrap)
                    else "degraded"
                ),
                "total_servers": len(bootstrap),
                "healthy_servers": healthy,
                "critical_required": len(critical),
                "critical_initialized": initialized,
                "critical_runtime_verified": runtime_verified,
                "fleet_initialized": all_initialized,
                "fleet_runtime_verified": all_runtime_verified,
                "errors": errors,
            }
        return {
            "status": "healthy" if healthy > 0 else "degraded",
            "total_servers": len(servers),
            "healthy_servers": healthy,
            "errors": errors,
        }
    except Exception:
        return {"status": "unhealthy", "error": "MCP registry connectivity unavailable"}


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

    Sprint 8:
    - Emits ai_osop_ready_status metric (1/0/0.5)
    - Tracks last 5 checks for flapping detection
    - Reports degraded (not not_ready) when only non-critical deps are unhealthy
    """
    # Parallelize individually deadline-bounded probes. Serial probes could
    # stall a pod's readiness response for three full dependency deadlines.
    redis, neo4j, postgres, mcp_registry = await asyncio.gather(
        _check_redis(),
        _check_neo4j(),
        _check_postgres(),
        _check_mcp_registry(),
    )
    checks = {
        "redis": redis,
        "neo4j": neo4j,
        "postgres": postgres,
        "mcp_registry": mcp_registry,
    }

    # Missing/not-yet-initialized dependencies are NOT evidence of health.
    # Earlier logic let UNKNOWN count as healthy, advertising a new pod
    # ready before its durable execution fences existed.
    critical_unhealthy = any(
        c["status"] != "healthy"
        for name, c in checks.items()
        if name in ("redis", "neo4j", "postgres")
    )
    # Startup only proves registration and schema negotiation. In particular,
    # a live HTTP client session is not a running, authorized MCP provider.
    # Development deployments can inspect a degraded fleet, but production
    # must not advertise HTTP 200 readiness if even one of the eleven
    # configured MCPs lacks independently verified runtime health. An absent
    # bootstrap manifest must never fall back to a nonempty registry's sockets.
    production = settings.environment.strip().lower() in {"production", "prod"}
    if production and (
        mcp_registry["status"] != "healthy"
        or mcp_registry.get("total_servers") != 11
        or mcp_registry.get("critical_required") != 5
        or mcp_registry.get("critical_initialized") != 5
        or mcp_registry.get("critical_runtime_verified") != 5
        or mcp_registry.get("fleet_initialized") != 11
        or mcp_registry.get("fleet_runtime_verified") != 11
    ):
        critical_unhealthy = True

    # Non-critical: MCP registry
    non_critical_degraded = any(
        c["status"] != "healthy"
        for name, c in checks.items()
        if name not in ("redis", "neo4j", "postgres")
    )

    if critical_unhealthy:
        READY_STATUS.set(0.0)
        _readiness_history.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "status": "not_ready",
                "checks": {name: c["status"] for name, c in checks.items()},
            }
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "timestamp": datetime.utcnow().isoformat(),
                "checks": checks,
                "history": list(_readiness_history),
            },
        )

    # Determine overall status
    if non_critical_degraded:
        overall_status = "degraded"
        READY_STATUS.set(0.5)
    else:
        overall_status = "ready"
        READY_STATUS.set(1.0)

    _readiness_history.append(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "status": overall_status,
            "checks": {name: c["status"] for name, c in checks.items()},
        }
    )

    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
        "history": list(_readiness_history),
    }
