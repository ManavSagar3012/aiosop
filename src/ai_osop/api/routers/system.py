"""AI-OSOP System Router

System health, configuration, sandbox status, and skill stats.
"""

import asyncio
import re
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text

from ai_osop.api.deps import require_role, state, verify_token
from ai_osop.api.mcp_fleet_readiness import mcp_fleet_process_visibility
from ai_osop.api.mcp_operator_recovery import recover_configured_mcp_transport
from ai_osop.core.config import settings
from ai_osop.core.observability import render_prometheus, update_active_agents
from ai_osop.memory.authorization_store import AuthorizationDenied, guard_sql

router = APIRouter(prefix="/system", tags=["system"])


async def _dlq_owner(engagement_id: str, operator: Dict[str, Any]) -> None:
    """Recheck durable signed ROE and exact tenant owner before any DLQ read.

    A shared development API key or a senior role does not grant ownership of
    another tenant's failed-task evidence. No Redis session cache is trusted.
    """
    if (
        not isinstance(engagement_id, str)
        or len(engagement_id) > 64
        or not engagement_id
        or not all(ch.isascii() and (ch.isalnum() or ch in "._:@-") for ch in engagement_id)
        or not isinstance(operator, dict)
        or not isinstance(operator.get("sub"), str)
        or not isinstance(operator.get("claims"), dict)
        or type(operator["claims"].get("exp")) is not int
    ):
        raise HTTPException(status_code=403, detail="Signed engagement operator required")
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    maker = getattr(memory, "_async_session", None)
    if not callable(maker):
        raise HTTPException(status_code=503, detail="Durable DLQ owner verification unavailable")
    try:
        async with maker() as db:
            async with db.begin():
                row = (
                    (
                        await db.execute(
                            text(
                                "SELECT created_by FROM session_states "
                                "WHERE session_id=:sid FOR SHARE"
                            ),
                            {"sid": engagement_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None or row["created_by"] != operator["sub"]:
                    raise HTTPException(status_code=403, detail="Engagement owner required")
                await guard_sql(db, engagement_id)
    except HTTPException:
        raise
    except AuthorizationDenied as exc:
        raise HTTPException(status_code=403, detail="Current signed ROE required") from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Durable DLQ authorization unavailable"
        ) from exc


@router.get("/skills/stats")
async def get_skill_stats(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))
):
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
async def get_system_config(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))
):
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
async def get_sandbox_status(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))
):
    """Report configured sandbox mode without fabricating runtime measurements.

    Guard enforcement requires evidence from the sandbox runtime itself.  The
    settings object alone cannot establish whether an eBPF filter or network
    policy is actually active, so these are deliberately reported as unknown.
    """
    return {
        "runtime": settings.sandbox_runtime,
        "ebpf_filter_active": None,
        "tetragon_policy": None,
        "active_blocks": None,
        "cpu_load": None,
        "memory_usage": None,
        "network_guard_status": "unknown",
        "telemetry_available": False,
        "status_reason": "Sandbox runtime telemetry is not connected to this endpoint",
    }


@router.get("/mcp/health")
async def get_mcp_health(operator: Dict[str, Any] = Depends(require_role("senior_operator"))):
    """Return bounded process telemetry without tenant-private MCP connection data.

    The global server list is NOT a signed engagement tool registry or actual
    reachability certificate. Use the authenticated signed Flow tool catalog
    for per-engagement declared tools. Never publish host/port, auth tokens,
    arbitrary remote tool manifests, defaults or description strings here.
    """
    orch = state.get("orchestrator")
    mcp_registry = getattr(orch, "mcp_registry", None)
    servers_by_id = getattr(mcp_registry, "_servers", None)
    if not isinstance(servers_by_id, dict) or len(servers_by_id) > 32:
        raise HTTPException(503, "Bounded MCP health registry unavailable")
    servers: List[Dict[str, Any]] = []
    for server_id, conn in sorted(servers_by_id.items()):
        if (
            not isinstance(server_id, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", server_id)
            or getattr(conn, "server_id", None) != server_id
            or not callable(getattr(conn, "get_circuit_state", None))
        ):
            raise HTTPException(503, "Untrusted MCP server identity")
        circuit = conn.get_circuit_state()
        if circuit not in {"closed", "open", "half_open"}:
            raise HTTPException(503, "Unsupported MCP circuit telemetry")
        counters = (
            "_failure_count",
            "_success_count",
            "_recovery_attempts",
            "_consecutive_successes",
        )
        if (
            any(
                type(getattr(conn, name, None)) is not int
                or not 0 <= getattr(conn, name) <= 1_000_000_000
                for name in counters
            )
            or type(getattr(conn, "_initialized", None)) is not bool
        ):
            raise HTTPException(503, "Unsupported MCP counter telemetry")
        servers.append(
            {
                "server_id": server_id,
                "circuit_state": circuit,
                "failure_count": conn._failure_count,
                "success_count": conn._success_count,
                "recovery_attempts": conn._recovery_attempts,
                "consecutive_successes": conn._consecutive_successes,
                "initialized": conn._initialized,
                "runtime_health_verified": False,
            }
        )
    return {"servers": servers, "catalog_scope": "process_health_only_unverified"}


@router.get("/mcp/fleet-readiness")
async def get_mcp_fleet_readiness(
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Reveal all 11 configured service gaps, not mock runtime certification.

    Call the existing validated/redacted registry function rather than expose
    provider credentials, endpoint addresses, tenant-private tools or manifests.
    The absence of registration is not evidence that a service is unreachable.
    """
    health = await get_mcp_health(operator=operator)
    try:
        return mcp_fleet_process_visibility(health)
    except ValueError as exc:
        raise HTTPException(503, "Fleet telemetry unavailable") from exc


@router.get("/provider/vault-join-status")
async def get_provider_vault_join_status(
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Read-only, nonsecret pending trust state, NEVER paid-provider readiness."""
    from ai_osop.core.provider_vault_runtime_join import ProviderVaultRuntimeJoin

    join = state.get("provider_vault_join")
    if type(join) is not ProviderVaultRuntimeJoin:
        return asdict(ProviderVaultRuntimeJoin().health())
    try:
        return asdict(join.health())
    except Exception:
        raise HTTPException(503, "Independent provider trust status UNKNOWN") from None


@router.post("/mcp/{server_id}/ping")
async def ping_mcp_server(
    server_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Ping a registered MCP server to check latency and reachability."""
    orch = state.get("orchestrator")
    if not orch or not getattr(orch, "mcp_registry", None):
        raise HTTPException(status_code=503, detail="MCP registry unavailable")
    res = await orch.mcp_registry.ping_server(server_id)
    if res.get("status") == "not_registered":
        raise HTTPException(status_code=404, detail=f"Server {server_id} not registered")
    return res


@router.post("/mcp/{server_id}/reconcile-local")
async def reconcile_local_mcp_transport(
    server_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """One bounded server-owned loopback handshake, never tool/Action replay.

    A provider launched after API startup can be registered without restarting
    the application. This endpoint accepts NO URL, credential, tool, request
    body, Task authorization, grant or arbitrary port from its caller.
    """
    orch = state.get("orchestrator")
    registry = getattr(orch, "mcp_registry", None)
    report = state.get("mcp_bootstrap_readiness")
    if registry is None or not isinstance(report, dict):
        raise HTTPException(503, "MCP recovery registry unavailable")
    # Import only on demand: main imports this router before mounting it.
    from ai_osop.api.main import configured_mcp_server_specs

    try:
        return await recover_configured_mcp_transport(
            server_id,
            registry=registry,
            specs=configured_mcp_server_specs(),
            bootstrap=report,
        )
    except ValueError as exc:
        raise HTTPException(409, "MCP recovery not authorized for configured transport") from exc


@router.post("/mcp/{server_id}/reset-circuit")
async def reset_mcp_circuit(
    server_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Reset an open or half-open circuit breaker for an MCP server."""
    orch = state.get("orchestrator")
    if not orch or not getattr(orch, "mcp_registry", None):
        raise HTTPException(status_code=503, detail="MCP registry unavailable")
    success = orch.mcp_registry.reset_circuit(server_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Server {server_id} not registered")
    return {"server_id": server_id, "status": "circuit_reset", "circuit_state": "closed"}


@router.get("/dlq/stats")
async def get_dlq_stats(
    engagement_id: str = Query(min_length=1, max_length=64),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Owner-only engagement DLQ stats; never expose global tenant totals."""
    await _dlq_owner(engagement_id, operator)
    dlq = state["orchestrator"].dlq
    entries = await dlq.list_entries(engagement_id=engagement_id)
    # Enforce owner-scope at the serializer even if a cache or adapter ignores
    # its filtering argument.
    entries = [row for row in entries if row.engagement_id == engagement_id]
    return {
        "pending": sum(row.status == "pending_review" for row in entries),
        "requeued": sum(row.status == "requeued" for row in entries),
        "discarded": sum(row.status == "discarded" for row in entries),
    }


@router.get("/dlq/entries")
async def list_dlq_entries(
    engagement_id: str = Query(min_length=1, max_length=64),
    status: str = None,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
):
    """Owner-only safe summary; never return stored tool arguments or secrets."""
    await _dlq_owner(engagement_id, operator)
    dlq = state["orchestrator"].dlq
    entries = await dlq.list_entries(engagement_id=engagement_id, status=status)
    return {
        "entries": [
            {
                "id": e.id,
                "task_id": e.task_id,
                "engagement_id": e.engagement_id,
                "task_type": e.task_type,
                "status": e.status,
                "created_at": e.created_at.isoformat(),
                "resolved_at": e.resolved_at.isoformat() if e.resolved_at else None,
                "replay_authorized": False,
            }
            for e in entries[:100]
            if e.engagement_id == engagement_id
        ],
        "truncated": len(entries) > 100,
    }


@router.post("/dlq/requeue")
async def requeue_dlq_entry(
    dlq_entry_id: str,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Never replay a consequential UNKNOWN task from a mutable Redis DLQ.

    The legacy queue reset had no signed Flow/version/approval check, no
    idempotent TaskORM claim, and no remote outcome reconciliation. There is
    no safe general requeue until a separate human-authorized, PostgreSQL
    atomic recovery workflow is implemented.
    """
    raise HTTPException(
        status_code=409,
        detail="Unsafe DLQ replay is disabled; reconcile the original "
        "execution and create a new signed, human-approved task",
    )


@router.post("/dlq/discard")
async def discard_dlq_entry(
    dlq_entry_id: str,
    engagement_id: str = Query(min_length=1, max_length=64),
    operator_notes: str = "",
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
):
    """Signed/current owner-scoped PostgreSQL disposition with durable audit.

    Never mutate a Redis-cached DLQEntry after a separate ownership check:
    revocation, a concurrent discard, or a foreign-entry replacement could
    otherwise race with the cache read and overwrite another tenant's row.
    """
    from ai_osop.memory.dlq_resolution import (
        DLQResolutionDenied,
        DLQResolutionStore,
    )

    memory = getattr(state.get("orchestrator"), "session_memory", None)
    try:
        outcome = await DLQResolutionStore(memory).discard(
            engagement_id, dlq_entry_id, operator.get("sub", ""), operator_notes
        )
    except (DLQResolutionDenied, AuthorizationDenied) as exc:
        raise HTTPException(status_code=403, detail="Signed DLQ disposition denied") from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Durable DLQ disposition unavailable") from exc
    if outcome == "not_found":
        raise HTTPException(status_code=404, detail="DLQ entry not found")
    if outcome != "discarded":
        raise HTTPException(status_code=409, detail="DLQ entry is already resolved")
    return {"status": "discarded", "dlq_entry_id": dlq_entry_id}


@router.get("/readiness/trust-score")
async def get_trust_score(
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator"))
):
    """Truthful release-certification status, not a synthetic trust score.

    Process liveness and dependency reachability are separate from security,
    crash recovery, signed evidence and externally qualified release gates.
    There is no durable certification authority backing a numeric score.
    """
    return {
        "trust_score": None,
        "readiness": "unverified",
        "last_audited": None,
        "production_certified": False,
        "independent_release_verification": False,
        "reason": "No authoritative independent production release certificate is available",
    }
