"""Senior-host-only supervised MCP transport recovery for the exact eleven.

Use the existing bounded health/initialize recovery, with a fresh independent
inert Go host owner observation, no process launch or native Action.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional, Sequence

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.api.mcp_operator_recovery import _revoke, recover_configured_mcp_transport
from ai_osop.api.mcp_transport_operator_diagnostics import _bootstrap_records, _specification
from ai_osop.api.native_inert_fleet_control import HostInertFleetDenied, host_native_inert_control
from ai_osop.api.routers.native_inert_fleet import _no_client_config, _senior_host_guard
from ai_osop.mcp.native_inert_process_fleet import SIX_SERVICES
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry, MCPToolDefinition


router = APIRouter(prefix="/system", tags=["system"])
_JOIN_LOCK = asyncio.Lock()
_EXPECTED = frozenset(
    {
        "burp-mcp",
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
        "browser-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
    }
)


class SupervisedRecoveryDenied(ValueError):
    """Sanitized failure without host paths, bearers or provider bodies."""


def _request_journal(connection: Optional[MCPConnection]) -> Optional[tuple[Any, ...]]:
    """Deny outstanding/unknown work, preserve exact original request IDs."""
    if connection is None:
        return None
    seen = getattr(connection, "_seen_request_ids", None)
    executions = getattr(connection, "_executions", None)
    if (
        type(seen) is not dict
        or type(executions) is not dict
        or len(seen) > 1024
        or len(executions) > 512
        or any(type(name) is not str or not name for name in seen)
        or any(type(flag) is not bool or flag for flag in seen.values())
        or any(type(name) is not str or not name for name in executions)
        or any(
            type(getattr(item, "active", None)) is not bool or item.active
            for item in executions.values()
        )
    ):
        raise SupervisedRecoveryDenied("Outstanding or untrusted MCP Action journal")
    return (
        tuple(seen.items()),
        tuple((name, id(item), item.active) for name, item in executions.items()),
    )


def _valid_joined_connection(
    registry: MCPRegistry,
    name: str,
    configured: tuple[str, int, Optional[str]],
) -> bool:
    conn = registry._servers.get(name)
    if type(conn) is not MCPConnection:
        return False
    host, port, bearer = configured
    session = conn._session
    tools = conn._tools
    return bool(
        conn.server_id == name
        and conn.host == host
        and conn.port == port
        and conn.auth_token == bearer
        and session is not None
        and getattr(session, "closed", True) is False
        and conn._initialized is True
        and type(tools) is dict
        and 1 <= len(tools) <= 128
        and all(
            type(tool_name) is str
            and isinstance(tool, MCPToolDefinition)
            and tool.name == tool_name
            for tool_name, tool in tools.items()
        )
    )


async def _fresh_inert_owned_process(app: Any, server_id: str) -> Optional[bool]:
    """Check owned inert PIDs/socket without claiming registry port binding.

    The six owned Go servers have isolated ephemeral ports and /health 503;
    neither their process IDs nor endpoints imply authenticated MCP Action.
    """
    if server_id not in SIX_SERVICES:
        return None
    control = host_native_inert_control(app)
    if control is None:
        raise SupervisedRecoveryDenied("Independent inert Go host controller unavailable")
    try:
        evidence = await control.status()
    except HostInertFleetDenied as exc:
        raise SupervisedRecoveryDenied("Current inert Go process observation unavailable") from exc
    expected = [{"server_id": name, "observed": True} for name in SIX_SERVICES]
    if (
        type(evidence) is not dict
        or evidence.get("lifecycle") != "running_inert_unavailable"
        or evidence.get("classification") != "host_local_inert_process_only"
        or evidence.get("processes") != expected
        or evidence.get("mcp_initialized") is not False
        or evidence.get("signed_0033_witness_verified") is not False
        or evidence.get("native_target_execution_enabled") is not False
        or evidence.get("target_effect_verified") is not False
        or evidence.get("automatic_action_retry_authorized") is not False
        or evidence.get("production_certified") is not False
    ):
        raise SupervisedRecoveryDenied("Owned inert Go process not currently verified")
    return True


async def reconcile_single_supervised_transport(
    server_id: str,
    *,
    registry: MCPRegistry,
    bootstrap: dict[str, dict[str, Any]],
    specs: Sequence[tuple[str, str, int, Optional[str]]],
    app: Any,
) -> dict[str, Any]:
    """Bounded positive late-start readback, without native Action/replay."""
    if type(server_id) is not str or server_id not in _EXPECTED:
        raise SupervisedRecoveryDenied("Unknown configured MCP service")
    try:
        spec = _specification(specs)
        records = _bootstrap_records(bootstrap)
    except ValueError as exc:
        raise SupervisedRecoveryDenied("Complete MCP startup roster unavailable") from exc
    host, port, bearer = spec[server_id]
    if host != "127.0.0.1":
        raise SupervisedRecoveryDenied("Numeric loopback HTTP required")
    if (
        type(registry) is not MCPRegistry
        or type(registry._servers) is not dict
        or not set(registry._servers).issubset(_EXPECTED)
        or len(registry._servers) > 11
    ):
        raise SupervisedRecoveryDenied("Exact MCP registry unavailable")
    async with _JOIN_LOCK:
        before = registry._servers.get(server_id)
        if before is not None and (
            type(before) is not MCPConnection
            or before.server_id != server_id
            or before.host != host
            or before.port != port
            or before.auth_token != bearer
        ):
            raise SupervisedRecoveryDenied("MCP endpoint or bearer identity mismatch")
        snapshot = _request_journal(before)
        # This is a FRESH host observation, with neither start nor stop.
        go_owned = await _fresh_inert_owned_process(app, server_id)
        if registry._servers.get(server_id) is not before:
            raise SupervisedRecoveryDenied("MCP registry identity changed")
        if _request_journal(before) != snapshot:
            raise SupervisedRecoveryDenied("MCP Action journal changed")

        # Existing recover_configured_mcp_transport fast-path only checks the
        # initialized bit and bootstrap label. A closed/absent session must
        # renegotiate instead of advertising stale transport readiness.
        if (
            before is not None
            and before._initialized is True
            and not _valid_joined_connection(registry, server_id, (host, port, bearer))
        ):
            _revoke(before)
            records[server_id]["initialized"] = False
            records[server_id]["status"] = "unavailable"

        try:
            result = await recover_configured_mcp_transport(
                server_id, registry=registry, specs=specs, bootstrap=bootstrap
            )
        except asyncio.CancelledError:
            _revoke(registry._servers.get(server_id))
            raise
        except ValueError as exc:
            raise SupervisedRecoveryDenied("Supervised MCP transport rejected") from exc

        after = registry._servers.get(server_id)
        if result.get("status") not in {
            "initialized_transport_only",
            "already_initialized_unverified",
        }:
            raise SupervisedRecoveryDenied("Local MCP health or initialize unavailable")

        try:
            if (
                (before is not None and after is not before)
                or not _valid_joined_connection(registry, server_id, (host, port, bearer))
                or _request_journal(after) != (snapshot if before is not None else ((), ()))
                or _bootstrap_records(bootstrap)[server_id]["status"] != "initialized"
                or (
                    server_id in SIX_SERVICES
                    and await _fresh_inert_owned_process(app, server_id) is not True
                )
            ):
                raise SupervisedRecoveryDenied("Current supervised MCP state changed")
        except (SupervisedRecoveryDenied, ValueError, HostInertFleetDenied) as exc:
            # Revocation removes only declarations; preserve exact replay IDs.
            _revoke(after)
            records[server_id]["initialized"] = False
            records[server_id]["status"] = "unavailable"
            raise SupervisedRecoveryDenied("Supervised MCP witness became unknown") from exc
        except asyncio.CancelledError:
            # A lost HTTP acknowledgment during the postflight owner check
            # never leaves a fresh declaration dispatchable without that check.
            _revoke(after)
            records[server_id]["initialized"] = False
            records[server_id]["status"] = "unavailable"
            raise

        return {
            "server_id": server_id,
            "status": "supervised_initialized_transport_only",
            "host_owned_inert_go_process_observed": go_owned,
            "host_owned_inert_go_process_is_registry_endpoint_verified": False,
            "http_initialize_declaration_observed": True,
            "signed_0033_witness_verified": False,
            "current_signed_action_verified": False,
            "independent_target_effect_verified": False,
            "unknown_original_action_safe_to_retry": False,
            "automatic_process_start_performed": False,
            "tool_or_scan_executed": False,
            "production_certified": False,
        }


@router.post("/mcp/{server_id}/supervised-reconcile")
async def supervised_reconcile_endpoint(
    server_id: str,
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    """Explicit POST: local peer, signed senior JWT, zero supplied config."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    if request.client is None or request.client.host not in {"127.0.0.1", "::1"}:
        raise HTTPException(403, "Host-local senior operator required")
    if type(server_id) is not str or server_id not in _EXPECTED:
        raise HTTPException(404, "Unknown MCP service")
    orchestrator = state.get("orchestrator")
    registry = getattr(orchestrator, "mcp_registry", None)
    bootstrap = state.get("mcp_bootstrap_readiness")
    if not isinstance(registry, MCPRegistry):
        raise HTTPException(503, "MCP recovery registry unavailable")
    from ai_osop.api.main import configured_mcp_server_specs

    try:
        return await reconcile_single_supervised_transport(
            server_id,
            registry=registry,
            bootstrap=bootstrap,
            specs=configured_mcp_server_specs(),
            app=request.app,
        )
    except SupervisedRecoveryDenied as exc:
        raise HTTPException(409, "Supervised MCP transport reconciliation unavailable") from exc
