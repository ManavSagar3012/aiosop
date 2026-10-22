"""Read-only effective MCP transport join for the exact configured eleven.

This is process/HTTP and provider-declaration telemetry, never a signed Action,
native execution grant, original Task readback or independent target witness.
No network call, process launch, tool dispatch or registry mutation occurs here.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ai_osop.api.deps import require_role, state
from ai_osop.api.mcp_fleet_readiness import _FLEET, mcp_fleet_process_visibility
from ai_osop.api.native_inert_fleet_control import host_native_inert_control
from ai_osop.mcp.native_inert_process_fleet import SIX_SERVICES
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry, MCPToolDefinition


router = APIRouter(prefix="/system", tags=["system"])
_EXPECTED = {name: role for name, role in _FLEET}
_HOST_STATES = frozenset(
    {"host_unconfigured", "not_started", "starting", "running", "stopped", "unknown_closed"}
)
_BOOTSTRAP_STATUSES = frozenset({"unavailable", "registered", "initialized"})


def _specification(
    specs: Sequence[tuple[str, str, int, Optional[str]]],
) -> dict[str, tuple[str, int, Optional[str]]]:
    """Require complete trusted application configuration before any projection."""
    if type(specs) not in (list, tuple) or len(specs) != 11:
        raise ValueError("Exact eleven MCP configuration required")
    result: dict[str, tuple[str, int, Optional[str]]] = {}
    for row in specs:
        if (
            type(row) is not tuple
            or len(row) != 4
            or type(row[0]) is not str
            or row[0] not in _EXPECTED
            or row[0] in result
            or type(row[1]) is not str
            or not row[1]
            or len(row[1]) > 255
            or type(row[2]) is not int
            or not 1 <= row[2] <= 65535
            or (row[3] is not None and type(row[3]) is not str)
        ):
            raise ValueError("Invalid eleven MCP configuration")
        result[row[0]] = (row[1], row[2], row[3])
    if set(result) != set(_EXPECTED):
        raise ValueError("Incomplete eleven MCP configuration")
    return result


def _bootstrap_records(bootstrap: Any) -> dict[str, dict[str, Any]]:
    if type(bootstrap) is not dict or set(bootstrap) != set(_EXPECTED):
        raise ValueError("Exact eleven MCP startup readback unavailable")
    for name, importance in _FLEET:
        row = bootstrap.get(name)
        if (
            type(row) is not dict
            or set(row)
            != {"critical", "registered", "initialized", "status", "runtime_health_verified"}
            or row["critical"] is not (importance == "critical")
            or type(row["registered"]) is not bool
            or type(row["initialized"]) is not bool
            or type(row["status"]) is not str
            or row["status"] not in _BOOTSTRAP_STATUSES
            or row["runtime_health_verified"] is not False
            or (row["initialized"] and not row["registered"])
            or (row["initialized"] != (row["status"] == "initialized"))
            or (row["status"] == "registered" and not row["registered"])
        ):
            raise ValueError("Invalid MCP startup readback")
    return bootstrap


def _host_lifecycle(app: Any) -> str:
    """Passive controller-state read; status() may clean up PIDs on a fault."""
    control = host_native_inert_control(app)
    if control is None:
        return "host_unconfigured"
    observed = getattr(control, "_state", None)
    return observed if type(observed) is str and observed in _HOST_STATES else "unknown_closed"


def build_mcp_eleven_transport_diagnostics(
    *,
    process_health: dict[str, Any],
    registry: MCPRegistry,
    specs: Sequence[tuple[str, str, int, Optional[str]]],
    bootstrap: dict[str, dict[str, Any]],
    native_host_lifecycle: str = "host_unconfigured",
) -> dict[str, Any]:
    """Join validated process health to configured transport without effects.

    A provider's validly parsed manifest is only a *declared* schema. No
    operator-wide read can infer per-engagement signed authority or target
    ownership evidence from a successful initialize, a process or a tool list.
    """
    spec_by_id = _specification(specs)
    records = _bootstrap_records(bootstrap)
    process = mcp_fleet_process_visibility(process_health)
    if (
        not isinstance(registry, MCPRegistry)
        or type(registry._servers) is not dict
        or len(registry._servers) > 32
        or not set(registry._servers).issubset(_EXPECTED)
        or type(native_host_lifecycle) is not str
        or native_host_lifecycle not in _HOST_STATES
    ):
        raise ValueError("Bounded MCP registry or inert host status unavailable")

    joined: list[dict[str, Any]] = []
    for process_item in process["services"]:
        name = process_item["server_id"]
        host, port, token = spec_by_id[name]
        connection = registry._servers.get(name)
        if connection is not None and not isinstance(connection, MCPConnection):
            raise ValueError("Untrusted MCP registry connection")
        identity_match = (
            connection is not None
            and connection.server_id == name
            and connection.host == host
            and connection.port == port
            and connection.auth_token == token
        )
        session = getattr(connection, "_session", None) if identity_match else None
        session_open = session is not None and getattr(session, "closed", None) is False
        tools = getattr(connection, "_tools", None) if identity_match else None
        schema_observed = (
            identity_match
            and session_open
            and getattr(connection, "_initialized", None) is True
            and type(tools) is dict
            and 1 <= len(tools) <= 128
            and all(
                type(tool_name) is str
                and isinstance(tool, MCPToolDefinition)
                and tool_name == tool.name
                for tool_name, tool in tools.items()
            )
        )
        bootstrap_row = records[name]
        # Startup readbacks can be stale after reconnect/disconnect. They do
        # not override the live connection, its session or declared schema.
        if host != "127.0.0.1":
            effective = "unverified_nonnumeric_or_nonlocal_http"
        elif connection is None:
            effective = "not_registered"
        elif not identity_match:
            effective = "registry_identity_mismatch"
        elif not session_open:
            effective = "no_current_http_session"
        elif not schema_observed:
            effective = "connected_without_valid_current_declaration"
        elif not bootstrap_row["initialized"]:
            effective = "registry_initialized_bootstrap_stale"
        else:
            effective = "initialized_transport_declaration_only"

        is_native_go = name in SIX_SERVICES
        joined.append(
            {
                "server_id": name,
                "importance": process_item["importance"],
                "configured_transport": (
                    "numeric_loopback_http" if host == "127.0.0.1" else "unverified_http_host"
                ),
                "bootstrap_status": bootstrap_row["status"],
                "registry_registered": process_item["process_registered"],
                "registry_initialized": process_item["process_initialized"],
                "registry_identity_matches_config": identity_match if connection else None,
                "http_session_open": session_open if identity_match else None,
                "provider_schema_declared": bool(schema_observed),
                "provider_schema_independently_verified": False,
                "effective_transport_status": effective,
                "native_go_inert_host_lifecycle": native_host_lifecycle if is_native_go else None,
                # A host controller state is NOT fresh proof that a PID/socket
                # is currently owned, and is never a 0033 signed PID witness.
                "native_go_current_process_owned_verified": False,
                "current_signed_action_verified": False,
                "independently_verified_target_effect": False,
                "safe_to_retry_unknown_action": False,
                "production_certified": False,
            }
        )
    return {
        "catalog_scope": "configured_eleven_effective_transport_observation_only",
        "configured_count": len(_FLEET),
        "native_go_inert_control_installed": native_host_lifecycle != "host_unconfigured",
        "services": joined,
        "independently_verified_operations": None,
        "production_certified": False,
        "release_decision": "NOT PRODUCTION CERTIFIED / NOT READY",
    }


@router.get("/mcp/transport-diagnostics")
async def get_mcp_eleven_transport_diagnostics(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(require_role("senior_operator")),
) -> dict[str, Any]:
    """Mounted-ready senior read: no request-controlled network destinations."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    claims = operator.get("claims") if type(operator) is dict else None
    if (
        not isinstance(claims, dict)
        or type(claims.get("exp")) is not int
        or claims["exp"] <= 0
        or operator.get("role") != "senior_operator"
        or not isinstance(operator.get("sub"), str)
        or not operator["sub"].strip()
    ):
        raise HTTPException(403, "Signed senior operator required")
    if request.url.scheme != "https" and getattr(request.client, "host", None) not in {
        "127.0.0.1",
        "::1",
    }:
        raise HTTPException(403, "Local or HTTPS readback required")
    if request.scope.get("query_string"):
        raise HTTPException(422, "Transport diagnostics takes no URL parameters")
    orch = state.get("orchestrator")
    registry = getattr(orch, "mcp_registry", None)
    if not isinstance(registry, MCPRegistry):
        raise HTTPException(503, "MCP transport registry unavailable")
    # Existing senior endpoint already bounds identities and counters.
    from ai_osop.api.routers.system import get_mcp_health
    from ai_osop.api.main import configured_mcp_server_specs

    health = await get_mcp_health(operator=operator)
    try:
        return build_mcp_eleven_transport_diagnostics(
            process_health=health,
            registry=registry,
            specs=configured_mcp_server_specs(),
            bootstrap=state.get("mcp_bootstrap_readiness"),
            native_host_lifecycle=_host_lifecycle(request.app),
        )
    except ValueError as exc:
        raise HTTPException(503, "Effective MCP transport readback unavailable") from exc
