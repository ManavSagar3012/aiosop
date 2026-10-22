"""Explicit operator-controlled live MCP transport enrollment (never Action replay).

Startup may find the provider offline; after the separately authorized service
is launched this path performs ONE bounded, loopback-only health + manifest
negotiation. It does not run a tool, issue a grant, certify an effect, recover
UNKNOWN, or replace a registered identity with an empty replay journal.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, Sequence

from ai_osop.api.mcp_fleet_readiness import _FLEET
from ai_osop.mcp.protocol import MCPInitializeResponse, MCPRegistry

_LOCK = asyncio.Lock()
_DEADLINE = 8.0
_EXPECTED = {name: role == "critical" for name, role in _FLEET}


def _revoke(connection: Any) -> None:
    if connection is not None:
        connection._initialized = False
        connection._tools = {}
        connection._capabilities = []


async def recover_configured_mcp_transport(
    server_id: str,
    *,
    registry: MCPRegistry,
    specs: Sequence[tuple[str, str, int, Optional[str]]],
    bootstrap: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """One genuine local registry connect/initialize with no consequential call.

    `specs` is the application-owned startup roster, never caller-supplied
    HTTP inputs. Both absence of configuration and failure to prove the exact
    configured roster result in denial before any network request.
    """
    if (
        server_id not in _EXPECTED
        or type(bootstrap) is not dict
        or set(bootstrap) != set(_EXPECTED)
        or not isinstance(registry, MCPRegistry)
        or len(specs) != len(_EXPECTED)
        or {row[0] for row in specs} != set(_EXPECTED)
        or any(
            type(row) is not tuple
            or len(row) != 4
            or type(row[0]) is not str
            or type(row[1]) is not str
            or type(row[2]) is not int
            or not 1 <= row[2] <= 65535
            or (row[3] is not None and type(row[3]) is not str)
            for row in specs
        )
        or any(
            type(bootstrap.get(name)) is not dict or bootstrap[name].get("critical") is not critical
            for name, critical in _EXPECTED.items()
        )
    ):
        raise ValueError("Exact configured MCP roster unavailable")

    endpoint = next(row for row in specs if row[0] == server_id)
    _, host, port, token = endpoint
    # Native JSON MCP is HTTP, NOT independently pinned TLS. Credentials,
    # even a browser or SourceMap bearer, cannot traverse DNS or remote hosts.
    # Require the operator to configure the exact numeric loopback address.
    if host != "127.0.0.1":
        raise ValueError("Only pinned numeric loopback MCP recovery allowed")

    async with _LOCK:
        record = bootstrap[server_id]
        connection = registry._servers.get(server_id)
        if connection is not None and (
            connection.server_id != server_id
            or connection.host != host
            or connection.port != port
            or connection.auth_token != token
        ):
            raise ValueError("Registered MCP transport identity differs from configuration")
        if connection is not None and any(
            getattr(execution, "active", None) is not False
            for execution in connection._executions.values()
        ):
            raise ValueError("Original in-flight MCP action cannot be reconnected")
        if (
            connection is not None
            and connection._initialized is True
            and record.get("status") == "initialized"
            and record.get("initialized") is True
        ):
            return {
                "server_id": server_id,
                "status": "already_initialized_unverified",
                "runtime_health_verified": False,
                "current_authorized_operation_verified": False,
                "independent_target_effect_verified": False,
                "safe_to_retry_unknown_action": False,
            }
        record["status"] = "unavailable"
        record["initialized"] = False
        record["runtime_health_verified"] = False
        _revoke(connection)
        try:
            if connection is None:
                connection = await asyncio.wait_for(
                    registry.register_server(server_id, host, port, token),
                    timeout=_DEADLINE,
                )
            else:
                # Reuse the SAME MCPConnection and its used request IDs; never
                # construct a second object after an ambiguous original Action.
                await asyncio.wait_for(connection.connect(), timeout=_DEADLINE)
            record["registered"] = True
            declaration = await asyncio.wait_for(
                registry.initialize_server(
                    server_id, scope={}, credentials={}, session_id="operator-inert-reconcile"
                ),
                timeout=_DEADLINE,
            )
            if (
                not isinstance(declaration, MCPInitializeResponse)
                or declaration.server_id != server_id
                or declaration.status != "ready"
                or not declaration.tools
                or len({tool.name for tool in declaration.tools}) != len(declaration.tools)
                or registry._servers.get(server_id) is not connection
                or connection._initialized is not True
                or connection._session is None
            ):
                raise ValueError("MCP manifest not initialized")
        except asyncio.CancelledError:
            _revoke(connection)
            raise
        except Exception:
            _revoke(connection)
            return {
                "server_id": server_id,
                "status": "unavailable",
                "runtime_health_verified": False,
                "current_authorized_operation_verified": False,
                "independent_target_effect_verified": False,
                "safe_to_retry_unknown_action": False,
            }
        record["initialized"] = True
        record["status"] = "initialized"
        return {
            "server_id": server_id,
            "status": "initialized_transport_only",
            "runtime_health_verified": False,
            "current_authorized_operation_verified": False,
            "independent_target_effect_verified": False,
            "safe_to_retry_unknown_action": False,
        }
