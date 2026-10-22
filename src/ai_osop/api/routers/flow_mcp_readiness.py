"""Owner-scoped join of durable MCP Actions with local negotiated MCP metadata.

Unlike PentAGI's per-worker runtime, the shared MCP registry is process-local.
This read-only operator view MUST NOT equate an initialized catalog, a completed
provider request, or a signed Action with an independently observed target effect.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ai_osop.api.routers.flow_mcp_actions import (
    _binding,
    _error,
    _executor,
    _headers,
    _operator,
)
from ai_osop.mcp.protocol import MCPToolDefinition, SideEffectClass
from ai_osop.orchestrator.flow_mcp_action_executor import (
    FlowMCPActionDenied,
    _manifest_sha256,
    _tool_definition,
)

router = APIRouter(prefix="/flows", tags=["flow-mcp-provider-readiness"])

# Trusted configured startup IDs, not an arbitrary client or process-global
# registry enumeration. The full list is intentionally static and privacy-safe.
_SERVER_IDS = (
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
)
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ACTION_STATES = frozenset({"prepared", "reserved", "unknown", "finished", "cancelled"})
_CIRCUITS = frozenset({"open", "closed", "half_open"})


def _summarize(registry: Any, records: Any) -> list[Dict[str, Any]]:
    """Inert, bounded signed-action counters. Never inspect raw parameters."""
    servers = getattr(registry, "_servers", None)
    if (
        not isinstance(servers, dict)
        or len(servers) > 32
        or not isinstance(records, list)
        or len(records) > 100
    ):
        raise ValueError("Unbounded runtime inventory")
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in _SERVER_IDS}
    for row in records:
        if (
            not isinstance(row, dict)
            or row.get("status") not in _ACTION_STATES
            or row.get("server_id") not in grouped
            or not isinstance(row.get("tool_name"), str)
            or not _NAME.fullmatch(row["tool_name"])
            or not isinstance(row.get("declaration_sha256"), str)
            or not _SHA.fullmatch(row["declaration_sha256"])
        ):
            raise ValueError("Untrusted durable MCP Action catalog")
        grouped[row["server_id"]].append(row)

    out: list[Dict[str, Any]] = []
    for server_id in _SERVER_IDS:
        connection = servers.get(server_id)
        present = connection is not None
        initialized = False
        circuit = "unavailable"
        count = 0
        if present:
            if getattr(connection, "server_id", None) != server_id:
                raise ValueError("Mismatched runtime server")
            circuit = connection.get_circuit_state()
            if circuit not in _CIRCUITS:
                raise ValueError("Invalid circuit health")
            initialized = connection._initialized is True
            declared = connection._tools
            if not isinstance(declared, dict) or len(declared) > 128:
                raise ValueError("Unbounded runtime tools")
            if initialized:
                for tool_name, definition in declared.items():
                    if (
                        not isinstance(tool_name, str)
                        or not _NAME.fullmatch(tool_name)
                        or not isinstance(definition, MCPToolDefinition)
                        or definition.name != tool_name
                        or not isinstance(definition.side_effect_class, SideEffectClass)
                    ):
                        raise ValueError("Untrusted runtime tool manifest")
                count = len(declared)
        states = Counter(row["status"] for row in grouped[server_id])
        changed = 0
        for action in grouped[server_id]:
            if action["status"] != "prepared":
                continue
            # A stale or undeclared tool is never reported usable. Do not
            # calculate a positive approval: actual dispatch must recheck the
            # signed Task, lease, reviewer, target and resource SHA afresh.
            try:
                current = _tool_definition(registry, server_id, action["tool_name"])
                matches = _manifest_sha256(server_id, current) == action["declaration_sha256"]
            except Exception:
                matches = False
            if not matches:
                changed += 1
        out.append(
            {
                "server_id": server_id,
                "registered_in_process": present,
                "manifest_initialized": initialized,
                "circuit_state": circuit,
                "declared_tool_count": count,
                "prepared_actions": states["prepared"],
                "reserved_actions": states["reserved"],
                "unknown_actions": states["unknown"],
                "finished_actions": states["finished"],
                "cancelled_actions": states["cancelled"],
                "stale_prepared_declarations": changed,
                "runtime_health_verified": False,
                "provider_side_signed_admission_verified": False,
                "execution_authorized": False,
                "independent_target_effect_verified": False,
            }
        )
    return out


@router.get("/{flow_id}/mcp-provider-readiness")
async def get_flow_mcp_provider_readiness(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=5, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """No health GET, initialization, provider I/O, Task mutation or approval."""
    _headers(response)
    binding = _binding(
        flow_id, expected_engagement_id, expected_revision, expected_authorization_version
    )
    try:
        service = _executor()
        # The original signed current ROE/Flow owner gate is strictly stronger
        # than the older global MCP catalog's senior-role-only shortcut.
        await service._authority(binding, operator)
        ledger = await service.store.list(binding, operator["sub"])
        actions = ledger.get("actions") if isinstance(ledger, dict) else None
        if ledger.get("flow_id") != flow_id:
            raise ValueError("Mismatched signed action catalog")
        servers = _summarize(service.registry, actions)
        # Authority may have been revoked while we fetched PostgreSQL rows.
        await service._authority(binding, operator)
        return {
            "engagement_id": expected_engagement_id,
            "flow_id": flow_id,
            "flow_revision": expected_revision,
            "authorization_version": expected_authorization_version,
            "kind": "signed_action_and_process_inventory_unverified",
            "provider_contacted": False,
            "execution_authorized": False,
            "independent_target_effect_verified": False,
            "servers": servers,
        }
    except HTTPException:
        raise
    except FlowMCPActionDenied as exc:
        raise _error(exc) from exc
    except Exception as exc:
        raise HTTPException(503, "Current signed MCP provider readiness unavailable") from exc
