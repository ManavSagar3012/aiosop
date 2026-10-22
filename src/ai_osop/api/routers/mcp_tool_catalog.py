"""Tenant-fenced, non-executable catalog of *declared* live MCP tool metadata.

PentAGI's flow-tool registry is tied to each Flow's worker.  AI-OSOP's MCP
registry is global, so merely serializing its definitions to operators would
leak private provider configuration and risk implying tool-use authorization.
This route supplies only a bounded display catalog after durable signed Flow
admission.  No remote discovery, tool call, initialization, or grant occurs.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.mcp.protocol import MCPRegistry, MCPToolDefinition, SideEffectClass
from ai_osop.memory.session_memory import SessionMemory

router = APIRouter(prefix="/engagements", tags=["mcp-tool-catalog"])
_ENGAGEMENT = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,90}\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")
_STATES = frozenset({"closed", "open", "half_open"})


@router.get("/{engagement_id}/flow-tool-catalog")
async def read_flow_tool_catalog(
    engagement_id: str,
    response: Response,
    flow_id: str = Query(..., min_length=6, max_length=96),
    expected_flow_revision: int = Query(..., ge=0),
    expected_authorization_version: int = Query(..., ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Read registered tool *declarations*, never execution capability.

    The registry is process-global; this endpoint cannot claim that a tool is
    reachable, authorized for this engagement or tested on its target. A real
    tool invocation must independently pass the production signed Task/ROE,
    human approval, scope, and pre-dispatch MCP gates.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if not _ENGAGEMENT.fullmatch(engagement_id) or not _FLOW.fullmatch(flow_id):
        raise HTTPException(422, "Bounded Flow catalog identity required")
    if (
        not isinstance(operator, dict)
        or operator.get("role") not in {"operator", "senior_operator"}
        or not isinstance(operator.get("sub"), str)
        or not isinstance(operator.get("claims"), dict)
        or type(operator["claims"].get("exp")) is not int
        or operator["claims"]["exp"] <= int(datetime.now(timezone.utc).timestamp())
    ):
        raise HTTPException(403, "Signed operator identity required")
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    registry = getattr(orch, "mcp_registry", None)
    if not isinstance(memory, SessionMemory) or not isinstance(registry, MCPRegistry):
        raise HTTPException(503, "Signed MCP catalog unavailable")

    async def current_authority() -> None:
        signed = await memory.assert_signed_authorization(
            engagement_id, expected_version=expected_authorization_version
        )
        session = await memory.load_session_state(engagement_id)
        flow = await memory.load_flow(flow_id)
        if (
            signed is None
            or signed.version != expected_authorization_version
            or session is None
            or session.session_id != engagement_id
            or session.phase in {"halted", "completed"}
            or getattr(session.scope, "engagement_id", None) != engagement_id
            # A global senior role does not delegate another tenant's private
            # MCP inventory. Explicit scoped reviewer rights belong to a
            # different signed workflow, not this owner-only Flow catalog.
            or session.created_by != operator["sub"]
            or flow is None
            or flow.id != flow_id
            or flow.engagement_id != engagement_id
            or flow.status not in {"pending", "running"}
            or flow.revision != expected_flow_revision
        ):
            raise ValueError("Current signed catalog ownership unavailable")

    try:
        await current_authority()
        servers = registry._servers
        if not isinstance(servers, dict) or len(servers) > 32:
            raise ValueError("MCP server catalog is unbounded")
        entries = []
        count = 0
        for server_id, connection in sorted(servers.items()):
            if not isinstance(server_id, str) or not _NAME.fullmatch(server_id):
                raise ValueError("Malformed server identity")
            if connection is None or connection.server_id != server_id:
                raise ValueError("Registry server identity mismatch")
            # Uninitialized entries have not negotiated a real tool manifest;
            # never represent them as available or fill in invented tools.
            initialized = connection._initialized is True
            circuit = connection.get_circuit_state()
            if circuit not in _STATES:
                raise ValueError("Unsupported tool circuit state")
            declared = connection._tools
            if not isinstance(declared, dict) or len(declared) > 128:
                raise ValueError("MCP tool catalog is unbounded")
            tools = []
            if initialized:
                for tool_name, definition in sorted(declared.items()):
                    if (
                        not isinstance(tool_name, str)
                        or not _NAME.fullmatch(tool_name)
                        or not isinstance(definition, MCPToolDefinition)
                        or definition.name != tool_name
                        or not isinstance(definition.side_effect_class, SideEffectClass)
                        or type(definition.requires_approval) is not bool
                        or type(definition.scope_check) is not bool
                    ):
                        raise ValueError("Untrusted MCP manifest shape")
                    count += 1
                    if count > 256:
                        raise ValueError("Combined MCP tool catalog is unbounded")
                    tools.append(
                        {
                            "name": tool_name,
                            "side_effect_class": definition.side_effect_class.value,
                            "declared_requires_approval": definition.requires_approval,
                            "declared_scope_check": definition.scope_check,
                            "signed_task_required_for_execution": True,
                            "execution_authorized": False,
                            "runtime_health_verified": False,
                        }
                    )
            entries.append(
                {
                    "server_id": server_id,
                    "manifest_initialized": initialized,
                    "circuit_state": circuit,
                    "runtime_health_verified": False,
                    "tools": tools,
                }
            )
        # The entire registry snapshot is subject to a second current signed
        # authority check; no response may outlive intervening awaits/revoke.
        await current_authority()
        return {
            "engagement_id": engagement_id,
            "flow_id": flow_id,
            "flow_revision": expected_flow_revision,
            "authorization_version": expected_authorization_version,
            "catalog_kind": "declarations_only_unverified",
            "execution_authorized": False,
            "servers": entries,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Current signed MCP tool catalog unavailable") from exc
