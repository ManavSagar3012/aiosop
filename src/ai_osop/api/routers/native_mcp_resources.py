"""Authenticated, one-shot source bytes for an already redeemed native grant.

Only mounted behind separately pinned TLS. This endpoint never authorizes a
tool invocation; it verifies current authorization and offers inert bytes once.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.api.routers.native_mcp_redemption import (
    _bounded_json,
    _service_principal,
    _trust_roots,
)
from ai_osop.core.native_mcp_grant_signing import verify_grant
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_resource_delivery import NativeMCPResourceDelivery

router = APIRouter(tags=["native-mcp-original-resources"])


@router.post("/native-grants/resources")
async def offer_native_mcp_original_resources(
    request: Request, response: Response
) -> Dict[str, Any]:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    server_id, secret = _service_principal(request)
    # Shared bounded JSON parser normalizes a bare issuer grant into
    # {"grant": signed, "worker_proof": None} for the *redemption* API.
    # Resource delivery is a distinct post-redemption call: never accept a
    # supervisor proof again here, and verify only the original signed grant.
    envelope = await _bounded_json(request)
    if envelope["worker_proof"] is not None:
        raise HTTPException(422, "Original signed resource grant required")
    signed = envelope["grant"]
    try:
        # Public trust root MUST be independently provisioned, not extracted
        # from the same signed token. The resource store also verifies the
        # issuer and current source independently before any byte disclosure.
        claims = verify_grant(signed, public_keys=_trust_roots())
        if claims["server_id"] != server_id or claims.get("resource_sha256") is None:
            raise ValueError("Separate resource capability required")
        orch = state.get("orchestrator")
        memory = getattr(orch, "session_memory", None)
        registry = getattr(orch, "mcp_registry", None)
        if memory is None or registry is None:
            raise ValueError("Current native execution authority unavailable")
        return await NativeMCPResourceDelivery(FlowMCPActionStore(memory, registry)).offer(
            signed, server_id=server_id, server_secret=secret
        )
    except Exception as exc:
        # Even on a committed DB offer, an ACK loss is UNKNOWN; never replay.
        raise HTTPException(
            409, "Native original resource delivery UNKNOWN or authority unavailable"
        ) from exc
