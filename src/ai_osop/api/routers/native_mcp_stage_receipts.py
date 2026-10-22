"""Pinned service-only, never operator-callable, native worker stage testimony."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.api.routers.native_mcp_redemption import (
    _service_principal,
    _trust_roots,
)
from ai_osop.core.native_mcp_grant_signing import verify_grant
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_stage_receipts import NativeStageReceiptStore

router = APIRouter(tags=["native-mcp-worker-stage-receipts"])


@router.post("/native-grants/stage-receipt")
async def submit_native_worker_stage_receipt(
    request: Request, response: Response
) -> Dict[str, Any]:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    server_id, secret = _service_principal(request)
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
        or request.headers.get("content-length", "").isdigit()
        and int(request.headers["content-length"]) > 8192
    ):
        raise HTTPException(403, "Native worker stage proof unavailable")
    # Enforce the bound WHILE streaming, never after eagerly buffering an
    # arbitrary request body into application memory.
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > 8192:
            raise HTTPException(403, "Native worker stage proof exceeds bounds")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not 1 <= len(raw) <= 8192:
        raise HTTPException(403, "Native worker stage proof unavailable")
    try:
        import json

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            obj: dict[str, Any] = {}
            for key, value in items:
                if key in obj:
                    raise ValueError("Ambiguous duplicate signed worker receipt")
                obj[key] = value
            return obj

        body = json.loads(raw, object_pairs_hook=pairs)
        if type(body) is not dict or set(body) != {"grant", "receipt"}:
            raise ValueError("Wrong signed stage receipt format")
        signed = body["grant"]
        claims = verify_grant(signed, public_keys=_trust_roots())
        if claims["server_id"] != server_id or claims["resource_sha256"] is None:
            raise ValueError("Stage requires signed original resource authority")
        orch = state.get("orchestrator")
        memory = getattr(orch, "session_memory", None)
        registry = getattr(orch, "mcp_registry", None)
        if memory is None or registry is None:
            raise ValueError("Native stage authority unavailable")
        return await NativeStageReceiptStore(FlowMCPActionStore(memory, registry)).record(
            signed, body["receipt"], server_id=server_id, server_secret=secret
        )
    except Exception as exc:
        raise HTTPException(
            409, "Native worker receipt UNKNOWN or current source authority unavailable"
        ) from exc
