"""Central source-side SourceMap original-byte preflight, not a data endpoint."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.sourcemap_source_authority import (
    SourceMapSourceAuthorityStore,
    SourceMapSourceDenied,
    validate_request,
)

router = APIRouter(tags=["native-sourcemap-source-authority"])


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate source credentials or identity")
        result[key] = value
    return result


def _service_bearer(request: Request) -> None:
    if request.scope.get("query_string"):
        raise HTTPException(403, "SourceMap service query credentials prohibited")
    if sum(name.lower() == b"authorization" for name, _ in request.scope.get("headers", [])) != 1:
        raise HTTPException(401, "Dedicated SourceMap service bearer required")
    provided = request.headers.get("authorization", "")
    if not provided.startswith("Bearer ") or len(provided) > 520:
        raise HTTPException(401, "Dedicated SourceMap service identity required")
    supplied = provided[7:]
    expected = os.getenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "")
    client = os.getenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
    if (
        not 32 <= len(supplied) <= 512
        or not 32 <= len(expected) <= 512
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in supplied + expected)
        or (client and hmac.compare_digest(expected, client))
        or not hmac.compare_digest(
            hashlib.sha256(supplied.encode("ascii")).digest(),
            hashlib.sha256(expected.encode("ascii")).digest(),
        )
    ):
        raise HTTPException(403, "Independent SourceMap issuer identity rejected")


async def _bounded_request(request: Request) -> dict[str, str]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].lower().strip()
        != "application/json"
    ):
        raise HTTPException(415, "SourceMap source JSON required")
    body = bytearray()
    async for fragment in request.stream():
        if len(fragment) > 2048 - len(body):
            raise HTTPException(413, "SourceMap source request exceeds bound")
        body.extend(fragment)
    try:
        value = json.loads(
            body,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Unsafe JSON constant")),
        )
        return validate_request(value)
    except (ValueError, TypeError, UnicodeError, SourceMapSourceDenied) as exc:
        raise HTTPException(422, "Invalid or ambiguous SourceMap source request") from exc


@router.post("/native-sourcemap/source-preflight")
async def source_preflight(request: Request, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    _service_bearer(request)
    claimed = await _bounded_request(request)
    try:
        orchestrator = state.get("orchestrator")
        memory = getattr(orchestrator, "session_memory", None)
        registry = getattr(orchestrator, "mcp_registry", None)
        if memory is None or registry is None:
            raise SourceMapSourceDenied(503, "Original signed SourceMap storage unavailable")
        authority = SourceMapSourceAuthorityStore(FlowMCPActionStore(memory, registry))
        return await authority.admit(claimed)
    except SourceMapSourceDenied as exc:
        raise HTTPException(exc.status, "Current SourceMap source admission unavailable") from exc
    except Exception as exc:
        raise HTTPException(503, "Durable SourceMap source authority unavailable") from exc
