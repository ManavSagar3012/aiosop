"""Read-only, signed current-Action SourceMap status/recovery admission.

The separate status service bearer is NOT a native tool bearer, never makes
an original file available, and cannot consume/replay the original 0027 Action.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.api.routers.native_sourcemap_source_authority import _bounded_request
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.sourcemap_source_authority import SourceMapSourceDenied
from ai_osop.memory.sourcemap_status_authority import SourceMapStatusAuthorityStore

router = APIRouter(tags=["native-sourcemap-status-authority"])


def _dedicated_status_bearer(request: Request) -> None:
    if request.scope.get("query_string"):
        raise HTTPException(403, "SourceMap status query credentials prohibited")
    if sum(name.lower() == b"authorization" for name, _ in request.scope.get("headers", [])) != 1:
        raise HTTPException(401, "Dedicated SourceMap status service bearer required")
    given = request.headers.get("authorization", "")
    supplied = given[7:] if given.startswith("Bearer ") else ""
    required = os.getenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", "")
    source = os.getenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "")
    native = os.getenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", "")
    if (
        len(given) > 520
        or not 32 <= len(supplied) <= 512
        or not 32 <= len(required) <= 512
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in supplied + required)
        or (source and hmac.compare_digest(required, source))
        or (native and hmac.compare_digest(required, native))
        or not hmac.compare_digest(
            hashlib.sha256(supplied.encode("ascii")).digest(),
            hashlib.sha256(required.encode("ascii")).digest(),
        )
    ):
        raise HTTPException(403, "Independent SourceMap status identity rejected")


@router.post("/native-sourcemap/status-preflight")
async def status_preflight(request: Request, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    _dedicated_status_bearer(request)
    original = await _bounded_request(request)
    try:
        orchestrator = state.get("orchestrator")
        memory = getattr(orchestrator, "session_memory", None)
        registry = getattr(orchestrator, "mcp_registry", None)
        if memory is None or registry is None:
            raise SourceMapSourceDenied(503, "Current original SourceMap status unavailable")
        authority = SourceMapStatusAuthorityStore(FlowMCPActionStore(memory, registry))
        return await authority.admit(original)
    except SourceMapSourceDenied as exc:
        raise HTTPException(exc.status, "Current original SourceMap status unavailable") from exc
    except Exception as exc:
        raise HTTPException(503, "Signed original SourceMap status unavailable") from exc
