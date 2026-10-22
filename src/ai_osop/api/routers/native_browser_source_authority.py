"""Separate native Browser service admission immediately before navigation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.memory.browser_source_authority import (
    BrowserSourceAuthorityStore,
    BrowserSourceDenied,
    validate_request,
)
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore

router = APIRouter(tags=["native-browser-source-authority"])


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate browser source field")
        value[key] = item
    return value


def _authenticate(request: Request) -> None:
    if request.scope.get("query_string"):
        raise HTTPException(403, "Browser source query credentials prohibited")
    if sum(k.lower() == b"authorization" for k, _ in request.scope.get("headers", [])) != 1:
        raise HTTPException(401, "Dedicated browser service identity required")
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 520:
        raise HTTPException(401, "Dedicated browser service bearer required")
    supplied = header[7:]
    expected = os.environ.get("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", "")
    provider = os.environ.get("OSOP_BROWSER_MCP_BEARER_TOKEN", "")
    if (
        not 32 <= len(supplied) <= 512
        or not 32 <= len(expected) <= 512
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in supplied + expected)
        or (provider and hmac.compare_digest(expected, provider))
        or not hmac.compare_digest(
            hashlib.sha256(supplied.encode("ascii")).digest(),
            hashlib.sha256(expected.encode("ascii")).digest(),
        )
    ):
        raise HTTPException(403, "Independent browser service credential rejected")


async def _parse(request: Request) -> dict[str, str]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Bounded browser source JSON required")
    body = bytearray()
    async for fragment in request.stream():
        if len(fragment) > 2048 - len(body):
            raise HTTPException(413, "Browser source request too large")
        body.extend(fragment)
    try:
        value = json.loads(
            body,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")),
        )
        return validate_request(value)
    except (ValueError, TypeError, UnicodeError, BrowserSourceDenied) as exc:
        raise HTTPException(422, "Invalid or ambiguous browser source request") from exc


@router.post("/native-browser/source-preflight")
async def preflight_native_browser_source(request: Request, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    _authenticate(request)
    claimed = await _parse(request)
    try:
        orch = state.get("orchestrator")
        memory = getattr(orch, "session_memory", None)
        registry = getattr(orch, "mcp_registry", None)
        if memory is None or registry is None:
            raise BrowserSourceDenied(503, "Browser source authority unavailable")
        store = BrowserSourceAuthorityStore(FlowMCPActionStore(memory, registry))
        return await store.admit(claimed)
    except BrowserSourceDenied as exc:
        raise HTTPException(exc.status, "Current browser source admission unavailable") from exc
    except Exception as exc:
        raise HTTPException(503, "Durable browser source authority unavailable") from exc
