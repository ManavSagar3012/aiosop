"""Host-only original 0027/0034 Browser CURRENT signed authority readback.

Never accepts Browser's own provider token, signs original navigation grants,
retries an UNKNOWN dispatch, verifies raw artifact bytes, or claims target effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.orchestrator.browser_current_authority_readback import (
    BrowserCurrentAuthorityDenied,
    BrowserCurrentAuthorityReadback,
    verify_current_browser_authority,
)

router = APIRouter(tags=["native-browser-current-authority"])
_MAX_REQUEST = 12288


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate Browser authority member")
        result[name] = value
    return result


def _service_bearer(request: Request) -> None:
    # Host-only channels may terminate TLS at this API, or use local
    # numeric-loopback cleartext between the TLS terminator and process.
    # Never accept a dedicated bearer over non-loopback plaintext HTTP.
    scheme = request.url.scheme
    peer = getattr(request.client, "host", None)
    if scheme != "https" and (scheme != "http" or peer not in {"127.0.0.1", "::1"}):
        raise HTTPException(403, "Host-only Browser authority transport required")
    if request.scope.get("query_string"):
        raise HTTPException(403, "Browser current-authority URL credentials forbidden")
    if sum(name.lower() == b"authorization" for name, _ in request.scope.get("headers", [])) != 1:
        raise HTTPException(401, "Dedicated central Browser authority bearer required")
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 520:
        raise HTTPException(401, "Dedicated central Browser authority bearer required")
    supplied = header[7:]
    expected = os.environ.get("OSOP_BROWSER_CURRENT_AUTHORITY_SERVICE_TOKEN", "")
    other_tokens = (
        os.environ.get("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", ""),
        os.environ.get("OSOP_BROWSER_MCP_BEARER_TOKEN", ""),
        os.environ.get("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", ""),
        os.environ.get("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", ""),
    )
    if (
        not 32 <= len(supplied) <= 512
        or not 32 <= len(expected) <= 512
        or any(ord(char) < 33 or ord(char) > 126 for char in supplied + expected)
        or any(token and hmac.compare_digest(expected, token) for token in other_tokens)
        or not hmac.compare_digest(
            hashlib.sha256(supplied.encode("ascii")).digest(),
            hashlib.sha256(expected.encode("ascii")).digest(),
        )
    ):
        raise HTTPException(403, "Independent central Browser authority credential rejected")


async def _parse(request: Request) -> tuple[dict[str, Any], dict[str, Any]]:
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Bounded Browser authority JSON required")
    total = bytearray()
    async for chunk in request.stream():
        if len(chunk) > _MAX_REQUEST - len(total):
            raise HTTPException(413, "Browser authority request too large")
        total.extend(chunk)
    try:
        data = json.loads(
            total,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON")),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("Nonintegral Browser identity")),
        )
        if type(data) is not dict or set(data) != {"source_proof", "provider_evidence"}:
            raise ValueError("Exact original source and provider envelopes required")
        for key in ("source_proof", "provider_evidence"):
            envelope = data[key]
            if (type(envelope) is not dict or set(envelope) != {"claims", "kid", "signature"}
                    or type(envelope["claims"]) is not dict):
                raise ValueError("Exact signed Browser envelope required")
        return data["source_proof"], data["provider_evidence"]
    except (ValueError, TypeError, UnicodeError) as error:
        raise HTTPException(422, "Ambiguous original Browser authority request rejected") from error


@router.post("/native-browser/current-authority/readback")
async def current_original_browser_authority(request: Request, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    _service_bearer(request)
    source, evidence = await _parse(request)
    try:
        orch = state.get("orchestrator")
        memory = getattr(orch, "session_memory", None)
        registry = getattr(orch, "mcp_registry", None)
        if memory is None or registry is None:
            raise BrowserCurrentAuthorityDenied("Central Browser authority unavailable")
        proof = await BrowserCurrentAuthorityReadback(
            FlowMCPActionStore(memory, registry)
        ).corroborate(source, evidence)
        expected = {
            name: source["claims"][name]
            for name in ("request_id", "engagement_id", "flow_id", "task_id",
                         "subtask_id", "action_id", "owner_id", "preflight_id")
        }
        verify_current_browser_authority(proof, expected)
        return {
            "status": "current_central_authority_only",
            "authority_proof": proof,
            "original_browser_artifact_bytes_verified": False,
            "independent_target_effect_verified": False,
            "automatic_retry_authorized": False,
            "production_release_certified": False,
        }
    except (BrowserCurrentAuthorityDenied, KeyError, ValueError, TypeError) as error:
        raise HTTPException(503, "Original Browser current central authority UNKNOWN") from error
    except Exception as error:
        raise HTTPException(503, "Original Browser central authority unavailable") from error
