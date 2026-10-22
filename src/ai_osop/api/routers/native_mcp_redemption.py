"""Separately authenticated native server->PostgreSQL grant redemption.

The bearer is *service-channel authentication*, not Action authorization. The
grant's Ed25519 proof, current ROE/Task/lease and one-shot PostgreSQL CAS are
independent mandatory controls. Never expose a grant on an operator API.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Response

from ai_osop.api.deps import state
from ai_osop.core.native_mcp_grant_signing import (
    NativeGrantDenied,
    claim_sha256,
    verify_grant,
)

router = APIRouter(tags=["native-mcp-grant-redemption"])


def _strict_pairs(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("Duplicate native grant JSON")
        value[name] = item
    return value


def _service_principal(request: Request) -> tuple[str, str]:
    """Dedicated independent service credential; absent always denies.

    Deploy only behind an independently authenticated TLS/mTLS ingress. This
    proof does not replace the signed grant nor native TLS pinning.
    """
    # The independently provisioned per-server secret is checked again, in
    # constant time, by NativeMCPExecutionGrantStore._authenticate_server.
    # Merely claiming a server ID never authorizes redemption.
    server_id = request.headers.get("x-osop-native-server-id", "")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", server_id):
        raise HTTPException(401, "Bounded native MCP server identity required")
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 520:
        raise HTTPException(401, "Independent native MCP service bearer required")
    token = header.removeprefix("Bearer ")
    if not 20 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise HTTPException(403, "Untrusted native MCP service identity")
    if "token" in request.query_params or "grant" in request.query_params:
        raise HTTPException(403, "Native capability must not be passed in URL")
    return server_id, token


def _trust_roots() -> Dict[str, str]:
    raw = os.environ.get("OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON", "")
    if not 2 <= len(raw) <= 8192:
        raise NativeGrantDenied("Independently trusted native issuer keys unavailable")
    parsed = json.loads(raw, object_pairs_hook=_strict_pairs)
    if not isinstance(parsed, dict) or not 1 <= len(parsed) <= 16:
        raise NativeGrantDenied("Independently trusted native issuer keys unavailable")
    return parsed


async def _bounded_json(request: Request) -> Dict[str, Any]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Native redemption requires bounded JSON")
    body = bytearray()
    async for fragment in request.stream():
        if len(fragment) > 4096 - len(body):
            raise HTTPException(413, "Native grant metadata exceeds safe bound")
        body.extend(fragment)
    try:
        document = json.loads(
            body,
            object_pairs_hook=_strict_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Invalid JSON constant")),
        )
        if not isinstance(document, dict):
            raise ValueError("Incomplete grant envelope")
        if set(document) == {"claims", "kid", "signature"}:
            return {"grant": document, "worker_proof": None}
        if set(document) != {"grant", "worker_proof"} or (
            type(document["grant"]) is not dict
            or set(document["grant"]) != {"claims", "kid", "signature"}
            or type(document["worker_proof"]) is not dict
            or set(document["worker_proof"]) != {"claims", "kid", "signature"}
        ):
            raise ValueError("Incomplete supervised grant envelope")
        return document
    except (ValueError, TypeError, UnicodeError) as exc:
        raise HTTPException(422, "Invalid or ambiguous native MCP capability") from exc


async def _redeem_trusted(
    document: Dict[str, Any],
    *,
    server_id: str,
    server_secret: str,
    worker_proof: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Run only after separate service authentication and Ed25519 proof."""
    from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
    from ai_osop.memory.native_mcp_execution_grants import NativeMCPExecutionGrantStore

    try:
        claims = verify_grant(document, public_keys=_trust_roots())
        digest = claim_sha256(claims)
        orch = state.get("orchestrator")
        memory = getattr(orch, "session_memory", None)
        registry = getattr(orch, "mcp_registry", None)
        if memory is None or registry is None:
            raise NativeGrantDenied("Native MCP live authority is not available")
        store = NativeMCPExecutionGrantStore(FlowMCPActionStore(memory, registry))
        if worker_proof is None:
            # Preserve the existing one-time RAM-only 0029 inert API contract.
            # Source still rejects a resource-bound grant without separate
            # independently signed supervisor proof.
            accepted = await store.redeem(
                document, server_id=server_id, server_secret=server_secret
            )
        else:
            accepted = await store.redeem(
                document,
                server_id=server_id,
                server_secret=server_secret,
                worker_proof=worker_proof,
            )
        if (
            not isinstance(accepted, dict)
            or set(accepted) != {"grant_id", "request_id", "claim_sha256", "durably_redeemed"}
            or accepted.get("durably_redeemed") is not True
        ):
            raise NativeGrantDenied("Native MCP durable admission unconfirmed")
        if (
            accepted.get("grant_id") != claims["grant_id"]
            or accepted.get("request_id") != claims["request_id"]
            or accepted.get("claim_sha256") != digest
        ):
            raise NativeGrantDenied("Native MCP durable grant identity changed")
        return {
            "grant_id": claims["grant_id"],
            "request_id": claims["request_id"],
            "claim_sha256": digest,
            "durably_redeemed": True,
        }
    except Exception as exc:
        # This can occur after PG COMMIT and ACK loss. Never disclose SQL,
        # signer material or a replay-capable grant. The server must not retry.
        raise HTTPException(409, "Native MCP outcome UNKNOWN or grant authority revoked") from exc


@router.post("/native-mcp/grants/redeem")
@router.post("/native-grants/redeem")
async def redeem_native_mcp_grant(request: Request, response: Response) -> Dict[str, Any]:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    server_id, secret = _service_principal(request)
    envelope = await _bounded_json(request)
    return await _redeem_trusted(
        envelope["grant"],
        server_id=server_id,
        server_secret=secret,
        worker_proof=envelope["worker_proof"],
    )
