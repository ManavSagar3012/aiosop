"""Service-only, separately authenticated 0033 native supervisor observations.

This ingress cannot start native tools, issue grants, dispatch Actions, retry
UNKNOWN results, or certify independent target effects. Each accepted event
is independently verified against current signed source in PostgreSQL by the
native worker supervision store, not by an untrusted HTTP claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import Field, StrictInt, StrictStr

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_mcp_actions import (
    _StrictBody,
    _binding,
    _executor,
    _headers,
    _operator,
    _parse,
)
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_supervisor_reconciliation import NativeMCPSupervisorReconciler
from ai_osop.memory.native_mcp_worker_supervision import NativeMCPWorkerSupervisionStore

router = APIRouter(tags=["native-mcp-independent-worker-supervision"])
_SUPERVISOR = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,79}\Z")
_GRANT = re.compile(r"ngr-[a-f0-9]{32}\Z")
_SUSPECT_STATES = frozenset({"provisioned", "running", "terminating", "terminated", "unknown"})
_GRANT_STATES = frozenset({"issued", "redeemed", "unknown", "revoked"})
_SUSPECT_CLASSES = frozenset({"suspected_orphan_unverified", "pending_independent_recovery"})


class RequestWorkerRecovery(_StrictBody):
    grant_id: StrictStr = Field(min_length=36, max_length=36)
    expected_supervisor_revision: StrictInt = Field(ge=1)


def _public_suspects(raw: Any, *, minimum_age_seconds: int, limit: int) -> Dict[str, Any]:
    """Strict allowlist: never return grant, request, worker or container IDs."""
    if (
        type(raw) is not dict
        or set(raw)
        != {
            "source",
            "candidates",
            "independent_process_liveness_verified",
            "automatic_reaping_enabled",
        }
        or raw["source"] != "durable_0033_last_transition_not_heartbeat"
        or raw["independent_process_liveness_verified"] is not False
        or raw["automatic_reaping_enabled"] is not False
        or type(raw["candidates"]) is not list
        or len(raw["candidates"]) > limit
    ):
        raise ValueError("Untrusted supervisor candidate metadata")
    result = []
    for index, candidate in enumerate(raw["candidates"], 1):
        if (
            type(candidate) is not dict
            or set(candidate)
            != {
                "grant_id",
                "request_id",
                "worker_id",
                "epoch",
                "revision",
                "state",
                "grant_status",
                "age_since_last_signed_transition_seconds",
                "classification",
                "container_destroyed_verified",
                "execution_replay_authorized",
            }
            or type(candidate["grant_id"]) is not str
            or _GRANT.fullmatch(candidate["grant_id"]) is None
            or type(candidate["request_id"]) is not str
            or re.fullmatch(r"req-[a-f0-9]{48}", candidate["request_id"]) is None
            or type(candidate["worker_id"]) is not str
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,95}", candidate["worker_id"]) is None
            or type(candidate["epoch"]) is not int
            or candidate["epoch"] <= 0
            or type(candidate["revision"]) is not int
            or not 1 <= candidate["revision"] < 2**31
            or candidate["state"] not in _SUSPECT_STATES
            or candidate["grant_status"] not in _GRANT_STATES
            or candidate["classification"] not in _SUSPECT_CLASSES
            or (candidate["state"] in {"unknown", "terminating"})
            != (candidate["classification"] == "pending_independent_recovery")
            or type(candidate["age_since_last_signed_transition_seconds"]) is not int
            or not minimum_age_seconds
            <= candidate["age_since_last_signed_transition_seconds"]
            <= 10 * 366 * 86400
            or candidate["container_destroyed_verified"] is not False
            or candidate["execution_replay_authorized"] is not False
        ):
            raise ValueError("Invalid or deceptive supervisor candidate")
        result.append(
            {
                "ordinal": index,
                "state": candidate["state"],
                "grant_status": candidate["grant_status"],
                "age_since_last_signed_transition_seconds": candidate[
                    "age_since_last_signed_transition_seconds"
                ],
                "classification": candidate["classification"],
                "container_destroyed_verified": False,
                "execution_replay_authorized": False,
            }
        )
    return {
        "source": "durable_0033_last_transition_not_heartbeat",
        "classification": "READ_ONLY_SUSPECT_UNVERIFIED",
        "count": len(result),
        "candidates": result,
        "independent_process_liveness_verified": False,
        "automatic_reaping_enabled": False,
        "worker_state_mutated": False,
        "independent_target_effect_verified": False,
    }


@router.get("/flows/{flow_id}/native-mcp-supervision/suspects")
async def read_native_worker_orphan_suspects(
    flow_id: str,
    request: Request,
    response: Response,
    expected_engagement_id: str = Query(min_length=5, max_length=64),
    expected_revision: int = Query(ge=0, le=2147483647),
    expected_authorization_version: int = Query(ge=1, le=2147483647),
    minimum_age_seconds: int = Query(default=60, ge=60, le=86400),
    limit: int = Query(default=20, ge=1, le=32),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Signed owner-scoped PG candidates only; never perform recovery/cleanup."""
    _headers(response)
    accepted_keys = {
        "expected_engagement_id",
        "expected_revision",
        "expected_authorization_version",
        "minimum_age_seconds",
        "limit",
    }
    seen_keys: set[str] = set()
    for name, _ in request.query_params.multi_items():
        if name not in accepted_keys or name in seen_keys:
            raise HTTPException(422, "Ambiguous signed supervisor read request")
        seen_keys.add(name)
    if not {
        "expected_engagement_id",
        "expected_revision",
        "expected_authorization_version",
    }.issubset(seen_keys):
        raise HTTPException(422, "Incomplete signed Flow boundary")
    binding = _binding(
        flow_id, expected_engagement_id, expected_revision, expected_authorization_version
    )
    sub, role, token_sha = (operator.get("sub"), operator.get("role"), operator.get("token_sha256"))
    claims = operator.get("claims")
    exp = claims.get("exp") if type(claims) is dict else None
    authorization = request.headers.get("authorization", "")
    if (
        type(sub) is not str
        or not 1 <= len(sub) <= 64
        or role not in {"operator", "senior_operator"}
        or type(token_sha) is not str
        or re.fullmatch(r"[a-f0-9]{64}", token_sha) is None
        or type(exp) is not int
        or exp <= int(time.time())
        or not authorization.startswith("Bearer ")
        or not hmac.compare_digest(
            hashlib.sha256(authorization[7:].encode("utf-8")).hexdigest(), token_sha
        )
    ):
        raise HTTPException(403, "Current signed owner identity unavailable")
    try:
        service = _executor()
        await service._authority(binding, operator)
        observed = await NativeMCPSupervisorReconciler(
            NativeMCPWorkerSupervisionStore(service.store)
        ).suspects(binding, sub, minimum_age_seconds=minimum_age_seconds, limit=limit)
        safe = _public_suspects(observed, minimum_age_seconds=minimum_age_seconds, limit=limit)
        # Recheck signed source and original verified actor after awaited DB work.
        await service._authority(binding, operator)
        if (
            operator.get("sub") != sub
            or operator.get("role") != role
            or operator.get("token_sha256") != token_sha
            or type(operator.get("claims")) is not dict
            or operator["claims"].get("exp") != exp
            or exp <= int(time.time())
            or request.headers.get("authorization") != authorization
            or not hmac.compare_digest(
                hashlib.sha256(authorization[7:].encode("utf-8")).hexdigest(), token_sha
            )
        ):
            raise ValueError("Owner identity changed during signed read")
        return safe
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            503, "Signed owner supervisor suspects UNKNOWN or source changed"
        ) from exc


def _principal(request: Request) -> tuple[str, str]:
    if request.query_params:
        raise HTTPException(403, "Supervisor tokens must never be supplied in URL")
    supervisor = request.headers.get("x-osop-supervisor-id", "")
    bearer = request.headers.get("authorization", "")
    if not _SUPERVISOR.fullmatch(supervisor) or not bearer.startswith("Bearer "):
        raise HTTPException(401, "Independent supervisor identity required")
    secret = bearer.removeprefix("Bearer ")
    if (
        not 20 <= len(secret) <= 512
        or len(bearer) > 520
        or any(ord(character) < 33 or ord(character) > 126 for character in secret)
    ):
        raise HTTPException(403, "Untrusted supervisor service credential")
    return supervisor, secret


def _unique(items: list[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError("Ambiguous duplicate field")
        result[name] = value
    return result


async def _body(request: Request) -> dict[str, Any]:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].lower().strip()
        != "application/json"
    ):
        raise HTTPException(415, "Supervisor observation requires JSON")
    data = bytearray()
    async for fragment in request.stream():
        if len(fragment) > 8192 - len(data):
            raise HTTPException(413, "Supervisor observation exceeds safe bound")
        data.extend(fragment)
    if not 1 <= len(data) <= 8192:
        raise HTTPException(422, "Empty supervisor observation")
    try:
        parsed = json.loads(
            data,
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON constant")),
        )
        if (
            type(parsed) is not dict
            or set(parsed) != {"grant", "observation"}
            or type(parsed["grant"]) is not dict
            or type(parsed["observation"]) is not dict
            or set(parsed["observation"]) != {"claims", "kid", "signature"}
        ):
            raise ValueError("Wrong supervisor observation envelope")
        return parsed
    except (UnicodeError, ValueError, TypeError) as exc:
        raise HTTPException(422, "Malformed or ambiguous supervisor observation") from exc


@router.post("/native-supervisor/observe")
async def record_native_supervisor_observation(
    request: Request, response: Response
) -> Dict[str, Any]:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    supervisor_id, supervisor_secret = _principal(request)
    body = await _body(request)
    orchestrator = state.get("orchestrator")
    memory = getattr(orchestrator, "session_memory", None)
    registry = getattr(orchestrator, "mcp_registry", None)
    if memory is None or registry is None:
        raise HTTPException(503, "Native supervisor source authority unavailable")
    try:
        store = NativeMCPWorkerSupervisionStore(FlowMCPActionStore(memory, registry))
        result = await store.record(
            body["grant"],
            body["observation"],
            supervisor_id=supervisor_id,
            supervisor_secret=supervisor_secret,
        )
        if (
            type(result) is not dict
            or set(result)
            != {
                "grant_id",
                "worker_id",
                "epoch",
                "revision",
                "state",
                "supervisor_observed",
                "independent_target_effect_verified",
                "original_action_status",
            }
            or result["supervisor_observed"] is not True
            or result["independent_target_effect_verified"] is not False
            or result["original_action_status"] != "unknown"
        ):
            raise ValueError("Supervisor receipt does not confirm durable record")
        return result
    except Exception as exc:
        # The source transaction may have COMMITTED before the ACK was lost.
        # Caller MUST read back by owner, never automatically repeat a
        # consequential Action or promote a worker-signed receipt to effect.
        raise HTTPException(
            409, "Supervisor observation UNKNOWN or source authority changed"
        ) from exc


@router.post("/flows/{flow_id}/native-mcp-supervision/recovery")
async def request_native_worker_cleanup_recovery(
    flow_id: str,
    request: Request,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Persist human metadata-only recovery intent, never execute/replay.

    An UNKNOWN/terminating worker still needs an independently authenticated
    supervisor to verify termination and cleanup. This operation does not
    change an Action, worker status, target effect or invoke any container.
    """
    _headers(response)
    body: RequestWorkerRecovery = await _parse(request, RequestWorkerRecovery)
    if _GRANT.fullmatch(body.grant_id) is None:
        raise HTTPException(422, "Bounded original native grant required")
    binding = _binding(
        flow_id,
        body.expected_engagement_id,
        body.expected_revision,
        body.expected_authorization_version,
    )
    service = _executor()
    try:
        await service._authority(binding, operator)
        store = NativeMCPWorkerSupervisionStore(service.store)
        result = await store.request_recovery(
            binding,
            operator["sub"],
            body.grant_id,
            body.expected_supervisor_revision,
            explicit_human_confirmation=True,
        )
        if (
            type(result) is not dict
            or result.get("grant_id") != body.grant_id
            or result.get("recovery_intent_recorded") is not True
            or result.get("worker_execution_replayed") is not False
            or result.get("independent_target_effect_verified") is not False
        ):
            raise ValueError("Durable metadata-only recovery intent unavailable")
        await service._authority(binding, operator)
        return {
            "grant_id": body.grant_id,
            "supervisor_revision": body.expected_supervisor_revision,
            "recovery_intent_recorded": True,
            "worker_execution_replayed": False,
            "independent_target_effect_verified": False,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            409, "Supervisor recovery intent UNKNOWN; read back before any further request"
        ) from exc
