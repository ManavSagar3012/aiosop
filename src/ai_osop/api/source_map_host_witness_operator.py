"""Senior operator diagnostic for independently witnessed ORIGINAL SourceMap.

An HTTP caller supplies only the original engagement/request identifiers. A
separately enrolled, host-pinned read-only source supplies original signed
proofs. The existing SourceMap0033CurrentWitness must cryptographically verify
them and rejoin current PostgreSQL authority before any positive response.

This module neither produces proofs nor issues a 0035 preflight or 0029 grant;
UNKNOWN Action recovery, process startup, staging, mounts and scanner calls
are outside its interface. Missing independent host enrollment fails closed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ai_osop.api.deps import require_role
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.orchestrator.sourcemap_0033_current_witness import (
    SourceMap0033CurrentWitness,
    SourceMap0033CurrentWitnessDenied,
)
from ai_osop.orchestrator.sourcemap_original_stage import _roots

_PATH = "/system/source-map/host-witness/readback"
_HOST_SLOT = "_independently_host_enrolled_source_map_witness_20261022"
_MAX_BODY = 512
_MAX_EVIDENCE = 131072
_REQUEST_ID = re.compile(r"req-[a-f0-9]{48}\Z")
_ENGAGEMENT_ID = re.compile(r"eng-[A-Za-z0-9._:@-]{1,75}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ROOT_ENVS = (
    "OSOP_SOURCEMAP_0033_SUPERVISOR_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_SUPERVISOR_PROCESS_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_NATIVE_SUPERVISOR_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
    "OSOP_SOURCEMAP_NATIVE_STAGE_OBSERVER_TRUSTED_PUBLIC_KEYS_JSON",
)
_IDENTITY = (
    "request_id",
    "engagement_id",
    "flow_id",
    "task_id",
    "subtask_id",
    "action_id",
    "owner_id",
    "approval_id",
    "lease_id",
    "artifact_sha256",
    "manifest_sha256",
    "authorization_sha256",
)
_PROOFS = frozenset(
    {
        "supervisor_observation",
        "source_status",
        "source_preflight_proof",
        "native_grant_token",
        "live_process_witness",
        "signed_supervisor_source",
        "native_mount_witness",
    }
)


@dataclass(frozen=True)
class HostPinnedSourceMapReadback:
    """Original evidence resolved by an external enrolled host-only reader.

    The reader MUST be read-only and resolve an immutable host-bound record;
    this structure is never decoded from an HTTP request. It supplies signed
    observations for verification, not an asserted verification result.
    """

    original_identity: Mapping[str, str]
    signed_proofs: Mapping[str, Any]


HostPinnedSourceMapReader = Callable[[str, str, str], Awaitable[HostPinnedSourceMapReadback]]


def _unknown(reason: str) -> dict[str, Any]:
    return {
        "status": "UNVERIFIED",
        "reason": reason,
        "original_0013_0015_current_verified": False,
        "signed_0033_current_witness_verified": False,
        "current_pid_and_nonroot_mount_verified": False,
        "read_only_host_mount_verified": False,
        "one_use_grant_and_binding_verified": False,
        "original_action_replayed": False,
        "authorizes_execution": False,
        "target_effect_verified": False,
        "automatic_retry_authorized": False,
        "production_certified": False,
    }


def _deny(reason: str, status: int = 503) -> None:
    raise HTTPException(
        status_code=status,
        detail=_unknown(reason),
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("Duplicate operator request field")
        found[key] = value
    return found


async def _parse(request: Request) -> tuple[str, str]:
    if request.scope.get("query_string"):
        _deny("QUERY_PARAMETERS_FORBIDDEN", 403)
    scheme = request.url.scheme
    client = getattr(request.client, "host", None)
    if scheme != "https" and (scheme != "http" or client not in {"127.0.0.1", "::1"}):
        _deny("SECURE_HOST_TRANSPORT_REQUIRED", 403)
    if "origin" in request.headers:
        _deny("BROWSER_ORIGIN_FORBIDDEN", 403)
    if sum(key.lower() == b"authorization" for key, _ in request.scope.get("headers", [])) != 1:
        _deny("SIGNED_SENIOR_BEARER_REQUIRED", 401)
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 16391:
        _deny("SIGNED_SENIOR_BEARER_REQUIRED", 401)
    if request.headers.get("content-encoding"):
        _deny("INVALID_OPERATOR_REQUEST", 415)
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        _deny("INVALID_OPERATOR_REQUEST", 415)
    data = bytearray()
    async for chunk in request.stream():
        if len(chunk) > _MAX_BODY - len(data):
            _deny("INVALID_OPERATOR_REQUEST", 413)
        data.extend(chunk)
    try:
        decoded = json.loads(
            data.decode("utf-8", "strict"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
        _deny("INVALID_OPERATOR_REQUEST", 422)
    if (
        type(decoded) is not dict
        or set(decoded) != {"engagement_id", "request_id"}
        or type(decoded["engagement_id"]) is not str
        or _ENGAGEMENT_ID.fullmatch(decoded["engagement_id"]) is None
        or type(decoded["request_id"]) is not str
        or _REQUEST_ID.fullmatch(decoded["request_id"]) is None
    ):
        _deny("INVALID_OPERATOR_REQUEST", 422)
    return decoded["engagement_id"], decoded["request_id"]


def _pin_roots() -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    """Freeze the externally enrolled, mutually distinct *public* trust roots."""
    observed: set[bytes] = set()
    pins: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    for name in _ROOT_ENVS:
        keys = _roots(name)
        if not keys or observed.intersection(keys.values()):
            raise ValueError("Independent signer enrollment unavailable")
        observed.update(keys.values())
        pins.append(
            (
                name,
                tuple(sorted((kid, hashlib.sha256(key).hexdigest()) for kid, key in keys.items())),
            )
        )
    return tuple(pins)


class SourceMapHostWitnessOperator:
    """Explicit host enrollment; never receives trust roots from the client."""

    def __init__(
        self,
        *,
        independently_enrolled: bool = False,
        host_pinned_reader: Optional[HostPinnedSourceMapReader] = None,
        actions: Optional[FlowMCPActionStore] = None,
    ) -> None:
        self._reader = host_pinned_reader
        self._actions = actions
        self._enabled = bool(independently_enrolled is True)
        self._lock = asyncio.Lock()
        self._pins: Optional[tuple[tuple[str, tuple[tuple[str, str], ...]], ...]] = None
        if self._enabled and callable(self._reader) and isinstance(actions, FlowMCPActionStore):
            try:
                self._pins = _pin_roots()
            except Exception:
                # Partial/mismatched enrollment is never interpreted as ready.
                self._pins = None

    async def readback(
        self, engagement_id: str, request_id: str, operator_id: str
    ) -> dict[str, Any]:
        if (
            not self._enabled
            or self._pins is None
            or not callable(self._reader)
            or not isinstance(self._actions, FlowMCPActionStore)
        ):
            return _unknown("INDEPENDENT_HOST_VERIFIER_UNAVAILABLE")
        async with self._lock:
            try:
                if _pin_roots() != self._pins:
                    return _unknown("TRUST_ROOT_ROTATION_UNVERIFIED")
                # The independently enrolled reader must never issue a new
                # Action, preflight, grant or mount as part of this operation.
                record = await asyncio.wait_for(
                    self._reader(engagement_id, request_id, operator_id), timeout=3.0
                )
                if type(record) is not HostPinnedSourceMapReadback:
                    return _unknown("HOST_ORIGINAL_RECORD_UNVERIFIED")
                identity = record.original_identity
                proofs = record.signed_proofs
                if (
                    type(identity) is not dict
                    or set(identity) != set(_IDENTITY)
                    or type(proofs) is not dict
                    or set(proofs) != _PROOFS
                    or identity.get("request_id") != request_id
                    or identity.get("engagement_id") != engagement_id
                    or any(type(identity[k]) is not str or not identity[k] for k in _IDENTITY)
                    or any(
                        _SHA.fullmatch(identity[key]) is None
                        for key in ("artifact_sha256", "manifest_sha256", "authorization_sha256")
                    )
                ):
                    return _unknown("HOST_ORIGINAL_IDENTITY_UNVERIFIED")
                for kind in ("source_status", "source_preflight_proof"):
                    envelope = proofs[kind]
                    if (
                        type(envelope) is not dict
                        or set(envelope) != {"claims", "kid", "signature"}
                        or type(envelope["claims"]) is not dict
                        or any(envelope["claims"].get(k) != identity[k] for k in _IDENTITY)
                    ):
                        return _unknown("SIGNED_ORIGINAL_IDENTITY_MISMATCH")
                if len(json.dumps(proofs, allow_nan=False)) > _MAX_EVIDENCE:
                    return _unknown("HOST_EVIDENCE_TOO_LARGE")
                if _pin_roots() != self._pins:
                    return _unknown("TRUST_ROOT_ROTATION_UNVERIFIED")
                verified = await asyncio.wait_for(
                    SourceMap0033CurrentWitness(self._actions).corroborate(**dict(proofs)),
                    timeout=5.0,
                )
                if _pin_roots() != self._pins:
                    return _unknown("TRUST_ROOT_ROTATION_UNVERIFIED")
                if (
                    type(verified) is not dict
                    or verified.get("status") != "corroborated_read_only"
                    or verified.get("observed_mount_read_only") is not True
                    or verified.get("authorizes_execution") is not False
                    or verified.get("authorizes_mount_or_replay") is not False
                    or type(verified.get("0033_epoch")) is not int
                    or verified["0033_epoch"] <= 0
                    or type(verified.get("0033_revision")) is not int
                    or verified["0033_revision"] <= 0
                ):
                    return _unknown("CURRENT_SOURCE_MAP_WITNESS_UNVERIFIED")
                return {
                    "status": "CURRENT_ORIGINAL_HOST_WITNESS_VERIFIED",
                    "original_0013_0015_current_verified": True,
                    "signed_0033_current_witness_verified": True,
                    "current_pid_and_nonroot_mount_verified": True,
                    "read_only_host_mount_verified": True,
                    "one_use_grant_and_binding_verified": True,
                    "original_action_replayed": False,
                    "authorizes_execution": False,
                    "target_effect_verified": False,
                    "automatic_retry_authorized": False,
                    "production_certified": False,
                }
            except (SourceMap0033CurrentWitnessDenied, asyncio.TimeoutError):
                return _unknown("INDEPENDENT_CURRENT_WITNESS_UNAVAILABLE")
            except Exception:
                # No token, original bytes, PID, private path, exception or
                # unverified signed claims may be exposed to an API client.
                return _unknown("INDEPENDENT_CURRENT_WITNESS_UNAVAILABLE")


def install_host_source_map_witness_operator(app: Any, service: SourceMapHostWitnessOperator) -> None:
    """Host-only, one-time enrollment into the existing mounted API router.

    Public roots, the current original action store and external host record
    reader must already be independently configured; this routine never
    supplies signing keys, original PID/mount evidence, or new grant authority.
    """
    app_state = getattr(app, "state", None)
    if (
        app_state is None
        or hasattr(app_state, _HOST_SLOT)
        or type(service) is not SourceMapHostWitnessOperator
        or service._enabled is not True
        or service._pins is None
        or not callable(service._reader)
        or not isinstance(service._actions, FlowMCPActionStore)
    ):
        raise ValueError("Independent SourceMap current host signer enrollment unavailable")
    setattr(app_state, _HOST_SLOT, service)


def create_source_map_host_witness_router(
    service: Optional[SourceMapHostWitnessOperator] = None,
) -> APIRouter:
    active = service if service is not None else SourceMapHostWitnessOperator()
    router = APIRouter(tags=["source-map-host-witness"])

    @router.post(_PATH)
    async def source_map_host_witness_readback(
        request: Request,
        response: Response,
        operator: dict[str, Any] = Depends(require_role("senior_operator")),
    ) -> dict[str, Any]:
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        engagement, original_request = await _parse(request)
        claims = operator.get("claims")
        if (
            operator.get("role") != "senior_operator"
            or type(operator.get("sub")) is not str
            or not operator["sub"].strip()
            or type(claims) is not dict
            or type(claims.get("exp")) is not int
            or claims["exp"] <= int(time.time())
        ):
            _deny("SIGNED_SENIOR_OPERATOR_REQUIRED", 403)
        # The default router is included exactly once at application import.
        # A separately authenticated host supervisor can install original
        # trust before lifespan, but no client request may select the reader,
        # trust roots, native mount, process or original Action evidence.
        enrolled = active if service is not None else getattr(request.app.state, _HOST_SLOT, active)
        if type(enrolled) is not SourceMapHostWitnessOperator:
            _deny("INDEPENDENT_HOST_VERIFIER_UNAVAILABLE")
        result = await enrolled.readback(engagement, original_request, operator["sub"])
        if result["status"] == "UNVERIFIED":
            _deny(result["reason"])
        return result

    return router


# Mounting this default router cannot silently enroll a host verifier.
router = create_source_map_host_witness_router()
