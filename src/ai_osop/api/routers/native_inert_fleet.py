"""Senior-JWT-only API for explicitly host-configured, inert local Go PIDs.

Mounted-ready, but deliberately NOT mounted here. No request supplies binary
paths, hashes, ports, native grants, tasks, keys, targets or arbitrary config.
All process effects are strictly bounded, local and non-scanning /health.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ai_osop.api.deps import require_role
from ai_osop.api.native_inert_fleet_control import (
    HostInertFleetDenied,
    host_native_inert_control,
)


router = APIRouter(prefix="/system/native-inert-fleet", tags=["native-inert-fleet"])


async def _senior_host_guard(
    request: Request,
    operator: dict[str, Any] = Depends(require_role("senior_operator")),
) -> dict[str, Any]:
    """Role assertion is backed by existing locally signed or OIDC JWT logic.

    The legacy shared dev API key cannot produce role senior_operator, and
    neither a query token nor an unsigned user-reported claim is admitted.
    All this runs BEFORE any process/control operation.
    """
    claims = operator.get("claims")
    if (
        operator.get("role") != "senior_operator"
        or not isinstance(operator.get("sub"), str)
        or not operator["sub"].strip()
        or not isinstance(claims, dict)
        or type(claims.get("exp")) is not int
        or not 0 < claims["exp"]
    ):
        raise HTTPException(403, "Signed senior operator JWT required")
    scheme = request.url.scheme
    peer = getattr(request.client, "host", None)
    if scheme != "https" and (scheme != "http" or peer not in {"127.0.0.1", "::1"}):
        raise HTTPException(403, "Host-local or authenticated HTTPS transport required")
    if request.scope.get("query_string"):
        raise HTTPException(403, "Native inert fleet URL parameters forbidden")
    if sum(name.lower() == b"authorization" for name, _ in request.scope.get("headers", [])) != 1:
        raise HTTPException(401, "Exactly one senior JWT bearer required")
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer ") or len(header) > 16391:
        raise HTTPException(401, "Signed senior JWT bearer required")
    # Web origin traffic is never an accepted operator control channel.
    if "origin" in request.headers:
        raise HTTPException(403, "Browser origin control forbidden")
    return operator


async def _no_client_config(request: Request) -> None:
    """No JSON, form, file, arbitrary path, keys, targets or approval in body."""
    count = 0
    async for chunk in request.stream():
        count += len(chunk)
        if count > 0:
            raise HTTPException(422, "Native inert lifecycle accepts no request body")
    if request.headers.get("content-type", "").strip():
        # A content-type without a body is harmless but unnecessary; do not
        # allow a client to claim a configuration protocol through headers.
        raise HTTPException(415, "Native inert host control takes no client configuration")


def _host(request: Request) -> Any:
    controller = host_native_inert_control(request.app)
    if controller is None:
        raise HTTPException(503, "Independent host-reviewed six-Go pins unavailable")
    return controller


@router.get("/status")
async def native_inert_fleet_status(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    controller = host_native_inert_control(request.app)
    if controller is None:
        return {
            "lifecycle": "host_unconfigured",
            "classification": "host_local_inert_process_only",
            "processes": [],
            "mcp_initialized": False,
            "signed_0033_witness_verified": False,
            "native_target_execution_enabled": False,
            "target_effect_verified": False,
            "automatic_action_retry_authorized": False,
            "production_certified": False,
        }
    try:
        return await controller.status()
    except HostInertFleetDenied as exc:
        raise HTTPException(503, "Native inert fleet current status UNKNOWN") from exc


@router.post("/start")
async def start_native_inert_fleet(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    controller = _host(request)
    try:
        return await controller.start()
    except HostInertFleetDenied as exc:
        raise HTTPException(503, "Native inert fleet start denied or UNKNOWN") from exc


@router.post("/stop")
async def stop_native_inert_fleet(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    controller = _host(request)
    try:
        return await controller.stop()
    except HostInertFleetDenied as exc:
        raise HTTPException(503, "Native inert fleet stop completion UNKNOWN") from exc
