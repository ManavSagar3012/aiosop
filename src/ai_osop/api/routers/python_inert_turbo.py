"""Senior-host-only operator lifecycle for the actually disabled Turbo MCP.

This is process ownership evidence, not an Action, native scanner grant, or
signed target effect. Host-installed SHA pins are never accepted over HTTP.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ai_osop.api.routers.native_inert_fleet import _no_client_config, _senior_host_guard
from ai_osop.mcp.python_inert_host_supervisor import (
    PythonInertHostDenied,
    PythonInertHostSupervisor,
)

router = APIRouter(prefix="/system/python-inert-turbo", tags=["python-inert-turbo"])
_SLOT = "_host_pinned_python_inert_turbo_20261022"


def install_host_python_inert_turbo(app: Any, controller: PythonInertHostSupervisor) -> None:
    """Trusted host-only pre-lifespan enrollment, never request or env control."""
    if (
        type(controller) is not PythonInertHostSupervisor
        or controller._opt_in is not True
        or getattr(app, "state", None) is None
        or hasattr(app.state, _SLOT)
    ):
        raise PythonInertHostDenied()
    # Validate full source SHA and strict regular-file identity before storing.
    controller._reviewed_source()
    setattr(app.state, _SLOT, controller)


def host_python_inert_turbo(app: Any) -> Optional[PythonInertHostSupervisor]:
    value = getattr(getattr(app, "state", None), _SLOT, None)
    return value if type(value) is PythonInertHostSupervisor else None


def _inert_response(lifecycle: str, observed: bool = False) -> dict[str, Any]:
    return {
        "service_id": "turbo-intruder-mcp",
        "lifecycle": lifecycle,
        "process_owned": observed,
        "listener_owned": observed,
        "health_unavailable": observed,
        "mcp_initialized": False,
        "signed_action_verified": False,
        "native_execution_enabled": False,
        "independent_target_effect_verified": False,
        "production_certified": False,
    }


@router.get("/status")
async def read_python_inert_turbo(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    controller = host_python_inert_turbo(request.app)
    if controller is None:
        return _inert_response("host_unconfigured")
    if controller._child is None:
        return _inert_response("stopped")
    try:
        observed = await controller.status()
    except PythonInertHostDenied as exc:
        raise HTTPException(503, "Host inert Turbo ownership UNKNOWN") from exc
    return _inert_response("running_disabled_unavailable", observed.health_unavailable)


@router.post("/start")
async def start_python_inert_turbo(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    controller = host_python_inert_turbo(request.app)
    if controller is None:
        raise HTTPException(503, "Host-reviewed inert Turbo source not enrolled")
    try:
        observed = await controller.start()
    except PythonInertHostDenied as exc:
        raise HTTPException(503, "Disabled Turbo process start unavailable or UNKNOWN") from exc
    return _inert_response("running_disabled_unavailable", observed.health_unavailable)


@router.post("/stop")
async def stop_python_inert_turbo(
    request: Request,
    response: Response,
    operator: dict[str, Any] = Depends(_senior_host_guard),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    await _no_client_config(request)
    controller = host_python_inert_turbo(request.app)
    if controller is None:
        raise HTTPException(503, "Host-reviewed inert Turbo source not enrolled")
    try:
        await controller.stop()
    except (PythonInertHostDenied, OSError, TimeoutError) as exc:
        raise HTTPException(503, "Disabled Turbo teardown UNKNOWN") from exc
    return _inert_response("stopped")


async def shutdown_host_python_inert_turbo(app: Any) -> None:
    controller = host_python_inert_turbo(app)
    if controller is not None:
        await controller.stop()
