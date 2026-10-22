"""Host-only opt-in controller for *inert* six-Go process lifecycle.

The caller must install independently reviewed binary SHA pins as an in-memory
host authority, never from an HTTP request, environment path JSON, or a user
profile. No process is launched at import, router mount or host enrollment.
This controller signs no 0033 PID witness and never invokes any MCP tool.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from ai_osop.mcp.native_inert_process_fleet import (
    OPT_IN_ENV,
    SIX_SERVICES,
    NativeInertProcessFleet,
    VerifiedGoBinary,
)


class HostInertFleetDenied(RuntimeError):
    """Sanitized error, never exposes executable paths or host secrets."""


@dataclass(frozen=True)
class HostInertFleetAuthority:
    """Separately authorized host-only pins, not HTTP configuration.

    A trusted host process must independently verify the offline build inputs
    before constructing this object. This is not signed host or Task authority.
    """

    build_root: Path
    binaries: dict[str, VerifiedGoBinary]


def _freeze_authority(value: HostInertFleetAuthority) -> HostInertFleetAuthority:
    if type(value) is not HostInertFleetAuthority or not isinstance(value.build_root, Path):
        raise HostInertFleetDenied("Host-verified six-Go pins required")
    if (
        not value.build_root.is_absolute()
        or type(value.binaries) is not dict
        or set(value.binaries) != set(SIX_SERVICES)
    ):
        raise HostInertFleetDenied("Host-verified six-Go pins required")
    binaries: dict[str, VerifiedGoBinary] = {}
    for name in SIX_SERVICES:
        item = value.binaries.get(name)
        if (
            type(item) is not VerifiedGoBinary
            or not isinstance(item.path, Path)
            or not item.path.is_absolute()
            or item.path.name != f"{name}.exe"
            or type(item.sha256) is not str
            or len(item.sha256) != 64
            or any(character not in "0123456789abcdef" for character in item.sha256)
        ):
            raise HostInertFleetDenied("Host-verified six-Go pins required")
        binaries[name] = VerifiedGoBinary(path=item.path, sha256=item.sha256)
    return HostInertFleetAuthority(build_root=value.build_root, binaries=binaries)


def _basic_state(state: str) -> dict[str, Any]:
    return {
        "lifecycle": state,
        "classification": "host_local_inert_process_only",
        "processes": [{"server_id": name, "observed": False} for name in SIX_SERVICES],
        "mcp_initialized": False,
        "signed_0033_witness_verified": False,
        "native_target_execution_enabled": False,
        "target_effect_verified": False,
        "automatic_action_retry_authorized": False,
        "production_certified": False,
    }


def _observed(rows: Any) -> dict[str, Any]:
    if (
        type(rows) is not tuple
        or len(rows) != len(SIX_SERVICES)
        or tuple(getattr(row, "server_id", None) for row in rows) != SIX_SERVICES
    ):
        raise HostInertFleetDenied("Current six-Go process observation unavailable")
    for row in rows:
        if (
            getattr(row, "status", None) != "unavailable"
            or getattr(row, "pid_owned", None) is not True
            or getattr(row, "listener_owned", None) is not True
            or getattr(row, "native_authority_verified", None) is not False
            or getattr(row, "execution_enabled", None) is not False
            or getattr(row, "target_effect_verified", None) is not False
            or getattr(row, "production_certified", None) is not False
        ):
            raise HostInertFleetDenied("Current six-Go process observation unavailable")
    status = _basic_state("running_inert_unavailable")
    status["processes"] = [{"server_id": name, "observed": True} for name in SIX_SERVICES]
    return status


async def _bounded_process_call(method: Callable[[], Any]) -> Any:
    """Do not orphan a process operation on request/ASGI cancellation.

    The production supervisor itself provides bounded process startup and
    termination. Await the final owned operation even if the client disconnects;
    caller then performs a separate mandatory cleanup of a lost start ACK.
    """
    task = asyncio.create_task(asyncio.to_thread(method))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        try:
            await asyncio.shield(task)
        except Exception:
            pass
        raise


class HostNativeInertFleetControl:
    """One host-controlled inert fleet, permanently closed after stop/failure."""

    def __init__(self, authority: HostInertFleetAuthority) -> None:
        self._authority = _freeze_authority(authority)
        self._lock = asyncio.Lock()
        self._fleet: Optional[NativeInertProcessFleet] = None
        self._state = "not_started"

    async def status(self) -> dict[str, Any]:
        async with self._lock:
            if self._state != "running" or self._fleet is None:
                return _basic_state(self._state)
            try:
                observed = await _bounded_process_call(self._fleet.health)
                return _observed(observed)
            except BaseException:
                self._state = "unknown_closed"
                try:
                    await self._cleanup()
                except BaseException:
                    pass  # A failed cleanup is still UNKNOWN, not a live report.
                raise HostInertFleetDenied("Inert process status UNKNOWN") from None

    async def start(self) -> dict[str, Any]:
        async with self._lock:
            if self._state != "not_started":
                raise HostInertFleetDenied("Inert fleet already attempted; no action retry")
            if os.getenv(OPT_IN_ENV) != "1":
                raise HostInertFleetDenied("Host process opt-in unavailable")
            self._state = "starting"
            try:
                self._fleet = NativeInertProcessFleet(
                    binaries=dict(self._authority.binaries),
                    trusted_build_root=self._authority.build_root,
                    operator_opt_in=True,
                )
                result = await _bounded_process_call(self._fleet.start)
                snapshot = _observed(result)
                self._state = "running"
                return snapshot
            except BaseException as error:
                # A lost HTTP ACK is UNKNOWN. Stop owned processes; do not
                # auto-restart, replay native Actions or promote a result.
                self._state = "unknown_closed"
                try:
                    await self._cleanup()
                except BaseException:
                    pass  # Own handles stay in supervisor for manual cleanup.
                if isinstance(error, asyncio.CancelledError):
                    raise  # Keep request cancellation truthful after cleanup.
                raise HostInertFleetDenied("Inert start UNKNOWN and closed") from None

    async def stop(self) -> dict[str, Any]:
        async with self._lock:
            if self._state == "not_started":
                self._state = "stopped"
            else:
                try:
                    await self._cleanup()
                except BaseException:
                    self._state = "unknown_closed"
                    raise HostInertFleetDenied("Inert stop completion UNKNOWN") from None
                self._state = "stopped"
            return _basic_state(self._state)

    async def _cleanup(self) -> None:
        if self._fleet is not None:
            await _bounded_process_call(self._fleet.stop)


_APP_CONTROL_SLOT = "_host_native_inert_fleet_control_20261021"


def install_host_native_inert_fleet_control(app: Any, authority: HostInertFleetAuthority) -> None:
    """Host bootstrap hook; never used inside an HTTP endpoint or lifespan.

    Do not call automatically. Only a trusted deployment/operator component
    should construct authority from independently pinned offline build assets.
    """
    state = getattr(app, "state", None)
    if state is None or hasattr(state, _APP_CONTROL_SLOT):
        raise HostInertFleetDenied("Host inert fleet authority already set or unavailable")
    control = HostNativeInertFleetControl(authority)
    setattr(state, _APP_CONTROL_SLOT, control)


def host_native_inert_control(app: Any) -> Optional[HostNativeInertFleetControl]:
    control = getattr(getattr(app, "state", None), _APP_CONTROL_SLOT, None)
    return control if type(control) is HostNativeInertFleetControl else None


async def shutdown_host_native_inert_fleet_control(app: Any) -> None:
    """Explicit host-owned lifespan shutdown hook; no implicit router startup.

    The prime's existing lifespan must invoke this if this opt-in controller is
    mounted so child PIDs do not outlive an API that stops before manual STOP.
    """
    controller = host_native_inert_control(app)
    if controller is not None:
        await controller.stop()
