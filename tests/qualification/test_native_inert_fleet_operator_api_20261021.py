"""Mounted-ready native inert fleet operator router with real JWT validation.

Uses actual FastAPI routes + production deps JWT verifier and real controller.
Mocks ONLY the OS process supervisor to avoid Go, app DB, Docker, external
targets/providers; signer and route authorization use genuine local HS256 JWT.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import native_inert_fleet_control as control
from ai_osop.api import deps
from ai_osop.api.routers import native_inert_fleet as route
from ai_osop.core.config import settings
from ai_osop.memory.operator_revocation import OperatorRevoked, OperatorRevocationUnavailable
from ai_osop.mcp.native_inert_process_fleet import (
    InertProcessHealth,
    OPT_IN_ENV,
    SIX_SERVICES,
    VerifiedGoBinary,
)


BASE = "/system/native-inert-fleet"
SECRET = "isolated-inert-fleet-local-jwt-secret-20261021"
DEV_TOKEN = "dev-inert-api-shared-token"
PRIVATE = "private-offline-binary-path-and-hash-test-do-not-echo"


def bearer(role: str = "senior_operator", *, key: str = SECRET, expired: bool = False) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "operator-signed-inert-test",
            "role": role,
            "iat": now - 5,
            "exp": now - 2 if expired else now + 300,
        },
        key,
        algorithm="HS256",
    )


class FakeNativeProcessFleet:
    constructed: list["FakeNativeProcessFleet"] = []
    should_fail = False
    delayed = False

    def __init__(
        self, *, binaries: Any, trusted_build_root: Any, operator_opt_in: bool = False
    ) -> None:
        assert operator_opt_in is True
        assert set(binaries) == set(SIX_SERVICES)
        assert isinstance(trusted_build_root, Path)
        self.binaries = binaries
        self.root = trusted_build_root
        self.start_calls = 0
        self.health_calls = 0
        self.stop_calls = 0
        self.closed = False
        self.started = False
        type(self).constructed.append(self)

    def start(self) -> tuple[InertProcessHealth, ...]:
        self.start_calls += 1
        if self.delayed:
            time.sleep(0.08)
        if self.should_fail:
            raise RuntimeError(PRIVATE)
        self.started = True
        return self.health()

    def health(self) -> tuple[InertProcessHealth, ...]:
        self.health_calls += 1
        if self.closed or not self.started:
            raise RuntimeError(PRIVATE)
        return tuple(
            InertProcessHealth(
                server_id=name, pid=5000 + n, port=40000 + n, pid_owned=True, listener_owned=True
            )
            for n, name in enumerate(SIX_SERVICES)
        )

    def stop(self) -> None:
        self.stop_calls += 1
        self.closed = True


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "api_token", DEV_TOKEN)
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    FakeNativeProcessFleet.constructed = []
    FakeNativeProcessFleet.should_fail = False
    FakeNativeProcessFleet.delayed = False
    monkeypatch.setattr(control, "NativeInertProcessFleet", FakeNativeProcessFleet)

    app = FastAPI()
    app.include_router(route.router)
    routes = [r.path for r in app.routes if r.path.startswith(BASE)]
    assert set(routes) == {BASE + "/status", BASE + "/start", BASE + "/stop"}
    root = tmp_path.resolve()
    # Fake process backend NEVER runs these files. The actual production
    # supervisor independently checks Go build identity before spawning.
    authority = control.HostInertFleetAuthority(
        build_root=root,
        binaries={
            name: VerifiedGoBinary(
                root / f"{name}.exe", hashlib.sha256((PRIVATE + name).encode()).hexdigest()
            )
            for name in SIX_SERVICES
        },
    )
    return {"app": app, "authority": authority}


async def call(
    api: dict[str, Any],
    endpoint: str,
    *,
    method: str = "GET",
    token: Optional[str] = None,
    headers: Optional[list[tuple[str, str]]] = None,
    body: Optional[bytes] = None,
    host: str = "127.0.0.1",
    scheme: str = "http",
) -> httpx.Response:
    supplied = list(headers or [])
    if token is not None:
        supplied.append(("Authorization", "Bearer " + token))
    transport = httpx.ASGITransport(app=api["app"], client=(host, 24242))
    async with httpx.AsyncClient(
        transport=transport, base_url=f"{scheme}://native-inert-test.invalid"
    ) as client:
        return await client.request(method, BASE + endpoint, headers=supplied, content=body)


def install(api: dict[str, Any]) -> None:
    control.install_host_native_inert_fleet_control(api["app"], api["authority"])


def denied(response: httpx.Response, status: int) -> None:
    assert response.status_code == status, response.text
    assert PRIVATE not in response.text
    assert "pid" not in response.text
    assert "binary" not in response.text.lower()
    assert ".exe" not in response.text


@pytest.mark.asyncio
async def test_host_config_absent_is_status_only_never_implicit_start(api: dict[str, Any]) -> None:
    status = await call(api, "/status", token=bearer())
    assert status.status_code == 200, status.text
    data = status.json()
    assert data["lifecycle"] == "host_unconfigured"
    assert data["processes"] == []
    assert data["target_effect_verified"] is False
    assert data["production_certified"] is False
    assert data["signed_0033_witness_verified"] is False
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    denied(await call(api, "/stop", method="POST", token=bearer()), 503)
    assert FakeNativeProcessFleet.constructed == []


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["viewer", "operator"])
async def test_not_senior_signed_role_never_constructs_processes(
    api: dict[str, Any],
    role: str,
) -> None:
    install(api)
    for endpoint, method in (("/status", "GET"), ("/start", "POST"), ("/stop", "POST")):
        denied(await call(api, endpoint, method=method, token=bearer(role)), 403)
    assert FakeNativeProcessFleet.constructed == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token,status",
    [
        (None, 403),
        (DEV_TOKEN, 401),
        ("not-a-jwt", 401),
        (bearer(key="other-secret"), 401),
        (bearer(expired=True), 401),
    ],
)
async def test_missing_dev_wrong_signer_or_expired_bearer_fails_before_processes(
    api: dict[str, Any],
    token: Optional[str],
    status: int,
) -> None:
    install(api)
    denied(await call(api, "/start", method="POST", token=token), status)
    assert FakeNativeProcessFleet.constructed == []


@pytest.mark.asyncio
@pytest.mark.parametrize("denial,status", [("revoked", 401), ("unknown", 503)])
async def test_senior_jwt_revocation_or_missing_revocation_db_denies_before_any_pid(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    denial: str,
    status: int,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    monkeypatch.setattr(settings, "operator_revocation_required", True)

    class _FakeLedger:
        async def assert_active(self, *args: Any) -> None:
            if denial == "revoked":
                raise OperatorRevoked("fixture stale senior JWT")
            raise OperatorRevocationUnavailable("fixture app database offline")

    monkeypatch.setattr(deps, "_operator_revocation_ledger", lambda: _FakeLedger())
    denied(await call(api, "/start", method="POST", token=bearer()), status)
    assert FakeNativeProcessFleet.constructed == []


@pytest.mark.asyncio
async def test_no_host_optin_even_for_real_senior_and_pinned_host_config(
    api: dict[str, Any],
) -> None:
    install(api)
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    assert FakeNativeProcessFleet.constructed == []
    result = await call(api, "/status", token=bearer())
    assert result.status_code == 200
    assert result.json()["lifecycle"] == "not_started"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint,method",
    [
        ("/status", "GET"),
        ("/start", "POST"),
        ("/stop", "POST"),
    ],
)
async def test_start_stop_status_never_accept_client_supplied_config(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    endpoint: str,
    method: str,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    for malicious in (
        b'{"port":8084}',
        b'{"binary":"C:/private.exe"}',
        b'{"target":"https://victim.invalid"}',
        b"{}",
        b" ",
        b"x" * 2048,
    ):
        denied(await call(api, endpoint, method=method, token=bearer(), body=malicious), 422)
    denied(
        await call(
            api,
            endpoint,
            method=method,
            token=bearer(),
            headers=[("Content-Type", "application/json")],
        ),
        415,
    )
    denied(await call(api, endpoint + "?path=private", method=method, token=bearer()), 403)
    assert FakeNativeProcessFleet.constructed == []


@pytest.mark.asyncio
async def test_host_local_only_transport_and_duplicate_authorization_denied(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    denied(await call(api, "/start", method="POST", token=bearer(), host="203.0.113.10"), 403)
    denied(
        await call(
            api,
            "/start",
            method="POST",
            token=bearer(),
            headers=[("Origin", "https://untrusted.invalid")],
        ),
        403,
    )
    denied(
        await call(
            api,
            "/start",
            method="POST",
            token=bearer(),
            headers=[("Authorization", "Bearer " + bearer())],
        ),
        401,
    )
    assert FakeNativeProcessFleet.constructed == []


@pytest.mark.asyncio
async def test_senior_host_pinned_start_status_stop_no_0033_or_effect(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    assert FakeNativeProcessFleet.constructed == []  # mount never starts
    result = await call(api, "/start", method="POST", token=bearer())
    assert result.status_code == 200, result.text
    value = result.json()
    assert value["lifecycle"] == "running_inert_unavailable"
    assert value["mcp_initialized"] is False
    assert value["signed_0033_witness_verified"] is False
    assert value["native_target_execution_enabled"] is False
    assert value["target_effect_verified"] is False
    assert value["production_certified"] is False
    assert value["automatic_action_retry_authorized"] is False
    assert set(value) == {
        "lifecycle",
        "classification",
        "processes",
        "mcp_initialized",
        "signed_0033_witness_verified",
        "native_target_execution_enabled",
        "target_effect_verified",
        "automatic_action_retry_authorized",
        "production_certified",
    }
    assert value["processes"] == [{"server_id": name, "observed": True} for name in SIX_SERVICES]
    for secret in (PRIVATE, "pid", "port", "sha256", "binary", ".exe", "5000", "40000"):
        assert secret not in result.text
    assert result.headers["Cache-Control"] == "no-store"
    assert len(FakeNativeProcessFleet.constructed) == 1
    assert FakeNativeProcessFleet.constructed[0].start_calls == 1
    assert (await call(api, "/status", token=bearer())).json()["lifecycle"] == (
        "running_inert_unavailable"
    )
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    assert FakeNativeProcessFleet.constructed[0].start_calls == 1
    stopped = await call(api, "/stop", method="POST", token=bearer())
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["lifecycle"] == "stopped"
    assert FakeNativeProcessFleet.constructed[0].stop_calls == 1
    stopped_again = await call(api, "/stop", method="POST", token=bearer())
    assert stopped_again.status_code == 200
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    assert len(FakeNativeProcessFleet.constructed) == 1


@pytest.mark.asyncio
async def test_start_internal_error_unknown_closed_and_no_secrets_or_retry(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    FakeNativeProcessFleet.should_fail = True
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    assert len(FakeNativeProcessFleet.constructed) == 1
    assert FakeNativeProcessFleet.constructed[0].stop_calls == 1
    status = await call(api, "/status", token=bearer())
    assert status.status_code == 200
    assert status.json()["lifecycle"] == "unknown_closed"
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    assert FakeNativeProcessFleet.constructed[0].start_calls == 1


@pytest.mark.asyncio
async def test_provider_fake_ready_or_target_effect_refused_and_owned_pid_closed(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")

    def falsified_start(self: FakeNativeProcessFleet) -> tuple[InertProcessHealth, ...]:
        self.start_calls += 1
        self.started = True
        return tuple(
            InertProcessHealth(
                server_id=name,
                pid=5010 + n,
                port=40500 + n,
                pid_owned=True,
                listener_owned=True,
                target_effect_verified=True,
            )
            for n, name in enumerate(SIX_SERVICES)
        )

    monkeypatch.setattr(FakeNativeProcessFleet, "start", falsified_start)
    denied(await call(api, "/start", method="POST", token=bearer()), 503)
    assert len(FakeNativeProcessFleet.constructed) == 1
    assert FakeNativeProcessFleet.constructed[0].stop_calls == 1
    assert (await call(api, "/status", token=bearer())).json()["lifecycle"] == ("unknown_closed")


@pytest.mark.asyncio
async def test_cancelled_start_waits_for_owner_and_performs_cleanup(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    FakeNativeProcessFleet.delayed = True
    owner = control.host_native_inert_control(api["app"])
    assert owner is not None
    pending = asyncio.create_task(owner.start())
    for _ in range(500):
        if FakeNativeProcessFleet.constructed and FakeNativeProcessFleet.constructed[0].start_calls:
            break
        await asyncio.sleep(0.001)
    assert FakeNativeProcessFleet.constructed[0].start_calls == 1
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    owned = FakeNativeProcessFleet.constructed[0]
    assert owned.stop_calls == 1 and owned.closed is True
    assert (await owner.status())["lifecycle"] == "unknown_closed"
    with pytest.raises(control.HostInertFleetDenied, match="no action retry"):
        await owner.start()


@pytest.mark.asyncio
async def test_explicit_host_shutdown_hook_stops_only_owned_fleet(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await control.shutdown_host_native_inert_fleet_control(api["app"])
    assert FakeNativeProcessFleet.constructed == []
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    assert (await call(api, "/start", method="POST", token=bearer())).status_code == 200
    await control.shutdown_host_native_inert_fleet_control(api["app"])
    assert FakeNativeProcessFleet.constructed[0].closed
    assert (await call(api, "/status", token=bearer())).json()["lifecycle"] == "stopped"


@pytest.mark.asyncio
async def test_concurrent_start_only_one_operator_start(
    api: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(api)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    FakeNativeProcessFleet.delayed = True
    left, right = await asyncio.gather(
        call(api, "/start", method="POST", token=bearer()),
        call(api, "/start", method="POST", token=bearer()),
    )
    assert sorted([left.status_code, right.status_code]) == [200, 503]
    assert len(FakeNativeProcessFleet.constructed) == 1
    assert FakeNativeProcessFleet.constructed[0].start_calls == 1
    assert (await call(api, "/stop", method="POST", token=bearer())).status_code == 200


def test_only_host_can_install_exact_immutable_six_pins(api: dict[str, Any]) -> None:
    original = api["authority"]
    for broken in (
        control.HostInertFleetAuthority(build_root=Path("relative"), binaries=original.binaries),
        control.HostInertFleetAuthority(build_root=original.build_root, binaries={}),
        control.HostInertFleetAuthority(
            build_root=original.build_root,
            binaries={**original.binaries, "untrusted": original.binaries["nuclei-mcp"]},
        ),
        control.HostInertFleetAuthority(
            build_root=original.build_root,
            binaries={
                **original.binaries,
                "nuclei-mcp": VerifiedGoBinary(Path("some.exe"), "a" * 64),
            },
        ),
    ):
        with pytest.raises(control.HostInertFleetDenied):
            control.install_host_native_inert_fleet_control(api["app"], broken)
    install(api)
    with pytest.raises(control.HostInertFleetDenied, match="already set"):
        install(api)
    # The host authority copy cannot be changed by its original dict owner.
    original.binaries.clear()
    inner = control.host_native_inert_control(api["app"])
    assert inner is not None
    assert set(inner._authority.binaries) == set(SIX_SERVICES)


def test_static_route_control_does_not_mount_or_expose_target_tools() -> None:
    source = Path(route.__file__).read_text(encoding="utf-8")
    host_code = Path(control.__file__).read_text(encoding="utf-8")
    assert 'Depends(require_role("senior_operator"))' in source
    assert "include_router(" not in source
    for text in (source, host_code):
        assert "mcp/execute" not in text
        assert "native_grant=" not in text
        assert "scan_target(" not in text
        assert "os.system(" not in text
    assert "HostNativeInertFleetControl" in host_code


@pytest.mark.asyncio
async def test_prime_mounted_main_route_is_senior_only_without_startup_or_db(
    api: dict[str, Any],
) -> None:
    """Inspect actual main registration; ASGI lifespan deliberately disabled.

    Never inject host executable pins into production main.app, and never
    trigger its application lifespan, DB connections or process startup.
    """
    from ai_osop.api.main import app as actual_main

    candidates = [
        item for item in actual_main.routes if getattr(item, "path", "") == BASE + "/start"
    ]
    assert len(candidates) == 1 and "POST" in candidates[0].methods
    assert (
        len([item for item in actual_main.routes if getattr(item, "path", "") == BASE + "/status"])
        == 1
    )
    assert (
        len([item for item in actual_main.routes if getattr(item, "path", "") == BASE + "/stop"])
        == 1
    )
    transport = httpx.ASGITransport(app=actual_main, client=("127.0.0.1", 14145))
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        response = await client.post(
            BASE + "/start",
            headers={
                "Authorization": "Bearer " + bearer("operator"),
            },
        )
    denied(response, 403)
    assert FakeNativeProcessFleet.constructed == []
