"""Real isolated HTTP supervised recovery with signed senior-host requests.

No DB, Docker, original target, actual native executable, MCP action or scan.
Only /health and /mcp/initialize on disposable loopback listeners.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.api import native_inert_fleet_control as control
from ai_osop.api import mcp_eleven_supervised_recovery_join_20261022 as supervised
from ai_osop.api.mcp_eleven_supervised_recovery_join_20261022 import router
from ai_osop.api.mcp_fleet_readiness import _FLEET
from ai_osop.mcp.native_inert_process_fleet import (
    InertProcessHealth,
    OPT_IN_ENV,
    SIX_SERVICES,
    VerifiedGoBinary,
)
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry
from tests.qualification.test_mcp_all_eleven_real_bootstrap_transport_20261021 import (
    _local_fleet,
)
from tests.qualification.test_mcp_all_eleven_transport_recovery_20261021 import owned_fixture


SECRET = "local-supervised-eleven-recovery-jwt-20261022"
PRIVATE = "NEVER-ECHO-LOCAL-HOST-CREDENTIAL-20261022"
NON_GO = "browser-mcp"
GO = "recon-mcp"


def _token(role: str = "senior_operator", *, expired: bool = False) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "local-supervised-test",
            "role": role,
            "iat": now - 5,
            "exp": now - 5 if expired else now + 300,
        },
        SECRET,
        algorithm="HS256",
    )


@pytest.fixture
def isolated(monkeypatch: pytest.MonkeyPatch) -> tuple[FastAPI, MCPRegistry, dict[str, Any]]:
    monkeypatch.setattr(main.settings, "jwt_secret", SECRET)
    monkeypatch.setattr(main.settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(main.settings, "jwt_issuer", None)
    monkeypatch.setattr(main.settings, "jwt_audience", None)
    monkeypatch.setattr(main.settings, "operator_revocation_required", False)
    monkeypatch.setattr(main.settings, "environment", "development")
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    registry = MCPRegistry()
    bootstrap = {
        name: {
            "critical": role == "critical",
            "registered": False,
            "initialized": False,
            "status": "unavailable",
            "runtime_health_verified": False,
        }
        for name, role in _FLEET
    }
    monkeypatch.setitem(deps.state, "orchestrator", SimpleNamespace(mcp_registry=registry))
    monkeypatch.setitem(deps.state, "mcp_bootstrap_readiness", bootstrap)
    api = FastAPI()
    api.include_router(router)
    assert [route.path for route in api.routes].count(
        "/system/mcp/{server_id}/supervised-reconcile"
    ) == 1
    return api, registry, bootstrap


def _specs(target: str, port: int, *, host: str = "127.0.0.1", bearer: Optional[str] = None):
    return [
        (
            name,
            host if name == target else "127.0.0.1",
            port if name == target else 65520,
            bearer if name == target else None,
        )
        for name, _ in _FLEET
    ]


async def _post(
    api: FastAPI,
    service: str = NON_GO,
    *,
    token: Optional[str] = None,
    peer: str = "127.0.0.1",
    query: str = "",
    body: Optional[bytes] = None,
    extra_headers: Optional[dict[str, str]] = None,
) -> httpx.Response:
    headers = {"Authorization": "Bearer " + token} if token is not None else {}
    headers.update(extra_headers or {})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=api, client=(peer, 28993)),
        base_url="http://supervised-fixture.invalid",
    ) as client:
        return await client.post(
            f"/system/mcp/{service}/supervised-reconcile{query}",
            headers=headers,
            content=body,
        )


@pytest.mark.asyncio
async def test_auth_host_body_and_unconfigured_registry_never_open_transport(isolated) -> None:
    api, registry, _ = isolated
    for result in (
        await _post(api),
        await _post(api, token=_token("operator")),
        await _post(api, token=_token(expired=True)),
        await _post(api, token=_token(), peer="203.0.113.27"),
        await _post(api, token=_token(), query="?request_id=old-unknown"),
        await _post(api, token=_token(), body=b'{"port":8082}'),
        await _post(api, token=_token(), extra_headers={"Origin": "https://attacker.invalid"}),
        await _post(api, service="unknown-service", token=_token()),
    ):
        assert result.status_code in {401, 403, 404, 415, 422, 503}, result.text
        assert PRIVATE not in result.text
    assert registry._servers == {}
    assert (await _post(api, token=_token())).status_code == 409


@pytest.mark.asyncio
async def test_non_go_late_started_real_http_readback_and_repeat_without_extra_http(
    isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, registry, bootstrap = isolated
    async with owned_fixture(NON_GO, "untrusted_success") as (port, server):
        monkeypatch.setattr(
            main, "configured_mcp_server_specs", lambda: _specs(NON_GO, port, bearer=PRIVATE)
        )
        good = await _post(api, token=_token())
        assert good.status_code == 200, good.text
        assert good.headers["cache-control"] == "no-store"
        assert good.headers["x-content-type-options"] == "nosniff"
        body = good.json()
        assert body == {
            "server_id": NON_GO,
            "status": "supervised_initialized_transport_only",
            "host_owned_inert_go_process_observed": None,
            "host_owned_inert_go_process_is_registry_endpoint_verified": False,
            "http_initialize_declaration_observed": True,
            "signed_0033_witness_verified": False,
            "current_signed_action_verified": False,
            "independent_target_effect_verified": False,
            "unknown_original_action_safe_to_retry": False,
            "automatic_process_start_performed": False,
            "tool_or_scan_executed": False,
            "production_certified": False,
        }
        assert PRIVATE not in good.text and str(port) not in good.text
        assert [kind for kind, _ in server.calls] == ["health", "initialize"]
        assert set(registry._servers) == {NON_GO}
        assert bootstrap[NON_GO]["status"] == "initialized"
        same = registry._servers[NON_GO]
        repeated = await _post(api, token=_token())
        assert repeated.status_code == 200
        assert registry._servers[NON_GO] is same
        assert [kind for kind, _ in server.calls] == ["health", "initialize"]
        assert not any(kind in {"execute", "status", "cancel"} for kind, _ in server.calls)
    await registry.close_all()


@pytest.mark.asyncio
async def test_stale_closed_http_session_is_reinitialized_preserving_unknown_history(
    isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, registry, bootstrap = isolated
    async with owned_fixture(NON_GO, "untrusted_success") as (port, server):
        monkeypatch.setattr(main, "configured_mcp_server_specs", lambda: _specs(NON_GO, port))
        assert (await _post(api, token=_token())).status_code == 200
        connection = registry._servers[NON_GO]
        connection._seen_request_ids["req-previous-unknown"] = False
        await connection._session.close()
        assert connection._initialized is True
        assert bootstrap[NON_GO]["initialized"] is True
        replay = await _post(api, token=_token())
        assert replay.status_code == 200, replay.text
        assert registry._servers[NON_GO] is connection
        assert connection._seen_request_ids == {"req-previous-unknown": False}
        assert [kind for kind, _ in server.calls] == [
            "health",
            "initialize",
            "health",
            "initialize",
        ]
        assert connection._initialized is True
        assert bootstrap[NON_GO]["status"] == "initialized"
        assert not any(kind in {"execute", "status", "cancel"} for kind, _ in server.calls)
    await registry.close_all()


@pytest.mark.asyncio
async def test_active_action_and_misbound_bearer_refuse_before_http(
    isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, registry, bootstrap = isolated
    async with owned_fixture(NON_GO, "untrusted_success") as (port, server):
        monkeypatch.setattr(main, "configured_mcp_server_specs", lambda: _specs(NON_GO, port))
        conn = MCPConnection(server_id=NON_GO, host="127.0.0.1", port=port)
        registry._servers[NON_GO] = conn
        conn._seen_request_ids["req-active"] = True
        assert (await _post(api, token=_token())).status_code == 409
        assert server.calls == []
        conn._seen_request_ids["req-active"] = False
        conn._executions["req-still-active"] = SimpleNamespace(active=True)
        assert (await _post(api, token=_token())).status_code == 409
        assert server.calls == []
        conn._executions["req-still-active"].active = False
        conn.auth_token = PRIVATE
        assert (await _post(api, token=_token())).status_code == 409
        assert server.calls == []
        conn.auth_token = None
        result = await _post(api, token=_token())
        assert result.status_code == 200, result.text
        assert registry._servers[NON_GO] is conn
        assert conn._seen_request_ids["req-active"] is False
        assert conn._executions["req-still-active"].active is False
        assert [kind for kind, _ in server.calls] == ["health", "initialize"]
        assert bootstrap[NON_GO]["status"] == "initialized"
    await registry.close_all()


@pytest.mark.asyncio
async def test_nonnumeric_host_and_unsupported_service_never_send_bearer(
    isolated, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, registry, _ = isolated
    async with owned_fixture(NON_GO, "untrusted_success") as (_, server):
        for hostname in ("localhost", "127.0.0.2", "internal.invalid", "::1"):
            monkeypatch.setattr(
                main,
                "configured_mcp_server_specs",
                lambda hostname=hostname: _specs(NON_GO, 49181, host=hostname, bearer=PRIVATE),
            )
            denied = await _post(api, token=_token())
            assert denied.status_code == 409
            assert PRIVATE not in denied.text
        assert server.calls == []
        assert registry._servers == {}


class FakeOnlyInertSupervisor:
    """Fake OS process handles: actual host controller verifies output shape."""

    constructed: list["FakeOnlyInertSupervisor"] = []
    fail_on_health_call = 0

    def __init__(self, *, binaries: Any, trusted_build_root: Path, operator_opt_in: bool):
        assert set(binaries) == set(SIX_SERVICES)
        assert operator_opt_in is True
        self.calls = 0
        self.stopped = False
        type(self).constructed.append(self)

    def start(self) -> tuple[InertProcessHealth, ...]:
        return self.health()

    def health(self) -> tuple[InertProcessHealth, ...]:
        self.calls += 1
        if self.stopped or self.calls == self.fail_on_health_call:
            raise RuntimeError(PRIVATE)
        return tuple(
            InertProcessHealth(
                server_id=name,
                pid=32000 + i,
                port=47000 + i,
                pid_owned=True,
                listener_owned=True,
            )
            for i, name in enumerate(SIX_SERVICES)
        )

    def stop(self) -> None:
        self.stopped = True


def _install_fake_host(
    api: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> control.HostNativeInertFleetControl:
    FakeOnlyInertSupervisor.constructed = []
    FakeOnlyInertSupervisor.fail_on_health_call = 0
    monkeypatch.setattr(control, "NativeInertProcessFleet", FakeOnlyInertSupervisor)
    pins = {name: VerifiedGoBinary(tmp_path / f"{name}.exe", "a" * 64) for name in SIX_SERVICES}
    control.install_host_native_inert_fleet_control(
        api, control.HostInertFleetAuthority(build_root=tmp_path, binaries=pins)
    )
    host = control.host_native_inert_control(api)
    assert host is not None
    return host


@pytest.mark.asyncio
async def test_six_go_host_requires_manual_start_and_observes_owned_inert_processes(
    isolated,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api, registry, _ = isolated
    async with owned_fixture(GO, "untrusted_success") as (port, server):
        monkeypatch.setattr(main, "configured_mcp_server_specs", lambda: _specs(GO, port))
        assert (await _post(api, GO, token=_token())).status_code == 409
        host = _install_fake_host(api, monkeypatch, tmp_path)
        assert (await _post(api, GO, token=_token())).status_code == 409
        assert FakeOnlyInertSupervisor.constructed == []
        assert server.calls == []
        monkeypatch.setenv(OPT_IN_ENV, "1")
        started = await host.start()
        assert started["lifecycle"] == "running_inert_unavailable"
        result = await _post(api, GO, token=_token())
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["host_owned_inert_go_process_observed"] is True
        assert body["host_owned_inert_go_process_is_registry_endpoint_verified"] is False
        assert body["signed_0033_witness_verified"] is False
        assert body["production_certified"] is False
        assert [kind for kind, _ in server.calls] == ["health", "initialize"]
        assert len(FakeOnlyInertSupervisor.constructed) == 1
        assert FakeOnlyInertSupervisor.constructed[0].calls == 3
        await host.stop()
    await registry.close_all()


@pytest.mark.asyncio
async def test_lost_go_host_status_after_initialize_revokes_manifest_and_cleans_up(
    isolated,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api, registry, bootstrap = isolated
    async with owned_fixture(GO, "untrusted_success") as (port, server):
        monkeypatch.setattr(main, "configured_mcp_server_specs", lambda: _specs(GO, port))
        host = _install_fake_host(api, monkeypatch, tmp_path)
        monkeypatch.setenv(OPT_IN_ENV, "1")
        await host.start()  # Health call 1
        FakeOnlyInertSupervisor.fail_on_health_call = 3  # Post-init observation fails
        denied = await _post(api, GO, token=_token())
        assert denied.status_code == 409
        assert PRIVATE not in denied.text
        assert [kind for kind, _ in server.calls] == ["health", "initialize"]
        assert host._state == "unknown_closed"
        assert FakeOnlyInertSupervisor.constructed[0].stopped is True
        assert registry._servers[GO]._initialized is False
        assert registry._servers[GO]._tools == {}
        assert bootstrap[GO]["status"] == "unavailable"
    await registry.close_all()


@pytest.mark.asyncio
async def test_all_eleven_configured_specs_recover_over_owned_loopback_http_only(
    isolated,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    api, registry, bootstrap = isolated
    # Suppress all ambient provider credentials on disposable local fixtures.
    for field in (
        "burp_api_key",
        "shodan_api_key",
        "browser_mcp_auth_token",
        "cloud_mcp_auth_token",
    ):
        monkeypatch.setattr(main.settings, field, None)
    monkeypatch.delenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", raising=False)
    host = _install_fake_host(api, monkeypatch, tmp_path)
    monkeypatch.setenv(OPT_IN_ENV, "1")
    await host.start()
    try:
        async with _local_fleet(monkeypatch) as calls:
            assert {name for name, *_ in main.configured_mcp_server_specs()} == {
                name for name, _ in _FLEET
            }
            for name, _ in _FLEET:
                answer = await _post(api, name, token=_token())
                assert answer.status_code == 200, (name, answer.text)
                data = answer.json()
                assert data["server_id"] == name
                assert data["host_owned_inert_go_process_observed"] is (
                    True if name in SIX_SERVICES else None
                )
                assert data["host_owned_inert_go_process_is_registry_endpoint_verified"] is False
                assert data["unknown_original_action_safe_to_retry"] is False
                assert data["signed_0033_witness_verified"] is False
                assert data["independent_target_effect_verified"] is False
                assert data["production_certified"] is False
                assert bootstrap[name]["status"] == "initialized"
                assert [event for event, _ in calls[name]] == ["health", "initialize"]
            assert len(registry._servers) == 11
            assert all(
                not any(event in {"execute", "cancel", "status"} for event, _ in entries)
                for entries in calls.values()
            )
    finally:
        await registry.close_all()
        await host.stop()


@pytest.mark.asyncio
async def test_postflight_ack_cancellation_revokes_transport_without_replaying_unknown(
    isolated,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, registry, bootstrap = isolated
    async with owned_fixture(GO, "untrusted_success") as (port, server):
        calls = 0

        async def interrupted_current_owner(_app: Any, _name: str) -> bool:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise asyncio.CancelledError
            return True

        monkeypatch.setattr(supervised, "_fresh_inert_owned_process", interrupted_current_owner)
        with pytest.raises(asyncio.CancelledError):
            await supervised.reconcile_single_supervised_transport(
                GO,
                registry=registry,
                bootstrap=bootstrap,
                specs=_specs(GO, port),
                app=api,
            )
        assert calls == 2
        conn = registry._servers[GO]
        assert conn._initialized is False
        assert conn._tools == {}
        assert conn._seen_request_ids == {}
        assert bootstrap[GO]["status"] == "unavailable"
        assert [kind for kind, _ in server.calls] == ["health", "initialize"]
        assert not any(kind in {"execute", "status", "cancel"} for kind, _ in server.calls)
    await registry.close_all()
