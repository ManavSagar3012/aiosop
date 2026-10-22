"""Mounted senior JWT + actual bounded eleven-local-HTTP transport join.

Only disposable loopback /health + /mcp/initialize fixture endpoints are used.
No application lifespan, app DB, Docker, native executable, paid provider,
scanner, grant, original signed Action, or external target is accessed.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.api.mcp_fleet_readiness import _FLEET
from ai_osop.api.mcp_transport_operator_diagnostics import (
    build_mcp_eleven_transport_diagnostics,
    router,
)
from ai_osop.api.routers.system import get_mcp_health
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry
from tests.qualification.test_mcp_all_eleven_real_bootstrap_transport_20261021 import (
    _local_fleet,
)


SECRET = "isolated-20261022-eleven-transport-local-jwt"
PRIVATE = "EXTERNAL-TARGET-CREDENTIAL-SHOULD-NEVER-BE-EMITTED"
ROUTE = "/system/mcp/transport-diagnostics"


def _jwt(role: str = "senior_operator", *, expired: bool = False, key: str = SECRET) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "signed-local-senior",
            "role": role,
            "iat": now - 4,
            "exp": now - 4 if expired else now + 240,
        },
        key,
        algorithm="HS256",
    )


@pytest.fixture
def isolate(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[FastAPI, MCPRegistry, dict[str, dict[str, Any]]]:
    monkeypatch.setattr(main.settings, "jwt_secret", SECRET)
    monkeypatch.setattr(main.settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(main.settings, "jwt_issuer", None)
    monkeypatch.setattr(main.settings, "jwt_audience", None)
    monkeypatch.setattr(main.settings, "operator_revocation_required", False)
    monkeypatch.setattr(main.settings, "environment", "development")
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    registry = MCPRegistry()
    report = {
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
    monkeypatch.setitem(deps.state, "mcp_bootstrap_readiness", report)
    api = FastAPI()
    api.include_router(router)
    assert [r.path for r in api.routes].count(ROUTE) == 1
    return api, registry, report


async def _read(
    api: FastAPI,
    *,
    token: str = "",
    path: str = ROUTE,
    scheme: str = "http",
    peer: str = "127.0.0.1",
) -> httpx.Response:
    transport = httpx.ASGITransport(app=api, client=(peer, 24023))
    headers = {"Authorization": "Bearer " + token} if token else {}
    async with httpx.AsyncClient(
        transport=transport, base_url=f"{scheme}://transport-local-fixture.invalid"
    ) as client:
        return await client.get(path, headers=headers)


def _specs(*, host: str = "127.0.0.1", token: str = PRIVATE) -> list[tuple[str, str, int, str]]:
    return [(name, host, 49171 + i, token) for i, (name, _) in enumerate(_FLEET)]


def _process_health() -> dict[str, Any]:
    return {"catalog_scope": "process_health_only_unverified", "servers": []}


@pytest.mark.asyncio
async def test_readback_requires_valid_senior_jwt_and_keeps_read_only(isolate) -> None:
    api, registry, _ = isolate
    for token, expected in (
        ("", 403),
        (_jwt("operator"), 403),
        (_jwt(expired=True), 401),
        (_jwt(key="wrong-signing-key"), 401),
    ):
        denied = await _read(api, token=token)
        assert denied.status_code == expected, denied.text
    assert registry._servers == {}

    response = await _read(api, token=_jwt())
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    payload = response.json()
    assert payload["configured_count"] == 11
    assert payload["native_go_inert_control_installed"] is False
    assert payload["independently_verified_operations"] is None
    assert len(payload["services"]) == 11
    assert {row["server_id"] for row in payload["services"]} == {name for name, _ in _FLEET}
    assert sum(row["importance"] == "critical" for row in payload["services"]) == 5
    assert all(row["effective_transport_status"] == "not_registered" for row in payload["services"])
    assert all(row["provider_schema_declared"] is False for row in payload["services"])
    assert all(
        row["native_go_current_process_owned_verified"] is False for row in payload["services"]
    )
    assert all(row["current_signed_action_verified"] is False for row in payload["services"])
    assert all(row["independently_verified_target_effect"] is False for row in payload["services"])
    assert all(row["production_certified"] is False for row in payload["services"])
    assert PRIVATE not in response.text
    assert "49171" not in response.text


@pytest.mark.asyncio
async def test_secure_host_guard_query_denial_and_missing_registry(isolate, monkeypatch) -> None:
    api, _, _ = isolate
    assert (await _read(api, token=_jwt(), peer="203.0.113.99")).status_code == 403
    assert (
        await _read(api, token=_jwt(), path=ROUTE + "?target=untrusted.invalid")
    ).status_code == 422
    monkeypatch.setitem(deps.state, "orchestrator", None)
    missing = await _read(api, token=_jwt())
    assert missing.status_code == 503
    assert PRIVATE not in missing.text


def test_rejects_incomplete_or_forged_roster_and_untrusted_process_telemetry(isolate) -> None:
    _, registry, bootstrap = isolate
    base = dict(
        process_health=_process_health(),
        registry=registry,
        specs=_specs(),
        bootstrap=bootstrap,
    )
    for corrupt in (
        {**base, "specs": _specs()[:-1]},
        {**base, "specs": _specs()[:-1] + [_specs()[0]]},
        {**base, "bootstrap": {**bootstrap, "not-a-mcp": {}}},
        {
            **base,
            "process_health": {"servers": [{}], "catalog_scope": "process_health_only_unverified"},
        },
        {**base, "native_host_lifecycle": "provider_executed"},
    ):
        with pytest.raises(ValueError):
            build_mcp_eleven_transport_diagnostics(**corrupt)
    forged = {name: dict(row) for name, row in bootstrap.items()}
    forged["recon-mcp"]["runtime_health_verified"] = True
    with pytest.raises(ValueError):
        build_mcp_eleven_transport_diagnostics(**{**base, "bootstrap": forged})
    stale_certified = {name: dict(row) for name, row in bootstrap.items()}
    stale_certified["recon-mcp"]["initialized"] = True
    with pytest.raises(ValueError):
        build_mcp_eleven_transport_diagnostics(**{**base, "bootstrap": stale_certified})
    hostile = {name: dict(row) for name, row in bootstrap.items()}
    hostile["recon-mcp"]["status"] = ["initialized"]
    with pytest.raises(ValueError):
        build_mcp_eleven_transport_diagnostics(**{**base, "bootstrap": hostile})


def test_registered_process_cannot_hide_wrong_configured_identity_or_remote_http(isolate) -> None:
    _, registry, bootstrap = isolate
    registry._servers["recon-mcp"] = MCPConnection(
        server_id="recon-mcp", host="untrusted.example", port=44890, auth_token=PRIVATE
    )
    projection = build_mcp_eleven_transport_diagnostics(
        process_health=_process_health(),
        registry=registry,
        bootstrap=bootstrap,
        specs=_specs(),
    )
    row = next(item for item in projection["services"] if item["server_id"] == "recon-mcp")
    assert row["registry_identity_matches_config"] is False
    assert row["effective_transport_status"] == "registry_identity_mismatch"
    assert row["http_session_open"] is None
    assert PRIVATE not in repr(projection)
    assert "untrusted.example" not in repr(projection)
    assert "44890" not in repr(projection)

    foreign = build_mcp_eleven_transport_diagnostics(
        process_health=_process_health(),
        registry=MCPRegistry(),
        bootstrap=bootstrap,
        specs=_specs(host="untrusted.example"),
    )
    assert all(
        service["effective_transport_status"] == "unverified_nonnumeric_or_nonlocal_http"
        for service in foreign["services"]
    )
    assert PRIVATE not in repr(foreign) and "untrusted.example" not in repr(foreign)


@pytest.mark.asyncio
async def test_all_eleven_real_inert_loopback_initialize_join_without_extra_http(
    isolate, monkeypatch: pytest.MonkeyPatch
) -> None:
    api, registry, _ = isolate
    # The disposable loopback fixtures never receive ambient credentials.
    for key in (
        "burp_api_key",
        "shodan_api_key",
        "browser_mcp_auth_token",
        "cloud_mcp_auth_token",
    ):
        monkeypatch.setattr(main.settings, key, None)
    monkeypatch.delenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", raising=False)
    async with _local_fleet(monkeypatch) as calls:
        # Genuine aiohttp network health and initialize against eleven
        # test-owned ephemeral loopback listeners, using the real bootstrap.
        report = await main.register_optional_mcp_servers(registry)
        monkeypatch.setitem(deps.state, "mcp_bootstrap_readiness", report)
        assert all(row["status"] == "initialized" for row in report.values())
        for name in calls:
            assert [kind for kind, _ in calls[name]] == ["health", "initialize"]

        before = {name: len(history) for name, history in calls.items()}
        response = await _read(api, token=_jwt())
        assert response.status_code == 200, response.text
        assert all(len(calls[name]) == prior for name, prior in before.items())
        payload = response.json()
        assert len(payload["services"]) == 11
        assert all(
            item["configured_transport"] == "numeric_loopback_http"
            and item["effective_transport_status"] == "initialized_transport_declaration_only"
            and item["bootstrap_status"] == "initialized"
            and item["http_session_open"] is True
            and item["provider_schema_declared"] is True
            and item["provider_schema_independently_verified"] is False
            and item["current_signed_action_verified"] is False
            and item["independently_verified_target_effect"] is False
            and item["production_certified"] is False
            for item in payload["services"]
        )
        assert PRIVATE not in response.text
        assert all("/mcp/execute" not in kind for rows in calls.values() for kind, _ in rows)
        # Bootstrap records can become stale while a live session survives.
        stale = dict(report["recon-mcp"])
        stale["initialized"] = False
        stale["status"] = "registered"
        report["recon-mcp"] = stale
        again = await _read(api, token=_jwt())
        assert again.status_code == 200
        recon = next(x for x in again.json()["services"] if x["server_id"] == "recon-mcp")
        assert recon["effective_transport_status"] == "registry_initialized_bootstrap_stale"
        assert all(len(calls[name]) == prior for name, prior in before.items())
    await registry.close_all()


@pytest.mark.asyncio
async def test_controller_lifecycle_cannot_claim_live_pid_or_signed_native_grant(isolate) -> None:
    api, registry, bootstrap = isolate
    projection = build_mcp_eleven_transport_diagnostics(
        process_health=_process_health(),
        registry=registry,
        specs=_specs(),
        bootstrap=bootstrap,
        native_host_lifecycle="running",
    )
    assert projection["native_go_inert_control_installed"] is True
    go_ids = {
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
    }
    assert {
        row["server_id"]
        for row in projection["services"]
        if row["native_go_inert_host_lifecycle"] == "running"
    } == go_ids
    assert all(
        not row["native_go_current_process_owned_verified"] for row in projection["services"]
    )
    assert all(not row["current_signed_action_verified"] for row in projection["services"])
