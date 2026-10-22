"""Mounted senior-only MCP recovery with a real local HTTP transport.

The bearer is a locally generated synthetic test JWT, not production OIDC.
Only harmless health/initialize may reach a test-owned ephemeral listener.
No application lifespan, database, scanner, real provider or target is used.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from httpx import ASGITransport, AsyncClient
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.api.mcp_fleet_readiness import _FLEET
from ai_osop.mcp.protocol import MCPRegistry
from tests.qualification.test_mcp_all_eleven_transport_recovery_20261021 import owned_fixture

SECRET = "isolated-inert-mcp-reconciliation-signing-secret"
TARGET = "recon-mcp"


def _jwt(role: str = "senior_operator", *, expired: bool = False) -> dict[str, str]:
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": "local-senior-operator",
            "iss": "owned-fixture",
            "iat": now - 10,
            "exp": now - 5 if expired else now + 300,
            "role": role,
        },
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": "Bearer " + token}


@pytest.fixture
def mounted(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(main.settings, "environment", "production")
    monkeypatch.setattr(main.settings, "jwt_secret", SECRET)
    monkeypatch.setattr(main.settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(main.settings, "jwt_issuer", None)
    monkeypatch.setattr(main.settings, "jwt_audience", None)
    monkeypatch.setattr(main.settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    registry = MCPRegistry()
    monkeypatch.setitem(deps.state, "orchestrator", SimpleNamespace(mcp_registry=registry))
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
    monkeypatch.setitem(deps.state, "mcp_bootstrap_readiness", report)
    return registry, report


def _specs(port: int, *, target_host: str = "127.0.0.1"):
    return [
        (
            name,
            target_host if name == TARGET else "127.0.0.1",
            port if name == TARGET else 65520,
            None,
        )
        for name, _ in _FLEET
    ]


def test_default_localhost_normalizes_to_numeric_loopback_before_bearer_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Settings retain their older public defaults for compatibility, while
    # the actual client/bootstrap spec is safe numeric loopback, not a DNS or
    # hosts-file resolution of localhost carrying the native bearer.
    monkeypatch.setattr(main.settings, "burp_mcp_host", "localhost")
    monkeypatch.setattr(main.settings, "cloud_mcp_host", "localhost")
    monkeypatch.setattr(main.settings, "cloud_mcp_auth_token", "test-transport-only-bearer")
    configured = {
        name: (host, port, token) for name, host, port, token in main.configured_mcp_server_specs()
    }
    assert configured["burp-mcp"][0] == "127.0.0.1"
    assert configured["cloud-mcp"][0] == "127.0.0.1"
    assert configured["cloud-mcp"][2] == "test-transport-only-bearer"
    monkeypatch.setattr(main.settings, "cloud_mcp_host", "example.internal")
    assert (
        next(host for name, host, _, _ in main.configured_mcp_server_specs() if name == "cloud-mcp")
        == "example.internal"
    )


@pytest.mark.asyncio
async def test_real_mounted_senior_reconciles_one_late_started_provider_without_any_tool(
    mounted, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, report = mounted
    async with owned_fixture(TARGET, "untrusted_success") as (port, source):
        monkeypatch.setattr(main, "configured_mcp_server_specs", lambda: _specs(port))
        async with AsyncClient(
            transport=ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            endpoint = "/system/mcp/recon-mcp/reconcile-local"
            for headers, allowed in (
                ({}, False),
                (_jwt("operator"), False),
                (_jwt(expired=True), False),
            ):
                denied = await client.post(endpoint, headers=headers)
                assert denied.status_code in {401, 403}
                assert not allowed
            assert source.calls == []
            ready = await client.post(endpoint, headers=_jwt())
            assert ready.status_code == 200, ready.text[:200]
            result = ready.json()
            assert result == {
                "server_id": TARGET,
                "status": "initialized_transport_only",
                "runtime_health_verified": False,
                "current_authorized_operation_verified": False,
                "independent_target_effect_verified": False,
                "safe_to_retry_unknown_action": False,
            }
            assert report[TARGET]["initialized"] is True
            assert registry._servers[TARGET]._initialized is True
            assert [event for event, _ in source.calls] == ["health", "initialize"]

            repeated = await client.post(endpoint, headers=_jwt())
            assert repeated.status_code == 200
            assert repeated.json()["status"] == "already_initialized_unverified"
            assert [event for event, _ in source.calls] == ["health", "initialize"]

            # A source restarts with a broken manifest. The SAME connection
            # remains registered; its previous request ID still cannot replay.
            connection = registry._servers[TARGET]
            original_id = "req-one-use-after-ambiguous-ack"
            connection._seen_request_ids[original_id] = True
            connection._initialized = False
            report[TARGET]["initialized"] = False
            connection._executions[original_id] = SimpleNamespace(active=True)
            in_flight = await client.post(endpoint, headers=_jwt())
            assert in_flight.status_code == 409
            assert connection._seen_request_ids[original_id] is True
            assert [event for event, _ in source.calls] == ["health", "initialize"]
            connection._executions.pop(original_id)
            source.ready = False
            denied = await client.post(endpoint, headers=_jwt())
            assert denied.status_code == 200
            assert denied.json()["status"] == "unavailable"
            assert not connection._initialized and connection._tools == {}
            assert connection._seen_request_ids[original_id] is True
            assert not any(event == "execute" for event, _ in source.calls)

            source.ready = True
            recovered = await client.post(endpoint, headers=_jwt())
            assert recovered.status_code == 200
            assert recovered.json()["status"] == "initialized_transport_only"
            assert registry._servers[TARGET] is connection
            assert connection._seen_request_ids[original_id] is True
            assert report[TARGET]["runtime_health_verified"] is False
            assert not any(event == "execute" for event, _ in source.calls)
        await registry.close_all()


@pytest.mark.asyncio
async def test_mounted_reconcile_refuses_non_numeric_dns_and_unknown_server(
    mounted, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, _ = mounted
    async with owned_fixture(TARGET, "untrusted_success") as (port, source):
        monkeypatch.setattr(
            main,
            "configured_mcp_server_specs",
            lambda: _specs(port, target_host="localhost"),
        )
        async with AsyncClient(
            transport=ASGITransport(app=main.app), base_url="http://testserver"
        ) as client:
            wrong_host = await client.post("/system/mcp/recon-mcp/reconcile-local", headers=_jwt())
            assert wrong_host.status_code == 409
            not_configured = await client.post(
                "/system/mcp/synthetic-mcp/reconcile-local", headers=_jwt()
            )
            assert not_configured.status_code == 409
            assert not registry._servers and not source.calls
        await registry.close_all()
