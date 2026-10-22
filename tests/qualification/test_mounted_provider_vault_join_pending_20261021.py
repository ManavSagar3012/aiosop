"""No host vault or provider I/O: mounted senior trust diagnostics only."""

import time

import pytest
from httpx import ASGITransport, AsyncClient
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.core.provider_vault_runtime_join import ProviderVaultRuntimeJoin

SECRET = "test-only-pending-provider-vault-jwt"


def bearer(role: str) -> dict[str, str]:
    now = int(time.time())
    value = jwt.encode(
        {"sub": "host-operator-test", "role": role, "iat": now - 2, "exp": now + 120},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": "Bearer " + value}


@pytest.mark.asyncio
async def test_actual_main_provider_vault_join_status_never_overclaims(monkeypatch):
    monkeypatch.setattr(main.settings, "jwt_secret", SECRET)
    monkeypatch.setattr(main.settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(main.settings, "jwt_issuer", None)
    monkeypatch.setattr(main.settings, "jwt_audience", None)
    monkeypatch.setattr(main.settings, "environment", "production")
    monkeypatch.setattr(main.settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    monkeypatch.setitem(deps.state, "provider_vault_join", ProviderVaultRuntimeJoin())
    uri = "/system/provider/vault-join-status"
    assert any(route.path == uri for route in main.app.routes)
    async with AsyncClient(
        transport=ASGITransport(app=main.app), base_url="http://testserver"
    ) as client:
        for headers in ({}, bearer("operator")):
            denied = await client.get(uri, headers=headers)
            assert denied.status_code in {401, 403}
        status = await client.get(uri, headers=bearer("senior_operator"))
        assert status.status_code == 200
        result = status.json()
        assert result["code"] == "PENDING_HOST_ENROLLMENT"
        assert result["host_enrollment_verified"] is False
        assert result["shared_call_fence_enrolled"] is False
        assert result["provider_dispatch_authorized"] is False
        assert result["provider_contacted"] is False
        assert result["credential_exported"] is False
        assert "api_key" not in status.text and "private_key" not in status.text
