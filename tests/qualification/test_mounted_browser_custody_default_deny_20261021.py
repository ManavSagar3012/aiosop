"""Actual imported gateway's senior Browser custody endpoint denies absent host.

No app lifespan, provider, external Browser, certificate, application DB or key.
"""

import time

import pytest
from httpx import ASGITransport, AsyncClient
from jose import jwt

from ai_osop.api import deps, main

_KEY = "test-only-mounted-original-browser-deny-key"
_URI = "/system/browser/custody/readback"
_REQUEST = {"engagement_id": "eng-bounded-case", "request_id": "req-" + "a" * 48}


def _jwt(role: str) -> dict[str, str]:
    now = int(time.time())
    return {
        "Authorization": "Bearer "
        + jwt.encode(
            {"sub": "synthetic-human", "role": role, "iat": now - 5, "exp": now + 300},
            _KEY,
            algorithm="HS256",
        )
    }


@pytest.mark.asyncio
async def test_actual_browser_custody_router_is_senior_only_and_unverified_without_host(
    monkeypatch,
):
    monkeypatch.setattr(main.settings, "jwt_secret", _KEY)
    monkeypatch.setattr(main.settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(main.settings, "jwt_issuer", None)
    monkeypatch.setattr(main.settings, "jwt_audience", None)
    monkeypatch.setattr(main.settings, "environment", "production")
    monkeypatch.setattr(main.settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    assert sum(row.path == _URI for row in main.app.routes) == 1
    async with AsyncClient(
        transport=ASGITransport(app=main.app, client=("127.0.0.1", 12543)),
        base_url="http://127.0.0.1",
    ) as client:
        for headers in ({}, _jwt("operator")):
            response = await client.post(_URI, headers=headers, json=_REQUEST)
            assert response.status_code in {401, 403}
        failed = await client.post(_URI, headers=_jwt("senior_operator"), json=_REQUEST)
        assert failed.status_code == 503
        pending = failed.json()["detail"]
        assert pending["status"] == "UNVERIFIED"
        assert pending["current_original_artifact_bytes_verified"] is False
        assert pending["independent_target_effect_verified"] is False
        assert pending["automatic_retry_authorized"] is False
        assert pending["production_release_certified"] is False
        assert "png" not in failed.text.lower()
