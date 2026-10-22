"""Authenticated operator identity is derived exclusively from the API verifier."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api.routers.auth import router
from ai_osop.core.config import settings


@pytest.fixture
def app():
    service = FastAPI()
    service.include_router(router)
    return service


async def request_me(app, *, bearer=None, path="/auth/me"):
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        return await client.get(path, headers=headers)


def signed_token(claims):
    return jwt.encode(claims, "qualification-signing-key", algorithm="HS256")


@pytest.mark.asyncio
async def test_me_exposes_only_verified_jwt_subject_role_and_exp(app, monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "qualification-signing-key")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    exp = int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp())
    token = signed_token(
        {"sub": "alice", "role": "senior_operator", "exp": exp, "secret": "NEVER_EXPOSE"}
    )
    response = await request_me(app, bearer=token)
    assert response.status_code == 200
    assert response.json() == {"sub": "alice", "role": "senior_operator", "exp": exp}
    assert response.headers["cache-control"] == "no-store"
    assert "NEVER_EXPOSE" not in response.text
    assert token not in response.text


@pytest.mark.parametrize("bad", ["invalid", "missing_exp", "expired"])
@pytest.mark.asyncio
async def test_me_rejects_invalid_incomplete_and_expired_jwt(app, monkeypatch, bad):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "qualification-signing-key")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    payload = {"sub": "alice", "role": "operator"}
    if bad != "missing_exp":
        payload["exp"] = int(
            (
                datetime.now(timezone.utc) + timedelta(minutes=-5 if bad == "expired" else 5)
            ).timestamp()
        )
    token = "invalid.signature.text" if bad == "invalid" else signed_token(payload)
    response = await request_me(app, bearer=token)
    assert response.status_code == 401
    assert "alice" not in response.text


@pytest.mark.asyncio
async def test_me_requires_header_never_accepts_url_bearer(app, monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "api_token", "dev-only-shared-token")
    assert (await request_me(app)).status_code == 401
    no_header = await request_me(app, path="/auth/me?token=dev-only-shared-token")
    assert no_header.status_code == 403
    header_and_query = await request_me(
        app, bearer="dev-only-shared-token", path="/auth/me?token=another"
    )
    assert header_and_query.status_code == 403


@pytest.mark.asyncio
async def test_me_dev_static_token_has_no_invented_expiry(app, monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "api_token", "dev-only-shared-token")
    response = await request_me(app, bearer="dev-only-shared-token")
    assert response.status_code == 200
    assert response.json() == {
        "sub": "shared-development-token", "role": "dev_api_token", "exp": None,
    }


@pytest.mark.asyncio
async def test_me_production_requires_configured_jwt_secret(app, monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "api_token", "shared-token")
    response = await request_me(app, bearer="shared-token")
    assert response.status_code == 503
