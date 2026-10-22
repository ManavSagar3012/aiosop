"""Production tenant operations must have attributable bearer identities."""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from ai_osop.api.deps import verify_token
from ai_osop.core.config import settings


@pytest.mark.asyncio
async def test_static_api_token_is_rejected_for_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "api_token", "shared-admin-token")
    credential = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="shared-admin-token"
    )
    with pytest.raises(HTTPException) as exc:
        await verify_token(credentials=credential, token=None)
    assert exc.value.status_code == 503
    assert "OSOP_JWT_SECRET" in exc.value.detail


@pytest.mark.asyncio
async def test_query_parameter_bearer_is_rejected_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "test-jwt-signing-secret")
    with pytest.raises(HTTPException) as exc:
        await verify_token(credentials=None, token="exposed-in-url")
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_dev_shared_token_remains_usable_for_existing_development(monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "api_token", "local-development-token")
    cred = HTTPAuthorizationCredentials(
        scheme="Bearer", credentials="local-development-token"
    )
    result = await verify_token(credentials=cred, token=None)
    assert result == {"sub": "shared-development-token", "role": "dev_api_token"}
