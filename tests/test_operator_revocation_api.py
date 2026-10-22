"""Durable operator invalidation contract; no app database or external IdP."""

import hashlib
import time
from datetime import datetime

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.routers.auth import router as auth_router
from ai_osop.core.config import settings
from ai_osop.memory.operator_revocation import (
    OperatorRevocationLedger,
    OperatorRevocationUnavailable,
    OperatorRevoked,
)


class SimulatedSharedPostgresLedger:
    """Two API requests/readers share the same durable state, no allow cache."""

    def __init__(self):
        self.revoked = set()
        self.disabled = set()
        self.fail = False
        self.attempts = 0

    async def assert_active(self, token, principal):
        self.attempts += 1
        if self.fail:
            raise OperatorRevocationUnavailable("PG connection lost")
        if hashlib.sha256(token.encode()).hexdigest() in self.revoked:
            raise OperatorRevoked()
        if principal["sub"] in self.disabled:
            raise OperatorRevoked()

    async def revoke_token(self, token, principal):
        if self.fail:
            raise OperatorRevocationUnavailable("PG connection lost")
        digest = hashlib.sha256(token.encode()).hexdigest()
        previously = digest in self.revoked
        self.revoked.add(digest)
        return not previously

    async def disable_subject(self, subject, *, actor_id, disabled, reason):
        if self.fail:
            raise OperatorRevocationUnavailable("PG connection lost")
        assert actor_id == "admin"
        assert len(reason.strip()) >= 10
        if disabled:
            self.disabled.add(subject)
        else:
            self.disabled.discard(subject)


@pytest.fixture
def api(monkeypatch):
    ledger = SimulatedSharedPostgresLedger()
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", "local-inert-jwt-qualification-only")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    for attr in ("oidc_issuer", "oidc_audience", "oidc_jwks_url"):
        monkeypatch.setattr(settings, attr, None)
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    monkeypatch.setattr(deps, "_operator_revocation_ledger", lambda: ledger)
    # Both imports reference the same resolver by object; patch router as well.
    monkeypatch.setattr("ai_osop.api.routers.auth._operator_revocation_ledger", lambda: ledger)
    app = FastAPI()
    app.include_router(auth_router)

    def signed(subject="alice", role="operator"):
        return jwt.encode(
            {"sub": subject, "role": role, "exp": int(time.time()) + 900,
             "iat": int(time.time()), "jti": subject + "-token"},
            settings.jwt_secret, algorithm="HS256",
        )

    async def send(method, path, token, body=None):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://local.invalid",
        ) as client:
            return await client.request(
                method, path, headers={"Authorization": "Bearer " + token},
                json=body,
            )

    return ledger, signed, send


@pytest.mark.asyncio
async def test_logged_out_token_is_denied_on_another_http_request(api):
    ledger, sign, send = api
    token = sign()
    assert (await send("GET", "/auth/me", token)).status_code == 200
    logout = await send("POST", "/auth/logout", token)
    assert logout.status_code == 200 and logout.json() == {"status": "revoked"}
    assert (await send("GET", "/auth/me", token)).status_code == 401
    assert ledger.attempts == 3
    assert token not in repr(ledger.revoked)


@pytest.mark.asyncio
async def test_senior_disable_invalidates_existing_account_tokens(api):
    ledger, sign, send = api
    admin = sign("admin", "senior_operator")
    alice = sign()
    bob = sign("bob")
    assert (await send("GET", "/auth/me", alice)).status_code == 200
    change = {"reason": "Emergency compromised account"}
    assert (await send("POST", "/auth/operators/alice/disable", admin, change)).status_code == 200
    assert (await send("GET", "/auth/me", alice)).status_code == 401
    assert (await send("GET", "/auth/me", bob)).status_code == 200
    assert (await send("POST", "/auth/operators/bob/disable", alice, change)).status_code == 401
    assert (await send("POST", "/auth/operators/admin/disable", admin, change)).status_code == 403
    assert (await send("POST", "/auth/operators/bob/disable", bob, change)).status_code == 403
    assert (await send("POST", "/auth/operators/alice/enable", admin, change)).status_code == 200
    assert (await send("GET", "/auth/me", alice)).status_code == 200
    assert (await send("POST", "/auth/operators/bob/disable", admin, {"reason": "short"})).status_code == 422


@pytest.mark.asyncio
async def test_pg_down_denies_authenticated_operations_and_mutations(api):
    ledger, sign, send = api
    admin = sign("admin", "senior_operator")
    ledger.fail = True
    assert (await send("GET", "/auth/me", admin)).status_code == 503
    assert (await send("POST", "/auth/logout", admin)).status_code == 503
    assert (await send("POST", "/auth/operators/alice/disable", admin)).status_code == 503


@pytest.mark.asyncio
async def test_dev_shared_token_and_unconfigured_revocation_cannot_claim_logout(api, monkeypatch):
    ledger, sign, send = api
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    assert (await send("POST", "/auth/logout", sign())).status_code == 503
    assert ledger.revoked == set()


def test_revocation_storage_digests_are_bounded_and_not_plain_tokens():
    token = "signed.token.value"
    digest = OperatorRevocationLedger._digest(token)
    assert digest == hashlib.sha256(token.encode()).hexdigest()
    assert token not in digest
    with pytest.raises(ValueError):
        OperatorRevocationLedger._digest("x" * 16385)
    with pytest.raises(ValueError):
        OperatorRevocationLedger._actor({"sub": "bad\noperator"})
