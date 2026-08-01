"""Security hardening regression suite - AIOSOP-SEC-001.

Verifies:
  - JWT bypass (jwt_secret = False) is gone: OSOP_JWT_SECRET is honoured
  - Debug bearer-token print() is gone: no credential leakage in source
  - require_role() enforces roles correctly
  - Expired JWT -> 401
  - Invalid signature -> 401
  - Missing sub/role claims -> 401
  - api_token fallback works when jwt_secret is absent
  - assert_production_secrets() emits WARNING (not exception) in dev for weak secrets
"""

from __future__ import annotations

import inspect
import logging
import time
from typing import Any, Dict
from unittest.mock import patch

import pytest
from fastapi.security import HTTPAuthorizationCredentials

import ai_osop.api.deps as _deps
import ai_osop.core.config as _cfg

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_credentials(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _mint_jwt(
    secret: str,
    algorithm: str = "HS256",
    sub: str = "user-1",
    role: str = "senior_operator",
    exp_offset: int = 3600,
    include_sub: bool = True,
    include_role: bool = True,
) -> str:
    from jose import jwt

    claims: Dict[str, Any] = {"exp": int(time.time()) + exp_offset}
    if include_sub:
        claims["sub"] = sub
    if include_role:
        claims["role"] = role
    return jwt.encode(claims, secret, algorithm=algorithm)


# ---------------------------------------------------------------------------
# C2: no debug print() in verify_token source
# ---------------------------------------------------------------------------


def test_no_debug_print_in_verify_token():
    src = inspect.getsource(_deps.verify_token)
    assert "print(" not in src, "verify_token must not contain print() calls (credential leakage)"


# ---------------------------------------------------------------------------
# C1: JWT bypass is gone
# ---------------------------------------------------------------------------


def test_jwt_bypass_gone():
    src = inspect.getsource(_deps.verify_token)
    assert "jwt_secret = False" not in src, "JWT bypass hardcoded False must be removed"
    assert "Force bypass" not in src, "JWT bypass comment must be removed"


# ---------------------------------------------------------------------------
# AIOSOP-SEC-002: no ?token= query-param fallback on HTTP routes
# ---------------------------------------------------------------------------


def test_verify_token_has_no_query_param_fallback():
    """HTTP-facing verify_token must only accept the Authorization header.

    Regression guard: a `token: Optional[str] = Query(None)` parameter here
    would make every Depends(verify_token) route (engagements, findings,
    sessions, tasks, approvals, intelligence) accept a bearer credential via
    URL query string, which leaks into access logs / proxy logs / browser
    history. WebSocket auth (which needs a query-param path because browsers
    can't set custom headers on the handshake) must go through the separate
    verify_ws_token instead.
    """
    params = inspect.signature(_deps.verify_token).parameters
    assert (
        "token" not in params
    ), "verify_token regained a query-param token fallback (AIOSOP-SEC-002 regression)"


@pytest.mark.asyncio
async def test_verify_ws_token_accepts_raw_token_string():
    with (
        patch.object(_cfg.settings, "jwt_secret", None),
        patch.object(_cfg.settings, "api_token", "correct-api-token"),
    ):
        result = await _deps.verify_ws_token("correct-api-token")
    assert result["role"] == "senior_operator"


@pytest.mark.asyncio
async def test_verify_ws_token_rejects_missing_token():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await _deps.verify_ws_token(None)
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# verify_token: JWT path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_jwt_accepted():
    secret = "test-secret-strong"
    token = _mint_jwt(secret=secret)
    with (
        patch.object(_cfg.settings, "jwt_secret", secret),
        patch.object(_cfg.settings, "jwt_algorithm", "HS256"),
        patch.object(_cfg.settings, "jwt_audience", None),
        patch.object(_cfg.settings, "jwt_issuer", None),
    ):
        result = await _deps.verify_token(credentials=_make_credentials(token))
    assert result["sub"] == "user-1"
    assert result["role"] == "senior_operator"


@pytest.mark.asyncio
async def test_expired_jwt_returns_401():
    from fastapi import HTTPException

    secret = "test-secret-strong"
    token = _mint_jwt(secret=secret, exp_offset=-10)
    with (
        patch.object(_cfg.settings, "jwt_secret", secret),
        patch.object(_cfg.settings, "jwt_algorithm", "HS256"),
        patch.object(_cfg.settings, "jwt_audience", None),
        patch.object(_cfg.settings, "jwt_issuer", None),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _deps.verify_token(credentials=_make_credentials(token))
    assert exc_info.value.status_code == 401
    assert "expired" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_invalid_signature_returns_401():
    from fastapi import HTTPException

    token = _mint_jwt(secret="correct")
    with (
        patch.object(_cfg.settings, "jwt_secret", "wrong-secret"),
        patch.object(_cfg.settings, "jwt_algorithm", "HS256"),
        patch.object(_cfg.settings, "jwt_audience", None),
        patch.object(_cfg.settings, "jwt_issuer", None),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _deps.verify_token(credentials=_make_credentials(token))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_jwt_missing_role_claim_returns_401():
    from fastapi import HTTPException

    secret = "test-secret-strong"
    token = _mint_jwt(secret=secret, include_role=False)
    with (
        patch.object(_cfg.settings, "jwt_secret", secret),
        patch.object(_cfg.settings, "jwt_algorithm", "HS256"),
        patch.object(_cfg.settings, "jwt_audience", None),
        patch.object(_cfg.settings, "jwt_issuer", None),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _deps.verify_token(credentials=_make_credentials(token))
    assert exc_info.value.status_code == 401
    assert "role" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_jwt_missing_sub_claim_returns_401():
    from fastapi import HTTPException

    secret = "test-secret-strong"
    token = _mint_jwt(secret=secret, include_sub=False)
    with (
        patch.object(_cfg.settings, "jwt_secret", secret),
        patch.object(_cfg.settings, "jwt_algorithm", "HS256"),
        patch.object(_cfg.settings, "jwt_audience", None),
        patch.object(_cfg.settings, "jwt_issuer", None),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _deps.verify_token(credentials=_make_credentials(token))
    assert exc_info.value.status_code == 401
    assert "sub" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# verify_token: api_token fallback (no jwt_secret)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_token_fallback_accepted():
    with (
        patch.object(_cfg.settings, "jwt_secret", None),
        patch.object(_cfg.settings, "api_token", "correct-api-token"),
    ):
        result = await _deps.verify_token(credentials=_make_credentials("correct-api-token"))
    assert result["role"] == "senior_operator"


@pytest.mark.asyncio
async def test_api_token_fallback_wrong_returns_401():
    from fastapi import HTTPException

    with (
        patch.object(_cfg.settings, "jwt_secret", None),
        patch.object(_cfg.settings, "api_token", "correct"),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _deps.verify_token(credentials=_make_credentials("wrong"))
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_no_credentials_returns_403():
    from fastapi import HTTPException

    with (
        patch.object(_cfg.settings, "jwt_secret", None),
        patch.object(_cfg.settings, "api_token", None),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _deps.verify_token(credentials=None)
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# require_role
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_role_passes():
    guard = _deps.require_role("senior_operator")
    result = await guard(operator={"sub": "op", "role": "senior_operator"})
    assert result["role"] == "senior_operator"


@pytest.mark.asyncio
async def test_require_role_blocks_wrong_role():
    from fastapi import HTTPException

    guard = _deps.require_role("senior_operator")
    with pytest.raises(HTTPException) as exc_info:
        await guard(operator={"sub": "op", "role": "viewer"})
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_privilege_escalation_blocked():
    from fastapi import HTTPException

    guard = _deps.require_role("senior_operator")
    with pytest.raises(HTTPException) as exc_info:
        await guard(operator={"sub": "bad-actor", "role": "operator"})
    assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# assert_production_secrets
# ---------------------------------------------------------------------------


def test_assert_production_secrets_warns_in_dev(caplog):
    orig_env = _cfg.settings.environment
    orig_pass = _cfg.settings.neo4j_password
    orig_jwt = _cfg.settings.jwt_secret
    orig_audit = _cfg.settings.audit_secret_key
    try:
        _cfg.settings.environment = "development"
        _cfg.settings.neo4j_password = "change-me-local"
        _cfg.settings.jwt_secret = None
        _cfg.settings.audit_secret_key = None
        with caplog.at_level(logging.WARNING):
            _cfg.assert_production_secrets()  # must NOT raise
        assert any(
            "WEAK-SECRET" in r.message for r in caplog.records
        ), "Expected AIOSOP-SEC-WEAK-SECRET warning for weak dev secrets"
    finally:
        _cfg.settings.environment = orig_env
        _cfg.settings.neo4j_password = orig_pass
        _cfg.settings.jwt_secret = orig_jwt
        _cfg.settings.audit_secret_key = orig_audit


def test_assert_production_secrets_raises_in_prod_weak():
    orig_env = _cfg.settings.environment
    orig_pass = _cfg.settings.neo4j_password
    orig_jwt = _cfg.settings.jwt_secret
    orig_audit = _cfg.settings.audit_secret_key
    try:
        _cfg.settings.environment = "production"
        _cfg.settings.neo4j_password = "change-me-local"
        _cfg.settings.jwt_secret = "strong"
        _cfg.settings.audit_secret_key = "strong"
        with pytest.raises(RuntimeError, match="NEO4J"):
            _cfg.assert_production_secrets()
    finally:
        _cfg.settings.environment = orig_env
        _cfg.settings.neo4j_password = orig_pass
        _cfg.settings.jwt_secret = orig_jwt
        _cfg.settings.audit_secret_key = orig_audit


def test_assert_secrets_passes_when_strong():
    orig_env = _cfg.settings.environment
    orig_pass = _cfg.settings.neo4j_password
    orig_jwt = _cfg.settings.jwt_secret
    orig_audit = _cfg.settings.audit_secret_key
    try:
        _cfg.settings.environment = "production"
        _cfg.settings.neo4j_password = "very-strong-neo4j-password-32chars!"
        _cfg.settings.jwt_secret = "very-strong-jwt-secret-32chars!!"
        _cfg.settings.audit_secret_key = "very-strong-audit-secret-32chars!"
        _cfg.assert_production_secrets()  # must not raise
    finally:
        _cfg.settings.environment = orig_env
        _cfg.settings.neo4j_password = orig_pass
        _cfg.settings.jwt_secret = orig_jwt
        _cfg.settings.audit_secret_key = orig_audit


async def test_jwt_tenant_id_extracted_and_defaults():
    """A JWT carrying a tenant_id claim surfaces it on the operator dict;
    a JWT without one falls back to 'default'."""
    secret = "a" * 32
    with patch.object(_cfg.settings, "jwt_secret", secret), patch.object(
        _cfg.settings, "jwt_algorithm", "HS256"
    ), patch.object(_cfg.settings, "jwt_audience", None), patch.object(
        _cfg.settings, "jwt_issuer", None
    ):
        from jose import jwt as _jwt
        import time as _t

        claims = {
            "sub": "user-t",
            "role": "senior_operator",
            "exp": int(_t.time()) + 3600,
            "tenant_id": "org-blue",
        }
        token = _jwt.encode(claims, secret, algorithm="HS256")
        op = await _deps._authenticate(token)
        assert op["tenant_id"] == "org-blue"

        claims.pop("tenant_id")
        token = _jwt.encode(claims, secret, algorithm="HS256")
        op = await _deps._authenticate(token)
        assert op["tenant_id"] == "default"
