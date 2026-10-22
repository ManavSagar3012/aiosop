"""Signed authorization store fast tests; no application PostgreSQL access."""

import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from ai_osop.core.models import ScopeDefinition, SessionState
from ai_osop.memory.authorization_store import (
    AuthorizationDenied,
    AuthorizationStore,
    _policy_binding_matches,
    guard_sql,
)
from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe


def make_signed_session(
    monkeypatch,
    *,
    session_id="eng-authorization-test",
    version=1,
    private_key=None,
    owner="operator-owner",
    authorization_id=None,
    domains=None,
    roe_override=None,
):
    """Exercise the real Ed25519 verifier, never self-assert a fake receipt."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    key = private_key or Ed25519PrivateKey.generate()
    kid = "qual-kid"
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON",
        json.dumps({kid: base64.b64encode(pub).decode("ascii")}),
    )
    aid = authorization_id or f"auth-version-{version}"
    start = now - timedelta(hours=1)
    end = now + timedelta(hours=1)
    scope = ScopeDefinition(
        engagement_id=session_id,
        domains=domains if domains is not None else ["authorized.example"],
        ips=[],
        exclusions=[],
        allowed_techniques=["passive"],
        restrictions=["no-production-scans"],
        approval_required_for=["exploitation"],
        testing_window_start=start,
        testing_window_end=end,
        authorization_ref=aid,
    )
    roe = (
        dict(roe_override)
        if roe_override is not None
        else {"llm_call_budget_total": 3, "allow_automated_exploitation": False}
    )
    policy = {
        "engagement_id": session_id,
        "created_by": owner,
        "authorization_id": aid,
        "key_id": kid,
        "version": version,
        "domains": scope.domains,
        "ips": scope.ips,
        "exclusions": scope.exclusions,
        "allowed_techniques": scope.allowed_techniques,
        "restrictions": scope.restrictions,
        "approval_required_for": scope.approval_required_for,
        "testing_window_start": start.isoformat().replace("+00:00", "Z"),
        "testing_window_end": end.isoformat().replace("+00:00", "Z"),
        "roe": roe,
        "issued_at": (now - timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
        "not_before": (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
    }
    signature = base64.urlsafe_b64encode(
        key.sign(canonical_json_bytes(policy))
    ).decode("ascii").rstrip("=")
    envelope = {"version": version, "policy": policy, "signature": signature}
    verified = verify_signed_roe(
        envelope, expected_engagement_id=session_id, expected_owner=owner,
        expected_scope=scope, expected_roe=roe, now=now,
    )
    session = SessionState(
        session_id=session_id, scope=scope, roe=roe, created_by=owner,
    )
    return session, verified, envelope, key


def test_register_preparation_accepts_only_verified_signature(monkeypatch):
    session, verified, envelope, _ = make_signed_session(monkeypatch)
    prepare = AuthorizationStore._prepare
    args = (session.session_id, "operator-owner",
            session.scope.model_dump(mode="json"), session.roe, session.created_by)
    with pytest.raises(AuthorizationDenied, match="must be verified"):
        prepare(args[0], envelope, *args[1:])
    trusted = prepare(args[0], verified, *args[1:])
    assert trusted["version"] == 1
    assert trusted["digest"] == verified.policy_digest
    assert trusted["signature"] == verified.signature
    assert "PRIVATE KEY" not in trusted["policy"]
    with pytest.raises(AuthorizationDenied, match="signature"):
        prepare(args[0], replace(verified, signature="A" * 86), *args[1:])
    with pytest.raises(AuthorizationDenied, match="does not match engagement"):
        prepare(args[0], verified, args[1], args[2], {"tampered": True}, args[4])
    with pytest.raises(AuthorizationDenied, match="owner"):
        prepare(args[0], verified, "another-tenant", *args[2:])


def test_signed_policy_requires_exact_authoritative_scope_owner_and_roe(monkeypatch):
    session, _, envelope, _ = make_signed_session(monkeypatch)
    policy = envelope["policy"]
    scope = session.scope.model_dump(mode="json")
    assert _policy_binding_matches(
        policy, session.session_id, scope, session.roe, session.created_by,
    )
    assert not _policy_binding_matches(
        policy, session.session_id, {**scope, "domains": ["evil.example"]},
        session.roe, session.created_by,
    )
    assert not _policy_binding_matches(
        policy, session.session_id, {**scope, "authorization_ref": "auth-stolen"},
        session.roe, session.created_by,
    )
    assert not _policy_binding_matches(
        policy, session.session_id, scope, session.roe, "different-owner",
    )


@pytest.mark.asyncio
async def test_guard_denies_missing_ledger_and_postgres_failure_without_fallback():
    class _Rows:
        def mappings(self):
            return self

        def one_or_none(self):
            return None

    memory = SimpleNamespace(_async_session=None)
    store = AuthorizationStore(memory)
    with pytest.raises(AuthorizationDenied, match="PostgreSQL session unavailable"):
        await store.assert_active("eng-legacy")
    db = SimpleNamespace(execute=AsyncMock(return_value=_Rows()))
    with pytest.raises(AuthorizationDenied, match="unavailable"):
        await guard_sql(db, "eng-legacy")
    db.execute.assert_awaited_once()
    db.execute.side_effect = RuntimeError("DB_PASSWORD_UNTRUSTED")
    with pytest.raises(AuthorizationDenied) as failed:
        await guard_sql(db, "eng-other")
    assert "DB_PASSWORD" not in str(failed.value)


@pytest.mark.asyncio
async def test_guard_rejects_invalid_fence_without_query():
    db = SimpleNamespace(execute=AsyncMock())
    for version, digest in ((True, None), (0, None), (None, "x")):
        with pytest.raises(AuthorizationDenied):
            await guard_sql(db, "eng-authorization-test", version, digest)
    with pytest.raises(AuthorizationDenied):
        await guard_sql(db, "eng%2Fwrong")
    db.execute.assert_not_awaited()
