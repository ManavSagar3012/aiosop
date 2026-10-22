"""End-to-end gateway-to-orchestrator signed policy admission without a target."""

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ScopeDefinition
from ai_osop.memory.authorization_store import AuthorizationDenied, AuthorizationStore
from ai_osop.orchestrator.orchestrator import Orchestrator
from ai_osop.safety.signed_roe import SignedROEError, canonical_json_bytes


def _signed(monkeypatch, *, owner="operator-test", eng="eng-signed-create"):
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv(
        "OSOP_ROE_TRUSTED_KEYS_JSON",
        json.dumps({"test-signing-key": base64.b64encode(raw).decode("ascii")}),
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    when = lambda offset: (now + timedelta(hours=offset)).isoformat().replace("+00:00", "Z")
    roe = {"llm_call_budget_total": 3, "allow_active_scanning": False}
    policy = {
        "engagement_id": eng,
        "created_by": owner,
        "domains": ["authorized.example.test"],
        "ips": [],
        "exclusions": [],
        "allowed_techniques": ["recon"],
        "restrictions": ["no_exploitation"],
        "approval_required_for": ["rce"],
        "testing_window_start": when(-1),
        "testing_window_end": when(2),
        "roe": roe,
        "issued_at": when(-2),
        "not_before": when(-1),
        "expires_at": when(3),
        "version": 1,
        "authorization_id": "auth-test-one",
        "key_id": "test-signing-key",
    }
    signature = base64.urlsafe_b64encode(
        private.sign(canonical_json_bytes(policy))
    ).rstrip(b"=").decode("ascii")
    scope = ScopeDefinition(
        engagement_id=eng, domains=policy["domains"],
        approval_required_for=policy["approval_required_for"],
        allowed_techniques=policy["allowed_techniques"],
        restrictions=policy["restrictions"],
        testing_window_start=now + timedelta(hours=-1),
        testing_window_end=now + timedelta(hours=2),
        authorization_ref=policy["authorization_id"],
    )
    return scope, roe, {"policy": policy, "signature": signature, "version": 1}


@pytest.mark.asyncio
async def test_signed_creation_calls_atomic_postgresql_admission_before_hot_cache(
    monkeypatch,
):
    scope, roe, signed = _signed(monkeypatch)
    memory = AsyncMock()
    orch = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch._audit_log = AsyncMock()
    persist = AsyncMock(return_value={"version": 1})
    monkeypatch.setattr(AuthorizationStore, "create_authorized_session", persist)

    session = await orch.create_engagement(
        scope, roe, created_by="operator-test", signed_roe=signed
    )
    assert session.session_id == "eng-signed-create"
    assert session.scope.engagement_id == session.session_id
    assert persist.await_count == 1
    saved, verified, owner = persist.await_args.args
    assert saved.session_id == session.session_id
    assert verified.policy_digest and verified.version == 1
    assert owner == "operator-test"
    memory.store_session_state.assert_awaited_once()
    memory.persist_session_state.assert_not_awaited()
    assert orch._sessions[session.session_id] is session


@pytest.mark.asyncio
async def test_invalid_policy_or_database_failure_never_populates_runtime(
    monkeypatch,
):
    scope, roe, signed = _signed(monkeypatch)
    memory = AsyncMock()
    orch = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch._audit_log = AsyncMock()
    persist = AsyncMock(side_effect=RuntimeError("database unavailable"))
    monkeypatch.setattr(AuthorizationStore, "create_authorized_session", persist)
    with pytest.raises(RuntimeError, match="database unavailable"):
        await orch.create_engagement(
            scope, roe, created_by="operator-test", signed_roe=signed
        )
    memory.store_session_state.assert_not_awaited()
    assert orch._sessions == {}
    tampered = dict(signed)
    tampered["signature"] = "A" * 86
    with pytest.raises(SignedROEError):
        await orch.create_engagement(
            scope, roe, created_by="operator-test", signed_roe=tampered
        )
    persist.assert_awaited_once()
    with pytest.raises(WorkflowException):
        await orch.create_engagement(scope, roe, created_by="operator-test")


@pytest.mark.asyncio
async def test_duplicate_authorized_creation_after_lost_ack_is_a_read_only_result(
    monkeypatch,
):
    scope, roe, signed = _signed(monkeypatch)
    memory = AsyncMock()
    orch = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch._audit_log = AsyncMock()
    memory.load_session_state.return_value = __import__(
        "ai_osop.core.models", fromlist=["SessionState"]
    ).SessionState(
        session_id=scope.engagement_id, scope=scope, roe=roe,
        phase="reconnaissance", created_by="operator-test",
    )
    insert = AsyncMock(side_effect=AuthorizationDenied("Engagement already exists"))
    check = AsyncMock(return_value=True)
    monkeypatch.setattr(AuthorizationStore, "create_authorized_session", insert)
    monkeypatch.setattr(AuthorizationStore, "assert_active", check)
    existing = await orch.create_engagement(
        scope, roe, created_by="operator-test", signed_roe=signed
    )
    assert existing.phase == "reconnaissance"  # never rewound by retry
    check.assert_awaited_once()
    assert check.await_args.kwargs["expected_digest"]
    memory.store_session_state.assert_not_awaited()
    orch._audit_log.assert_not_awaited()


@pytest.mark.asyncio
async def test_secondary_cache_or_audit_outage_after_commit_does_not_hide_session(
    monkeypatch,
):
    scope, roe, signed = _signed(monkeypatch)
    memory = AsyncMock()
    memory.store_session_state.side_effect = RuntimeError("redis offline")
    orch = Orchestrator(memory, AsyncMock(), AsyncMock(), AsyncMock())
    orch._audit_log = AsyncMock(side_effect=RuntimeError("secondary audit offline"))
    persist = AsyncMock(return_value={"status": "active"})
    monkeypatch.setattr(AuthorizationStore, "create_authorized_session", persist)
    session = await orch.create_engagement(
        scope, roe, created_by="operator-test", signed_roe=signed
    )
    assert orch._sessions[session.session_id] is session
    persist.assert_awaited_once()
    memory.persist_session_state.assert_not_awaited()
