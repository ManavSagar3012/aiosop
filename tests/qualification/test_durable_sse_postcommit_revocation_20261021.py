"""Post-commit durable-read and legacy SSE revocation boundaries (local only).

Calls the EXISTING mounted FastAPI subscription/SSE routes using ASGITransport,
local signed JWTs and the prior synthetic SQL fixture. No app DB, real IdP,
network target, Docker, tool dispatch, or durable stream qualification. The
OIDC tests verify local RSA JWT + claims against a MOCK provider status gate;
they cannot establish a real IdP's freshness or transport behavior.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Dict
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import HTTPException
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ai_osop.api import deps
from ai_osop.api.routers import durable_supervision_subscriptions as durable
from ai_osop.api.routers import supervision as sse
from tests.test_durable_supervision_subscriptions_api_20261021 import (
    _binding, _call, env as subscription_env,
)


_SUBSCRIBER = "subscr-" + "9" * 32
_BASE = f"/supervision/engagements/eng-a/subscriptions/{_SUBSCRIBER}"
_SSE = "/supervision/engagements/eng-a/events/stream?task_id=task-a"


def _row(sequence: int = 12) -> Dict[str, Any]:
    return {
        "id": "evt-a12", "sequence": sequence,
        "engagement_id": "eng-a", "task_id": "task-a",
        "kind": "agent.message", "actor_id": "operator-a",
        "payload": {"status": "UNKNOWN", "safe_to_retry": False},
        "created_at": datetime(2026, 10, 21, 12, 0, 0),
    }


async def _post(env: Dict[str, Any], operation: str, body: Dict[str, Any],
                token: str | None = None) -> httpx.Response:
    return await _call(env, operation, body, token=token)


async def _subscribe(env: Dict[str, Any]) -> Dict[str, Any]:
    reply = await _post(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert reply.status_code == 200, reply.text
    return reply.json()["lease"]


def _live_revocation_ledger(env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """Make verify_token consult a synthetic, CURRENT token/subject ledger."""
    env["pg"].revoked.clear()
    env["pg"].disabled.clear()
    deps.settings.operator_revocation_required = True

    async def assert_active(token: str, operator: Dict[str, Any]) -> None:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if digest in env["pg"].revoked or operator.get("sub") in env["pg"].disabled:
            from ai_osop.memory.operator_revocation import OperatorRevoked
            raise OperatorRevoked("synthetic revoked bearer")

    monkeypatch.setattr(deps, "_operator_revocation_ledger",
                        lambda: SimpleNamespace(assert_active=assert_active))


@pytest.mark.asyncio
async def test_mounted_durable_read_postcommit_recheck_denies_revoked_token(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Revocation just AFTER store.read_batch commits must not publish JSON."""
    env = subscription_env
    _live_revocation_ledger(env, monkeypatch)
    lease = await _subscribe(env)
    original = durable.DurableSupervisionSubscriptions.read_batch
    observed_commit = 0

    async def revoke_after_read(self: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal observed_commit
        events = await original(self, *args, **kwargs)
        observed_commit += 1
        env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
        return events

    monkeypatch.setattr(durable.DurableSupervisionSubscriptions,
                        "read_batch", revoke_after_read)
    response = await _post(env, "/read", {**_binding(lease), "limit": 2})
    assert observed_commit == 1
    assert response.status_code in (401, 403, 409), response.text
    assert '"sequence":12' not in response.text
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_mounted_read_revocation_after_final_check_is_still_response_gap(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deterministic revocation after last _context but before JSON send."""
    env = subscription_env
    _live_revocation_ledger(env, monkeypatch)
    lease = await _subscribe(env)
    original_privacy = durable._privacy
    late = 0

    def revocation_after_authorization(response: Any) -> None:
        nonlocal late
        late += 1
        env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
        original_privacy(response)

    monkeypatch.setattr(durable, "_privacy", revocation_after_authorization)
    response = await _post(env, "/read", {**_binding(lease), "limit": 2})
    assert late == 1
    assert response.status_code == 200, response.text
    assert [event["sequence"] for event in response.json()["events"]] == [12, 18]
    assert response.json()["cursor"] == 0
    assert response.json()["acknowledged"] is False
    assert response.json()["delivery_semantics"] == "at_least_once"
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 0
    assert (await _post(env, "/read", _binding(lease))).status_code in (401, 403, 409)


@pytest.mark.asyncio
async def test_mounted_lost_ack_http_response_does_not_auto_retry_or_cancel(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transport cancellation AFTER ACK commit leaves committed cursor and no replay."""
    env = subscription_env
    lease = await _subscribe(env)
    committed, never_release = asyncio.Event(), asyncio.Event()
    original = durable.DurableSupervisionSubscriptions.acknowledge

    async def block_after_commit(self: Any, *args: Any, **kwargs: Any) -> Any:
        value = await original(self, *args, **kwargs)
        committed.set()
        await never_release.wait()
        return value

    monkeypatch.setattr(durable.DurableSupervisionSubscriptions,
                        "acknowledge", block_after_commit)
    payload = {**_binding(lease), "expected_cursor": 0, "next_sequence": 12}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env["app"]),
                                 base_url="http://unit.test") as client:
        pending = asyncio.create_task(client.post(
            _BASE + "/ack", json=payload,
            headers={"Authorization": "Bearer " + env["jwt"]},
        ))
        await asyncio.wait_for(committed.wait(), timeout=5)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 12
    # A second ACK is NOT an automatic retry and may not replay this cursor.
    stale = await _post(env, "/ack", payload)
    assert stale.status_code == 409
    reading = await _post(env, "/read", {**_binding({**lease, "cursor": 12}), "limit": 5})
    assert reading.status_code == 200, reading.text
    assert [x["sequence"] for x in reading.json()["events"]] == [18]
    assert reading.json()["acknowledged"] is False
    assert not any("tool_dispatch" in x.lower() or "claim_mcp_dispatch" in x.lower()
                   for x in env["pg"].statements)


@pytest.mark.asyncio
async def test_live_sse_asgi_revalidates_after_batch_before_event(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A revocation committed while fetching a batch blocks the next yield."""
    env = subscription_env
    _live_revocation_ledger(env, monkeypatch)
    env["app"].include_router(sse.router)
    store = SimpleNamespace()
    calls = 0

    async def after_select(*args: Any, **kwargs: Any) -> list[Dict[str, Any]]:
        nonlocal calls
        calls += 1
        env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
        return [_row()]

    store.list_events_after = after_select
    async def access(_engagement: str, _operator: Dict[str, Any],
                     _task: Any = None) -> Any:
        return store
    monkeypatch.setattr(sse, "_access", access)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env["app"]),
                                 base_url="http://unit.test") as client:
        reply = await client.get(_SSE, headers={"Authorization": "Bearer " + env["jwt"]})
    assert reply.status_code == 200
    assert calls == 1
    assert "event: auth_required" in reply.text
    assert "id: 12" not in reply.text
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_sse_revocation_after_serialization_is_rechecked_before_yield(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = subscription_env
    _live_revocation_ledger(env, monkeypatch)
    env["app"].include_router(sse.router)
    store = SimpleNamespace(list_events_after=AsyncMock(return_value=[_row()]))
    async def access(_engagement: str, _operator: Dict[str, Any],
                     _task: Any = None) -> Any:
        return store
    monkeypatch.setattr(sse, "_access", access)
    original_check = sse._sse_committed_event
    changed = 0

    def revoke_after_final_check(*args: Any, **kwargs: Any) -> Any:
        nonlocal changed
        result = original_check(*args, **kwargs)
        if result is not None and changed == 0:
            changed += 1
            env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
        return result

    monkeypatch.setattr(sse, "_sse_committed_event", revoke_after_final_check)
    async def no_delay(_: Any) -> None:
        return None
    monkeypatch.setattr(sse.asyncio, "sleep", no_delay)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env["app"]),
                                 base_url="http://unit.test") as client:
        reply = await client.get(_SSE, headers={"Authorization": "Bearer " + env["jwt"]})
    assert reply.status_code == 200
    assert changed == 1
    assert "event: auth_required" in reply.text
    assert "id: 12\nevent: supervision\n" not in reply.text
    assert '"status":"UNKNOWN"' not in reply.text
    assert not env["pg"].rows  # SSE never creates/ACKs 0040 subscriber state.


@pytest.mark.asyncio
async def test_sse_disconnect_after_select_stops_before_yield(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct generator: new per-event disconnected check blocks a frame."""
    disconnected = False
    store = SimpleNamespace()
    async def get_events(*args: Any, **kwargs: Any) -> list[Dict[str, Any]]:
        nonlocal disconnected
        disconnected = True  # Synthetic HTTP disconnect after initial poll check.
        return [_row()]
    store.list_events_after = get_events
    monkeypatch.setattr(sse, "_stream_revalidate", AsyncMock(return_value=store))

    class Request:
        headers = {"last-event-id": "0"}
        async def is_disconnected(self) -> bool:
            return disconnected

    response = await sse.stream_events("eng-a", Request(), 0, "task-a",
                                       {"sub": "operator-a", "role": "operator"})
    stream = response.body_iterator
    try:
        with pytest.raises(StopAsyncIteration):
            await anext(stream)
        assert disconnected
        assert sse._stream_revalidate.await_count == 3
    finally:
        await stream.aclose()


@pytest.mark.asyncio
async def test_sse_revocation_after_final_live_check_still_has_transport_gap(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last completed check cannot cover later ASGI frame publication.

    Flip durable token status *after* the newly added final bearer check
    succeeds. This is deliberately narrower than the previously fixed
    revocation-after-serialization race. It proves generator semantics,
    not delivery to a remote client.
    """
    env = subscription_env
    _live_revocation_ledger(env, monkeypatch)
    env["app"].include_router(sse.router)
    store = SimpleNamespace(list_events_after=AsyncMock(return_value=[_row()]))

    async def access(_engagement: str, _operator: Dict[str, Any],
                     _task: Any = None) -> Any:
        return store

    monkeypatch.setattr(sse, "_access", access)
    original_revalidate = sse._stream_revalidate
    calls = 0

    async def revoke_after_last_revalidate(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        current = await original_revalidate(*args, **kwargs)
        calls += 1
        # Route admission, batch poll, first per-event guard, final guard.
        if calls == 4:
            env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
        return current

    monkeypatch.setattr(sse, "_stream_revalidate", revoke_after_last_revalidate)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env["app"]),
                                 base_url="http://unit.test") as client:
        reply = await client.get(_SSE, headers={"Authorization": "Bearer " + env["jwt"]})
    assert reply.status_code == 200
    assert calls == 4  # No later authorization is required before this yield.
    assert "id: 12\nevent: supervision\n" in reply.text
    assert '"status":"UNKNOWN"' in reply.text
    # The ASGI stream need not perform a subsequent poll after disconnect; do
    # not invent a later auth_required frame or claim transport delivery.
    assert (await _post(env, "/acquire", {"replica_id": "replica-other"})).status_code in (
        401, 403, 409,
    )
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_asgi_sse_http_cancellation_mid_poll_never_acks_durable_subscriber(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cancel a real ASGI GET while the committed-event SELECT is suspended."""
    env = subscription_env
    lease = await _subscribe(env)
    env["app"].include_router(sse.router)
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def blocked_select(*args: Any, **kwargs: Any) -> list[Dict[str, Any]]:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    store = SimpleNamespace(list_events_after=blocked_select)

    async def access(_engagement: str, _operator: Dict[str, Any],
                     _task: Any = None) -> Any:
        return store

    monkeypatch.setattr(sse, "_access", access)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env["app"]),
                                 base_url="http://unit.test") as client:
        pending = asyncio.create_task(client.get(
            _SSE, headers={"Authorization": "Bearer " + env["jwt"]},
        ))
        await asyncio.wait_for(entered.wait(), timeout=5)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        await asyncio.wait_for(cancelled.wait(), timeout=5)

    row = env["pg"].rows[("eng-a", _SUBSCRIBER)]
    assert row["cursor_sequence"] == lease["cursor"] == 0
    assert row["lease_generation"] == lease["generation"]
    assert not any("claim_mcp_dispatch" in sql.lower() for sql in env["pg"].statements)


def _oidc_credentials(monkeypatch: pytest.MonkeyPatch) -> tuple[str, dict[str, bool], str]:
    """Local ephemeral RSA/JWT plus MOCK IdP introspection, no network."""
    issuer, audience, actor_subject = "https://oidc.invalid", "osop-operators", "human-7"
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption())
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    token = jwt.encode({
        "sub": actor_subject, "iss": issuer, "aud": audience,
        "exp": now + 300, "iat": now - 2, "nbf": now - 2,
        "groups": ["operators"],
    }, private_pem, algorithm="RS256", headers={"kid": "local-test-key", "typ": "JWT"})
    config = {
        "issuer": issuer, "audience": audience, "algorithms": ("RS256",),
        "role_claim": "groups", "role_map": {"operators": "operator"},
        "token_typ": "JWT", "max_token_seconds": 3600,
    }
    active = {"enabled": True}

    async def key(*args: Any, **kwargs: Any) -> Any:
        return public_pem

    async def introspection(*args: Any, **kwargs: Any) -> None:
        if not active["enabled"]:
            raise HTTPException(401, "Synthetic IdP token inactive")

    monkeypatch.setattr(deps, "_oidc_config", lambda: config)
    monkeypatch.setattr(deps, "_oidc_key", key)
    monkeypatch.setattr(deps, "_require_active_oidc_token", introspection)
    actor = "oidc-" + hashlib.sha256((issuer + "\0" + actor_subject).encode()).hexdigest()[:48]
    return token, active, actor


@pytest.mark.asyncio
async def test_oidc_namespaced_signed_actor_and_live_status_rechecked_on_read(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = subscription_env
    token, active, actor = _oidc_credentials(monkeypatch)
    # OIDC signed 'human-7' is not the unrelated local owner 'operator-a'.
    foreign = await _post(env, "/acquire", {"replica_id": "replica-one"}, token)
    assert foreign.status_code == 403
    env["pg"].owners["eng-a"] = actor
    acquired = await _post(env, "/acquire", {"replica_id": "replica-one"}, token)
    assert acquired.status_code == 200, acquired.text
    lease = acquired.json()["lease"]
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["subject"] == actor
    active["enabled"] = False
    denied = await _post(env, "/read", _binding(lease, task_id=None), token)
    assert denied.status_code == 401
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_oidc_introspection_fails_closed_at_sse_pre_emit_boundary(
    subscription_env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch,
) -> None:
    env = subscription_env
    token, active, actor = _oidc_credentials(monkeypatch)
    env["pg"].owners["eng-a"] = actor
    env["app"].include_router(sse.router)
    async def fetch(*args: Any, **kwargs: Any) -> list[Dict[str, Any]]:
        active["enabled"] = False  # Simulated IdP revocation after batch read.
        return [_row()]
    store = SimpleNamespace(list_events_after=fetch)
    async def access(_engagement: str, operator: Dict[str, Any],
                     _task: Any = None) -> Any:
        assert operator["sub"] == actor
        return store
    monkeypatch.setattr(sse, "_access", access)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env["app"]),
                                 base_url="http://unit.test") as client:
        reply = await client.get(_SSE, headers={"Authorization": "Bearer " + token})
    assert reply.status_code == 200
    assert "event: auth_required" in reply.text
    assert "id: 12" not in reply.text
    assert not env["pg"].rows
