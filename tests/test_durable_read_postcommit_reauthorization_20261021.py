"""Postcommit subscriber readback rechecks current bearer and signed ROE.

Actual mounted FastAPI, real store logic, synthetic transaction executor only.
No deployed IdP, database, target or provider is accessed.
"""

import hashlib
from typing import Any, Dict

import pytest

from ai_osop.api.routers import durable_supervision_subscriptions as api
from tests.test_durable_supervision_subscriptions_api_20261021 import (
    _binding,
    _call,
    env as env,
)

__all__ = ["env"]


@pytest.mark.asyncio
async def test_token_revocation_after_store_read_before_response_denied(
    env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    acquired = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert acquired.status_code == 200
    lease = acquired.json()["lease"]
    original_read = api.DurableSupervisionSubscriptions.read_batch

    async def revoke_after_commit(self, principal, binding, *, limit=50):
        events = await original_read(self, principal, binding, limit=limit)
        env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
        return events

    monkeypatch.setattr(api.DurableSupervisionSubscriptions, "read_batch", revoke_after_commit)
    response = await _call(env, "/read", {**_binding(lease), "limit": 10})
    assert response.status_code == 409
    assert response.json() == {"detail": "Durable supervision subscription denied or unavailable"}
    assert env["pg"].rows[("eng-a", lease["subscriber_id"])]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_signed_roe_change_after_store_read_prevents_payload_release(
    env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    acquired = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert acquired.status_code == 200
    original_read = api.DurableSupervisionSubscriptions.read_batch

    async def revoke_roe_after_commit(self, principal, binding, *, limit=50):
        events = await original_read(self, principal, binding, limit=limit)
        env["pg"].guard_live = False
        return events

    monkeypatch.setattr(api.DurableSupervisionSubscriptions, "read_batch", revoke_roe_after_commit)
    response = await _call(env, "/read", _binding(acquired.json()["lease"]))
    assert response.status_code == 409
    assert "events" not in response.json()
