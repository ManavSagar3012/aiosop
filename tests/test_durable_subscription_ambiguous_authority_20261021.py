"""Mounted subscriber authority ambiguity regression with isolated fake storage.

No application database or live producer is contacted; this tests the real
FastAPI router and worker42 store admission against a synthetic PG executor.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx
import pytest

from tests.test_durable_supervision_subscriptions_api_20261021 import (
    FakeSession,
    Result,
    _BASE,
    _call,
    env as env,  # pytest imports this fixture for its test-function injection
)

__all__ = ["env"]


@pytest.mark.asyncio
async def test_task_missing_signed_roe_digest_denied_before_lease(
    env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original_execute = FakeSession.execute

    async def missing_digest(
        self: FakeSession, query: Any, params: Optional[Dict[str, Any]] = None
    ) -> Result:
        if str(query).startswith("SELECT payload FROM tasks"):
            return Result({"payload": {"_authorization_version": 4}})
        return await original_execute(self, query, params)

    monkeypatch.setattr(FakeSession, "execute", missing_digest)
    response = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert response.status_code == 409
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_task_wrong_signed_roe_digest_denied_before_lease(
    env: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original_execute = FakeSession.execute

    async def wrong_digest(
        self: FakeSession, query: Any, params: Optional[Dict[str, Any]] = None
    ) -> Result:
        if str(query).startswith("SELECT payload FROM tasks"):
            return Result(
                {"payload": {"_authorization_version": 4, "_authorization_sha256": "f" * 64}}
            )
        return await original_execute(self, query, params)

    monkeypatch.setattr(FakeSession, "execute", wrong_digest)
    response = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert response.status_code == 409
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_duplicate_json_authority_fields_cannot_create_or_revoke(env: Dict[str, Any]) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env["app"]), base_url="http://unit.test"
    ) as client:
        headers = {"Authorization": f"Bearer {env['jwt']}", "Content-Type": "application/json"}
        duplicate = await client.post(
            _BASE + "/acquire",
            content='{"replica_id":"replica-one","replica_id":"replica-two","task_id":"task-a"}',
            headers=headers,
        )
        assert duplicate.status_code == 422
        assert not env["pg"].rows

        acquired = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
        assert acquired.status_code == 200
        duplicate_revoke = await client.post(
            _BASE + "/revoke",
            content='{"task_id":null,"task_id":"task-a"}',
            headers=headers,
        )
        assert duplicate_revoke.status_code == 422
        assert env["pg"].rows[("eng-a", "subscr-" + "9" * 32)]["revoked_at"] is None


@pytest.mark.asyncio
async def test_duplicate_nested_or_wrong_content_type_denied_before_write(
    env: Dict[str, Any]
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env["app"]), base_url="http://unit.test"
    ) as client:
        headers = {"Authorization": f"Bearer {env['jwt']}", "Content-Type": "application/json"}
        nested = await client.post(
            _BASE + "/acquire",
            content='{"replica_id":"replica-one","extra":{"x":1,"x":2}}',
            headers=headers,
        )
        assert nested.status_code == 422
        wrong_type = await client.post(
            _BASE + "/acquire",
            content='{"replica_id":"replica-one"}',
            headers={"Authorization": f"Bearer {env['jwt']}", "Content-Type": "text/plain"},
        )
        assert wrong_type.status_code in {415, 422}
        assert not env["pg"].rows
