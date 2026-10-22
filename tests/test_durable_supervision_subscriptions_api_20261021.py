"""Strict durable subscriber API qualification, mocked PostgreSQL and local signed JWT.

Uses worker42's *real* durable store SQL/CAS logic with its deterministic
transactional PostgreSQL fake. Signed ROE verification and supervisor tenant
checker are explicitly FAKE; the local HS256 JWT verifier, live token guard,
revocation queries, ASGI request validation, and store leases/ACKs are real.
No migration, app database, providers, targets, or Docker are accessed.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, Optional

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.routers import durable_supervision_subscriptions as api
from ai_osop.memory import authorization_store
from tests.test_durable_supervision_subscriptions_20261021 import (
    Memory,
    Result,
    Session,
    SimulatedPostgres,
)

_SECRET = "isolated-signed-jwt-test-secret-for-durable-subscriptions"
_SUBSCRIBER = "subscr-" + "9" * 32
_BASE = f"/supervision/engagements/eng-a/subscriptions/{_SUBSCRIBER}"
_AUTH = "a" * 64


class FakePG(SimulatedPostgres):
    def __init__(self) -> None:
        super().__init__()
        self.revoked: set[str] = set()
        self.disabled: set[str] = set()
        self.task_version = 4
        self.guard_live = True

    def session(self) -> "FakeSession":
        return FakeSession(self)


class FakeSession(Session):
    async def execute(self, query: Any, params: Optional[dict[str, Any]] = None) -> Result:
        statement = str(query)
        params = params or {}
        if "FROM operator_token_revocations" in statement:
            digest = None
            # The SQLAlchemy compiled bind name is data, never a string
            # concatenation query. Simulate a revoked current bearer by flag.
            if self.pg.revoked:
                digest = "revoked-current-token"
            return Result(digest)
        if "FROM operator_subject_controls" in statement:
            return Result("operator-a" in self.pg.disabled)
        if statement.startswith("SELECT payload FROM tasks"):
            if (params.get("engagement"), params.get("task")) not in self.pg.tasks:
                return Result()
            return Result(
                {
                    "payload": {
                        "_authorization_version": self.pg.task_version,
                        "_authorization_sha256": _AUTH,
                    }
                }
            )
        return await super().execute(query, params)


def _token(subject: str, role: str = "operator", *, expires: int = 3600) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": subject, "role": role, "exp": now + expires, "iat": now, "iss": "local-jwt"},
        _SECRET,
        algorithm="HS256",
    )


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    pg = FakePG()
    memory = Memory(pg)
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(
            environment="testing",
            jwt_secret=_SECRET,
            jwt_algorithm="HS256",
            jwt_issuer="",
            jwt_audience="",
            api_token="",
            operator_revocation_required=False,
            oidc_issuer=None,
            oidc_audience=None,
            oidc_jwks_url=None,
        ),
    )
    # Routing module has imported verify_token; its function reads deps.settings.
    monkeypatch.setattr(api, "_memory", lambda: memory)

    async def fake_current_roe(
        _db: Any,
        engagement: str,
        expected_version: Optional[int] = None,
        expected_digest: Optional[str] = None,
    ) -> Any:
        if (
            engagement not in pg.owners
            or not pg.guard_live
            or expected_version not in (None, 4)
            or expected_digest not in (None, _AUTH)
        ):
            return None
        return SimpleNamespace(version=4, policy_sha256=_AUTH)

    monkeypatch.setattr(api, "guard_sql", fake_current_roe)
    monkeypatch.setattr(authorization_store, "guard_sql", fake_current_roe)

    async def fake_supervisor_access(
        engagement_id: str, operator: Dict[str, Any], task_id: Optional[str] = None
    ) -> Any:
        if engagement_id not in pg.owners:
            raise HTTPException(404, "No such engagement")
        if operator.get("role") != "senior_operator" and pg.owners[engagement_id] != operator.get(
            "sub"
        ):
            raise HTTPException(403, "Other tenant")
        if task_id is not None and (engagement_id, task_id) not in pg.tasks:
            raise HTTPException(403, "Other tenant task")
        return object()

    monkeypatch.setattr(api, "_supervisor_access", fake_supervisor_access)
    web = FastAPI()
    web.include_router(api.router)
    return {
        "app": web,
        "pg": pg,
        "jwt": _token("operator-a"),
        "other": _token("operator-b"),
        "memory": memory,
    }


async def _call(
    env: Dict[str, Any],
    path: str,
    body: Dict[str, Any],
    *,
    token: Optional[str] = None,
) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env["app"]),
        base_url="http://unit.test",
    ) as client:
        return await client.post(
            _BASE + path,
            json=body,
            headers={"Authorization": "Bearer " + (token or env["jwt"])},
        )


def _binding(lease: Dict[str, Any], *, task_id: Optional[str] = "task-a") -> Dict[str, Any]:
    return {
        "replica_id": lease["replica_id"],
        "lease_id": lease["lease_id"],
        "generation": lease["generation"],
        "cursor": lease["cursor"],
        "task_id": task_id,
    }


@pytest.mark.asyncio
async def test_api_signed_owner_end_to_end_no_provider_activation(env: Dict[str, Any]) -> None:
    acquired = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert acquired.status_code == 200, acquired.text
    assert acquired.headers["Cache-Control"] == "private, no-store"
    lease = acquired.json()["lease"]
    assert lease["delivery_semantics"] == "at_least_once"
    assert lease["provider_effect"] == "unobserved"
    reading = await _call(env, "/read", {**_binding(lease), "limit": 10})
    assert reading.status_code == 200, reading.text
    assert [event["sequence"] for event in reading.json()["events"]] == [12, 18]
    assert reading.json()["acknowledged"] is False
    assert reading.json()["cursor"] == 0
    # ACK must be the next committed Task event, not a chosen later sequence.
    skipped = await _call(
        env, "/ack", {**_binding(lease), "expected_cursor": 0, "next_sequence": 18}
    )
    assert skipped.status_code == 409
    committed = await _call(
        env, "/ack", {**_binding(lease), "expected_cursor": 0, "next_sequence": 12}
    )
    assert committed.status_code == 200, committed.text
    current = committed.json()["lease"]
    assert current["cursor"] == 12
    replay = await _call(
        env, "/ack", {**_binding(lease), "expected_cursor": 0, "next_sequence": 12}
    )
    assert replay.status_code == 409
    renewed = await _call(env, "/renew", {**_binding(current), "lease_seconds": 25})
    assert renewed.status_code == 200
    after = await _call(env, "/read", _binding(renewed.json()["lease"]))
    assert [event["sequence"] for event in after.json()["events"]] == [18]
    released = await _call(env, "/release", _binding(renewed.json()["lease"]))
    assert released.status_code == 200
    reacquired = await _call(env, "/acquire", {"replica_id": "replica-two", "task_id": "task-a"})
    assert reacquired.status_code == 200, reacquired.text
    assert reacquired.json()["lease"]["cursor"] == 12
    assert reacquired.json()["lease"]["generation"] > lease["generation"]
    revoked = await _call(env, "/revoke", {"task_id": "task-a"})
    assert revoked.status_code == 200
    assert (
        await _call(env, "/acquire", {"replica_id": "replica-three", "task_id": "task-a"})
    ).status_code == 409
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 12
    # The API never invokes any MCP or scanner code, and reads only committed
    # tenant rows in the store's simulated PG executor.
    assert not any("tool_dispatch" in statement.lower() for statement in env["pg"].statements)


@pytest.mark.asyncio
async def test_api_denies_other_tenant_and_foreign_task_before_store(env: Dict[str, Any]) -> None:
    foreign = await _call(env, "/acquire", {"replica_id": "replica-one"}, token=env["other"])
    assert foreign.status_code == 403
    wrong_task = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-b"})
    assert wrong_task.status_code == 403
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_api_revocation_and_signed_authorization_fence_cursor(env: Dict[str, Any]) -> None:
    response = await _call(env, "/acquire", {"replica_id": "replica-one", "task_id": "task-a"})
    assert response.status_code == 200
    lease = response.json()["lease"]
    env["pg"].disabled.add("operator-a")
    assert (
        await _call(env, "/ack", {**_binding(lease), "expected_cursor": 0, "next_sequence": 12})
    ).status_code == 409
    env["pg"].disabled.clear()
    env["pg"].revoked.add(hashlib.sha256(env["jwt"].encode()).hexdigest())
    assert (await _call(env, "/renew", _binding(lease))).status_code == 409
    env["pg"].revoked.clear()
    env["pg"].guard_live = False
    assert (await _call(env, "/read", _binding(lease))).status_code == 409
    env["pg"].guard_live = True
    env["pg"].task_version = 5
    assert (
        await _call(env, "/ack", {**_binding(lease), "expected_cursor": 0, "next_sequence": 12})
    ).status_code == 409
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_api_rejects_cross_replica_and_expired_lease(env: Dict[str, Any]) -> None:
    response = await _call(env, "/acquire", {"replica_id": "replica-one"})
    assert response.status_code == 200
    lease = response.json()["lease"]
    rogue = _binding(lease, task_id=None)
    rogue["replica_id"] = "replica-rogue"
    assert (await _call(env, "/read", rogue)).status_code == 409
    env["pg"].now += timedelta(seconds=31)
    assert (
        await _call(
            env,
            "/ack",
            {**_binding(lease, task_id=None), "expected_cursor": 0, "next_sequence": 12},
        )
    ).status_code == 409
    recovered = await _call(env, "/acquire", {"replica_id": "replica-recovery"})
    assert recovered.status_code == 200
    assert recovered.json()["lease"]["lease_id"] != lease["lease_id"]
    assert (await _call(env, "/release", _binding(lease, task_id=None))).status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        {"replica_id": "replica-a", "authorization_sha256": _AUTH},
        {"replica_id": "replica-a", "role": "senior_operator"},
        {"replica_id": "replica-a", "cursor": 99},
        {"replica_id": "../other"},
        {"replica_id": "replica-a", "lease_seconds": True},
        {"replica_id": "replica-a", "lease_seconds": 121},
        {"replica_id": "replica-a", "task_id": "task-other-tenant"},
        {"replica_id": "replica-a", "task_id": "task-" + "a" * 60},
    ],
)
async def test_api_strict_fields_no_caller_minted_authority(
    env: Dict[str, Any], bad: Dict[str, Any]
) -> None:
    response = await _call(env, "/acquire", bad)
    assert response.status_code in (403, 422)
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_api_unknown_lease_fields_and_boolean_cursor_rejected(env: Dict[str, Any]) -> None:
    acquired = await _call(env, "/acquire", {"replica_id": "replica-a"})
    assert acquired.status_code == 200
    body = _binding(acquired.json()["lease"], task_id=None)
    for corrupted in (
        {**body, "cursor": True},
        {**body, "lease_until": datetime.now(timezone.utc).isoformat()},
        {**body, "principal_subject": "operator-b"},
        {**body, "generation": 0},
    ):
        result = await _call(env, "/ack", {**corrupted, "expected_cursor": 0, "next_sequence": 12})
        assert result.status_code == 422
    assert env["pg"].rows[("eng-a", _SUBSCRIBER)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_api_signed_token_expiry_and_no_query_fallback(env: Dict[str, Any]) -> None:
    expired = _token("operator-a", expires=-10)
    response = await _call(env, "/acquire", {"replica_id": "replica-a"}, token=expired)
    assert response.status_code in (401, 403)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env["app"]), base_url="http://unit.test"
    ) as client:
        query = await client.post(
            _BASE + "/acquire?token=" + env["jwt"], json={"replica_id": "replica-a"}
        )
    assert query.status_code in (401, 403)
    assert not env["pg"].rows


@pytest.mark.asyncio
async def test_api_duplicate_bearer_header_fails_before_subscriber_insert(
    env: Dict[str, Any],
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=env["app"]), base_url="http://unit.test"
    ) as client:
        response = await client.post(
            _BASE + "/acquire",
            json={"replica_id": "replica-one"},
            headers=[
                ("Authorization", "Bearer " + env["jwt"]),
                ("Authorization", "Bearer " + env["other"]),
            ],
        )
    assert response.status_code in (401, 403)
    assert not env["pg"].rows
