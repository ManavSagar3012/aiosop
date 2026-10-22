"""Qualification of seven routes on actual ai_osop.api.main.app, NOT a new FastAPI app.

Real: main router registration, middleware, local HS256 JWT signature/expiry,
supervision._access invocation, worker42's durable subscriber store SQL/CAS,
Pydantic request validation, and independent ASGI HTTP request handling.

Synthetic: owned in-process transactional PostgreSQL SQL model (borrowed from
the earlier unit fixture), signed ROE result, persisted supervisor ownership,
token/subject revocation rows, and tenant events. No PostgreSQL process or
0040 migration, application lifespan/DB, network, targets, or providers.

The unpatched main AuditLogMiddleware is also independently exercised as an
expected-failure until its actual production implementation is corrected.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import timedelta
from types import SimpleNamespace
from typing import Any, Dict, Optional

import httpx
import pytest
from fastapi import HTTPException
from jose import jwt

from ai_osop.api import deps, main
from ai_osop.api.routers import durable_supervision_subscriptions as api
from ai_osop.api.routers import supervision
from ai_osop.api.routers.durable_supervision_subscriptions import _memory as _real_memory
from ai_osop.memory import authorization_store
from tests.test_durable_supervision_subscriptions_api_20261021 import (
    FakePG,
    FakeSession,
    Memory,
)

_K = "mounted-asgi-local-hs256-qualification-key-only"
_SUB = "subscr-" + "a" * 32
_SUB_B = "subscr-" + "b" * 32
_BASE = "/supervision/engagements/eng-a/subscriptions/"
_SHA = "a" * 64
_OPS = frozenset({"acquire", "renew", "read", "ack", "cursor-readback", "release", "revoke"})


def _jwt(subject: str, role: str = "operator", *, exp_seconds: int = 3600, secret: str = _K) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": subject, "role": role, "exp": now + exp_seconds, "iat": now, "iss": "local-jwt"},
        secret,
        algorithm="HS256",
    )


class _LocalAuditLogger:
    """Test-only probe around unrelated stdlib logger kwarg incompatibility."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def info(self, label: str, **kwargs: Any) -> None:
        self.records.append({"label": label, **kwargs})


class _SupervisorAccess:
    """Explicit synthetic ownership store, used by REAL supervision._access."""

    def __init__(self, pg: FakePG) -> None:
        self.pg = pg
        self.calls: list[tuple[str, str, str, Optional[str]]] = []

    async def assert_access(
        self, engagement_id: str, actor: str, role: str, task_id: Optional[str]
    ) -> None:
        self.calls.append((engagement_id, actor, role, task_id))
        if (
            engagement_id not in self.pg.owners
            or (role != "senior_operator" and self.pg.owners[engagement_id] != actor)
            or (task_id is not None and (engagement_id, task_id) not in self.pg.tasks)
        ):
            raise supervision.SupervisionConflict("Persisted ownership denied")


@pytest.fixture
def mounted(monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
    pg = FakePG()
    memory = Memory(pg)
    keeper = _SupervisorAccess(pg)
    audit = _LocalAuditLogger()
    # no main.app re-construction or duplicate include_router; the imported
    # production main.app stack is used, with its unrelated audit logging
    # compatibility seam clearly isolated in this synthetic qualification.
    monkeypatch.setattr(main, "logger", audit)
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(
            environment="testing",
            jwt_secret=_K,
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
    # _context invokes real supervisor._access, not a fake replacement.
    monkeypatch.setattr(api, "_memory", lambda: memory)
    monkeypatch.setattr(supervision, "_supervision", lambda: keeper)

    async def _engagement(operator: Dict[str, Any], engagement: str) -> object:
        if engagement not in pg.owners:
            raise HTTPException(status_code=404, detail="Engagement absent")
        if operator["role"] != "senior_operator" and pg.owners[engagement] != operator["sub"]:
            raise HTTPException(status_code=403, detail="Foreign engagement")
        return object()

    monkeypatch.setattr(supervision, "assert_engagement_access", _engagement)

    async def _signed_roe(
        _session: Any,
        engagement: str,
        expected_version: Optional[int] = None,
        expected_digest: Optional[str] = None,
    ) -> Any:
        if (
            engagement not in pg.owners
            or not pg.guard_live
            or expected_version not in (None, 4)
            or expected_digest not in (None, _SHA)
        ):
            # Real authorization_store.guard_sql raises on invalid ROE.
            # Never invent a new policy or continue on an inactive approval.
            raise PermissionError("Signed current authorization revoked")
        return SimpleNamespace(version=4, policy_sha256=_SHA)

    monkeypatch.setattr(api, "guard_sql", _signed_roe)
    monkeypatch.setattr(authorization_store, "guard_sql", _signed_roe)
    assert api._supervisor_access is supervision._access
    return {
        "pg": pg,
        "memory": memory,
        "keeper": keeper,
        "audit": audit,
        "owner": _jwt("operator-a"),
        "other": _jwt("operator-b"),
        "senior": _jwt("operator-b", "senior_operator"),
        "viewer": _jwt("operator-a", "viewer"),
    }


def _path(action: str, sub: str = _SUB, eng: str = "eng-a") -> str:
    assert action in _OPS
    return f"/supervision/engagements/{eng}/subscriptions/{sub}/{action}"


async def _request(
    env: Dict[str, Any],
    action: str,
    body: Dict[str, Any],
    *,
    token: Optional[str] = None,
    sub: str = _SUB,
    eng: str = "eng-a",
) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False),
        base_url="http://main-app.invalid",
        timeout=5,
    ) as client:
        return await client.post(
            _path(action, sub, eng),
            json=body,
            headers={"Authorization": "Bearer " + (token or env["owner"])},
        )


def _lease(lease: Dict[str, Any], *, task: Optional[str] = "task-a") -> Dict[str, Any]:
    return {
        "replica_id": lease["replica_id"],
        "lease_id": lease["lease_id"],
        "generation": lease["generation"],
        "cursor": lease["cursor"],
        "task_id": task,
    }


def test_registered_production_paths_have_single_actual_endpoint() -> None:
    targets = {
        item.path: item
        for item in main.app.routes
        if item.path.startswith("/supervision/engagements/") and "/subscriptions/" in item.path
        and item.endpoint.__module__ == api.__name__
    }
    assert set(targets) == {_path(action, "{subscriber_id}", "{engagement_id}") for action in _OPS}
    from fastapi.routing import APIRoute

    for action in _OPS:
        route = targets[_path(action, "{subscriber_id}", "{engagement_id}")]
        assert isinstance(route, APIRoute)
        assert route.methods == {"POST"}
        route_method = {
            "ack": "acknowledge",
            "cursor-readback": "readback_subscriber_cursor",
        }.get(action, action)
        assert route.endpoint is getattr(api, route_method)
        assert route.response_model is not None


@pytest.mark.asyncio
async def test_registered_main_app_accepts_signed_owner_and_fences_ack(
    mounted: Dict[str, Any]
) -> None:
    acquired = await _request(
        mounted, "acquire", {"replica_id": "replica-first", "task_id": "task-a"}
    )
    assert acquired.status_code == 200, acquired.text[:200]
    lease = acquired.json()["lease"]
    assert lease["engagement_id"] == "eng-a" and lease["subscriber_id"] == _SUB
    assert acquired.headers["cache-control"] == "private, no-store"
    assert acquired.headers["x-content-type-options"] == "nosniff"
    assert lease["delivery_semantics"] == "at_least_once"
    assert lease["provider_effect"] == "unobserved"
    assert mounted["keeper"].calls[0] == ("eng-a", "operator-a", "operator", "task-a")
    got = await _request(mounted, "read", {**_lease(lease), "limit": 10})
    assert got.status_code == 200, got.text[:200]
    assert [item["sequence"] for item in got.json()["events"]] == [12, 18]
    assert got.json()["acknowledged"] is False
    skip = await _request(
        mounted, "ack", {**_lease(lease), "expected_cursor": 0, "next_sequence": 18}
    )
    assert skip.status_code == 409
    first = await _request(
        mounted, "ack", {**_lease(lease), "expected_cursor": 0, "next_sequence": 12}
    )
    assert first.status_code == 200, first.text[:200]
    next_lease = first.json()["lease"]
    assert next_lease["cursor"] == 12
    stale = await _request(
        mounted, "ack", {**_lease(lease), "expected_cursor": 0, "next_sequence": 12}
    )
    assert stale.status_code == 409
    assert mounted["pg"].rows[("eng-a", _SUB)]["cursor_sequence"] == 12
    assert mounted["audit"].records and all(
        row["label"] == "api_audit" for row in mounted["audit"].records
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant,expected",
    [
        ("other-tenant", 403),
        ("other-task", 403),
        ("viewer", 403),
        ("wrong-secret", 401),
        ("expired", 401),
    ],
)
async def test_signed_actor_and_task_tenant_bound_at_mounted_route(
    mounted: Dict[str, Any], variant: str, expected: int
) -> None:
    token = {
        "other-tenant": mounted["other"],
        "other-task": mounted["owner"],
        "viewer": mounted["viewer"],
        "wrong-secret": _jwt("operator-a", secret="wrong"),
        "expired": _jwt("operator-a", exp_seconds=-3),
    }[variant]
    task = "task-b" if variant == "other-task" else "task-a"
    result = await _request(
        mounted,
        "acquire",
        {"replica_id": "replica-first", "task_id": task},
        token=token,
    )
    assert result.status_code == expected, (variant, result.status_code, result.text[:200])
    assert not mounted["pg"].rows


@pytest.mark.asyncio
async def test_signed_senior_global_access_does_not_bypass_task_roe(
    mounted: Dict[str, Any]
) -> None:
    senior = await _request(
        mounted,
        "acquire",
        {"replica_id": "replica-senior", "task_id": "task-a"},
        token=mounted["senior"],
        sub=_SUB_B,
    )
    assert senior.status_code == 200, senior.text[:200]
    assert mounted["pg"].rows[("eng-a", _SUB_B)]["subject"] == "operator-b"
    assert ("eng-a", "operator-b", "senior_operator", "task-a") in mounted["keeper"].calls
    wrong = await _request(
        mounted,
        "acquire",
        {"replica_id": "replica-senior", "task_id": "task-b"},
        token=mounted["senior"],
    )
    assert wrong.status_code == 403


@pytest.mark.asyncio
async def test_current_signed_roe_and_task_revision_revocation_denies_cursor(
    mounted: Dict[str, Any]
) -> None:
    first = await _request(mounted, "acquire", {"replica_id": "replica-a", "task_id": "task-a"})
    assert first.status_code == 200
    current = _lease(first.json()["lease"])
    mounted["pg"].guard_live = False
    revoked = await _request(mounted, "ack", {**current, "expected_cursor": 0, "next_sequence": 12})
    assert revoked.status_code in (403, 409), revoked.text[:200]
    mounted["pg"].guard_live = True
    mounted["pg"].task_version = 5
    altered = await _request(mounted, "ack", {**current, "expected_cursor": 0, "next_sequence": 12})
    assert altered.status_code == 409, altered.text[:200]
    assert mounted["pg"].rows[("eng-a", _SUB)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_real_signed_bearer_subject_revocation_and_token_digest(
    mounted: Dict[str, Any]
) -> None:
    acquired = await _request(mounted, "acquire", {"replica_id": "replica-a"})
    assert acquired.status_code == 200
    lease = _lease(acquired.json()["lease"], task=None)
    mounted["pg"].revoked.add(hashlib.sha256(mounted["owner"].encode()).hexdigest())
    assert (await _request(mounted, "renew", lease)).status_code == 409
    mounted["pg"].revoked.clear()
    mounted["pg"].disabled.add("operator-a")
    assert (await _request(mounted, "release", lease)).status_code == 409
    mounted["pg"].disabled.clear()
    assert mounted["pg"].rows[("eng-a", _SUB)]["lease_id"] == lease["lease_id"]


@pytest.mark.asyncio
async def test_multireplica_fencing_release_recover_and_revocation(mounted: Dict[str, Any]) -> None:
    first, second = await asyncio.gather(
        _request(mounted, "acquire", {"replica_id": "replica-a"}),
        _request(mounted, "acquire", {"replica_id": "replica-b"}),
    )
    assert sorted([first.status_code, second.status_code]) == [200, 409]
    winning = first if first.status_code == 200 else second
    lease = _lease(winning.json()["lease"], task=None)
    assert (
        await _request(mounted, "renew", {**lease, "replica_id": "replica-rogue"})
    ).status_code == 409
    assert (
        await _request(mounted, "read", {**lease, "generation": lease["generation"] + 1})
    ).status_code == 409
    mounted["pg"].now += timedelta(seconds=31)
    assert (
        await _request(mounted, "ack", {**lease, "expected_cursor": 0, "next_sequence": 12})
    ).status_code == 409
    recovery = await _request(mounted, "acquire", {"replica_id": "replica-recovery"})
    assert recovery.status_code == 200
    subsequent = recovery.json()["lease"]
    assert subsequent["generation"] > lease["generation"]
    assert subsequent["lease_id"] != lease["lease_id"]
    assert (await _request(mounted, "release", lease)).status_code == 409
    revoked = await _request(mounted, "revoke", {})
    assert revoked.status_code == 200
    assert (await _request(mounted, "renew", _lease(subsequent, task=None))).status_code == 409
    assert (await _request(mounted, "acquire", {"replica_id": "replica-new"})).status_code == 409


@pytest.mark.asyncio
async def test_mounted_renew_release_and_reacquire_preserve_committed_cursor(
    mounted: Dict[str, Any]
) -> None:
    initial = await _request(
        mounted, "acquire", {"replica_id": "replica-first", "task_id": "task-a"}
    )
    assert initial.status_code == 200
    lease = initial.json()["lease"]
    renewed = await _request(mounted, "renew", {**_lease(lease), "lease_seconds": 15})
    assert renewed.status_code == 200, renewed.text[:200]
    active = renewed.json()["lease"]
    assert active["lease_id"] == lease["lease_id"]
    ack_one = await _request(
        mounted, "ack", {**_lease(active), "expected_cursor": 0, "next_sequence": 12}
    )
    assert ack_one.status_code == 200
    ack_two = await _request(
        mounted,
        "ack",
        {**_lease(ack_one.json()["lease"]), "expected_cursor": 12, "next_sequence": 18},
    )
    assert ack_two.status_code == 200
    final_lease = ack_two.json()["lease"]
    assert final_lease["cursor"] == 18
    given_up = await _request(mounted, "release", _lease(final_lease))
    assert given_up.status_code == 200, given_up.text[:200]
    replacement = await _request(
        mounted, "acquire", {"replica_id": "replica-restarted", "task_id": "task-a"}
    )
    assert replacement.status_code == 200
    recovered = replacement.json()["lease"]
    assert recovered["cursor"] == 18
    assert recovered["generation"] > final_lease["generation"]
    assert recovered["lease_id"] != final_lease["lease_id"]
    empty = await _request(mounted, "read", _lease(recovered))
    assert empty.status_code == 200
    assert empty.json()["events"] == []
    assert mounted["pg"].rows[("eng-a", _SUB)]["cursor_sequence"] == 18


@pytest.mark.asyncio
async def test_main_mounted_body_is_strict_and_does_not_mint_roe(mounted: Dict[str, Any]) -> None:
    for body in (
        {"replica_id": "replica-one", "role": "senior_operator"},
        {"replica_id": "replica-one", "authorization_sha256": _SHA},
        {"replica_id": "replica-one", "task_id": "task-" + "a" * 60},
        {"replica_id": "replica-one", "lease_seconds": True},
        {"replica_id": "../../replay"},
    ):
        denied = await _request(mounted, "acquire", body)
        assert denied.status_code == 422, (body, denied.status_code, denied.text[:100])
    assert mounted["pg"].rows == {}


@pytest.mark.asyncio
async def test_mount_rejects_unknown_unregistered_verb(mounted: Dict[str, Any]) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False),
        base_url="http://main-app.invalid",
    ) as client:
        result = await client.get(
            _path("ack"), headers={"Authorization": "Bearer " + mounted["owner"]}
        )
    assert result.status_code == 405


@pytest.mark.asyncio
async def test_unmodified_main_audit_middleware_returns_credential_denial_not_500() -> None:
    """Regression: actual main audit logging must not mask a bearer denial."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main.app, raise_app_exceptions=False),
        base_url="http://main-app.invalid",
    ) as client:
        denied = await client.post(_path("acquire"), json={"replica_id": "replica-one"})
    assert denied.status_code in (401, 403), denied.status_code


@pytest.mark.asyncio
async def test_signing_issuer_rebind_does_not_take_existing_subscription(
    mounted: Dict[str, Any]
) -> None:
    acquired = await _request(mounted, "acquire", {"replica_id": "replica-a", "task_id": "task-a"})
    assert acquired.status_code == 200
    lease = _lease(acquired.json()["lease"])
    now = int(time.time())
    other_issuer = jwt.encode(
        {
            "sub": "operator-a",
            "role": "operator",
            "exp": now + 3600,
            "iat": now,
            "iss": "different-signed-local-issuer",
        },
        _K,
        algorithm="HS256",
    )
    attempted = await _request(mounted, "read", lease, token=other_issuer)
    assert attempted.status_code == 409, attempted.text[:200]
    assert mounted["pg"].rows[("eng-a", _SUB)]["issuer"] == "local-jwt"


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["token_revoked", "roe_revoked"])
async def test_revocation_during_cursor_write_rolls_back_transaction(
    mounted: Dict[str, Any], monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """Synthetic race: revoke AFTER SQL UPDATE but BEFORE PG transaction commit.

    The store's independent post-write guard must roll back the CAS mutation.
    No production revocation writer or real PG locks are simulated here.
    """
    acquired = await _request(
        mounted, "acquire", {"replica_id": "replica-owner", "task_id": "task-a"}
    )
    assert acquired.status_code == 200
    lease = _lease(acquired.json()["lease"])
    pg = mounted["pg"]
    digest = hashlib.sha256(mounted["owner"].encode("utf-8")).hexdigest()
    changed = {"count": 0}

    class _RevokingSession(FakeSession):
        async def execute(self, query: Any, params: Optional[dict[str, Any]] = None) -> Any:
            result = await super().execute(query, params)
            if str(query).startswith(
                "UPDATE supervision_durable_subscriptions SET cursor_sequence=:next"
            ):
                changed["count"] += 1
                if change == "token_revoked":
                    pg.revoked.add(digest)
                else:
                    pg.guard_live = False
            return result

    monkeypatch.setattr(mounted["memory"], "_async_session", lambda: _RevokingSession(pg))
    denied = await _request(mounted, "ack", {**lease, "expected_cursor": 0, "next_sequence": 12})
    assert denied.status_code == 409, denied.text[:200]
    assert changed["count"] == 1
    assert pg.rows[("eng-a", _SUB)]["cursor_sequence"] == 0


@pytest.mark.asyncio
async def test_mounted_missing_storage_fails_closed_before_lease_write(
    mounted: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api, "_memory", _real_memory)
    monkeypatch.setitem(deps.state, "orchestrator", None)
    denied = await _request(mounted, "acquire", {"replica_id": "replica-a"})
    assert denied.status_code == 503, denied.text[:200]
    assert not mounted["pg"].rows
