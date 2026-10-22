"""Mounted owner-facing 0033 SUSPECTS; no Docker, PG or action side effects."""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from ai_osop.api.routers import native_mcp_supervision as module

FLOW = "flow-current-test"
ENG = "eng-current-test"
TOKEN = "signed-disposable-operator"
BASE = f"/flows/{FLOW}/native-mcp-supervision/suspects"
QUERY = (
    "?expected_engagement_id=eng-current-test&expected_revision=4&expected_authorization_version=7"
)


def candidate() -> dict:
    return {
        "grant_id": "ngr-" + "1" * 32,
        "request_id": "req-" + "2" * 48,
        "worker_id": "worker-isolated-source",
        "epoch": 53,
        "revision": 2,
        "state": "unknown",
        "grant_status": "unknown",
        "age_since_last_signed_transition_seconds": 340,
        "classification": "pending_independent_recovery",
        "container_destroyed_verified": False,
        "execution_replay_authorized": False,
    }


def source(*items: dict) -> dict:
    return {
        "source": "durable_0033_last_transition_not_heartbeat",
        "candidates": list(items),
        "independent_process_liveness_verified": False,
        "automatic_reaping_enabled": False,
    }


@pytest.fixture
def setup(monkeypatch):
    actor = {
        "sub": "owner-verified",
        "role": "operator",
        "token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest(),
        "claims": {"exp": 9999999999},
    }
    app = FastAPI()
    app.include_router(module.router)

    async def get_operator():
        return actor

    app.dependency_overrides[module._operator] = get_operator
    authority = AsyncMock(return_value=None)
    service = SimpleNamespace(store=object(), _authority=authority)
    monkeypatch.setattr(module, "_executor", lambda: service)
    monkeypatch.setattr(module, "NativeMCPWorkerSupervisionStore", lambda store: store)
    observed = source(candidate())
    reads = []

    class Reconciler:
        def __init__(self, store):
            assert store is service.store

        async def suspects(self, binding, owner_id, **kwargs):
            reads.append((copy.deepcopy(binding), owner_id, kwargs))
            return copy.deepcopy(observed)

    monkeypatch.setattr(module, "NativeMCPSupervisorReconciler", Reconciler)
    return SimpleNamespace(
        app=app,
        actor=actor,
        authority=authority,
        service=service,
        observed=observed,
        reads=reads,
    )


async def query(setup, path=BASE + QUERY, *, headers=None):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=setup.app),
        base_url="http://test",
    ) as client:
        return await client.get(path, headers=headers or {"Authorization": "Bearer " + TOKEN})


@pytest.mark.asyncio
async def test_owner_get_is_bounded_inert_and_has_no_private_identity(setup):
    result = await query(setup)
    assert result.status_code == 200
    assert result.headers["cache-control"] == "private, no-store"
    assert result.headers["x-content-type-options"] == "nosniff"
    body = result.json()
    assert body == {
        "source": "durable_0033_last_transition_not_heartbeat",
        "classification": "READ_ONLY_SUSPECT_UNVERIFIED",
        "count": 1,
        "candidates": [
            {
                "ordinal": 1,
                "state": "unknown",
                "grant_status": "unknown",
                "age_since_last_signed_transition_seconds": 340,
                "classification": "pending_independent_recovery",
                "container_destroyed_verified": False,
                "execution_replay_authorized": False,
            }
        ],
        "independent_process_liveness_verified": False,
        "automatic_reaping_enabled": False,
        "worker_state_mutated": False,
        "independent_target_effect_verified": False,
    }
    for private in (
        "ngr-",
        "req-",
        "worker-isolated",
        "container_id",
        "sha256",
        "network_id",
        "file_path",
        "nonce",
        "signature",
        "epoch",
    ):
        assert private not in result.text
    assert setup.authority.await_count == 2
    expected, owner, options = setup.reads[0]
    assert expected == {
        "flow_id": FLOW,
        "engagement_id": ENG,
        "revision": 4,
        "version": 7,
    }
    assert owner == "owner-verified" and options == {
        "minimum_age_seconds": 60,
        "limit": 20,
    }


@pytest.mark.asyncio
async def test_explicit_bounds_are_forwarded_without_docker_or_writes(setup):
    result = await query(setup, BASE + QUERY + "&minimum_age_seconds=300&limit=3")
    assert result.status_code == 200
    assert setup.reads[0][2] == {"minimum_age_seconds": 300, "limit": 3}
    assert result.json()["worker_state_mutated"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        "&limit=0",
        "&limit=33",
        "&minimum_age_seconds=59",
        "&minimum_age_seconds=86401",
        "&expected_revision=-1",
        "&expected_authorization_version=0",
    ],
)
async def test_bad_bounds_denied_before_authority_and_reconciler(setup, extra):
    response = await query(setup, BASE + QUERY + extra)
    assert response.status_code == 422
    assert not setup.reads
    assert setup.authority.await_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        "&expected_engagement_id=eng-foreign",
        "&expected_revision=9",
        "&minimum_age_seconds=60&minimum_age_seconds=120",
        "&grant_id=ngr-" + "f" * 32,
        "&token=private",
    ],
)
async def test_reject_ambiguous_or_private_query_before_any_source_read(setup, extra):
    response = await query(setup, BASE + QUERY + extra)
    assert response.status_code == 422
    assert setup.authority.await_count == 0
    assert not setup.reads


@pytest.mark.asyncio
async def test_missing_or_unbound_bearer_does_not_read_source(setup):
    response = await query(setup, headers={"Authorization": "Bearer forged"})
    assert response.status_code == 403
    assert not setup.reads


@pytest.mark.asyncio
async def test_revoked_authority_at_first_check_or_after_db_read_is_denied(setup):
    setup.authority.side_effect = HTTPException(403, "revoked")
    response = await query(setup)
    assert response.status_code == 403
    assert not setup.reads
    setup.authority.reset_mock(side_effect=True)
    setup.authority.side_effect = [None, RuntimeError("revoked mid-read")]
    response = await query(setup)
    assert response.status_code == 503
    assert len(setup.reads) == 1
    assert "owner-verified" not in response.text


@pytest.mark.asyncio
async def test_post_auth_owner_identity_change_denies_readback(setup):
    async def mutating(*args, **kwargs):
        setup.actor["sub"] = "foreign-owner"
        return source(candidate())

    setup_reads = setup.reads
    setup_reads.clear()
    # Swap injected Reconciler class with the same type but changed source
    # via the module's override, without changing any authenticated source.
    old = module.NativeMCPSupervisorReconciler

    class Mutating(old):
        async def suspects(self, binding, owner_id, **kwargs):
            setup_reads.append((binding, owner_id, kwargs))
            return await mutating()

    module.NativeMCPSupervisorReconciler = Mutating
    try:
        response = await query(setup)
        assert response.status_code == 503
        assert setup.authority.await_count == 2
    finally:
        module.NativeMCPSupervisorReconciler = old


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "added_secret",
        "claimed_cleanup",
        "claimed_live",
        "wrong_class",
        "wrong_state",
        "unexpected_count",
        "malformed_revision",
        "duplicate_identity",
    ],
)
async def test_source_forgery_never_reaches_public_payload(setup, tamper):
    item = candidate()
    if tamper == "added_secret":
        item["private_key"] = "leak"
    elif tamper == "claimed_cleanup":
        item["container_destroyed_verified"] = True
    elif tamper == "claimed_live":
        setup.observed["independent_process_liveness_verified"] = True
    elif tamper == "wrong_class":
        item["classification"] = "verified_orphan"
    elif tamper == "wrong_state":
        item["state"] = "reaped"
    elif tamper == "unexpected_count":
        setup.observed["candidates"] = [item] * 33
    elif tamper == "malformed_revision":
        item["revision"] = True
    elif tamper == "duplicate_identity":
        setup.observed["extra"] = "secret"
    if tamper not in {"claimed_live", "unexpected_count", "duplicate_identity"}:
        setup.observed["candidates"] = [item]
    response = await query(setup)
    assert response.status_code == 503
    assert "leak" not in response.text
    assert "ngr-" not in response.text
