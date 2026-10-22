"""Mounted service-only signed supervision, with no execution endpoint."""

from types import SimpleNamespace

import httpx
import pytest

from ai_osop.api.deps import state
from ai_osop.api.main import app
from ai_osop.api.routers import native_mcp_supervision as api
from ai_osop.api.routers.flow_mcp_actions import _operator

_ROUTE = "/native-supervisor/observe"
_SUPERVISOR = "independent-container-observer"
_SECRET = "independent-native-worker-supervisor-test-secret"


def _payload():
    return {
        "grant": {"claims": {}, "kid": "issuer", "signature": "untrusted"},
        "observation": {"claims": {}, "kid": "observer", "signature": "untrusted"},
    }


@pytest.mark.asyncio
async def test_anonymous_and_query_credentials_never_enter_supervisor_store(monkeypatch):
    class Never:
        def __init__(self, *_):
            raise AssertionError("Unauthenticated request entered database store")

    monkeypatch.setattr(api, "NativeMCPWorkerSupervisionStore", Never)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://localhost"
    ) as client:
        assert (await client.post(_ROUTE, json=_payload())).status_code == 401
        assert (
            await client.post(
                _ROUTE + "?token=stolen",
                json=_payload(),
                headers={
                    "X-OSOP-Supervisor-ID": _SUPERVISOR,
                    "Authorization": "Bearer " + _SECRET,
                },
            )
        ).status_code == 403


@pytest.mark.asyncio
async def test_strict_supervisor_ingress_mount_stream_body_and_unknown_ack(monkeypatch):
    previous = state.get("orchestrator")
    memory = object()
    registry = object()
    state["orchestrator"] = SimpleNamespace(session_memory=memory, mcp_registry=registry)
    observed = []

    class Store:
        def __init__(self, actions):
            observed.append("initialized")

        async def record(self, grant, observation, *, supervisor_id, supervisor_secret):
            assert grant == _payload()["grant"]
            assert observation == _payload()["observation"]
            assert supervisor_id == _SUPERVISOR
            assert supervisor_secret == _SECRET
            observed.append("recorded")
            return {
                "grant_id": "ngr-" + "1" * 32,
                "worker_id": "worker-qualification",
                "epoch": 1,
                "revision": 1,
                "state": "provisioned",
                "supervisor_observed": True,
                "independent_target_effect_verified": False,
                "original_action_status": "unknown",
            }

    monkeypatch.setattr(api, "NativeMCPWorkerSupervisionStore", Store)
    monkeypatch.setattr(api, "FlowMCPActionStore", lambda memory, registry: (memory, registry))
    headers = {
        "Authorization": "Bearer " + _SECRET,
        "X-OSOP-Supervisor-ID": _SUPERVISOR,
        "Content-Type": "application/json",
    }
    try:
        assert len([r for r in app.routes if r.path == _ROUTE and "POST" in r.methods]) == 1
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://localhost"
        ) as client:
            accepted = await client.post(_ROUTE, json=_payload(), headers=headers)
            assert accepted.status_code == 200
            assert accepted.json()["independent_target_effect_verified"] is False
            assert accepted.headers["Cache-Control"] == "private, no-store"
            assert observed == ["initialized", "recorded"]
            oversized = await client.post(_ROUTE, content=b"X" * 8193, headers=headers)
            assert oversized.status_code == 413
            ambiguous = await client.post(
                _ROUTE,
                content=b'{"grant":{},"grant":{},"observation":{}}',
                headers=headers,
            )
            assert ambiguous.status_code == 422
            assert observed == ["initialized", "recorded"]
            monkeypatch.setattr(
                api,
                "NativeMCPWorkerSupervisionStore",
                lambda *_: (_ for _ in ()).throw(RuntimeError("private-storage-secret")),
            )
            unknown = await client.post(_ROUTE, json=_payload(), headers=headers)
            assert unknown.status_code == 409
            assert "private-storage-secret" not in unknown.text
    finally:
        if previous is None:
            state.pop("orchestrator", None)
        else:
            state["orchestrator"] = previous


@pytest.mark.asyncio
async def test_operator_recovery_only_persists_signed_metadata_not_worker_execution(monkeypatch):
    from unittest.mock import AsyncMock

    grant_id = "ngr-" + "a" * 32
    route = "/flows/flow-native-ledger/native-mcp-supervision/recovery"
    observed = []
    authority = AsyncMock()
    service = SimpleNamespace(_authority=authority, store=object())
    monkeypatch.setattr(api, "_executor", lambda: service)

    class Store:
        def __init__(self, action_store):
            assert action_store is service.store

        async def request_recovery(
            self, binding, actor, grant, revision, *, explicit_human_confirmation
        ):
            observed.append((binding, actor, grant, revision, explicit_human_confirmation))
            return {
                "grant_id": grant,
                "supervisor_revision": revision,
                "recovery_intent_recorded": True,
                "worker_execution_replayed": False,
                "independent_target_effect_verified": False,
            }

    monkeypatch.setattr(api, "NativeMCPWorkerSupervisionStore", Store)
    app.dependency_overrides[_operator] = lambda: {
        "sub": "operator-owner",
        "role": "operator",
        "claims": {"exp": 2000000000},
    }
    body = {
        "expected_engagement_id": "eng-native-ledger",
        "expected_revision": 3,
        "expected_authorization_version": 7,
        "explicit_human_confirmation": True,
        "grant_id": grant_id,
        "expected_supervisor_revision": 4,
    }
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://localhost"
        ) as client:
            response = await client.post(route, json=body)
            assert response.status_code == 200, response.text
            assert response.json() == {
                "grant_id": grant_id,
                "supervisor_revision": 4,
                "recovery_intent_recorded": True,
                "worker_execution_replayed": False,
                "independent_target_effect_verified": False,
            }
            assert authority.await_count == 2
            assert len(observed) == 1
            assert observed[0][1:] == ("operator-owner", grant_id, 4, True)
            assert response.headers["Cache-Control"] == "private, no-store"
            refused = await client.post(route, json={**body, "explicit_human_confirmation": False})
            assert refused.status_code == 422
            malicious = await client.post(route, json={**body, "grant_id": "../../foreign"})
            assert malicious.status_code == 422
            assert len(observed) == 1
    finally:
        app.dependency_overrides.pop(_operator, None)
