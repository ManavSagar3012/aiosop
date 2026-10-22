"""Senior operator signed admission explanation; no provider or application DB."""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI, HTTPException

from ai_osop.api.routers import provider_invoices
from ai_osop.memory.authorization_store import AuthorizationDenied, VerifiedAuthorization


class Session:
    def __init__(self, owner="owner", roe=None, phase="running"):
        self.owner = owner
        self.roe = roe if roe is not None else {
            "llm_call_budget_total": 4,
            "llm_cost_budget_usd": 5.0,
            "llm_precharge_max_call_usd": 1.0,
        }
        self.phase = phase

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    @asynccontextmanager
    async def begin(self):
        yield

    async def execute(self, statement):
        sql = str(statement)
        assert "FROM session_states" in sql
        assert "FOR UPDATE" in sql or "FOR SHARE" in sql
        return SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(
            created_by=self.owner, roe=self.roe, phase=self.phase,
        ))


class Ledger:
    def __init__(self, session=None, summary=None):
        self.session = session or Session()
        self.summary = AsyncMock(return_value=summary or {
            "engagement_id": "eng-1", "calls": 1, "unknown_calls": 0,
            "unpriced_calls": 0, "unreconciled_cost_calls": 0,
            "outstanding_precharge_usd": "0.00000000",
            "invoice_adjusted_cost_usd": "0.50000000",
        })
        self.reserve = AsyncMock(side_effect=AssertionError("No model reservation from GET"))
        self.settle = AsyncMock(side_effect=AssertionError("No model settlement from GET"))

    def _sessions(self):
        return self.session


class Routes:
    version = 2

    def capability_report(self):
        return [{
            "provider": "openai", "model": "model-test",
            "operations": ["completion"], "allowed_roles": ["workflow"],
            "configured_capabilities": ["text_completion"],
            "deployment": "locally_configured", "credential_env": "MUST_NEVER_RETURN",
        }]


def api(ledger, *, owner_error=None, signed_error=None, configured=None):
    app = FastAPI()
    app.include_router(provider_invoices.router)
    app.dependency_overrides[provider_invoices._verified_senior] = lambda: {
        "sub": "owner", "role": "senior_operator"
    }
    owner = AsyncMock(side_effect=owner_error, return_value=ledger)
    verified = VerifiedAuthorization(
        session_id="eng-1", authorization_id="authorization-1", version=4,
        kid="kid-1", policy_sha256="0" * 64, policy={},
    )
    guard = AsyncMock(side_effect=signed_error, return_value=verified)
    return app, owner, guard, configured or Routes()


@pytest.mark.asyncio
async def test_mounted_route_explains_signed_budget_without_paid_calls():
    from ai_osop.api.main import app as production

    path = "/supervision/engagements/{engagement_id}/model-usage/provider-admission-explanation"
    assert any(route.path == path and "GET" in route.methods for route in production.routes)
    ledger = Ledger()
    app, owner, guard, routes = api(ledger)
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes),
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get(path.replace("{engagement_id}", "eng-1"))
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "requires_atomic_admission"
    assert result["signed_roe_current_at_read"] is True
    assert result["budget"]["recorded_calls"] == 1
    assert result["budget"]["signed_call_limit"] == 4
    assert result["budget"]["signed_cost_limit_usd"] == "5.0"
    assert result["budget"]["signed_max_precharge_usd"] == "1.0"
    assert result["routes"][0]["allowed_roles"] == ["workflow"]
    assert "credential_env" not in str(result)
    assert all(result[key] is False for key in (
        "admission_attempted", "execution_admitted", "provider_called",
        "reservation_created", "provider_native_cost_ceiling_verified",
    ))
    assert response.headers["cache-control"] == "private, no-store"
    owner.assert_awaited_once_with("eng-1", {"sub": "owner", "role": "senior_operator"})
    guard.assert_awaited_once()
    ledger.summary.assert_awaited_once_with("eng-1")
    ledger.reserve.assert_not_awaited()
    ledger.settle.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("overrides, expected", [
    ({"calls": 4}, "signed_call_quota_exhausted"),
    ({"unknown_calls": 1}, "unreconciled_provider_outcome"),
    ({"unpriced_calls": 1, "invoice_adjusted_cost_usd": None}, "cost_ledger_incomplete"),
    ({"invoice_adjusted_cost_usd": "4.50000000"}, "signed_cost_budget_exhausted"),
])
async def test_real_ledger_snapshot_produces_specific_budget_blocker(overrides, expected):
    ledger = Ledger()
    ledger.summary.return_value.update(overrides)
    app, owner, guard, routes = api(ledger)
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes),
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-1/model-usage/provider-admission-explanation")
    assert result.status_code == 200
    assert result.json()["status"] == "blocked"
    assert expected in result.json()["reasons"]
    ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoked_signed_key_yields_unknown_and_no_budget_or_provider_disclosure():
    ledger = Ledger()
    app, owner, guard, routes = api(ledger, signed_error=AuthorizationDenied("key-removed"))
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes) as configured,
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-1/model-usage/provider-admission-explanation")
    assert result.status_code == 200
    assert result.json()["status"] == "unavailable"
    assert result.json()["budget"] is None
    assert result.json()["routes"] == []
    assert result.json()["reasons"] == ["signed_authorization_unavailable"]
    configured.assert_not_called()
    ledger.summary.assert_not_awaited()


@pytest.mark.asyncio
async def test_foreign_tenant_rejected_before_signed_source_or_ledger_reads():
    ledger = Ledger()
    app, owner, guard, routes = api(ledger, owner_error=HTTPException(403, "Not owner"))
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes) as configured,
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-foreign/model-usage/provider-admission-explanation")
    assert result.status_code == 403
    guard.assert_not_awaited()
    configured.assert_not_called()
    ledger.summary.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_owner_changed_mid_read_denied_without_provider_catalog():
    ledger = Ledger(session=Session(owner="other-tenant-owner"))
    app, owner, guard, routes = api(ledger)
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes) as configured,
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-1/model-usage/provider-admission-explanation")
    assert result.status_code == 403
    configured.assert_not_called()
    ledger.summary.assert_not_awaited()


@pytest.mark.asyncio
async def test_unconfigured_local_provider_routes_are_blocked_without_auth_escalation():
    ledger = Ledger()
    app, owner, guard, _ = api(ledger)
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=None),
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-1/model-usage/provider-admission-explanation")
    assert result.status_code == 200
    assert result.json()["status"] == "blocked"
    assert result.json()["routes"] == []
    assert "provider_routes_not_configured" in result.json()["reasons"]
    assert "no_locally_configured_deployment" in result.json()["reasons"]
    ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_mismatched_signed_engagement_identity_fails_closed():
    ledger = Ledger()
    app, owner, guard, routes = api(ledger)
    guard.return_value = VerifiedAuthorization(
        session_id="eng-other", authorization_id="authorization-other", version=4,
        kid="kid-1", policy_sha256="0" * 64, policy={},
    )
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes) as configured,
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-1/model-usage/provider-admission-explanation")
    assert result.status_code == 200
    assert result.json()["status"] == "unavailable"
    assert result.json()["budget"] is None
    configured.assert_not_called()
    ledger.summary.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_or_foreign_model_ledger_returns_no_admission_claim():
    ledger = Ledger()
    ledger.summary.return_value["engagement_id"] = "eng-foreign"
    app, owner, guard, routes = api(ledger)
    with (
        patch.object(provider_invoices, "_owned_ledger", owner),
        patch.object(provider_invoices, "guard_sql", guard),
        patch("ai_osop.core.provider_routing.configured_routes", return_value=routes),
    ):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            result = await client.get("/supervision/engagements/eng-1/model-usage/provider-admission-explanation")
    assert result.status_code == 503
    assert "eng-foreign" not in result.text
    ledger.reserve.assert_not_awaited()
