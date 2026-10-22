"""Offline OpenAI Costs API integration and invoice trust boundary checks."""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai_osop.api.deps import state
from ai_osop.api.routers import provider_invoices
from ai_osop.memory import provider_invoice_trust as trust

PROJECT = "proj_ProviderBounded123"
KEY = "sk-admin-unit-test-key-never-send-to-network"
PATH = "/supervision/engagements/eng-1/model-usage/provider-costs/openai/observe"
RECONCILE = "/supervision/engagements/eng-1/model-usage/calls/call-1/invoice/reconcile"
HEADERS = {"Authorization": "Bearer verified-senior", "Content-Type": "application/json"}


def window():
    today = int(time.time()) // 86400 * 86400
    return {"start_time": today - 2 * 86400, "end_time": today}


def page(
    *,
    value=0.12345678,
    currency="usd",
    project=PROJECT,
    has_more=False,
    next_page=None,
    start=None,
    line_item="input_tokens",
):
    times = window()
    start = times["start_time"] if start is None else start
    return {
        "object": "page",
        "data": [
            {
                "object": "bucket",
                "start_time": start,
                "end_time": start + 86400,
                "results": [
                    {
                        "object": "organization.costs.result",
                        "project_id": project,
                        "line_item": line_item,
                        "amount": {"value": value, "currency": currency},
                    }
                ],
            }
        ],
        "has_more": has_more,
        "next_page": next_page,
    }


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_TRUST_MODE", "openai_costs")
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_PROJECT_ID", PROJECT)
    monkeypatch.setenv("OPENAI_ADMIN_KEY", KEY)


def install_transport(monkeypatch, handler):
    original = httpx.AsyncClient
    captured = []

    def factory(**kwargs):
        captured.append(kwargs)
        return original(
            transport=httpx.MockTransport(handler),
            timeout=kwargs["timeout"],
            follow_redirects=kwargs["follow_redirects"],
            trust_env=kwargs["trust_env"],
        )

    monkeypatch.setattr(trust.httpx, "AsyncClient", factory)
    return captured


@pytest.mark.asyncio
async def test_fixed_https_admin_origin_and_provider_project_costs(configured, monkeypatch):
    requested = []

    def handler(request):
        requested.append(request)
        assert request.method == "GET"
        assert (
            str(request.url.copy_with(query=None)) == "https://api.openai.com/v1/organization/costs"
        )
        assert request.headers["authorization"] == "Bearer " + KEY
        assert request.headers["accept-encoding"] == "identity"
        assert request.url.params.get_list("project_ids") == [PROJECT]
        assert request.url.params.get_list("group_by") == ["project_id", "line_item"]
        assert request.url.params["bucket_width"] == "1d"
        assert request.url.params["limit"] == "31"
        assert request.url.params["start_time"] == str(window()["start_time"])
        assert request.url.params["end_time"] == str(window()["end_time"])
        assert not request.content
        return httpx.Response(200, json=page())

    configs = install_transport(monkeypatch, handler)
    result = await trust.OpenAICostSource().observe(**window())
    assert len(requested) == 1
    assert configs[0]["trust_env"] is False
    assert configs[0]["follow_redirects"] is False
    assert result["provider_cost_usd"] == "0.12345678"
    assert result["source_authenticated"] is True
    assert result["individual_call_cost_verified"] is False
    assert result["ledger_mutated"] is False
    assert KEY not in str(result) and PROJECT not in str(result)
    assert result["buckets"] == 1 and result["cost_lines"] == 1


@pytest.mark.asyncio
async def test_valid_paginated_costs_aggregate_exactly_once(configured, monkeypatch):
    seen = []
    start = window()["start_time"]

    def handler(request):
        seen.append(request.url.params.get("page"))
        if len(seen) == 1:
            return httpx.Response(
                200,
                json=page(
                    value=0.11,
                    has_more=True,
                    next_page="cursor-safe-001",
                ),
            )
        assert request.url.params["page"] == "cursor-safe-001"
        return httpx.Response(200, json=page(value=0.22, start=start + 86400))

    install_transport(monkeypatch, handler)
    result = await trust.OpenAICostSource().observe(**window())
    assert seen == [None, "cursor-safe-001"]
    assert result["provider_cost_usd"] == "0.33"
    assert result["pages"] == 2
    assert result["buckets"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        {"currency": "eur"},
        {"project": "proj_OtherTenant"},
        {"value": -1},
        {"value": "0.1"},
        {"value": True},
        {"value": 1e12},
        {"value": 0.0000000000001},
        {"has_more": True, "next_page": None},
        {"has_more": False, "next_page": "should-not-exist"},
    ],
)
async def test_invalid_currency_scope_amount_or_pagination_fails_closed(
    configured,
    monkeypatch,
    mutation,
):
    install_transport(monkeypatch, lambda _request: httpx.Response(200, json=page(**mutation)))
    with pytest.raises(trust.ProviderCostInvalid):
        await trust.OpenAICostSource().observe(**window())


@pytest.mark.asyncio
async def test_repeated_cursor_rejected_without_partial_return(configured, monkeypatch):
    def handler(request):
        start = window()["start_time"]
        if request.url.params.get("page") is not None:
            start += 86400
        return httpx.Response(
            200,
            json=page(
                start=start,
                has_more=True,
                next_page="stuck",
            ),
        )

    install_transport(monkeypatch, handler)
    with pytest.raises(trust.ProviderCostInvalid, match="repeated"):
        await trust.OpenAICostSource().observe(**window())


@pytest.mark.asyncio
async def test_overlapping_bucket_pages_rejected(configured, monkeypatch):
    def handler(request):
        return httpx.Response(
            200,
            json=page(
                has_more=request.url.params.get("page") is None,
                next_page="next" if request.url.params.get("page") is None else None,
            ),
        )

    install_transport(monkeypatch, handler)
    with pytest.raises(trust.ProviderCostInvalid, match="Overlapping"):
        await trust.OpenAICostSource().observe(**window())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "https://evil.invalid/grab"}),
        httpx.Response(401, json={"error": "secret admin key leaked"}),
        httpx.Response(429, json={"error": "rate limited"}),
        httpx.Response(200, content=b"{}", headers={"Content-Type": "text/plain"}),
        httpx.Response(200, content=b"x" * (64 * 1024 + 1)),
        httpx.Response(200, content=b'{"object":"page","object":"duplicate"}'),
        httpx.Response(200, json={"object": "page", "data": [], "has_more": "false"}),
    ],
)
async def test_bad_http_responses_never_return_trusted_evidence(configured, monkeypatch, response):
    install_transport(monkeypatch, lambda _request: response)
    with pytest.raises((trust.ProviderCostUnavailable, trust.ProviderCostInvalid)):
        await trust.OpenAICostSource().observe(**window())


@pytest.mark.asyncio
async def test_provider_transport_failure_does_not_expose_admin_secret(configured, monkeypatch):
    def handler(_request):
        raise httpx.ConnectError("provider unreachable with secret " + KEY)

    install_transport(monkeypatch, handler)
    with pytest.raises(trust.ProviderCostUnavailable) as raised:
        await trust.OpenAICostSource().observe(**window())
    assert KEY not in str(raised.value)


@pytest.mark.asyncio
async def test_empty_cost_buckets_preserve_unknown_cost_instead_of_reporting_zero(
    configured,
    monkeypatch,
):
    install_transport(
        monkeypatch,
        lambda _request: httpx.Response(
            200,
            json={"object": "page", "data": [], "has_more": False, "next_page": None},
        ),
    )
    observed = await trust.OpenAICostSource().observe(**window())
    assert observed["provider_cost_usd"] is None
    assert observed["provider_cost_data_present"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "mode",
        "key",
        "project",
        "missing_key",
        "missing_project",
    ],
)
async def test_opt_in_configuration_failure_blocks_request(configured, monkeypatch, change):
    if change == "mode":
        monkeypatch.setenv("OSOP_PROVIDER_INVOICE_TRUST_MODE", "operator_only")
    elif change == "key":
        monkeypatch.setenv("OPENAI_ADMIN_KEY", "insecure")
    elif change == "project":
        monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_PROJECT_ID", "https://evil.invalid")
    elif change == "missing_key":
        monkeypatch.delenv("OPENAI_ADMIN_KEY")
    else:
        monkeypatch.delenv("OSOP_PROVIDER_INVOICE_OPENAI_PROJECT_ID")
    with pytest.raises(trust.ProviderCostUnavailable):
        await trust.OpenAICostSource().observe(**window())


@pytest.mark.parametrize(
    "times",
    [
        {"start_time": 0, "end_time": 0},
        {"start_time": 0, "end_time": 32 * 86400},
        {"start_time": 1728000001, "end_time": 1728086400},
        {"start_time": True, "end_time": 1728086400},
        {"start_time": -86400, "end_time": 0},
    ],
)
def test_invalid_or_oversized_reporting_windows(times):
    with pytest.raises(trust.ProviderCostInvalid):
        trust._range(**times)


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_ENGAGEMENT_ID", "eng-1")

    class OwnerDB:
        def __init__(self):
            self.owner = "senior-1"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def execute(self, _statement):
            return SimpleNamespace(scalar_one_or_none=lambda: self.owner)

    database = OwnerDB()
    memory = SimpleNamespace(_async_session=lambda: database)
    monkeypatch.setitem(state, "orchestrator", SimpleNamespace(session_memory=memory))
    ledger = SimpleNamespace(
        summary=AsyncMock(
            return_value={
                "provider_reported_cost_usd": None,
                "operator_attested_invoice_cost_usd": "1.25",
                "invoice_adjusted_cost_usd": None,
                "unreconciled_cost_calls": 2,
            }
        ),
        reconcile_provider_invoice=AsyncMock(return_value=True),
        adjust_provider_invoice=AsyncMock(return_value=True),
        audit_openai_cost_observation=AsyncMock(return_value=True),
    )
    factory = MagicMock(return_value=ledger)
    monkeypatch.setattr(provider_invoices, "ModelUsageLedger", factory)
    monkeypatch.setattr(provider_invoices, "settings", SimpleNamespace(jwt_secret="jwt-test"))
    identity = {
        "sub": "senior-1",
        "role": "senior_operator",
        "claims": {"exp": int(datetime.now(timezone.utc).timestamp()) + 3600},
    }
    verified = AsyncMock(return_value=identity)
    monkeypatch.setattr(provider_invoices, "verify_token", verified)
    source = SimpleNamespace(
        observe=AsyncMock(
            return_value={
                "source": "openai_organization_costs_api",
                "source_authenticated": True,
                "source_scope": "configured_openai_project",
                "project_sha256": hashlib.sha256(PROJECT.encode()).hexdigest(),
                **window(),
                "provider_cost_usd": "0.125",
                "provider_cost_data_present": True,
                "currency": "USD",
                "pages": 1,
                "buckets": 1,
                "cost_lines": 1,
                "individual_call_cost_verified": False,
                "provider_hard_cost_cap_verified": False,
                "ledger_mutated": False,
                "source_checked_at_utc": int(time.time()),
            }
        )
    )
    monkeypatch.setattr(provider_invoices, "OpenAICostSource", lambda: source)
    app = FastAPI()
    app.include_router(provider_invoices.router)
    return SimpleNamespace(
        client=TestClient(app),
        database=database,
        memory=memory,
        ledger=ledger,
        factory=factory,
        identity=identity,
        verified=verified,
        source=source,
    )


def test_provider_observation_requires_senior_owner_and_stays_read_only(api, configured):
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 200
    body = reply.json()
    assert body["provider_cost_usd"] == "0.125"
    assert body["source_authenticated"] is True
    assert body["provider_project_comparable_to_engagement"] is False
    assert body["local_ledger"]["operator_attested_invoice_cost_usd"] == "1.25"
    assert body["local_ledger"]["provider_reported_cost_usd"] is None
    assert body["local_ledger"]["unreconciled_cost_calls"] == 2
    assert body["execution_outcome"] == "unknown"
    assert body["ledger_mutated"] is False
    assert body["safe_to_retry"] is False
    api.source.observe.assert_awaited_once_with(**window())
    api.ledger.summary.assert_awaited_once_with("eng-1")
    api.ledger.reconcile_provider_invoice.assert_not_awaited()
    api.ledger.adjust_provider_invoice.assert_not_awaited()


@pytest.mark.parametrize(
    "bad_claims",
    [
        {"role": "operator"},
        {"role": "senior-operator"},
        {"sub": None},
        {"sub": "different-owner"},
        {"claims": {"exp": 1}},
    ],
)
def test_provider_observation_retains_senior_rbac(api, configured, bad_claims):
    api.verified.return_value = {**api.identity, **bad_claims}
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code in {401, 403}
    api.source.observe.assert_not_awaited()


def test_provider_observation_denies_different_durable_owner(api, configured):
    api.database.owner = "someone-else"
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 403
    api.source.observe.assert_not_awaited()


def test_verified_only_mode_rejects_operator_submitted_invoices(api, configured, monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_TRUST_MODE", "verified_only")
    body = {
        "expected_task_id": "task-1",
        "expected_model": "openai/gpt-test",
        "expected_operation": "completion",
        "expected_authorization_version": 7,
        "provider": "openai",
        "invoice_reference": "inv-123",
        "invoice_line_id": "line-123",
        "invoice_sha256": "a" * 64,
        "billed_cost_usd": "0.02",
    }
    reply = api.client.post(RECONCILE, headers=HEADERS, json=body)
    assert reply.status_code == 403
    api.ledger.reconcile_provider_invoice.assert_not_awaited()
    # Independent project-wide read-only provider cost observation stays enabled.
    assert api.client.post(PATH, headers=HEADERS, json=window()).status_code == 200


def test_operator_only_mode_disables_provider_costs(api, monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_INVOICE_TRUST_MODE", "operator_only")
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 503
    api.source.observe.assert_not_awaited()


def test_provider_mode_blocks_payload_spoofing_and_raw_keys(api, configured):
    reply = api.client.post(PATH, headers=HEADERS, json={**window(), "admin_key": KEY})
    assert reply.status_code == 422
    assert KEY not in reply.text
    api.source.observe.assert_not_awaited()


def test_provider_outage_does_not_expose_remote_exception_or_update_invoice(api, configured):
    api.source.observe.side_effect = OSError("secret " + KEY)
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 503
    assert KEY not in reply.text
    api.ledger.reconcile_provider_invoice.assert_not_awaited()
    api.ledger.adjust_provider_invoice.assert_not_awaited()
