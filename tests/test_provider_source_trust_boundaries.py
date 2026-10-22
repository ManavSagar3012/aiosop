"""Native OpenAI project aggregate trust boundaries, entirely offline.

An administrator-scoped Organization Costs API response proves only a
configured-project aggregate at a completed UTC date window. It cannot attest
individual AI-OSOP calls, reconcile UNKNOWN, or supply a hard spend cap.
"""

import hashlib
import time
from decimal import Decimal
from unittest.mock import AsyncMock

import httpx
import pytest

from ai_osop.memory import provider_invoice_trust as trust
from ai_osop.api.routers import provider_invoices
from tests.test_provider_invoice_source_auth import (
    KEY,
    PATH,
    PROJECT,
    HEADERS,
    api,
    configured,
    install_transport,
    page,
    window,
)


def _proof(**revisions):
    today = int(time.time()) // 86400 * 86400
    proof = {
        "source": "openai_organization_costs_api",
        "source_authenticated": True,
        "source_scope": "configured_openai_project",
        "project_sha256": hashlib.sha256(PROJECT.encode()).hexdigest(),
        "start_time": today - 2 * 86400,
        "end_time": today,
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
    proof.update(revisions)
    return proof


def _runtime_mutation(mutation):
    # Parameter sets are constructed at pytest collection time. A future
    # timestamp computed there can become an ordinary past observation by
    # the time the complete multi-minute backend suite reaches this test.
    if mutation.get("source_checked_at_utc") == "__future_at_execution__":
        return {**mutation, "source_checked_at_utc": int(time.time()) + 3600}
    return mutation


@pytest.mark.parametrize(
    "corruption",
    [
        {"source": "operator_attested"},
        {"source_authenticated": False},
        {"source_scope": "any_project"},
        {"project_sha256": "f" * 64},
        {"start_time": 0},
        {"end_time": 0},
        {"currency": "eur"},
        {"individual_call_cost_verified": True},
        {"provider_hard_cost_cap_verified": True},
        {"ledger_mutated": True},
        {"source_checked_at_utc": 1},
        {"source_checked_at_utc": "__future_at_execution__"},
        {"pages": 0},
        {"pages": 5},
        {"buckets": 60},
        {"buckets": 0},
        {"cost_lines": 513},
        {"cost_lines": 0},
        {"provider_cost_data_present": False},
        {"provider_cost_usd": None},
        {"provider_cost_usd": "0.0000000000001"},
        {"provider_cost_usd": "-1"},
        {"provider_cost_usd": "NaN"},
        {"provider_cost_usd": "1e2000"},
        {"provider_cost_usd": 0.125},
        {"independent_call_verified": True},
    ],
)
def test_substituted_source_snapshot_fails_closed(configured, corruption):
    snapshot = _proof(**_runtime_mutation(corruption))
    with pytest.raises(trust.ProviderCostInvalid):
        trust.verify_observation(snapshot, **window())


@pytest.mark.parametrize(
    "mutation",
    [
        {"source_checked_at_utc": 1},
        {"source_checked_at_utc": "__future_at_execution__"},
        {"project_sha256": "0" * 64},
        {"individual_call_cost_verified": True},
        {"ledger_mutated": True},
        {"start_time": 0},
        {"provider_cost_data_present": False},
        {"source": "unsigned_cost_table"},
        {"currency": "eur"},
        {"extra": "claims it is an invoice"},
    ],
)
def test_api_refuses_bad_source_without_local_cost_or_audit(api, configured, mutation):
    api.source.observe.return_value = _proof(**_runtime_mutation(mutation))
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 422
    assert "project" not in reply.text.lower() or PROJECT not in reply.text
    assert KEY not in reply.text
    api.ledger.summary.assert_not_awaited()
    api.ledger.audit_openai_cost_observation.assert_not_awaited()


def test_missing_durable_auditor_denies_even_fresh_native_source(api, configured):
    del api.ledger.audit_openai_cost_observation
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 503
    assert reply.json() == {"detail": "Provider cost evidence unavailable"}
    api.source.observe.assert_awaited_once()
    api.ledger.summary.assert_awaited_once()


@pytest.mark.parametrize(
    "bound",
    [
        None,
        "",
        "eng-someone-elses-engagement",
        "https://untrusted.example",
        "../eng-1",
        "eng-1?override=true",
    ],
)
def test_project_aggregate_not_disclosed_without_exact_private_engagement_binding(
    api,
    configured,
    monkeypatch,
    bound,
):
    if bound is None:
        monkeypatch.delenv("OSOP_PROVIDER_INVOICE_OPENAI_ENGAGEMENT_ID")
    else:
        monkeypatch.setenv("OSOP_PROVIDER_INVOICE_OPENAI_ENGAGEMENT_ID", bound)
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 503
    assert PROJECT not in reply.text and KEY not in reply.text
    assert "provider_cost_usd" not in reply.text
    api.source.observe.assert_not_awaited()
    api.ledger.summary.assert_not_awaited()
    api.ledger.audit_openai_cost_observation.assert_not_awaited()


def test_owner_of_another_engagement_cannot_request_private_project_costs(
    api,
    configured,
):
    # Even a valid senior JWT that owns eng-2 must not read the project's
    # whole organization aggregate bound by the deployment to eng-1.
    reply = api.client.post(
        PATH.replace("eng-1", "eng-2"),
        headers=HEADERS,
        json=window(),
    )
    assert reply.status_code == 503
    api.source.observe.assert_not_awaited()
    api.ledger.summary.assert_not_awaited()


def test_client_cannot_override_project_binding_via_body(api, configured):
    reply = api.client.post(
        PATH,
        headers=HEADERS,
        json={
            **window(),
            "project_id": "proj_foreign",
            "engagement_id": "eng-2",
        },
    )
    assert reply.status_code == 422
    api.source.observe.assert_not_awaited()


@pytest.mark.parametrize("audit_result", [None, "recorded", 1, {"stored": True}])
def test_non_boolean_provider_audit_receipt_is_not_trusted(
    api,
    configured,
    audit_result,
):
    api.ledger.audit_openai_cost_observation.return_value = audit_result
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 503
    api.ledger.audit_openai_cost_observation.assert_awaited_once()


def test_repeated_fresh_observation_reports_idempotent_replay_not_failure(api, configured):
    api.ledger.audit_openai_cost_observation.return_value = False
    reply = api.client.post(PATH, headers=HEADERS, json=window())
    assert reply.status_code == 200
    body = reply.json()
    assert body["source_authenticated"] is True
    assert body["observation_recorded"] is False
    assert body["individual_call_cost_verified"] is False
    assert body["ledger_mutated"] is False
    assert body["provider_project_comparable_to_engagement"] is False
    assert body["provider_project_exclusivity_verified"] is False
    assert body["project_access_binding"] == "server_configured_engagement"
    assert body["safe_to_retry"] is False


@pytest.mark.asyncio
async def test_stable_source_uses_fixed_https_origin_and_exact_project_in_every_page(
    configured,
    monkeypatch,
):
    observed = []

    def handle(request):
        observed.append(request)
        assert request.method == "GET"
        assert str(request.url.copy_with(query=None)) == (
            "https://api.openai.com/v1/organization/costs"
        )
        assert request.headers["authorization"] == "Bearer " + KEY
        assert request.headers["accept-encoding"] == "identity"
        assert request.url.params.get_list("project_ids") == [PROJECT]
        assert request.url.params.get_list("group_by") == [
            "project_id",
            "line_item",
        ]
        if len(observed) == 1:
            return httpx.Response(
                200,
                json=page(
                    value=0.1,
                    has_more=True,
                    next_page="cursor-01",
                ),
            )
        assert request.url.params["page"] == "cursor-01"
        return httpx.Response(
            200,
            json=page(
                value=0.2,
                start=window()["start_time"] + 86400,
            ),
        )

    settings = install_transport(monkeypatch, handle)
    evidence = await trust.OpenAICostSource().observe(**window())
    trust.verify_observation(evidence, **window())
    assert evidence["provider_cost_usd"] == "0.3"
    assert evidence["pages"] == 2
    assert evidence["cost_lines"] == 2
    assert len(observed) == 2
    assert all(not opts["follow_redirects"] and not opts["trust_env"] for opts in settings)
    assert all(request.url.scheme == "https" for request in observed)
    assert KEY not in str(evidence) and PROJECT not in str(evidence)


@pytest.mark.asyncio
@pytest.mark.parametrize("length", ["invalid", "-1", str(65537), "9999999999999"])
async def test_bad_provider_declared_body_length_fails_before_trusting_costs(
    configured,
    monkeypatch,
    length,
):
    attempted = []

    def handler(request):
        attempted.append(request)
        return httpx.Response(200, json=page(), headers={"Content-Length": length})

    install_transport(monkeypatch, handler)
    with pytest.raises(trust.ProviderCostInvalid):
        await trust.OpenAICostSource().observe(**window())
    assert len(attempted) == 1


@pytest.mark.asyncio
async def test_provider_line_item_cannot_be_injected_as_extra_project(
    configured,
    monkeypatch,
):
    forged = page()
    forged["data"][0]["results"].append(
        {
            "object": "organization.costs.result",
            "project_id": "proj_UnrelatedTenant",
            "line_item": "external",
            "amount": {"currency": "usd", "value": 123},
        }
    )
    install_transport(monkeypatch, lambda _: httpx.Response(200, json=forged))
    with pytest.raises(trust.ProviderCostInvalid, match="project mismatch"):
        await trust.OpenAICostSource().observe(**window())


@pytest.mark.asyncio
async def test_source_has_no_id_per_call_price_or_verified_hard_cost_limit(
    configured,
    monkeypatch,
):
    install_transport(
        monkeypatch,
        lambda _: httpx.Response(200, json=page(value=0.2)),
    )
    evidence = await trust.OpenAICostSource().observe(**window())
    assert evidence["individual_call_cost_verified"] is False
    assert evidence["provider_hard_cost_cap_verified"] is False
    assert evidence["ledger_mutated"] is False
    assert evidence["source_scope"] == "configured_openai_project"
    assert "model" not in evidence
    assert "call_id" not in evidence
    assert "invoice" not in evidence


@pytest.mark.asyncio
async def test_missing_costs_remain_unknown_not_zero(
    configured,
    monkeypatch,
):
    install_transport(
        monkeypatch,
        lambda _: httpx.Response(
            200,
            json={
                "object": "page",
                "data": [],
                "has_more": False,
                "next_page": None,
            },
        ),
    )
    evidence = await trust.OpenAICostSource().observe(**window())
    assert evidence["provider_cost_data_present"] is False
    assert evidence["provider_cost_usd"] is None
    trust.verify_observation(evidence, **window())
