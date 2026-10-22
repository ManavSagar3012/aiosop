"""Official model listings wired through real LiteLLMClient and signed precharge.

Every provider listing and LiteLLM request is mocked; no paid calls or app DB.
"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ai_osop.core import provider_capability_discovery as discovery
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.provider_routing import ProviderRouteDenied, configured_routes
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain

_OPENAI = {
    "provider": "openai",
    "model": "openai/model-one",
    "operations": ["completion"],
    "credential_env": "OPENAI_API_KEY",
}
_ANTHROPIC = {
    "provider": "anthropic",
    "model": "anthropic/model-two",
    "operations": ["completion"],
    "credential_env": "ANTHROPIC_API_KEY",
}
_EMBED = {
    "provider": "openai",
    "model": "text-embedding-3-small",
    "operations": ["embedding"],
    "credential_env": "OPENAI_API_KEY",
}


def _openai(*models):
    return {
        "object": "list",
        "data": [
            {"id": model, "object": "model", "created": 1, "owned_by": "openai"} for model in models
        ],
    }


def _anthropic(*models, has_more=False, last_id=None):
    return {
        "data": [{"id": model, "type": "model"} for model in models],
        "has_more": has_more,
        "last_id": last_id,
    }


@pytest.fixture(autouse=True)
def _config(monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_CATALOG_MODE", "enforce")
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps(
            {
                "version": 1,
                "routes": [_OPENAI, _ANTHROPIC, _EMBED],
            }
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "openai-local-test-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-local-test-key")
    monkeypatch.setattr(discovery, "_catalog", discovery.ProviderCatalogDiscovery())
    monkeypatch.setattr("ai_osop.core.llm_client.settings.mock_llm", False)
    RequestContext.clear()
    yield
    RequestContext.clear()


def _transport(monkeypatch, handler):
    original = httpx.AsyncClient
    seen = []
    configs = []

    def wrapped(request):
        seen.append(request)
        return handler(request)

    def factory(**kwargs):
        configs.append(kwargs)
        return original(
            transport=httpx.MockTransport(wrapped),
            timeout=kwargs["timeout"],
            follow_redirects=kwargs["follow_redirects"],
            trust_env=kwargs["trust_env"],
        )

    monkeypatch.setattr(discovery.httpx, "AsyncClient", factory)
    return seen, configs


def _http_models(request):
    assert request.method == "GET"
    assert request.url.scheme == "https"
    assert request.url.port is None  # HTTPS defaults to 443
    assert request.headers["accept-encoding"] == "identity"
    if request.url.host == "api.openai.com":
        assert str(request.url.copy_with(query=None)) == "https://api.openai.com/v1/models"
        assert request.headers["authorization"] == "Bearer openai-local-test-key"
        assert "x-api-key" not in request.headers
        return httpx.Response(200, json=_openai("model-one", "text-embedding-3-small"))
    assert str(request.url.copy_with(query=None)) == "https://api.anthropic.com/v1/models"
    assert request.headers["x-api-key"] == "anthropic-local-test-key"
    assert request.headers["anthropic-version"] == "2023-06-01"
    assert "authorization" not in request.headers
    return httpx.Response(200, json=_anthropic("model-two"))


def _ledger():
    return SimpleNamespace(
        reserve=AsyncMock(return_value="call-authorized"),
        settle=AsyncMock(return_value=True),
    )


def _context():
    RequestContext.bind(engagement_id="eng-approved", task_id="task-signed")


def _response():
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="synthetic answer"))],
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2, billed_cost_usd=0.01),
    )


@pytest.mark.asyncio
async def test_optin_catalog_precedes_pg_reservation_then_single_model_call(monkeypatch):
    requests, configurations = _transport(monkeypatch, _http_models)
    _context()
    ledger = _ledger()
    order = []

    async def reserve(*args):
        assert len(requests) == 1  # No billable model call before catalog.
        order.append("pg-reserve")
        return "call-authorized"

    async def call(**kwargs):
        assert order == ["pg-reserve"]
        assert kwargs["model"] == "openai/model-one"
        assert kwargs["num_retries"] == 0
        order.append("provider-invoked")
        return _response()

    ledger.reserve.side_effect = reserve

    async def settle(*args, **kwargs):
        return True

    ledger.settle.side_effect = settle
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new=call):
        assert await client.complete([{"role": "user", "content": "testing"}]) == (
            "synthetic answer"
        )
    assert order == ["pg-reserve", "provider-invoked"]
    assert len(requests) == 1  # Two checks reuse the fresh catalog.
    assert configurations[0]["follow_redirects"] is False
    assert configurations[0]["trust_env"] is False
    ledger.reserve.assert_awaited_once_with(
        "eng-approved",
        "task-signed",
        "openai/model-one",
        "completion",
    )
    ledger.settle.assert_awaited_once()
    report = configured_routes().capability_report()
    item = next(row for row in report if row["model"] == "openai/model-one")
    assert item["provider_catalog_verified"] is True
    assert item["catalog_status"] == "served_in_listing"
    assert item["provider_native_cost_ceiling_verified"] is False
    assert item["provider_currently_available_verified"] is False
    assert "local-test-key" not in str(report)


@pytest.mark.asyncio
async def test_anthropic_list_pagination_is_bounded_and_authorized(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.url.params.get("after_id"))
        assert request.url.params["limit"] == "100"
        if len(seen) == 1:
            return httpx.Response(
                200,
                json=_anthropic(
                    "model-older",
                    has_more=True,
                    last_id="model-older",
                ),
            )
        assert seen[-1] == "model-older"
        return httpx.Response(200, json=_anthropic("model-two", has_more=False))

    _transport(monkeypatch, handler)
    snapshot = await discovery.configured_catalog().verify(
        configured_routes().resolve("anthropic/model-two", "completion")
    )
    assert snapshot.pages == 2
    assert snapshot.models == {"model-older", "model-two"}
    assert seen == [None, "model-older"]


@pytest.mark.asyncio
async def test_local_only_model_mismatch_chooses_fresh_qualified_fallback(monkeypatch):
    def handler(request):
        if request.url.host == "api.openai.com":
            return httpx.Response(200, json=_openai("not-primary"))
        return httpx.Response(200, json=_anthropic("model-two"))

    requests, _ = _transport(monkeypatch, handler)
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        send.return_value = _response()
        assert await client.complete([{"role": "user", "content": "approved"}])
        send.assert_awaited_once()
        assert send.await_args.kwargs["model"] == "anthropic/model-two"
        assert send.await_args.kwargs["api_key"] == "anthropic-local-test-key"
        ledger.reserve.assert_awaited_once_with(
            "eng-approved",
            "task-signed",
            "anthropic/model-two",
            "completion",
        )
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_explicit_model_missing_from_catalog_never_selects_fallback(monkeypatch):
    _transport(monkeypatch, lambda request: httpx.Response(200, json=_openai("other")))
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        with pytest.raises(discovery.ProviderCatalogModelAbsent):
            await client.complete(
                [{"role": "user", "content": "approved"}], model="openai/model-one"
            )
        send.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_failed_primary_catalog_never_triggers_second_provider(monkeypatch):
    requests, _ = _transport(
        monkeypatch,
        lambda request: httpx.Response(
            503,
            content=b"transient upstream failure",
        ),
    )
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        with pytest.raises(discovery.ProviderCatalogUnavailable):
            await client.complete([{"role": "user", "content": "approved"}])
        assert len(requests) == 1
        send.assert_not_awaited()
        ledger.reserve.assert_not_awaited()
    report = configured_routes().capability_report()[0]
    assert report["provider_catalog_verified"] is False
    assert report["catalog_status"] in {"unchecked", "unavailable"}


@pytest.mark.asyncio
async def test_stale_snapshot_is_rejected_if_provider_goes_down(monkeypatch):
    failed = False
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        return (
            httpx.Response(503)
            if failed
            else httpx.Response(
                200,
                json=_openai("model-one"),
            )
        )

    _transport(monkeypatch, handler)
    route = configured_routes().resolve("openai/model-one", "completion")
    snapshot = await discovery.configured_catalog().verify(route)
    assert snapshot.expires_at > snapshot.checked_at
    clock = snapshot.expires_at + 1
    with patch.object(discovery.time, "monotonic", return_value=clock):
        assert discovery.configured_catalog().status(route)["catalog_status"] == "stale"
        failed = True
        with pytest.raises(discovery.ProviderCatalogUnavailable):
            await discovery.configured_catalog().verify(route)
        report = discovery.configured_catalog().status(route)
        assert report["catalog_status"] == "stale_refresh_failed"
        assert report["provider_catalog_verified"] is False
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("error_mode", ["replay", "over_pages", "no_cursor"])
async def test_bad_anthropic_pagination_fails_closed_without_partial_cache(
    monkeypatch,
    error_mode,
):
    page_count = 0

    def handler(request):
        nonlocal page_count
        page_count += 1
        if error_mode == "no_cursor":
            return httpx.Response(
                200,
                json=_anthropic("older", has_more=True, last_id=None),
            )
        if error_mode == "replay":
            return httpx.Response(
                200,
                json=_anthropic("older", has_more=True, last_id="older"),
            )
        current = f"older-{page_count}"
        return httpx.Response(
            200,
            json=_anthropic(current, has_more=True, last_id=current),
        )

    requests, _ = _transport(monkeypatch, handler)
    route = configured_routes().resolve("anthropic/model-two", "completion")
    with pytest.raises(discovery.ProviderCatalogUnavailable):
        await discovery.configured_catalog().verify(route)
    assert len(requests) <= 3
    assert page_count <= 3
    assert discovery.configured_catalog().status(route)["provider_catalog_verified"] is False


@pytest.mark.asyncio
async def test_catalog_mode_misconfiguration_and_unlisted_route_fails_closed(monkeypatch):
    requests, _ = _transport(monkeypatch, _http_models)
    _context()
    ledger = _ledger()
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    monkeypatch.setenv("OSOP_PROVIDER_CATALOG_MODE", "fail_open")
    with pytest.raises(discovery.ProviderCatalogUnavailable):
        await client.complete([{"role": "user", "content": "synthetic"}])
    monkeypatch.setenv("OSOP_PROVIDER_CATALOG_MODE", "enforce")
    monkeypatch.delenv("OSOP_VERIFIED_PROVIDER_ROUTES_JSON")
    with pytest.raises(ProviderRouteDenied):
        await client.complete([{"role": "user", "content": "synthetic"}])
    assert requests == []
    ledger.reserve.assert_not_awaited()


@pytest.mark.parametrize(
    "route",
    [
        dict(_OPENAI, api_base="https://model-proxy.example.test/v1"),
        {
            "provider": "deepseek",
            "model": "deepseek/chat",
            "credential_env": "DEEPSEEK_API_KEY",
            "operations": ["completion"],
        },
    ],
)
@pytest.mark.asyncio
async def test_discovery_cannot_probe_custom_or_unsupported_provider(
    monkeypatch,
    route,
):
    monkeypatch.setenv(
        "OSOP_VERIFIED_PROVIDER_ROUTES_JSON",
        json.dumps(
            {
                "version": 1,
                "routes": [route],
            }
        ),
    )
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-test-secret")
    seen, _ = _transport(monkeypatch, _http_models)
    _context()
    ledger = _ledger()
    client = LiteLLMClient(primary_model=route["model"], usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        with pytest.raises(discovery.ProviderCatalogUnavailable):
            await client.complete([{"role": "user", "content": "approved"}], model=route["model"])
        assert not seen
        send.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_ledger_or_context_never_sends_catalog_request(monkeypatch):
    seen, _ = _transport(monkeypatch, _http_models)
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=None)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        with pytest.raises(ModelBudgetExceeded):
            await client._provider_call(
                "completion", "openai/model-one", 1, messages=[{"role": "user", "content": "ok"}]
            )
        send.assert_not_awaited()
    assert not seen


@pytest.mark.asyncio
async def test_embedding_catalog_does_not_bypass_precharge(monkeypatch):
    requests, _ = _transport(monkeypatch, _http_models)
    _context()
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as send:
        send.return_value = {"data": [{"embedding": [0.1, 0.2]}]}
        assert await client.get_embedding("synthetic") == [0.1, 0.2]
        ledger.reserve.assert_awaited_once_with(
            "eng-approved",
            "task-signed",
            "text-embedding-3-small",
            "embedding",
        )
        send.assert_awaited_once()
        assert len(requests) == 1


@pytest.mark.asyncio
async def test_post_submission_provider_error_is_unknown_never_catalog_fallback(monkeypatch):
    seen, _ = _transport(monkeypatch, _http_models)
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        send.side_effect = TimeoutError("model request may already be billed")
        with pytest.raises(ModelOutcomeUncertain):
            await client.complete([{"role": "user", "content": "synthetic"}])
        send.assert_awaited_once()
        ledger.reserve.assert_awaited_once()
        ledger.settle.assert_awaited_once()
        assert ledger.settle.await_args.kwargs["delivered"] is False
        assert len(seen) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"}),
        httpx.Response(200, content=b'{"data":[]}', headers={"Content-Type": "text/plain"}),
        httpx.Response(
            200,
            stream=httpx.ByteStream(b"compressed-not-accepted"),
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        ),
        httpx.Response(200, content=b"z" * 65537),
        httpx.Response(200, content=b'{"object":"list","object":"list","data":[]}'),
        httpx.Response(
            200,
            json={
                "object": "list",
                "data": [
                    {"object": "model", "id": "model-one"},
                    {"object": "model", "id": "model-one"},
                ],
            },
        ),
        httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"object": "model", "id": "model-one"}],
                "has_more": True,
            },
        ),
    ],
)
async def test_bad_json_oversized_redirect_and_duplicate_model_fail_closed(
    monkeypatch,
    response,
):
    requests, _ = _transport(monkeypatch, lambda request: response)
    route = configured_routes().resolve("openai/model-one", "completion")
    with pytest.raises(discovery.ProviderCatalogUnavailable):
        await discovery.configured_catalog().verify(route)
    assert len(requests) == 1
    assert discovery.configured_catalog().status(route)["provider_catalog_verified"] is False


@pytest.mark.asyncio
async def test_concurrent_model_list_checks_share_single_refresh(monkeypatch):
    seen, _ = _transport(monkeypatch, _http_models)
    route = configured_routes().resolve("openai/model-one", "completion")
    snapshots = await asyncio.gather(
        *(discovery.configured_catalog().verify(route) for _ in range(12))
    )
    assert len(seen) == 1
    assert all(s is snapshots[0] for s in snapshots)


@pytest.mark.asyncio
async def test_catalog_cannot_rescue_failed_signed_reservation(monkeypatch):
    seen, _ = _transport(monkeypatch, _http_models)
    _context()
    ledger = _ledger()
    ledger.reserve.side_effect = ModelBudgetExceeded("signed precharge denied")
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as send:
        with pytest.raises(ModelBudgetExceeded):
            await client.complete([{"role": "user", "content": "synthetic"}])
        assert len(seen) == 1
        send.assert_not_awaited()
        ledger.settle.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_postgres_precharge_before_provider_model_request(monkeypatch):
    from tests.test_model_precharge_budget import _pool_fixture

    seen, _ = _transport(monkeypatch, _http_models)
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)

    async def invoked(**kwargs):
        assert len(seen) == 1
        assert kwargs["model"] == "openai/model-one"
        assert kwargs["num_retries"] == 0
        assert len(pool.rows) == 1 and pool.rows[0].status == "reserved"
        assert any(
            event.kind == "llm.precharge_reserved"
            and event.payload["source"] == "signed_operator_worst_case"
            for event in pool.events
        )
        return _response()

    with patch("ai_osop.core.llm_client.litellm.acompletion", new=invoked):
        assert await client.complete([{"role": "user", "content": "synthetic"}])
    assert pool.rows[0].status == "settled"
    assert len([event for event in pool.events if event.kind == "llm.precharge_reserved"]) == 1
    assert len([event for event in pool.events if event.kind == "llm.precharge_settled"]) == 1


@pytest.mark.asyncio
async def test_replaced_credential_cannot_reuse_previous_credential_catalog(monkeypatch):
    seen, _ = _transport(monkeypatch, _http_models)
    route = configured_routes().resolve("openai/model-one", "completion")
    old_key = route.validate_deployment()
    await discovery.configured_catalog().verify(route, credential=old_key)
    monkeypatch.setenv("OPENAI_API_KEY", "new-valid-test-key")
    with pytest.raises(discovery.ProviderCatalogUnavailable, match="rotated"):
        await discovery.configured_catalog().verify(route, credential=old_key)
    assert len(seen) == 1
    assert discovery.configured_catalog().status(route)["provider_catalog_verified"] is False


@pytest.mark.asyncio
async def test_missing_ledger_or_context_does_not_query_catalog_preflight(monkeypatch):
    seen, _ = _transport(monkeypatch, _http_models)
    no_store = LiteLLMClient(primary_model="openai/model-one")
    with pytest.raises(ModelBudgetExceeded):
        await no_store.complete([{"role": "user", "content": "synthetic"}])
    no_context = LiteLLMClient(primary_model="openai/model-one", usage_store=_ledger())
    with pytest.raises(ModelBudgetExceeded):
        await no_context.complete([{"role": "user", "content": "synthetic"}])
    assert seen == []


def test_off_mode_preserves_existing_non_catalog_report(monkeypatch):
    monkeypatch.setenv("OSOP_PROVIDER_CATALOG_MODE", "off")
    report = configured_routes().capability_report()
    assert all("catalog_status" not in item for item in report)
    assert all(item["provider_catalog_verified"] is False for item in report)
