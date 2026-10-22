"""Explicit local route policy, provider-side unknown outcomes, ledger admission.

No live LLM, credentials, public endpoint, database or billable call. All
provider HTTP entry points are mocked and all outgoing calls are counted.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.core import provider_routing
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.provider_routing import (
    ProviderRouteDenied,
    ProviderRouteUnavailable,
    ProviderRoutes,
    configured_routes,
)
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain


_CONFIG_ENV = "OSOP_VERIFIED_PROVIDER_ROUTES_JSON"
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
_EMBEDDING = {
    "provider": "openai",
    "model": "text-embedding-3-small",
    "operations": ["embedding"],
    "credential_env": "OPENAI_API_KEY",
}


def _configure(monkeypatch, routes=None):
    monkeypatch.setenv(
        _CONFIG_ENV,
        json.dumps({"version": 1, "routes": routes or [_OPENAI, _ANTHROPIC, _EMBEDDING]}),
    )


@pytest.fixture(autouse=True)
def _local_mock_environment(monkeypatch):
    RequestContext.clear()
    monkeypatch.delenv(_CONFIG_ENV, raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("ai_osop.core.llm_client.settings.mock_llm", False)
    yield
    RequestContext.clear()


def _ledger():
    return SimpleNamespace(
        reserve=AsyncMock(return_value="call-signed-admitted"),
        settle=AsyncMock(return_value=True),
    )


def _response():
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="mock provider completion"))],
        usage=SimpleNamespace(
            prompt_tokens=9,
            completion_tokens=4,
            billed_cost_usd=0.01,
        ),
    )


def _context():
    RequestContext.bind(engagement_id="eng-allowlisted", task_id="task-authorized")


def test_absent_optin_preserves_existing_client_semantics():
    assert configured_routes() is None


@pytest.mark.parametrize(
    "invalid",
    [
        "",
        "{}",
        '{"version":1,"routes":[]}',
        '{"version":true,"routes":[]}',
        '{"version":1,"version":1,"routes":[]}',
        '{"version":1,"routes":{} }',
        '{"version":1,"routes":[{"provider":"openai"}]}',
        '{"version":1,"routes":[{}]}',
        '{"version":1,"routes":[{"provider":"openai","model":"gpt-a","operations":["completion"],"credential_env":"OPENAI_API_KEY","extra":true}]}',
        '{"version":1,"routes":[{"provider":"openai","model":"gpt-a","operations":["completion"],"credential_env":"OPENAI_API_KEY"}],"fallback":"anything"}',
        '{"version":NaN,"routes":[]}',
        "x" * 16385,
    ],
)
def test_invalid_route_document_fails_closed_without_secret_echo(monkeypatch, invalid):
    monkeypatch.setenv(_CONFIG_ENV, invalid)
    with pytest.raises(ProviderRouteDenied) as failure:
        configured_routes()
    assert not invalid or invalid not in str(failure.value)


@pytest.mark.parametrize(
    "bad_route",
    [
        dict(_OPENAI, model="other-provider/foo"),
        dict(_ANTHROPIC, model="gpt-missing-prefix"),
        dict(_OPENAI, model="example/../model"),
        dict(_OPENAI, model="bad model"),
        dict(_OPENAI, model="a" * 91),
        dict(_OPENAI, credential_env="ANTHROPIC_API_KEY"),
        dict(_OPENAI, credential_env="DATABASE_URL"),
        dict(_OPENAI, operations=["completion", "completion"]),
        dict(_OPENAI, operations=["tool_execution"]),
        dict(_OPENAI, operations=[True]),
        dict(_OPENAI, api_base="http://127.0.0.1:9000"),
        dict(_OPENAI, api_base="https://username:password@example.test/v1"),
        dict(_OPENAI, api_base="https://example.test/v1?token=secret"),
        dict(_OPENAI, api_base="https://localhost/v1"),
        dict(_OPENAI, api_base="https://127.0.0.2/v1"),
        dict(_OPENAI, api_base="https://169.254.169.254/v1"),
        dict(_OPENAI, api_base="https://192.168.1.3/v1"),
        dict(_OPENAI, api_base="https://provider.local/v1"),
        dict(_OPENAI, api_base="https://example.test:8443/v1"),
        dict(_OPENAI, api_base="https://example.test/v1#fragment"),
    ],
)
def test_unsafe_provider_alias_operation_credential_and_endpoint_rejected(
    monkeypatch,
    bad_route,
):
    _configure(monkeypatch, routes=[bad_route])
    with pytest.raises(ProviderRouteDenied):
        configured_routes()


def test_duplicate_model_and_overwide_catalog_denied(monkeypatch):
    _configure(monkeypatch, routes=[_OPENAI, _OPENAI])
    with pytest.raises(ProviderRouteDenied):
        configured_routes()
    _configure(monkeypatch, routes=[dict(_OPENAI, model=f"openai/model-{i}") for i in range(17)])
    with pytest.raises(ProviderRouteDenied):
        configured_routes()


def test_deployment_check_not_catalog_or_provider_capability_verification(monkeypatch):
    _configure(monkeypatch, routes=[_OPENAI, _ANTHROPIC])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    routes = configured_routes()
    assert isinstance(routes, ProviderRoutes)
    checks = routes.capability_report()
    assert checks == [
        {
            "model": "openai/model-one",
            "provider": "openai",
            "operations": ["completion"],
            "deployment": "locally_configured",
            "provider_catalog_verified": False,
            "provider_native_cost_ceiling_verified": False,
        },
        {
            "model": "anthropic/model-two",
            "provider": "anthropic",
            "operations": ["completion"],
            "deployment": "unavailable",
            "provider_catalog_verified": False,
            "provider_native_cost_ceiling_verified": False,
        },
    ]
    assert "test-secret" not in str(checks)
    with pytest.raises(ProviderRouteUnavailable):
        routes.resolve("anthropic/model-two", "completion").validate_deployment()
    with pytest.raises(ProviderRouteDenied):
        routes.resolve("openai/model-one", "embedding")
    with pytest.raises(ProviderRouteDenied):
        routes.resolve("openai/unapproved", "completion")


@pytest.mark.asyncio
async def test_paid_completion_reserved_before_single_allowlisted_dispatch(monkeypatch):
    _configure(monkeypatch, routes=[dict(_OPENAI, api_base="https://gateway.example.test/v1")])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    order = []
    ledger = _ledger()

    async def reserve(*args):
        order.append("postgres-precharge")
        return "call-route-admitted"

    async def provider(**kwargs):
        order.append("provider")
        assert kwargs["model"] == "openai/model-one"
        assert kwargs["api_key"] == "openai-only-test-secret"
        assert kwargs["api_base"] == "https://gateway.example.test/v1"
        assert kwargs["num_retries"] == 0
        return _response()

    async def settle(*args, **kwargs):
        order.append("postgres-settle")
        assert kwargs["delivered"] is True
        return True

    ledger.reserve.side_effect = reserve
    ledger.settle.side_effect = settle
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new=provider):
        assert await client.complete([{"role": "user", "content": "mock only"}]) == (
            "mock provider completion"
        )
    assert order == ["postgres-precharge", "provider", "postgres-settle"]
    ledger.reserve.assert_awaited_once_with(
        "eng-allowlisted",
        "task-authorized",
        "openai/model-one",
        "completion",
    )
    ledger.settle.assert_awaited_once()


@pytest.mark.asyncio
async def test_explicit_model_override_cannot_bypass_allowlist(monkeypatch):
    _configure(monkeypatch, routes=[_OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete([{"role": "user", "content": "mock only"}], model="openai/nope")
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forged_key",
    [
        "api_key",
        "api_base",
        "num_retries",
        "fallbacks",
        "model_list",
        "mock_response",
        "deployment_id",
    ],
)
async def test_caller_cannot_inject_provider_auth_or_hidden_fallback(
    monkeypatch,
    forged_key,
):
    _configure(monkeypatch, routes=[_OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete(
                [{"role": "user", "content": "mock only"}],
                **{forged_key: "foreign-credential"},
            )
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_preflight_fallback_has_only_one_reserved_provider_call(monkeypatch):
    _configure(monkeypatch, routes=[_ANTHROPIC, _OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="anthropic/model-two",
        fallback_model="openai/model-one",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        provider.return_value = _response()
        assert await client.complete([{"role": "user", "content": "mock only"}]) == (
            "mock provider completion"
        )
        provider.assert_awaited_once()
        assert provider.await_args.kwargs["model"] == "openai/model-one"
        assert provider.await_args.kwargs["api_key"] == "openai-only-test-secret"
        ledger.reserve.assert_awaited_once_with(
            "eng-allowlisted",
            "task-authorized",
            "openai/model-one",
            "completion",
        )
        ledger.settle.assert_awaited_once()


@pytest.mark.asyncio
async def test_unlisted_or_missing_fallback_denies_all_provider_calls(monkeypatch):
    _configure(monkeypatch, routes=[_ANTHROPIC])
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="anthropic/model-two",
        fallback_model="openai/model-one",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client.complete([{"role": "user", "content": "mock only"}])
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("ambiguous after provider accepted"),
        RuntimeError("provider 503"),
    ],
)
async def test_provider_execution_failure_is_unknown_no_fallback(monkeypatch, failure):
    _configure(monkeypatch, routes=[_OPENAI, _ANTHROPIC])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        provider.side_effect = failure
        with pytest.raises(ModelOutcomeUncertain, match="may have executed"):
            await client.complete([{"role": "user", "content": "mock only"}])
        assert provider.await_count == 1
        ledger.reserve.assert_awaited_once()
        ledger.settle.assert_awaited_once()
        assert ledger.settle.await_args.kwargs["delivered"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        ModelBudgetExceeded("signed cost admission denied"),
        TimeoutError("PG commit unknown"),
    ],
)
async def test_no_route_can_bypass_database_budget_or_pg_failure(monkeypatch, failure):
    _configure(monkeypatch, routes=[_OPENAI, _ANTHROPIC])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-only-test-secret")
    _context()
    ledger = _ledger()
    ledger.reserve.side_effect = failure
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        with pytest.raises(ModelBudgetExceeded):
            await client.complete([{"role": "user", "content": "mock only"}])
        provider.assert_not_awaited()
        ledger.settle.assert_not_awaited()


@pytest.mark.asyncio
async def test_provider_settlement_outage_never_falls_back(monkeypatch):
    _configure(monkeypatch, routes=[_OPENAI, _ANTHROPIC])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-only-test-secret")
    _context()
    ledger = _ledger()
    ledger.settle.side_effect = ConnectionError("PG unknown commit")
    client = LiteLLMClient(
        primary_model="openai/model-one",
        fallback_model="anthropic/model-two",
        usage_store=ledger,
    )
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        provider.return_value = _response()
        with pytest.raises(ModelOutcomeUncertain):
            await client.complete([{"role": "user", "content": "mock only"}])
        provider.assert_awaited_once()
        ledger.reserve.assert_awaited_once()


@pytest.mark.asyncio
async def test_embeddings_use_exact_allowlisted_model_and_ledger(monkeypatch):
    _configure(monkeypatch, routes=[_EMBEDDING])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as provider:
        provider.return_value = {
            "data": [{"embedding": [0.5, 0.25]}],
            "usage": {"prompt_tokens": 3, "billed_cost_usd": 0.000002},
        }
        assert await client.get_embedding("mock only") == [0.5, 0.25]
        provider.assert_awaited_once()
        assert provider.await_args.kwargs["num_retries"] == 0
        ledger.reserve.assert_awaited_once_with(
            "eng-allowlisted",
            "task-authorized",
            "text-embedding-3-small",
            "embedding",
        )
        ledger.settle.assert_awaited_once()


@pytest.mark.asyncio
async def test_direct_provider_dispatch_also_denied_if_model_unlisted(monkeypatch):
    _configure(monkeypatch, routes=[_OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as provider:
        with pytest.raises(ProviderRouteDenied):
            await client._provider_call(
                "embedding",
                "text-embedding-3-small",
                attempt=1,
                input=["mock only"],
            )
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoked_deployment_credentials_refuse_later_call(monkeypatch):
    _configure(monkeypatch, routes=[_OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    _context()
    ledger = _ledger()
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)
    with patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider:
        provider.return_value = _response()
        assert await client.complete([{"role": "user", "content": "mock only"}])
        monkeypatch.delenv("OPENAI_API_KEY")
        with pytest.raises(ProviderRouteDenied):
            await client.complete(
                [{"role": "user", "content": "mock only"}], model="openai/model-one"
            )
        assert provider.await_count == 1
        assert ledger.reserve.await_count == 1


@pytest.mark.asyncio
async def test_routed_client_preserves_actual_signed_pg_precharge_and_refund(monkeypatch):
    # Use the real ModelUsageLedger transaction/admission implementation
    # against the existing deterministic PG row-lock fixture. Only the
    # provider HTTP call is mocked; signed version and audit hold are real.
    from tests.test_model_precharge_budget import _pool_fixture

    _configure(monkeypatch, routes=[_OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    pool, ledger, _ = _pool_fixture(cost=1, ceiling=0.4)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    client = LiteLLMClient(primary_model="openai/model-one", usage_store=ledger)

    async def provider(**kwargs):
        assert kwargs["model"] == "openai/model-one"
        assert kwargs["num_retries"] == 0
        # Call admission and immutable hold must be recorded BEFORE the
        # HTTP provider is allowed to accept a request.
        assert len(pool.rows) == 1
        assert pool.rows[0].status == "reserved"
        assert any(event.kind == "llm.precharge_reserved" for event in pool.events)
        return _response()

    with patch("ai_osop.core.llm_client.litellm.acompletion", new=provider):
        assert await client.complete([{"role": "user", "content": "mock only"}]) == (
            "mock provider completion"
        )
    assert pool.rows[0].status == "settled"
    assert str(pool.rows[0].billed_cost_usd) == "0.01000000"
    holds = [event for event in pool.events if event.kind == "llm.precharge_reserved"]
    released = [event for event in pool.events if event.kind == "llm.precharge_settled"]
    assert len(holds) == len(released) == 1
    assert holds[0].payload["amount"] == "0.40000000"
    assert released[0].payload["released_usd"] == "0.39000000"
    assert released[0].payload["provider_native_cap_verified"] is False


@pytest.mark.asyncio
async def test_fallback_never_inherits_other_provider_endpoint_or_key(monkeypatch):
    _configure(monkeypatch, routes=[_ANTHROPIC, _OPENAI])
    monkeypatch.setenv("OPENAI_API_KEY", "openai-only-test-secret")
    monkeypatch.setattr(
        "ai_osop.core.llm_client.settings.llm_api_base",
        "https://anthropic-private.example.test",
    )
    monkeypatch.setattr(
        "ai_osop.core.llm_client.settings.llm_api_key",
        "anthropic-private-secret",
    )
    RequestContext.bind(engagement_id="eng-allowlisted", task_id="task-authorized")
    ledger = _ledger()
    client = LiteLLMClient(
        primary_model="anthropic/model-two",
        fallback_model="openai/model-one",
        usage_store=ledger,
    )

    async def provider(**kwargs):
        assert kwargs["model"] == "openai/model-one"
        assert kwargs["api_key"] == "openai-only-test-secret"
        assert "api_base" not in kwargs
        assert "anthropic-private-secret" not in str(kwargs)
        return _response()

    with patch("ai_osop.core.llm_client.litellm.acompletion", new=provider):
        assert await client.complete([{"role": "user", "content": "mock only"}]) == (
            "mock provider completion"
        )
    ledger.reserve.assert_awaited_once_with(
        "eng-allowlisted",
        "task-authorized",
        "openai/model-one",
        "completion",
    )
