"""Fail-closed production model admission across standalone and API clients."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain, ModelUsageLedger


@pytest.fixture(autouse=True)
def cleared_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


def _response():
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="verified response"))],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5, billed_cost_usd=0.003),
    )


def _ledger():
    return SimpleNamespace(
        reserve=AsyncMock(return_value="call-1"),
        settle=AsyncMock(return_value=True),
    )


@pytest.mark.asyncio
async def test_unbound_nonmock_client_never_reaches_primary_or_fallback():
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    client = LiteLLMClient(primary_model="openai/primary", fallback_model="openai/fallback")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        with pytest.raises(ModelBudgetExceeded, match="not configured"):
            await client.complete([{"role": "user", "content": "Verify"}])
        provider.assert_not_awaited()


@pytest.mark.asyncio
async def test_unbound_embedding_never_calls_provider_or_creates_fake_vector():
    client = LiteLLMClient()
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as provider,
    ):
        with pytest.raises(ModelBudgetExceeded):
            await client.get_embedding("Test content")
        provider.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "engagement,task",
    [("", "task-1"), ("api-bootstrap", "task-1"), ("eng-1", ""), ("", "")],
)
async def test_bound_provider_refuses_unscoped_and_background_without_task(engagement, task):
    ledger = _ledger()
    RequestContext.bind(engagement_id=engagement, task_id=task)
    client = LiteLLMClient(usage_store=ledger)
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        with pytest.raises(ModelBudgetExceeded, match="persisted engagement and task"):
            await client.complete([{"role": "user", "content": "Verify"}])
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()


@pytest.mark.asyncio
async def test_database_reserve_timeout_fails_closed_without_fallback():
    ledger = _ledger()
    ledger.reserve.side_effect = TimeoutError("database-connection-secret")
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        with pytest.raises(ModelBudgetExceeded, match="unavailable"):
            await client.complete([{"role": "user", "content": "Verify"}])
        provider.assert_not_awaited()
        assert ledger.reserve.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("admission", [None, "", 1234])
async def test_invalid_durable_reservation_refuses_provider(admission):
    ledger = _ledger()
    ledger.reserve.return_value = admission
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        with pytest.raises(ModelBudgetExceeded, match="no durable reservation"):
            await client.complete([{"role": "user", "content": "Verify"}])
        provider.assert_not_awaited()


@pytest.mark.asyncio
async def test_provider_transport_unknown_is_settled_unknown_once_and_never_falls_back():
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger, fallback_model="openai/fallback")
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        provider.side_effect = TimeoutError("network accepted then timed out")
        with pytest.raises(ModelOutcomeUncertain, match="may have executed"):
            await client.complete([{"role": "user", "content": "Verify"}])
        assert provider.await_count == 1
        ledger.settle.assert_awaited_once_with("call-1", "eng-1", None, delivered=False)


@pytest.mark.asyncio
async def test_settlement_outage_after_provider_success_does_not_trigger_fallback():
    ledger = _ledger()
    ledger.settle.side_effect = ConnectionError("pg offline")
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        provider.return_value = _response()
        with pytest.raises(ModelOutcomeUncertain, match="could not be persisted"):
            await client.complete([{"role": "user", "content": "Verify"}])
        assert provider.await_count == 1
        ledger.settle.assert_awaited_once()


@pytest.mark.asyncio
async def test_valid_bound_client_reserves_then_commits_before_exposing_answer():
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    order = []

    async def admit(*args):
        order.append("admit")
        return "call-1"

    async def provider_call(**kwargs):
        order.append("provider")
        return _response()

    async def settle(*args, **kwargs):
        order.append("settle")
        return True

    ledger.reserve.side_effect = admit
    ledger.settle.side_effect = settle
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new=provider_call),
    ):
        assert await client.complete([{"role": "user", "content": "Verify"}]) == "verified response"
        assert order == ["admit", "provider", "settle"]
        ledger.reserve.assert_awaited_once_with(
            "eng-1", "task-1", client.primary_model, "completion"
        )


@pytest.mark.asyncio
async def test_malformed_provider_completion_must_not_retry_or_fallback():
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
    ):
        provider.return_value = SimpleNamespace(choices=[])
        with pytest.raises(ModelOutcomeUncertain, match="unusable completion"):
            await client.complete([{"role": "user", "content": "Verify"}])
        assert provider.await_count == 1
        ledger.settle.assert_awaited_once()


@pytest.mark.asyncio
async def test_malformed_provider_embedding_does_not_generate_fake_zero_vector():
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-1", task_id="task-1")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as provider,
    ):
        provider.return_value = {"data": []}
        with pytest.raises(ModelOutcomeUncertain, match="unusable embedding"):
            await client.get_embedding("Verify")
        provider.assert_awaited_once()
        ledger.settle.assert_awaited_once()


def test_ledger_cannot_be_detached_or_swapped_after_binding():
    ledger = _ledger()
    client = LiteLLMClient(usage_store=ledger)
    client.set_usage_store(ledger)
    with pytest.raises(ValueError):
        client.set_usage_store(None)
    with pytest.raises(RuntimeError, match="cannot be replaced"):
        client.set_usage_store(_ledger())


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return SimpleNamespace(all=lambda: self.value)


class _UsageDB:
    def __init__(self, previous):
        self.responses = iter([None, previous])
        self.added = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def begin(self):
        return self

    async def execute(self, query):
        return _Result(next(self.responses))

    def add(self, value):
        self.added.append(value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "roe,previous,expected",
    [
        ({}, [], "no model usage budget"),
        (
            {"llm_call_budget_total": 4},
            [SimpleNamespace(status="unknown", billed_cost_usd=None)],
            "unreconciled outcome",
        ),
        ({"llm_call_budget_total": 0}, [], "quota exhausted"),
    ],
)
async def test_ledger_denies_missing_quota_unknown_outcome_and_zero_budget(roe, previous, expected):
    db = _UsageDB(previous)
    ledger = ModelUsageLedger(SimpleNamespace(_async_session=lambda: db))
    engagement = SimpleNamespace(
        roe=roe, scope={"engagement_id": "eng-1", "domains": ["example.test"]}
    )
    task = SimpleNamespace(
        type="recon",
        status="running",
        flow_id=None,
        approval_required=False,
    )
    ledger._guard = AsyncMock(return_value=(engagement, task))
    with pytest.raises(ModelBudgetExceeded, match=expected):
        await ledger.reserve("eng-1", "task-1", "openai/gpt-test", "completion")
    assert db.added == []
