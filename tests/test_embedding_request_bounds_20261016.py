"""PentAGI-style UTF-8 embedding limits before model budget/provider calls."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.core.embedding_bounds import (
    embedding_max_text_bytes,
    verify_embedding_request,
)
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelBudgetExceeded


@pytest.fixture(autouse=True)
def reset_context(monkeypatch):
    RequestContext.clear()
    monkeypatch.delenv("OSOP_EMBEDDING_MAX_TEXT_BYTES", raising=False)
    yield
    RequestContext.clear()


@pytest.mark.parametrize("raw", ["0", "1023", "262145", "-1", " 2048", "4e3", "nan", "", "999999"])
def test_config_invalid_fails_closed(monkeypatch, raw):
    monkeypatch.setenv("OSOP_EMBEDDING_MAX_TEXT_BYTES", raw)
    with pytest.raises(ModelBudgetExceeded, match="configuration"):
        embedding_max_text_bytes()


def test_byte_limit_counts_utf8_and_total_batch(monkeypatch):
    monkeypatch.setenv("OSOP_EMBEDDING_MAX_TEXT_BYTES", "1024")
    verify_embedding_request(["a" * 1024])
    verify_embedding_request(["a" * 200, "b" * 824])
    for bad in (["☃" * 342], ["a" * 1024, "x"], [], ["ok", ""], ["x"] * 17):
        with pytest.raises(ModelBudgetExceeded):
            verify_embedding_request(bad)
    with pytest.raises(ModelBudgetExceeded):
        verify_embedding_request(["\ud800"])
    with pytest.raises(ModelBudgetExceeded):
        verify_embedding_request("not a batch")


@pytest.mark.asyncio
async def test_oversized_embedding_never_reserves_or_contacts_provider(monkeypatch):
    monkeypatch.setenv("OSOP_EMBEDDING_MAX_TEXT_BYTES", "1024")
    ledger = SimpleNamespace(
        reserve=AsyncMock(return_value="call-safe"),
        settle=AsyncMock(return_value=True),
    )
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-test", task_id="task-test")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as provider,
    ):
        with pytest.raises(ModelBudgetExceeded):
            await client.get_embedding("☃" * 342)
        with pytest.raises(ModelBudgetExceeded):
            await client._provider_call(
                "embedding",
                "text-embedding-3-small",
                1,
                input=["a" * 1024, "x"],
            )
        provider.assert_not_awaited()
        ledger.reserve.assert_not_awaited()
        ledger.settle.assert_not_awaited()


@pytest.mark.asyncio
async def test_bounded_embedding_retains_signed_reserve_provider_settle_order():
    order = []

    async def reserve(*_args):
        order.append("reserve")
        return "call-safe"

    async def provider_call(**_kwargs):
        order.append("provider")
        return {"data": [{"embedding": [0.1, 0.2]}]}

    async def settle(*_args, **_kwargs):
        order.append("settle")
        return True

    ledger = SimpleNamespace(reserve=reserve, settle=settle)
    client = LiteLLMClient(usage_store=ledger)
    RequestContext.bind(engagement_id="eng-test", task_id="task-test")
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.aembedding", new=provider_call),
    ):
        assert await client.get_embedding("short authorized query") == [0.1, 0.2]
    assert order == ["reserve", "provider", "settle"]


@pytest.mark.asyncio
async def test_mock_embedding_does_not_bypass_byte_bound(monkeypatch):
    monkeypatch.setenv("OSOP_EMBEDDING_MAX_TEXT_BYTES", "1024")
    client = LiteLLMClient()
    with patch("ai_osop.core.llm_client.settings.mock_llm", True):
        with pytest.raises(ModelBudgetExceeded):
            await client.get_embedding("X" * 1025)
        assert len(await client.get_embedding("safe")) == 1536
