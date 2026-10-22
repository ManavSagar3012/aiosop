"""Focused tests for sanitized MCP and provider provenance writes."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.call_provenance import BestEffortProvenance, action_provenance, provider_usage
from ai_osop.core.llm_client import LiteLLMClient
from ai_osop.core.models import ExecutionActionRecord
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPConnection, MCPExecuteRequest, MCPRegistry
from ai_osop.memory.model_usage import ModelOutcomeUncertain


@pytest.fixture(autouse=True)
def clear_request_context():
    RequestContext.clear()
    yield
    RequestContext.clear()


def _engagement_context():
    RequestContext.bind(
        engagement_id="eng-provenance",
        request_id="req-test-parent",
        task_id="task-123",
        trace_id="f" * 32,
    )


def _model_usage_store():
    store = AsyncMock()
    store.reserve.return_value = "call-provenance-test"
    store.settle.return_value = True
    return store


def _mock_mcp_connection(server_id="test-mcp", status="success"):
    conn = MCPConnection(server_id, "localhost", 8080)
    conn._initialized = True
    conn._tools["safe_tool"] = SimpleNamespace(timeout_seconds=1)
    response = SimpleNamespace(
        status=200,
        json=AsyncMock(
            side_effect=lambda: {
                "request_id": conn._session.post.call_args.kwargs["json"]["request_id"],
                "status": status,
                "result": {"authorization": "SECRET-result-content"},
                "error": "SECRET-provider-error" if status == "error" else None,
            }
        ),
    )
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=response)
    ctx.__aexit__ = AsyncMock(return_value=False)
    conn._session = SimpleNamespace(post=MagicMock(return_value=ctx))
    return conn


def test_provider_usage_requires_actual_provider_fields():
    result = provider_usage(
        SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=123, completion_tokens=8),
            _hidden_params={"response_cost": 99.99},
        )
    )
    assert result == {
        "input_tokens": 123,
        "output_tokens": 8,
        "billed_cost_usd": None,
        "cost_source": "unavailable",
    }
    billed = provider_usage(
        {"usage": {"input_tokens": 4, "output_tokens": 3, "billed_cost_usd": 0.12}}
    )
    assert billed["billed_cost_usd"] == 0.12
    assert billed["cost_source"] == "provider_reported"
    assert provider_usage({"usage": {"cost": 0.12}})["billed_cost_usd"] is None
    assert (
        provider_usage({"usage": {"prompt_tokens": -2, "cost": float("inf")}})["billed_cost_usd"]
        is None
    )


def test_record_drops_sensitive_metadata_and_untrusted_ids():
    _engagement_context()
    record = action_provenance(
        "mcp.recon.safe_tool",
        "success",
        15,
        safe_metadata={
            "api_key": "SECRET",
            "result": {"token": "SECRET"},
            "server_id": "recon",
            "request_id": "req-mcp-1",
            "billed_cost_usd": 20,
            "cost_source": "unavailable",
        },
    )
    assert record["task_id"] == "task-123"
    assert record["engagement_id"] == "eng-provenance"
    assert record["safe_metadata"]["request_id"] == "req-test-parent"
    assert record["safe_metadata"]["correlation_id"] == "req-mcp-1"
    assert "SECRET" not in str(record)
    assert "cost_usd" not in record["safe_metadata"]
    persisted = ExecutionActionRecord(**record)
    assert persisted.task_id == "task-123"
    assert persisted.safe_metadata["correlation_id"] == "req-mcp-1"


@pytest.mark.asyncio
async def test_mcp_registry_emits_sanitized_correlated_success():
    _engagement_context()
    persistence = AsyncMock()
    registry = MCPRegistry()
    registry.set_provenance_callback(persistence)
    conn = _mock_mcp_connection()
    registry._servers["test-mcp"] = conn

    response = await registry.execute_tool("test-mcp", "safe_tool", {"auth": "SECRET-params"})
    assert response.status == "success"
    await registry._provenance_recorder.drain()
    persistence.assert_awaited_once()
    record = persistence.await_args.args[0]
    assert record["outcome"] == "success"
    assert record["tool_name"] == "mcp.test-mcp.safe_tool"
    assert record["safe_metadata"]["request_id"] == "req-test-parent"
    assert record["safe_metadata"]["server_id"] == "test-mcp"
    assert "SECRET" not in str(record)


@pytest.mark.asyncio
async def test_mcp_error_status_counted_as_failure_without_leaking():
    _engagement_context()
    persistence = AsyncMock(side_effect=RuntimeError("SECRET-callback-error"))
    conn = _mock_mcp_connection(status="error")
    conn.set_provenance_callback(persistence)
    response = await conn.execute(MCPExecuteRequest(tool_name="safe_tool", parameters={}))
    assert response.status == "error"
    assert conn._failure_count == 1
    await conn._provenance_recorder.drain()
    persistence.assert_awaited_once()
    assert persistence.await_args.args[0]["outcome"] == "error"


@pytest.mark.asyncio
async def test_mcp_timeout_and_circuit_open_capture_outcomes():
    _engagement_context()
    persistence = AsyncMock()
    conn = _mock_mcp_connection()
    conn.set_provenance_callback(persistence)
    timeout_ctx = MagicMock()
    timeout_ctx.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
    timeout_ctx.__aexit__ = AsyncMock()
    conn._session.post.return_value = timeout_ctx
    assert (
        await conn.execute(MCPExecuteRequest(tool_name="safe_tool", parameters={}))
    ).status == "unknown"
    conn._circuit_open = True
    from datetime import datetime

    conn._circuit_opened_at = datetime.utcnow()
    assert (
        await conn.execute(MCPExecuteRequest(tool_name="safe_tool", parameters={}))
    ).status == "circuit_open"
    await conn._provenance_recorder.drain()
    assert [call.args[0]["outcome"] for call in persistence.await_args_list] == [
        "unknown",
        "circuit_open",
    ]
    assert persistence.await_args_list[0].args[0]["safe_metadata"]["error_class"] == "TimeoutError"


@pytest.mark.asyncio
async def test_llm_usage_and_cost_are_provider_reported():
    _engagement_context()
    persistence = AsyncMock()
    usage_store = _model_usage_store()
    client = LiteLLMClient(provenance_callback=persistence, usage_store=usage_store)
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="response"))],
        usage=SimpleNamespace(prompt_tokens=20, completion_tokens=8, billed_cost_usd=0.005),
    )
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
        patch("ai_osop.core.observability.record_llm_call") as record_usage,
        patch("ai_osop.core.observability.record_engagement_cost") as record_cost,
    ):
        provider.return_value = response
        assert await client.complete([{"role": "user", "content": "SECRET prompt"}]) == "response"
        await client.drain_provenance()
    record_usage.assert_called_once()
    assert record_usage.call_args.kwargs["tokens_input"] == 20
    assert record_usage.call_args.kwargs["tokens_output"] == 8
    assert record_usage.call_args.kwargs["cost_usd"] == 0.005
    record_cost.assert_called_once_with("eng-provenance", 0.005)
    record = persistence.await_args.args[0]
    assert record["outcome"] == "success"
    assert record["safe_metadata"]["cost_usd"] == 0.005
    assert "SECRET" not in str(record)
    usage_store.reserve.assert_awaited_once()
    usage_store.settle.assert_awaited_once()
    assert usage_store.settle.await_args.kwargs["delivered"] is True


@pytest.mark.asyncio
async def test_llm_uncertain_anthropic_error_blocks_fallback_and_guessed_cost():
    _engagement_context()
    persistence = AsyncMock()
    usage_store = _model_usage_store()
    client = LiteLLMClient(
        primary_model="anthropic/primary",
        fallback_model="openai/fallback",
        provenance_callback=persistence,
        usage_store=usage_store,
    )
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="fallback answer"))],
        usage={"prompt_tokens": 11, "completion_tokens": 3},
        _hidden_params={"response_cost": 100.0},
    )
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.settings.llm_api_base", "https://example.test"),
        patch("ai_osop.core.llm_client.settings.llm_api_key", "SECRET-api-key"),
        patch("ai_osop.core.llm_client.litellm.acompletion", new_callable=AsyncMock) as provider,
        patch("ai_osop.core.observability.record_llm_call") as record_usage,
        patch("ai_osop.core.observability.record_engagement_cost") as record_cost,
    ):
        provider.side_effect = [RuntimeError("SECRET-first-error"), response]
        with pytest.raises(ModelOutcomeUncertain):
            await client.complete([{"role": "user", "content": "secret"}])
        await client.drain_provenance()
    assert provider.await_count == 1
    assert provider.await_args_list[0].kwargs["api_key"] == "SECRET-api-key"
    assert record_usage.call_count == 1
    assert record_usage.call_args.kwargs["cost_usd"] is None
    record_cost.assert_not_called()
    assert [call.args[0]["outcome"] for call in persistence.await_args_list] == ["error"]
    assert persistence.await_args_list[0].args[0]["safe_metadata"]["error_class"] == "RuntimeError"
    assert "SECRET" not in str([call.args[0] for call in persistence.await_args_list])
    usage_store.settle.assert_awaited_once()
    assert usage_store.settle.await_args.kwargs["delivered"] is False


@pytest.mark.asyncio
async def test_embedding_usage_and_mock_provider_is_not_charged():
    _engagement_context()
    persistence = AsyncMock()
    usage_store = _model_usage_store()
    client = LiteLLMClient(provenance_callback=persistence, usage_store=usage_store)
    with (
        patch("ai_osop.core.llm_client.settings.mock_llm", False),
        patch("ai_osop.core.llm_client.litellm.aembedding", new_callable=AsyncMock) as provider,
    ):
        provider.return_value = {"data": [{"embedding": [0.5, 0.7]}], "usage": {"prompt_tokens": 3}}
        assert await client.get_embedding("SECRET-text") == [0.5, 0.7]
        await client.drain_provenance()
    assert persistence.await_args.args[0]["tool_name"] == "llm.embedding"
    assert "SECRET" not in str(persistence.await_args.args[0])
    persistence.reset_mock()
    with patch("ai_osop.core.llm_client.settings.mock_llm", True):
        assert len(await client.get_embedding("anything")) == 1536
        await client.drain_provenance()
    persistence.assert_not_awaited()
    assert usage_store.reserve.await_count == 1


@pytest.mark.asyncio
async def test_provenance_skips_unscoped_calls_and_is_bounded():
    persistence = AsyncMock()
    recorder = BestEffortProvenance(persistence)
    recorder.submit(action_provenance("llm.completion", "success", 1))
    await recorder.drain()
    persistence.assert_not_awaited()
