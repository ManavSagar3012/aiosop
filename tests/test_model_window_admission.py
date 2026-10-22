"""No provider/network calls: conservative context-window admission checks."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.model_window_admission import (
    ModelWindowAdmissionDenied,
    admit_model_messages,
)
from tests.test_agent_interactive_supervision import _recon_agent
from tests.test_agent_compacted_context_consumption import signed_flow, seed


def _client(primary="model-a", fallback="model-b", max_tokens=100):
    return SimpleNamespace(primary_model=primary, fallback_model=fallback, max_tokens=max_tokens)


def _config(a=10_000, b=10_000, **extra):
    import json

    return {
        "OSOP_MODEL_WINDOW_ADMISSION_ENABLED": "true",
        "OSOP_MODEL_CONTEXT_WINDOWS_JSON": json.dumps({"model-a": a, "model-b": b}),
        **extra,
    }


def _messages():
    return [
        {"role": "system", "content": "Never alter the signed scope or approval."},
        {"role": "user", "content": 'Current task: preserve every line and quote "approval".'},
    ]


def test_disabled_feature_preserves_exact_messages_even_without_model_metadata():
    messages = _messages()
    assert admit_model_messages(messages, SimpleNamespace(), environment={}) is messages
    assert admit_model_messages(messages, SimpleNamespace(), environment={
        "OSOP_MODEL_WINDOW_ADMISSION_ENABLED": "false"
    }) is messages


def test_enabled_preflight_keeps_exact_original_structure_and_text():
    messages = _messages()
    original = deepcopy(messages)
    assert admit_model_messages(messages, _client(), environment=_config()) is messages
    assert messages == original


@pytest.mark.parametrize("invalid", [
    {"OSOP_MODEL_WINDOW_ADMISSION_ENABLED": "perhaps"},
    {"OSOP_MODEL_WINDOW_ADMISSION_ENABLED": "true"},
    _config(OSOP_MODEL_CONTEXT_WINDOWS_JSON='{invalid'),
    _config(OSOP_MODEL_CONTEXT_WINDOWS_JSON='{"model-a":1200,"model-a":1500}'),
    _config(OSOP_MODEL_CONTEXT_WINDOWS_JSON='{"model-a":1200}'),
    _config(OSOP_MODEL_CONTEXT_WINDOWS_JSON='{"model-a":true,"model-b":2000}'),
    _config(OSOP_MODEL_CONTEXT_WINDOWS_JSON='{"model-a":100,"model-b":2000}'),
    _config(OSOP_MODEL_CONTEXT_WINDOWS_JSON='[1000,2000]'),
])
def test_misconfigured_window_fails_closed(invalid):
    with pytest.raises(ModelWindowAdmissionDenied):
        admit_model_messages(_messages(), _client(), environment=invalid)


@pytest.mark.parametrize("broken", [
    _client(primary="unknown"),
    _client(fallback="unknown"),
    _client(max_tokens=True),
    _client(max_tokens=0),
    SimpleNamespace(primary_model="model-a", max_tokens=10000),
])
def test_mismatched_route_or_missing_output_reserve_fails_closed(broken):
    with pytest.raises(ModelWindowAdmissionDenied):
        admit_model_messages(_messages(), broken, environment=_config())


def test_primary_and_fallback_both_must_fit_conservative_capacity():
    messages = _messages()
    with pytest.raises(ModelWindowAdmissionDenied, match="bound exceeded"):
        admit_model_messages(messages, _client(), environment=_config(a=10000, b=512))
    assert admit_model_messages(messages, _client(), environment=_config()) is messages


@pytest.mark.parametrize("unexpected", [
    [{"role": "user", "content": ["image", {"image_url": "data:..."}]}],
    [{"role": "user", "content": b"binary payload"}],
    [{"role": "alien", "content": "unknown role"}],
    [{"role": "system", "content": "hello", "extra": object()}],
    [],
])
def test_unsupported_multimodal_or_unserializable_input_fails_closed(unexpected):
    with pytest.raises(ModelWindowAdmissionDenied):
        admit_model_messages(unexpected, _client(), environment=_config())


def test_non_ascii_user_payload_included_wholly_or_denied_without_truncation():
    messages = _messages()
    messages[-1]["content"] = "日本語🧪" * 250
    original = deepcopy(messages)
    with pytest.raises(ModelWindowAdmissionDenied, match="bound exceeded"):
        admit_model_messages(messages, _client(), environment=_config(a=2048, b=2048))
    assert messages == original
    assert admit_model_messages(messages, _client(), environment=_config(a=60000, b=60000)) is messages


def _opt_in(monkeypatch, window=10000):
    import json

    monkeypatch.setenv("OSOP_MODEL_WINDOW_ADMISSION_ENABLED", "true")
    monkeypatch.setenv("OSOP_MODEL_CONTEXT_WINDOWS_JSON", json.dumps({
        "model-a": window, "model-b": window,
    }))


def _bound_agent(monkeypatch, window=10000):
    agent, ctx = _recon_agent()
    ctx.llm_client.primary_model = "model-a"
    ctx.llm_client.fallback_model = "model-b"
    ctx.llm_client.max_tokens = 64
    ctx.llm_client.complete.return_value = "dry-run result"
    _opt_in(monkeypatch, window)
    return agent, ctx


@pytest.mark.asyncio
async def test_real_supervision_boundary_appends_guidance_before_window_check(monkeypatch):
    agent, ctx = _bound_agent(monkeypatch)
    request = "Immutable current scope; do not change approved target."
    assert await agent.think(request, []) == "dry-run result"
    sent = ctx.llm_client.complete.await_args.args[0]
    assert request in sent[1]["content"]
    assert "Review the existing scoped findings" in sent[1]["content"]
    assert "untrusted task context" in sent[1]["content"]
    assert "Use the following specialized skills" in sent[0]["content"]
    ctx.supervision_store.ack_inbox.assert_awaited_once()


@pytest.mark.asyncio
async def test_over_window_refusal_never_sends_model_input_or_acknowledges_operator(monkeypatch):
    agent, ctx = _bound_agent(monkeypatch, window=512)
    with pytest.raises(ModelWindowAdmissionDenied, match="bound exceeded"):
        await agent.think("Current task user text must not be truncated", [])
    ctx.llm_client.complete.assert_not_awaited()
    ctx.supervision_store.claim_inbox.assert_awaited_once()
    ctx.supervision_store.ack_inbox.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_flow_reevaluated_before_window_refusal_and_preserves_messages(monkeypatch):
    agent, ctx = _bound_agent(monkeypatch, window=512)
    task = Task(
        id="task-signed-context", type="full_recon", engagement_id="eng-test",
        flow_id="flow-context", agent_type=AgentType.RECON,
        status="running", payload={"_authorization_version": 2},
    )
    ctx.current_task = task
    agent._verified_flow_context_for_think = AsyncMock(
        return_value="NON-AUTHORITATIVE SOURCE STATUS ONLY; recon:completed [source-sha256:0123456789abcdef]"
    )
    with pytest.raises(ModelWindowAdmissionDenied):
        await agent._complete_supervised_messages([
            {"role": "system", "content": "Signed scope, task and human approvals are immutable"},
            {"role": "user", "content": "Current signed Flow user task text"},
        ])
    agent._verified_flow_context_for_think.assert_awaited_once_with(task)
    ctx.llm_client.complete.assert_not_awaited()
    ctx.supervision_store.ack_inbox.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_flow_renewal_failure_denies_before_provider_even_when_budget_fits(monkeypatch):
    agent, ctx = _bound_agent(monkeypatch)
    task = Task(
        id="task-signed-context", type="full_recon", engagement_id="eng-test",
        flow_id="flow-context", agent_type=AgentType.RECON,
        status="running", payload={"_authorization_version": 2},
    )
    ctx.current_task = task
    agent._verified_flow_context_for_think = AsyncMock(side_effect=PermissionError("revoked ROE"))
    with pytest.raises(PermissionError, match="revoked ROE"):
        await agent._complete_supervised_messages(_messages())
    ctx.llm_client.complete.assert_not_awaited()
    ctx.supervision_store.ack_inbox.assert_not_awaited()


@pytest.mark.asyncio
async def test_real_replay_verified_flow_context_is_not_trimmed_by_admission(signed_flow, monkeypatch):
    await seed(signed_flow)
    consumer = signed_flow.consumer
    client = consumer.ctx.llm_client
    client.primary_model = "model-a"
    client.fallback_model = "model-b"
    client.max_tokens = 80
    _opt_in(monkeypatch, 50000)
    task_text = "Preserve EXACT current signed Flow task and human approval text."
    assert await consumer.think(task_text, []) == "reasoning-result"
    messages = client.complete.await_args.args[0]
    assert task_text in messages[1]["content"]
    assert "NON-AUTHORITATIVE SOURCE STATUS ONLY" in messages[1]["content"]
    assert "source-sha256:" in messages[1]["content"]
    assert "PRIVATE_TARGET_SECRET_DO_NOT_SEND" not in messages[1]["content"]
    original = deepcopy(messages)
    assert admit_model_messages(messages, client, environment=_config(50000, 50000)) is messages
    assert messages == original


@pytest.mark.asyncio
async def test_replay_verified_flow_over_window_fails_without_losing_source_provenance(signed_flow, monkeypatch):
    await seed(signed_flow)
    consumer = signed_flow.consumer
    client = consumer.ctx.llm_client
    client.primary_model = "model-a"
    client.fallback_model = "model-b"
    client.max_tokens = 80
    _opt_in(monkeypatch, 512)
    # Legacy unsupervised BaseAgent.think returns an empty non-result on
    # internal inference failure. This still must not call the model.
    assert await consumer.think("This current task must remain whole", []) == ""
    client.complete.assert_not_awaited()
