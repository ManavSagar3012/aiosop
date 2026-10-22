"""Safe cooperative control and real model-boundary delivery of operator input."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.recon_agent import ReconAgent
from ai_osop.agents.supervision import AgentSupervision
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


def _message():
    return {
        "id": "msg-test",
        "task_id": "task-test",
        "engagement_id": "eng-test",
        "session_id": "supervision-task-test",
        "content": "Review the existing scoped findings before next step.",
    }


def _gate():
    store = AsyncMock()
    store.list_controls.return_value = []
    store.claim_inbox.return_value = [_message()]
    store.list_messages.return_value = []
    store.ack_inbox.return_value = {
        "id": "msg-test", "delivery_state": "consumed",
    }
    return AgentSupervision(
        store, "eng-test", "task-test", "consumer-test",
        AsyncMock(), poll_seconds=0.001,
    )


@pytest.mark.asyncio
async def test_inbox_is_not_acknowledged_until_consumed_by_model():
    gate = _gate()
    claimed = await gate.claim_model_input()
    assert claimed[0]["id"] == "msg-test"
    gate.store.ack_inbox.assert_not_awaited()
    context = gate.operator_context(claimed)
    assert "untrusted task context" in context
    assert _message()["content"] in context
    await gate.acknowledge_model_input(claimed)
    gate.store.ack_inbox.assert_awaited_once_with(
        "msg-test", "consumer-test", "consumed"
    )


@pytest.mark.asyncio
async def test_cooperative_pause_is_acknowledged_only_at_checkpoint():
    gate = _gate()
    pause = {
        "request_id": "control-pause", "action": "pause", "status": "pending"
    }
    resume = {
        "request_id": "control-resume", "action": "resume", "status": "pending"
    }
    gate.store.list_controls.side_effect = [[pause], [resume]]
    await gate.checkpoint()
    assert gate.authorize.await_count == 2
    assert [call.args[:2] for call in gate.store.resolve_control.await_args_list] == [
        ("control-pause", "acknowledged"),
        ("control-resume", "acknowledged"),
    ]


@pytest.mark.asyncio
async def test_cooperative_cancel_refuses_further_agent_dispatch():
    gate = _gate()
    gate.store.list_controls.return_value = [
        {"request_id": "control-cancel", "action": "cancel", "status": "pending"}
    ]
    with pytest.raises(asyncio.CancelledError):
        await gate.checkpoint()
    gate.store.claim_inbox.assert_not_awaited()
    gate.store.resolve_control.assert_not_awaited()


@pytest.mark.asyncio
async def test_distributed_pause_unknown_becomes_acknowledged_only_at_real_boundary():
    gate = _gate()
    gate.store.list_controls.side_effect = [
        [{"request_id": "ctrl-1", "action": "pause", "status": "unknown"}],
        [{"request_id": "ctrl-2", "action": "resume", "status": "pending"}],
    ]
    await gate.checkpoint()
    called = gate.store.resolve_control.await_args_list
    assert called[0].args[:2] == ("ctrl-1", "acknowledged")
    assert called[0].args[2]["execution_stopped"] is False


def _recon_agent():
    ctx = SimpleNamespace(
        agent_id="agent-test",
        agent_type=AgentType.RECON,
        session_id="eng-test",
        supervision_store=AsyncMock(),
        supervision_consumer_id="consumer-test",
        current_task=Task(
            id="task-test", type="full_recon", engagement_id="eng-test",
            agent_type=AgentType.RECON,
        ),
        llm_client=AsyncMock(),
        session_memory=AsyncMock(),
    )
    ctx.supervision_store.list_controls.return_value = []
    ctx.supervision_store.claim_inbox.return_value = [_message()]
    ctx.supervision_store.list_messages.return_value = []
    ctx.supervision_store.ack_inbox.return_value = {
        "id": "msg-test", "delivery_state": "consumed",
    }
    agent = ReconAgent(ctx)
    agent._validate_task = AsyncMock()
    return agent, ctx


@pytest.mark.asyncio
async def test_specialist_recon_prompt_gets_operator_input_and_durable_ack():
    agent, ctx = _recon_agent()
    ctx.llm_client.complete.return_value = "analysis-complete"
    result = await agent.think("Summarize approved work", [])
    assert result == "analysis-complete"
    model_messages = ctx.llm_client.complete.await_args.args[0]
    assert "Review the existing scoped findings" in model_messages[1]["content"]
    assert "Use the following specialized skills" in model_messages[0]["content"]
    ctx.supervision_store.ack_inbox.assert_awaited_once_with(
        "msg-test", "consumer-test", "consumed"
    )


@pytest.mark.asyncio
async def test_model_failure_does_not_lose_intervention():
    agent, ctx = _recon_agent()
    ctx.llm_client.complete.side_effect = RuntimeError("model unavailable")
    with pytest.raises(RuntimeError, match="model unavailable"):
        await agent.think("Summarize approved work", [])
    ctx.supervision_store.ack_inbox.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_consumption_ack_cannot_claim_delivered():
    from ai_osop.agents.supervision import SupervisionDeliveryUncertain

    agent, ctx = _recon_agent()
    ctx.llm_client.complete.return_value = "model succeeded"
    ctx.supervision_store.ack_inbox.return_value = None
    with pytest.raises(SupervisionDeliveryUncertain, match="uncertain"):
        await agent.think("Think about authorized evidence", [])


@pytest.mark.asyncio
async def test_revalidation_failure_prevents_model_and_message_claim():
    agent, ctx = _recon_agent()
    agent._validate_task.side_effect = ValueError("engagement authorization revoked")
    with pytest.raises(ValueError, match="authorization revoked"):
        await agent.think("Summarize approved work", [])
    ctx.supervision_store.claim_inbox.assert_not_awaited()
    ctx.llm_client.complete.assert_not_awaited()


@pytest.mark.asyncio
async def test_extractively_compacted_history_is_durable_and_source_anchored():
    gate = _gate()
    originals = [
        {
            **_message(),
            "id": "msg-" + str(index),
            "role": "operator",
            "delivery_state": "consumed",
            "content": "Study evidence " + str(index) + " and password=NEVER_PERSIST_RAW",
        }
        for index in range(12)
    ]
    gate.store.list_messages.return_value = originals
    await gate.compact_if_needed()
    call = gate.store.append_message.await_args.kwargs
    assert call["role"] == "agent"
    assert call["task_id"] == "task-test"
    assert call["session_id"] == "supervision-task-test"
    assert "msg-11" in call["content"]
    assert "NEVER_PERSIST_RAW" not in call["content"]
    assert call["idempotency_key"].startswith("summary-")
    history = await gate.recent_history_context()
    assert "msg-11" in history
    assert "NEVER_PERSIST_RAW" not in history
