"""Real terminal callback must project signed replay observations without opt-in."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher


def make_dispatcher(*, signed=True, verified=True):
    task = Task(
        id="task-replay-child",
        engagement_id="eng-owned",
        flow_id="flow-owned",
        type="navigate",
        status="completed",
        agent_type=AgentType.WORKFLOW,
        payload={"_authorization_version": 5} if signed else {},
        result={
            "status": "success",
            "verification_status": "provider_testimony_only" if verified else "unverified",
            "authorization_violation_verified": False,
        },
    )
    dispatcher = TerminalCallbackDispatcher.__new__(TerminalCallbackDispatcher)
    dispatcher.store = SimpleNamespace(plan_callback_effects=AsyncMock(return_value=True))
    dispatcher.orch = SimpleNamespace(
        _tasks={},
        graph_memory=SimpleNamespace(),
        adaptive_planner=None,
    )
    dispatcher._check_callback_owner = AsyncMock()
    dispatcher._load_authorized_task = AsyncMock(return_value=task)
    dispatcher._apply_effect = AsyncMock()
    dispatcher.worker_id = "callbacks-test"
    return dispatcher, task


@pytest.mark.asyncio
async def test_signed_replay_observation_projects_without_model_graph_retrieval(monkeypatch):
    monkeypatch.setattr("ai_osop.memory.graph_research_context.research_enabled", lambda: False)
    dispatcher, task = make_dispatcher()
    await TerminalCallbackDispatcher._project(
        dispatcher,
        {
            "id": "callback-replay",
            "lease_id": "lease-one",
            "engagement_id": task.engagement_id,
            "task_id": task.id,
        },
    )
    effects = dispatcher.store.plan_callback_effects.await_args.args[3]
    assert "signed_graph_research" in effects
    assert "graph_upsert" in effects
    assert dispatcher._apply_effect.await_count == len(effects)
    assert dispatcher.orch._tasks[task.id] is task


@pytest.mark.asyncio
@pytest.mark.parametrize("signed,verified", [(False, True), (True, False)])
async def test_unsigned_or_unverified_replay_does_not_invent_signed_projection(
    monkeypatch, signed, verified
):
    monkeypatch.setattr("ai_osop.memory.graph_research_context.research_enabled", lambda: False)
    dispatcher, task = make_dispatcher(signed=signed, verified=verified)
    await TerminalCallbackDispatcher._project(
        dispatcher,
        {
            "id": "callback-replay",
            "lease_id": "lease-one",
            "engagement_id": task.engagement_id,
            "task_id": task.id,
        },
    )
    effects = dispatcher.store.plan_callback_effects.await_args.args[3]
    assert "signed_graph_research" not in effects


@pytest.mark.asyncio
async def test_signed_source_target_terminal_callback_registers_durable_comparison_effect(monkeypatch):
    monkeypatch.setattr("ai_osop.memory.graph_research_context.research_enabled", lambda: False)
    dispatcher, task = make_dispatcher()
    task.payload["_comparison_role"] = "target"
    task.payload["source_user_label"] = "alice"
    task.payload["target_user_label"] = "bob"
    await TerminalCallbackDispatcher._project(
        dispatcher,
        {
            "id": "callback-paired",
            "lease_id": "lease-paired",
            "engagement_id": task.engagement_id,
            "task_id": task.id,
        },
    )
    effects = dispatcher.store.plan_callback_effects.await_args.args[3]
    assert effects.count("signed_diff_comparison") == 1
    assert effects.index("signed_graph_research") < effects.index("signed_diff_comparison")
    assert "graph_upsert" in effects
    assert dispatcher._apply_effect.await_count == len(effects)
