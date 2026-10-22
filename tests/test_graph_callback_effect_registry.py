"""The signed MCP graph projection must be a real durable callback effect."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore
from ai_osop.memory.supervision_store import SupervisionConflict


class FakeTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    def begin(self):
        return self


def lifecycle():
    callback = SimpleNamespace(
        id="callback-flow-signed",
        engagement_id="eng-flow",
        task_id="task-flow",
        effect_steps=None,
        updated_at=None,
    )
    store = TerminalLifecycleStore.__new__(TerminalLifecycleStore)
    store._sessions = lambda: FakeTransaction()
    store._owned_callback = AsyncMock(return_value=callback)
    store._append_event = AsyncMock()
    return store, callback


@pytest.mark.asyncio
async def test_signed_graph_projection_uses_real_write_ahead_effect_contract():
    store, callback = lifecycle()
    plan = [
        "sync_subtask",
        "graph_upsert",
        "signed_graph_research",
        "flow_refinement",
        "downstream_schedule",
    ]
    assert await store.plan_callback_effects("cb", "lease", "owner", plan)
    assert callback.effect_steps == {
        "order": plan,
        "states": {step: "pending" for step in plan},
    }
    assert await store.plan_callback_effects("cb", "lease", "owner", plan)
    for effect in plan:
        assert await store.start_callback_effect("cb", "lease", "owner", effect)
        assert await store.confirm_callback_effect("cb", "lease", "owner", effect)
    assert callback.effect_steps["states"] == {step: "done" for step in plan}
    assert not await store.start_callback_effect("cb", "lease", "owner", "signed_graph_research")
    assert store._append_event.await_count == 2 * len(plan)


@pytest.mark.asyncio
async def test_signed_graph_projection_cannot_be_inserted_after_plan_commit():
    store, _ = lifecycle()
    initial = ["sync_subtask", "graph_upsert", "signed_graph_research"]
    assert await store.plan_callback_effects("cb", "lease", "owner", initial)
    with pytest.raises(SupervisionConflict, match="changed"):
        await store.plan_callback_effects("cb", "lease", "owner", ["sync_subtask", "graph_upsert"])
    with pytest.raises(ValueError, match="invalid"):
        await store.plan_callback_effects(
            "cb", "lease", "owner", initial + ["arbitrary-code-execution"]
        )
