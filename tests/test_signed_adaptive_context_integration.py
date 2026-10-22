"""Adaptive checkpoint uses source-bound free compaction for signed Flow tasks."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.engagement_controller import GoalOrientedEngagementController


def _subject():
    sm = SessionMemory.__new__(SessionMemory)
    sm.create_checkpoint = AsyncMock(return_value="checkpoint-only")
    sm.persist_session_state = AsyncMock()
    source = Task(
        id="task-source-signed", type="planner_inference",
        agent_type=AgentType.RECON,
        engagement_id="eng-signed",
        flow_id="flow-signed",
        status="completed",
        payload={"_authorization_version": 6, "source": "durable"},
    )
    flow = FlowRecord(
        id="flow-signed", engagement_id="eng-signed",
        objective="Human-approved research context", status="running", revision=4,
    )
    sm.load_task_authoritative = AsyncMock(side_effect=lambda key: (
        source if key == source.id else None
    ))
    sm.load_flow = AsyncMock(return_value=flow)
    sm.assert_signed_authorization = AsyncMock(
        return_value=SimpleNamespace(version=6),
    )
    orch = SimpleNamespace(
        session_memory=sm,
        _sessions={},
        _agents={"ctx": SimpleNamespace(
            ctx=SimpleNamespace(agent_type=AgentType.CONTEXT_MANAGER),
        )},
        _tasks={},
        schedule_task=AsyncMock(),
    )
    return GoalOrientedEngagementController(orch), orch, sm, source


@pytest.mark.asyncio
async def test_signed_flow_adaptive_checkpoint_only_schedules_free_extract_compaction():
    controller, orch, sm, source = _subject()
    await controller._checkpoint_and_summarize(
        source, {"iterations": 2, "overall_goal": "Bounded signed research"},
    )
    orch.schedule_task.assert_awaited_once()
    task = orch.schedule_task.await_args.args[0]
    assert task.type == "compact_context"
    assert task.agent_type == AgentType.CONTEXT_MANAGER
    assert task.flow_id == source.flow_id
    assert task.dependencies == [source.id]
    assert task.max_retries == 0
    assert task.payload == {
        "source_task_ids": [source.id],
        "max_items": 8,
        "_authorization_version": 6,
    }
    assert "overall_goal" not in task.payload
    assert "summarize_context" not in str(task.model_dump())


@pytest.mark.asyncio
async def test_revoked_or_stale_signed_source_does_not_schedule_compaction():
    controller, orch, sm, source = _subject()
    sm.assert_signed_authorization.side_effect = PermissionError("revoked")
    await controller._checkpoint_and_summarize(
        source, {"iterations": 2, "overall_goal": "Not authoritative"},
    )
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_stale_flow_or_source_authorization_denies_context_preparation():
    controller, orch, sm, source = _subject()
    sm.load_flow.return_value.status = "paused"
    await controller._checkpoint_and_summarize(
        source, {"iterations": 2, "overall_goal": "Paused"},
    )
    orch.schedule_task.assert_not_awaited()
    sm.load_flow.return_value.status = "running"
    source.payload["_authorization_version"] = 5
    await controller._checkpoint_and_summarize(
        source, {"iterations": 2, "overall_goal": "Stale"},
    )
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_persisted_compaction_identity_blocks_restart_duplicate():
    controller, orch, sm, source = _subject()
    sm.load_task_authoritative.side_effect = lambda key: (
        source if key == source.id else SimpleNamespace(id=key)
    )
    await controller._checkpoint_and_summarize(
        source, {"iterations": 2, "overall_goal": "No duplicate"},
    )
    orch.schedule_task.assert_not_awaited()
