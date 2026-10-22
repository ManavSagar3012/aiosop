"""Signed differential observations keep durable Flow lineage without leaking bodies.

These tests do not invoke a browser, model or application database.
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import SubtaskRecord, Task
from ai_osop.core.signed_replay_comparison import observation_subtask_id
from ai_osop.orchestrator.flow_refinement import BoundedFlowRefiner
from ai_osop.orchestrator.orchestrator import Orchestrator


def _signed_task():
    task_id = "task-observed-target"
    return Task(
        id=task_id,
        engagement_id="eng-private",
        type="navigate",
        agent_type=AgentType.WORKFLOW,
        flow_id="flow-private",
        parent_task_id="task-replay-parent",
        subtask_id=observation_subtask_id(task_id),
        status="completed",
        approval_required=True,
        payload={"_comparison_role": "target", "user_label": "bob"},
    )


@pytest.mark.asyncio
async def test_signed_terminal_subtask_projection_never_stores_cross_account_response():
    task = _signed_task()
    subtask = SubtaskRecord(
        id=task.subtask_id,
        engagement_id=task.engagement_id,
        flow_id=task.flow_id,
        task_id=task.parent_task_id,
        title="Signed target observation",
        task_type="navigate",
        agent_type=AgentType.WORKFLOW,
        status="dispatched",
        execution_task_id=task.id,
    )
    memory = SimpleNamespace(
        list_subtasks=AsyncMock(return_value=[subtask]),
        store_subtask=AsyncMock(),
    )
    orchestrator = Orchestrator.__new__(Orchestrator)
    orchestrator.session_memory = memory
    private_result = {
        "status": "success",
        "body": {"access_token": "cross-account-private"},
        "cookies": "session=private",
        "provider_evidence": {"Authorization": "Bearer private"},
        "response_body_sha256": "deadbeef" * 8,
        "http_status_code": 200,
    }
    await orchestrator._sync_subtask_result(task, "completed", private_result)
    memory.store_subtask.assert_awaited_once()
    persisted = memory.store_subtask.await_args.args[0]
    rendered = persisted.result_summary
    assert json.loads(rendered) == {
        "status": "completed",
        "comparison_role": "target",
        "verification_status": "provider_testimony_only",
        "target_effect_verified": False,
        "authorization_violation_verified": False,
    }
    assert all(
        secret not in rendered
        for secret in ("cross-account-private", "Bearer", "cookies", "deadbeef", "200")
    )
    # An imported/malformed task that lost its approval flag is never
    # permitted to downgrade this privacy barrier.
    memory.store_subtask.reset_mock()
    task.approval_required = False
    await orchestrator._sync_subtask_result(task, "failed", private_result)
    redacted = memory.store_subtask.await_args.args[0].result_summary
    assert json.loads(redacted)["verification_status"] == "provider_testimony_only"
    assert "cross-account-private" not in redacted


@pytest.mark.asyncio
async def test_signed_observation_cannot_automatically_start_flow_refinement():
    task = _signed_task()
    orch = Orchestrator.__new__(Orchestrator)
    orch.flow_refiner = SimpleNamespace(on_subtask_completed=AsyncMock())
    await orch._refine_completed_flow_subtask(task, {"status": "success"})
    orch.flow_refiner.on_subtask_completed.assert_not_awaited()

    # Also fence direct callers of the refiner, not just the orchestrator.
    refiner = BoundedFlowRefiner.__new__(BoundedFlowRefiner)
    result = await refiner.on_subtask_completed(task, {"status": "success"})
    assert result == {
        "status": "ignored",
        "reason": "signed_observation_requires_review",
    }
