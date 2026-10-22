"""A signed TaskORM payload stays immutable across agent-local alias handling."""

from copy import deepcopy
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from tests.test_agent_lifecycle import _DummyAgent


def harness(result=None):
    context = SimpleNamespace(
        agent_id="agent-signed-input",
        agent_type=AgentType.RECON,
        session_id="eng-signed-input",
        current_task=None,
        status="idle",
        task_history=[],
        last_heartbeat=None,
        rate_limiter=SimpleNamespace(
            acquire=AsyncMock(),
            record_backpressure=Mock(),
        ),
    )
    agent = _DummyAgent(context)
    agent._validate_task = AsyncMock()
    agent.supervision_checkpoint = AsyncMock()
    agent._get_relevant_skills = AsyncMock(return_value=[])
    agent._update_working_memory = AsyncMock()
    agent._log_task_completion = AsyncMock()
    agent._log_task_failure = AsyncMock()
    agent._validate_output = AsyncMock(
        side_effect=lambda value: value,
    )
    task = Task(
        id="task-signed-input",
        engagement_id=context.session_id,
        type="full_recon",
        agent_type=AgentType.RECON,
        status="running",
        started_at=datetime.utcnow(),
        assigned_agent_id=context.agent_id,
        payload={
            "url": "https://example.com/",
            "_authorization_version": 5,
            "approval_id": "approval-persisted",
        },
    )
    original = deepcopy(task.payload)
    return agent, task, original


@pytest.mark.asyncio
async def test_alias_normalization_does_not_mutate_canonical_signed_payload():
    agent, task, original = harness()
    seen = []

    async def execute(local):
        seen.append(local)
        assert local is not task
        assert local.payload["target"] == "https://example.com/"
        assert local.payload["targets"] == ["https://example.com/"]
        assert local.payload["engagement_id"] == task.engagement_id
        assert local.payload["_authorization_version"] == 5
        # Research/supervision reads the authoritative Task snapshot, not
        # derived aliases that would change its TaskORM SHA provenance.
        assert agent.ctx.current_task is task
        assert agent.ctx.current_task.payload == original
        await agent.supervision_checkpoint(agent.ctx.current_task)
        return {"status": "success", "accepted": True}

    agent._execute = AsyncMock(side_effect=execute)
    outcome = await agent.execute_task(task)
    assert outcome["accepted"] is True
    assert len(seen) == 1
    assert task.payload == original
    assert task.status == "completed"
    agent._validate_task.assert_awaited_once_with(task)
    assert agent.ctx.current_task is None


@pytest.mark.asyncio
async def test_unknown_or_failure_never_persists_agent_local_aliases():
    for result in ("timeout", "failed"):
        agent, task, original = harness()
        if result == "failed":
            agent._execute = AsyncMock(side_effect=OSError("model maybe accepted"))
        else:
            agent._execute = AsyncMock(return_value={"status": "execution_unknown"})
        outcome = await agent.execute_task(task)
        assert outcome["status"] in {"failed", "execution_unknown"}
        assert task.payload == original
        assert task.retry_count == 0
        agent.ctx.rate_limiter.acquire.assert_awaited_once()
