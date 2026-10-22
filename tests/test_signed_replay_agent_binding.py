"""Signed differential replay can only stage children through the real scheduler."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.authenticated_resource_paths import ResourcePathDenied
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


def make_agent(*, legitimate=True, bound=True):
    sm = SessionMemory.__new__(SessionMemory)
    executor = SimpleNamespace(session_memory=sm) if bound else None
    payload = {
        "workflow_id": "workflow-1", "source_user_label": "owner-a",
        "target_user_label": "target-b", "_authorization_version": 2,
        "_flow_revision": 2,
    }
    parent = Task(
        type="replay_for_diff_auth", engagement_id="eng-1",
        agent_type=AgentType.WORKFLOW, payload=payload,
        approval_required=True,
    ) if legitimate else None
    agent = SimpleNamespace(
        ctx=SimpleNamespace(
            current_task=parent, session_id="eng-1",
            task_executor=executor, session_memory=sm,
        ),
        diff_auth_engine=SimpleNamespace(run_differential_test=AsyncMock(
            return_value={"status": "pending_execution_approval", "queued_task_ids": ["task-one"],
                          "findings_count": 0, "findings": []},
        )),
    )
    return agent, payload


@pytest.mark.asyncio
async def test_signed_replay_stages_only_and_never_fakes_findings():
    agent, payload = make_agent()
    result = await PlaywrightAgent._execute_diff_auth_replay(agent, payload)
    assert result["status"] == "pending_execution_approval"
    assert result["findings_count"] == 0
    agent.diff_auth_engine.run_differential_test.assert_awaited_once_with(
        "workflow-1", ["target-b"], "eng-1", agent.ctx.task_executor,
        parent_task=agent.ctx.current_task, source_user_label="owner-a",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", ["no_parent", "unbound", "wrong_session", "payload_tamper"])
async def test_untrusted_replay_runtime_cannot_start_nested_navigation(broken):
    agent, payload = make_agent(legitimate=broken != "no_parent", bound=broken != "unbound")
    if broken == "wrong_session":
        agent.ctx.session_id = "eng-other"
    if broken == "payload_tamper":
        payload = {**payload, "target_user_label": "foreign"}
    with pytest.raises(PermissionError):
        await PlaywrightAgent._execute_diff_auth_replay(agent, payload)
    agent.diff_auth_engine.run_differential_test.assert_not_awaited()


@pytest.mark.asyncio
async def test_register_binds_real_workflow_only_to_identical_durable_memory():
    sm = SessionMemory.__new__(SessionMemory)
    orch = SimpleNamespace(session_memory=sm, _agents={})
    agent = SimpleNamespace(
        ctx=SimpleNamespace(agent_id="browser-1", agent_type=AgentType.WORKFLOW,
                            session_memory=sm, task_executor=None),
        initialize=AsyncMock(),
    )
    await Orchestrator.register_agent(orch, agent)
    assert agent.ctx.task_executor is orch
    assert orch._agents["browser-1"] is agent

    other = SimpleNamespace(
        ctx=SimpleNamespace(agent_id="browser-foreign", agent_type=AgentType.WORKFLOW,
                            session_memory=SessionMemory.__new__(SessionMemory),
                            task_executor=None),
        initialize=AsyncMock(),
    )
    await Orchestrator.register_agent(orch, other)
    assert other.ctx.task_executor is None


@pytest.mark.asyncio
async def test_signed_navigation_uses_pg_identity_not_stale_redis():
    user = SimpleNamespace(
        engagement_id="eng-1", user_label="target-b", cookies=[{"name": "sid"}],
        local_storage={}, is_expired=lambda **_: False,
        to_playwright_storage_state=lambda: {"cookies": [{"name": "sid"}], "origins": []},
    )
    store = SimpleNamespace(
        get_session_authoritative=AsyncMock(return_value=user),
        get_session_or_none=AsyncMock(side_effect=AssertionError("stale Redis")),
    )
    task = Task(type="navigate", agent_type=AgentType.WORKFLOW, engagement_id="eng-1",
                payload={"_authorization_version": 2, "url": "https://authorized.example"})
    agent = SimpleNamespace(ctx=SimpleNamespace(current_task=task, session_id="eng-1"),
                            session_store=store)
    assert await PlaywrightAgent._load_storage_state(agent, "target-b") == {
        "cookies": [{"name": "sid"}], "origins": [],
    }
    store.get_session_or_none.assert_not_awaited()
    store.get_session_authoritative.return_value = None
    with pytest.raises(ResourcePathDenied):
        await PlaywrightAgent._load_storage_state(agent, "target-b")
    store.get_session_or_none.assert_not_awaited()
