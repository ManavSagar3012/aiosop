from unittest.mock import AsyncMock, patch

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.stateful_logic_agent import StatefulLogicAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import BusinessInvariant, Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "stateful-1"
    ctx.agent_type = AgentType.STATEFUL_LOGIC
    ctx.session_id = "test-session"
    ctx.llm_client = AsyncMock()
    ctx.session_memory = AsyncMock()
    ctx.graph_memory = AsyncMock()
    ctx.persona = "test_persona"
    ctx.current_task = None
    ctx.cost_incurred = 0.0
    ctx.audit_callback = AsyncMock()
    ctx.coordination_bus = AsyncMock()
    ctx.mcp_registry = AsyncMock()
    ctx.scope = None
    return ctx


@pytest.fixture
def agent(mock_context):
    return StatefulLogicAgent(mock_context)


# ------------------------------------------------------------------
# map_business_process: simple pay + ship workflow
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_map_business_process_pay_ship(agent) -> None:
    await agent.initialize()

    # graph_memory.get_workflow_steps returns steps that contain "pay" and "ship"
    agent.ctx.graph_memory.get_workflow_steps.return_value = [
        {"action_type": "pay", "endpoint": "/api/pay"},
        {"action_type": "ship", "endpoint": "/api/ship"},
    ]
    agent.ctx.graph_memory.add_business_invariant.return_value = None

    task = Task(
        id="task-sl-1",
        type="map_business_process",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"process_name": "order_flow", "workflow_id": "wf-001"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["states_mapped"] == 2
    # "pay" + "ship" triggers the "Payment Required Before Shipping" invariant
    assert result["invariants_discovered"] >= 1
    assert result["violation_tasks_queued"] >= 1
    agent.ctx.graph_memory.get_workflow_steps.assert_awaited_once_with("wf-001")


# ------------------------------------------------------------------
# map_business_process: workflow with delete action
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_map_business_process_with_delete(agent) -> None:
    await agent.initialize()

    agent.ctx.graph_memory.get_workflow_steps.return_value = [
        {"action_type": "delete", "endpoint": "/api/resource/1"},
    ]
    agent.ctx.graph_memory.add_business_invariant.return_value = None

    task = Task(
        id="task-sl-2",
        type="map_business_process",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"process_name": "resource_mgmt", "workflow_id": "wf-002"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["states_mapped"] == 1
    # "delete" triggers "Only Resource Owner Can Delete"
    assert result["invariants_discovered"] >= 1


# ------------------------------------------------------------------
# map_business_process: empty workflow returns zero invariants
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_map_business_process_empty_workflow(agent) -> None:
    await agent.initialize()

    agent.ctx.graph_memory.get_workflow_steps.return_value = []

    task = Task(
        id="task-sl-3",
        type="map_business_process",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"process_name": "empty_flow", "workflow_id": "wf-003"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["states_mapped"] == 0
    assert result["invariants_discovered"] == 0
    assert result["violation_tasks_queued"] == 0


# ------------------------------------------------------------------
# map_business_process: invariant persistence failure is swallowed
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_map_business_process_invariant_persist_failure(agent) -> None:
    await agent.initialize()

    agent.ctx.graph_memory.get_workflow_steps.return_value = [
        {"action_type": "pay", "endpoint": "/api/pay"},
        {"action_type": "ship", "endpoint": "/api/ship"},
    ]
    agent.ctx.graph_memory.add_business_invariant.side_effect = RuntimeError("DB down")

    task = Task(
        id="task-sl-4",
        type="map_business_process",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"process_name": "order_flow", "workflow_id": "wf-004"},
        engagement_id="test-session",
    )

    # Should NOT raise — the agent swallows invariant persistence errors
    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["invariants_discovered"] >= 1


# ------------------------------------------------------------------
# violate_invariant: with invariant_id
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_with_id(agent) -> None:
    await agent.initialize()

    agent.ctx.graph_memory.mark_invariant_violated.return_value = None

    task = Task(
        id="task-sl-5",
        type="violate_invariant",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={
            "strategy": "jump_ahead",
            "invariant_id": "inv-001",
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["violation_successful"] is True
    assert result["impact"] == "High (Financial Loss)"
    assert "reasoning" in result
    agent.ctx.graph_memory.mark_invariant_violated.assert_awaited_once_with("inv-001")


# ------------------------------------------------------------------
# violate_invariant: without invariant_id
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_without_id(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-sl-6",
        type="violate_invariant",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"strategy": "race_condition"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["violation_successful"] is True
    # mark_invariant_violated should NOT be called when no invariant_id
    agent.ctx.graph_memory.mark_invariant_violated.assert_not_awaited()


# ------------------------------------------------------------------
# violate_invariant: mark_invariant_violated failure is swallowed
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_mark_failure_swallowed(agent) -> None:
    await agent.initialize()

    agent.ctx.graph_memory.mark_invariant_violated.side_effect = RuntimeError("DB error")

    task = Task(
        id="task-sl-7",
        type="violate_invariant",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"strategy": "cross_tenant", "invariant_id": "inv-002"},
        engagement_id="test-session",
    )

    # Should NOT raise — the agent swallows the error
    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["violation_successful"] is True


# ------------------------------------------------------------------
# analyze_state_drift
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_analyze_state_drift(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-sl-8",
        type="analyze_state_drift",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"resource_id": "res-42"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["drift_detected"] is False


# ------------------------------------------------------------------
# Unknown task type
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_stateful_logic_unknown_task_type(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-sl-9",
        type="unknown_task_type",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "error"
    assert "Unknown task" in result["message"]
