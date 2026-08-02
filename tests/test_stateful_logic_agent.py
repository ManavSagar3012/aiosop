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
# violate_invariant: NO concrete request -> honest non-executed result
# (the old behavior fabricated violation_successful=True here)
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_hypothesis_only_not_fabricated(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-sl-5",
        type="violate_invariant",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={"strategy": "jump_ahead", "invariant_id": "inv-001"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["executed"] is False
    assert result["violation_successful"] is False  # never fabricated
    # No real test ran, so nothing is marked violated and no finding is persisted.
    agent.ctx.graph_memory.mark_invariant_violated.assert_not_awaited()
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()


# ------------------------------------------------------------------
# violate_invariant: concrete request + real (mocked) 200 -> demonstrated
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_real_execution_success(agent) -> None:
    await agent.initialize()
    agent.ctx.graph_memory.mark_invariant_violated.return_value = None
    agent.ctx.graph_memory.add_vulnerability.return_value = "vuln-bl-1"

    # Mock the HTTP layer so the test is hermetic but exercises the real path.
    class _Resp:
        status_code = 200
        text = '{"status":"SHIPPED"}'

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, *a, **k):
            return _Resp()

    with patch("ai_osop.agents.stateful_logic_agent.httpx.AsyncClient", _Client):
        task = Task(
            id="task-sl-6",
            type="violate_invariant",
            agent_type=AgentType.STATEFUL_LOGIC,
            payload={
                "strategy": "jump_ahead",
                "invariant_id": "inv-001",
                "request": {"method": "POST", "url": "http://127.0.0.1:3000/api/ship/123"},
                "success_criteria": {"status_in": [200], "body_contains": "SHIPPED"},
            },
            engagement_id="test-session",
        )
        result = await agent._execute(task)

    assert result["executed"] is True
    assert result["violation_successful"] is True
    assert result["response"]["status_code"] == 200
    # A genuine violation persists a real finding and marks the invariant.
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once()
    agent.ctx.graph_memory.mark_invariant_violated.assert_awaited_once_with("inv-001")


# ------------------------------------------------------------------
# violate_invariant: concrete request + real (mocked) 403 -> NOT demonstrated
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_real_execution_blocked(agent) -> None:
    await agent.initialize()

    class _Resp:
        status_code = 403
        text = "Forbidden"

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, *a, **k):
            return _Resp()

    with patch("ai_osop.agents.stateful_logic_agent.httpx.AsyncClient", _Client):
        task = Task(
            id="task-sl-7",
            type="violate_invariant",
            agent_type=AgentType.STATEFUL_LOGIC,
            payload={
                "strategy": "cross_tenant",
                "invariant_id": "inv-002",
                "request": {"method": "DELETE", "url": "http://127.0.0.1:3000/api/resource/1"},
                "success_criteria": {"status_in": [200]},
            },
            engagement_id="test-session",
        )
        result = await agent._execute(task)

    assert result["executed"] is True
    assert result["violation_successful"] is False  # blocked -> no fabrication
    agent.ctx.graph_memory.add_vulnerability.assert_not_awaited()
    agent.ctx.graph_memory.mark_invariant_violated.assert_not_awaited()


# ------------------------------------------------------------------
# violate_invariant: out-of-scope target is never executed
# ------------------------------------------------------------------
@pytest.mark.asyncio
async def test_violate_invariant_out_of_scope(mock_context) -> None:
    from datetime import datetime, timedelta

    from ai_osop.core.models import ScopeDefinition

    mock_context.scope = ScopeDefinition(
        engagement_id="test",
        domains=["127.0.0.1"],
        ips=["127.0.0.1/32"],
        exclusions=[],
        testing_window_start=datetime.utcnow() - timedelta(hours=1),
        testing_window_end=datetime.utcnow() + timedelta(hours=1),
    )
    agent = StatefulLogicAgent(mock_context)
    await agent.initialize()

    task = Task(
        id="task-sl-7b",
        type="violate_invariant",
        agent_type=AgentType.STATEFUL_LOGIC,
        payload={
            "strategy": "jump_ahead",
            "request": {"method": "GET", "url": "http://evil.com/api/ship"},
            "success_criteria": {"status_in": [200]},
        },
        engagement_id="test-session",
    )
    result = await agent._execute(task)

    assert result["executed"] is False
    assert result["violation_successful"] is False
    assert "out of scope" in result["reason"].lower()


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
