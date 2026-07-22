"""
Tests for the (de-simulated) GraphQL Specialist Agent.

Discovery now performs REAL introspection. These tests mock only the HTTP
introspection layer (_run_introspection) so they stay hermetic while exercising
the real parse/persist/honesty logic: a real schema yields parsed operations and
introspection_enabled=True; a disabled/non-GraphQL endpoint yields
introspection_enabled=False with zero operations (no fabrication).
"""

from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.graphql_agent import GraphQLAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task

# A realistic introspection __schema payload (shape a real server returns).
REAL_INTROSPECTION = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "subscriptionType": None,
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {"name": "me", "description": "current user"},
                {"name": "users", "description": "all users"},
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Mutation",
            "fields": [
                {"name": "deleteUser", "description": "admin only"},
                {"name": "login", "description": None},
            ],
        },
        {"kind": "SCALAR", "name": "String", "fields": None},
    ],
}


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "graphql-1"
    ctx.agent_type = AgentType.VULN_ANALYSIS
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
    return GraphQLAgent(mock_context)


@pytest.mark.asyncio
async def test_discover_schema_real_introspection(agent) -> None:
    """Introspection enabled -> operations parsed and persisted."""
    await agent.initialize()
    agent._run_introspection = AsyncMock(return_value=REAL_INTROSPECTION)

    task = Task(
        id="task-1",
        type="gql_discover_schema",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://target.example.com/graphql"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["introspection_enabled"] is True
    assert result["operations_count"] == 4  # me, users, deleteUser, login
    op_names = {o["name"] for o in result["operations"]}
    assert {"me", "users", "deleteUser", "login"} <= op_names
    agent.ctx.graph_memory.add_graphql_schema.assert_awaited_once()
    assert agent.ctx.graph_memory.add_graphql_operation.await_count == 4
    schema_arg = agent.ctx.graph_memory.add_graphql_schema.call_args[0][0]
    assert schema_arg.introspection_enabled is True


@pytest.mark.asyncio
async def test_discover_schema_introspection_disabled(agent) -> None:
    """Introspection disabled / not GraphQL -> honest result, no fabrication."""
    await agent.initialize()
    agent._run_introspection = AsyncMock(return_value=None)

    task = Task(
        id="task-2",
        type="gql_discover_schema",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://api.example.com/graphql"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["introspection_enabled"] is False
    assert result["operations_count"] == 0
    assert result["note"]  # honest explanation present
    stored = agent.discovered_schemas["https://api.example.com/graphql"]
    assert stored.introspection_enabled is False
    # No operations persisted when introspection is unavailable.
    agent.ctx.graph_memory.add_graphql_operation.assert_not_awaited()


@pytest.mark.asyncio
async def test_discover_schema_requires_url(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-2b",
        type="gql_discover_schema",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)
    assert result["status"] == "failed"


@pytest.mark.asyncio
async def test_find_hidden_operations(agent) -> None:
    """Hidden ops = introspected operations not exercised by the UI."""
    await agent.initialize()
    agent._run_introspection = AsyncMock(return_value=REAL_INTROSPECTION)

    task = Task(
        id="task-4",
        type="gql_find_hidden",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={
            "url": "https://target.example.com/graphql",
            "ui_actions": ["me", "users", "login"],  # deleteUser is NOT in the UI
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["introspection_enabled"] is True
    assert result["hidden_ops"] == ["deleteUser"]


@pytest.mark.asyncio
async def test_test_authorization_delegated(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-3",
        type="gql_test_authorization",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"resolver": "updateUser"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "delegated"
    assert "DiffAuthEngine" in result["message"]


@pytest.mark.asyncio
async def test_graphql_agent_unknown_task(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-5",
        type="unknown_task_type",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "failed"
    assert "Unknown task type" in result["error"]
