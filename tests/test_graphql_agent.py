from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.graphql_agent import GraphQLAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


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
async def test_graphql_agent_discover_schema(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-1",
        type="gql_discover_schema",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://target.example.com/graphql"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert "schema_id" in result
    assert result["schema_id"].startswith("gql-schema-")
    assert result["operations_count"] == 0
    agent.ctx.graph_memory.add_graphql_schema.assert_awaited_once()
    schema_arg = agent.ctx.graph_memory.add_graphql_schema.call_args[0][0]
    assert schema_arg.endpoint_url == "https://target.example.com/graphql"
    assert schema_arg.introspection_enabled is True
    assert schema_arg.engagement_id == "test-session"


@pytest.mark.asyncio
async def test_graphql_agent_discover_schema_stored_locally(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-2",
        type="gql_discover_schema",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://api.example.com/graphql", "force_introspection": False},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert "https://api.example.com/graphql" in agent.discovered_schemas
    stored_schema = agent.discovered_schemas["https://api.example.com/graphql"]
    assert stored_schema.introspection_enabled is False


@pytest.mark.asyncio
async def test_graphql_agent_test_authorization(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-3",
        type="gql_test_authorization",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"resolver": "updateUser"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "pending"
    assert "DiffAuthEngine" in result["message"]


@pytest.mark.asyncio
async def test_graphql_agent_find_hidden(agent) -> None:
    await agent.initialize()

    task = Task(
        id="task-4",
        type="gql_find_hidden",
        agent_type=AgentType.VULN_ANALYSIS,
        payload={"url": "https://target.example.com/graphql"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["hidden_ops"] == []


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
