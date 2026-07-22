from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.context_manager_agent import ContextManagerAgent
from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def context_agent() -> ContextManagerAgent:
    session_memory = AsyncMock()
    session_memory.get_agent_state.return_value = None
    session_memory.get_session_state.return_value = {"phase": "reconnaissance"}

    graph_memory = AsyncMock()
    graph_memory.get_graph_stats.return_value = {"assets": 2, "vulnerabilities": 1}

    vector_memory = AsyncMock()
    vector_memory.search_similar_payloads.return_value = [{"content": "payload-a"}]

    llm_client = AsyncMock()
    llm_client.complete.return_value = "Compact engagement summary."
    llm_client.get_embedding.return_value = [0.1] * 1536

    ctx = AgentContext(
        agent_id="ctx-001",
        agent_type=AgentType.CONTEXT_MANAGER,
        session_id="eng-001",
        session_memory=session_memory,
        graph_memory=graph_memory,
        vector_memory=vector_memory,
        llm_client=llm_client,
        mcp_registry=AsyncMock(),
        rate_limiter=AsyncMock(),
        threat_intel_adapter=AsyncMock(),
        audit_callback=AsyncMock(),
        coordination_bus=AsyncMock(),
    )
    return ContextManagerAgent(ctx)


@pytest.mark.asyncio
async def test_context_manager_summarizes_and_persists_context(
    context_agent: ContextManagerAgent,
) -> None:
    await context_agent._setup_resources()
    task = Task(
        type="summarize_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        payload={"engagement_id": "eng-001", "focus": "active findings"},
        engagement_id="eng-001",
    )
    context_agent.ctx.current_task = task

    result = await context_agent._execute(task)

    assert result["status"] == "success"
    assert result["context_snapshot"]["summary"] == "Compact engagement summary."
    context_agent.ctx.session_memory.store_agent_state.assert_awaited_once()


@pytest.mark.asyncio
async def test_context_manager_retrieves_semantic_context(
    context_agent: ContextManagerAgent,
) -> None:
    await context_agent._setup_resources()
    task = Task(
        type="retrieve_context",
        agent_type=AgentType.CONTEXT_MANAGER,
        payload={"query": "xss bypass", "limit": 1},
        engagement_id="eng-001",
    )

    result = await context_agent._execute(task)

    assert result["status"] == "success"
    assert result["matches"] == [{"content": "payload-a"}]
    context_agent.ctx.vector_memory.search_similar_payloads.assert_awaited_once()
