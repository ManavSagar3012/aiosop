from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.payload_agent import PayloadMutationAgent
from ai_osop.core.config import AgentType, VulnClass
from ai_osop.core.models import Payload, Task


@pytest.fixture
def mock_context():
    ctx = MagicMock(spec=AgentContext)
    ctx.agent_id = "test-payload-agent"
    ctx.agent_type = AgentType.PAYLOAD_MUTATION
    ctx.session_id = "test-session"

    ctx.llm_client = AsyncMock()
    ctx.llm_client.get_embedding.return_value = [0.1] * 1536
    ctx.llm_client.complete.return_value = "Mocked adapted payload content"

    ctx.vector_memory = AsyncMock()
    ctx.vector_memory.search_similar_payloads.return_value = []
    ctx.vector_memory.store_payload = AsyncMock()

    ctx.mcp_registry = AsyncMock()

    return ctx


@pytest.mark.asyncio
async def test_generate_payloads(mock_context):
    agent = PayloadMutationAgent(mock_context)
    await agent._setup_resources()

    # Mock the engine's initial population generation
    mock_payload = Payload(
        vuln_type=VulnClass.SQLI,
        content="' OR 1=1--",
        content_hash="mockhash",
        context={"param": "id"},
        engagement_id="test-session",
    )
    agent.engine.generate_initial_population = AsyncMock(return_value=[mock_payload])

    task = Task(
        type="generate_payloads",
        priority=5,
        agent_type=AgentType.PAYLOAD_MUTATION,
        payload={"vuln_type": "sqli", "context": {"param": "id"}, "count": 1},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert len(result["payloads"]) == 1
    # LLM should have refined it
    assert result["payloads"][0]["content"] == "Mocked adapted payload content"

    mock_context.vector_memory.search_similar_payloads.assert_called_once()
    mock_context.llm_client.complete.assert_called_once()


@pytest.mark.asyncio
async def test_process_feedback(mock_context):
    agent = PayloadMutationAgent(mock_context)
    await agent._setup_resources()

    # Mock fitness evaluation
    agent.engine.fitness_evaluator.evaluate = MagicMock(return_value=0.9)

    payload_obj = Payload(
        vuln_type=VulnClass.XSS,
        content="<script>alert(1)</script>",
        content_hash="xsshash",
        context={},
        engagement_id="test-session",
    )

    task = Task(
        type="process_feedback",
        priority=5,
        agent_type=AgentType.PAYLOAD_MUTATION,
        payload={
            "payload": payload_obj.model_dump(),
            "result": {"status": "success", "waf_blocked": False, "target": "example.com"},
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["updated_fitness"] == 0.9
    assert result["stored_semantically"] is True

    mock_context.vector_memory.store_payload.assert_called_once()


@pytest.mark.asyncio
async def test_evolve_population(mock_context):
    agent = PayloadMutationAgent(mock_context)
    await agent._setup_resources()

    mock_payload = Payload(
        vuln_type=VulnClass.SQLI,
        content="' OR 1=1--",
        content_hash="mockhash",
        context={},
        engagement_id="test-session",
    )

    agent.engine.evolve_population = AsyncMock(return_value=[mock_payload])

    task = Task(
        type="evolve_population",
        priority=5,
        agent_type=AgentType.PAYLOAD_MUTATION,
        payload={
            "vuln_type": "sqli",
            "context": {},
            "population": [mock_payload.model_dump()],
            "generations": 2,
        },
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["evolved_count"] == 1
    assert result["population"][0]["content"] == "' OR 1=1--"
    agent.engine.evolve_population.assert_called_once()
