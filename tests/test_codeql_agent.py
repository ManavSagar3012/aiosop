from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.agents.base import AgentContext
from ai_osop.agents.experimental.codeql_agent import CodeQLAgent
from ai_osop.core.config import AgentType
from ai_osop.core.models import Task


@pytest.fixture
def mock_context():
    ctx = AsyncMock(spec=AgentContext)
    ctx.agent_id = "codeql-1"
    ctx.agent_type = AgentType.SAST_ANALYSIS
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
    return CodeQLAgent(mock_context)


# ──────────────────── helpers ────────────────────

SAMPLE_SARIF = {
    "runs": [
        {
            "results": [
                {
                    "ruleId": "java/sql-injection",
                    "message": {"text": "Possible SQL injection via user input"},
                    "level": "error",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main/Dao.java"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "java/xss",
                    "message": {"text": "Reflected XSS"},
                    "level": "warning",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main/Controller.java"},
                                "region": {"startLine": 100},
                            }
                        }
                    ],
                },
            ]
        }
    ]
}


# ──────────────────── tests ────────────────────


@pytest.mark.asyncio
async def test_ingest_sarif_dict(agent) -> None:
    """SARIF payload supplied as a Python dict is ingested correctly."""
    await agent.initialize()

    task = Task(
        id="task-1",
        type="ingest_sarif",
        agent_type=AgentType.SAST_ANALYSIS,
        payload={"sarif_json": SAMPLE_SARIF},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["count"] == 2
    assert len(result["findings"]) == 2
    assert agent.findings_cache[0]["rule_id"] == "java/sql-injection"
    assert agent.findings_cache[0]["line"] == 42
    assert agent.findings_cache[1]["file_path"] == "src/main/Controller.java"


@pytest.mark.asyncio
async def test_ingest_sarif_json_string(agent) -> None:
    """SARIF payload supplied as a JSON string is parsed and ingested."""
    import json

    await agent.initialize()

    task = Task(
        id="task-2",
        type="ingest_sarif",
        agent_type=AgentType.SAST_ANALYSIS,
        payload={"sarif_json": json.dumps(SAMPLE_SARIF)},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["count"] == 2


@pytest.mark.asyncio
async def test_ingest_sarif_invalid_json(agent) -> None:
    """Invalid JSON string in sarif_json returns an error."""
    await agent.initialize()

    task = Task(
        id="task-3",
        type="ingest_sarif",
        agent_type=AgentType.SAST_ANALYSIS,
        payload={"sarif_json": "{{not-valid-json}}"},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "error"
    assert "Invalid JSON" in result["message"]


@pytest.mark.asyncio
async def test_map_sast_to_graph(agent) -> None:
    """Cached findings are mapped to the attack graph via Neo4j."""
    await agent.initialize()

    # Pre-populate the findings cache
    agent.findings_cache = [
        {
            "rule_id": "java/sql-injection",
            "message": "SQL Injection",
            "file_path": "src/main/Dao.java",
            "line": 42,
            "severity": "error",
            "type": "codeql_finding",
        }
    ]

    # Set up mock Neo4j driver chain — _driver must be MagicMock so session()
    # returns the context manager directly, not a coroutine (AsyncMock quirk).
    mock_record = {"id": "ep-123"}
    mock_result = AsyncMock()
    mock_result.__aiter__ = lambda self: self  # noqa: E731
    mock_result.__anext__ = AsyncMock(side_effect=[mock_record, StopAsyncIteration])

    mock_session = AsyncMock()
    mock_session.run.return_value = mock_result

    # Create async context manager for session
    mock_session_cm = AsyncMock()
    mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_cm.__aexit__ = AsyncMock(return_value=False)

    from unittest.mock import MagicMock
    agent.ctx.graph_memory._driver = MagicMock()
    agent.ctx.graph_memory._driver.session.return_value = mock_session_cm

    task = Task(
        id="task-4",
        type="map_sast_to_graph",
        agent_type=AgentType.SAST_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "success"
    assert result["mapped_findings"] == 1
    agent.ctx.graph_memory.add_vulnerability.assert_awaited_once()


@pytest.mark.asyncio
async def test_unknown_task_type(agent) -> None:
    """Unknown task type returns an error dict."""
    await agent.initialize()

    task = Task(
        id="task-5",
        type="nonexistent_task",
        agent_type=AgentType.SAST_ANALYSIS,
        payload={},
        engagement_id="test-session",
    )

    result = await agent._execute(task)

    assert result["status"] == "error"
    assert "Unknown task type" in result["message"]
