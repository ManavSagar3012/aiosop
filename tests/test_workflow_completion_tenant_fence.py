"""Workflow completion cannot borrow another tenant's graph evidence."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import Orchestrator


class GraphSession:
    def __init__(self, result):
        self.run = AsyncMock(return_value=SimpleNamespace(single=AsyncMock(return_value=result)))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


@pytest.mark.asyncio
@pytest.mark.parametrize("record,expected", [
    ({"workflow_exists": True, "step_count": 2, "evidence_count": 1}, True),
    ({"workflow_exists": True, "step_count": 2, "evidence_count": 0}, False),
    ({"workflow_exists": False, "step_count": 0, "evidence_count": 0}, False),
    (None, False),
])
async def test_completed_workflow_is_tenant_step_and_evidence_bound(record, expected):
    graph = GraphSession(record)
    orch = SimpleNamespace(graph_memory=SimpleNamespace(
        _driver=SimpleNamespace(session=lambda: graph)
    ))
    task = Task(id="task-producer", type="map_workflow", agent_type=AgentType.WORKFLOW,
                engagement_id="eng-original", payload={"url": "https://authorized.example"})
    result = await Orchestrator.validate_workflow_completion(
        orch, task, {"workflow_id": "wf-source"}
    )
    assert result is expected
    cypher, params = graph.run.await_args.args
    assert "Workflow {id: $workflow_id, engagement_id: $eid}" in cypher
    assert "Step {engagement_id: $eid, workflow_id: $workflow_id}" in cypher
    assert "Evidence {engagement_id: $eid, workflow_id: $workflow_id}" in cypher
    assert params == {"workflow_id": "wf-source", "eid": "eng-original"}


@pytest.mark.asyncio
@pytest.mark.parametrize("result", [{}, {"workflow_id": ""},
                                         {"workflow_id": "../other"}, None])
async def test_missing_or_malformed_workflow_receipt_never_reads_graph(result):
    graph = GraphSession({"workflow_exists": True, "step_count": 1, "evidence_count": 1})
    orch = SimpleNamespace(graph_memory=SimpleNamespace(
        _driver=SimpleNamespace(session=lambda: graph)
    ))
    task = Task(type="map_workflow", agent_type=AgentType.WORKFLOW, engagement_id="eng-original")
    assert await Orchestrator.validate_workflow_completion(orch, task, result) is False
    graph.run.assert_not_awaited()
