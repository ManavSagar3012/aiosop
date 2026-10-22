"""Graph projections must not rewrite or reuse a foreign tenant's Task nodes."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


class _Session:
    def __init__(self, graph: AsyncMock):
        self.graph = graph

    async def __aenter__(self):
        return self.graph

    async def __aexit__(self, *_args):
        return False


def _task(engagement_id: str, task_id: str) -> Task:
    return Task(
        id=task_id,
        engagement_id=engagement_id,
        type="map_workflow",
        agent_type=AgentType.WORKFLOW,
    )


@pytest.mark.asyncio
async def test_rejects_cross_tenant_task_dependency_without_graph_write():
    graph = AsyncMock()
    orch = Orchestrator.__new__(Orchestrator)
    orch.graph_memory = SimpleNamespace(
        _driver=SimpleNamespace(session=MagicMock(return_value=_Session(graph)))
    )
    await orch._persist_task_dependency(_task("eng-a", "task-parent"), _task("eng-b", "task-child"))
    graph.run.assert_not_awaited()
    orch.graph_memory._driver.session.assert_not_called()


@pytest.mark.asyncio
async def test_same_tenant_projection_never_reassigns_engagement_id():
    graph = AsyncMock()
    orch = Orchestrator.__new__(Orchestrator)
    orch.graph_memory = SimpleNamespace(
        _driver=SimpleNamespace(session=MagicMock(return_value=_Session(graph)))
    )
    await orch._persist_task_dependency(_task("eng-a", "task-parent"), _task("eng-a", "task-child"))
    cypher, parameters = graph.run.await_args.args
    assert "MERGE (p:Task {id: $parent_id, engagement_id: $eid})" in cypher
    assert "MERGE (c:Task {id: $child_id, engagement_id: $eid})" in cypher
    assert "SET p.type = $parent_type, p.engagement_id" not in cypher
    assert parameters["eid"] == "eng-a"


@pytest.mark.asyncio
async def test_spawned_read_joins_parent_and_child_to_same_tenant():
    record = AsyncMock()
    record.single = AsyncMock(return_value={"c": 1})
    graph = AsyncMock()
    graph.run.return_value = record
    memory = GraphMemory.__new__(GraphMemory)
    memory._driver = SimpleNamespace(session=MagicMock(return_value=_Session(graph)))
    assert await memory.task_has_spawned("task-parent", "eng-a") is True
    cypher, parameters = graph.run.await_args.args
    assert "(t:Task {id:$id, engagement_id:$eid})" in cypher
    assert "(c:Task {engagement_id:$eid})" in cypher
    assert parameters == {"id": "task-parent", "eid": "eng-a"}
    assert await memory.task_has_spawned("task-parent", "") is False
    assert graph.run.await_count == 1
