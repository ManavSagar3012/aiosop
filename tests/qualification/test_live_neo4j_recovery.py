"""Isolated Neo4j graph recovery qualification (opt-in, no target traffic)."""

import os
import uuid

import pytest
from neo4j import AsyncGraphDatabase

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.graph_memory import GraphMemory


@pytest.fixture
async def graph():
    uri = os.environ.get("OSOP_LIVE_NEO4J_URI")
    if not uri:
        pytest.skip("OSOP_LIVE_NEO4J_URI is not configured")
    instance = GraphMemory()
    instance._driver = AsyncGraphDatabase.driver(uri, auth=None)
    try:
        await instance._driver.verify_connectivity()
        await instance._setup_schema()
        yield instance
    finally:
        await instance.close()


@pytest.mark.asyncio
async def test_live_graph_marks_unknown_running_work_interrupted_without_replay(graph):
    suffix = uuid.uuid4().hex[:16]
    task = Task(
        id="task-neo-" + suffix,
        engagement_id="eng-neo-" + suffix,
        type="full_recon",
        agent_type=AgentType.RECON,
        status="running",
    )
    assert await graph.upsert_task(task)
    records = await graph.reset_interrupted_tasks()
    matches = [row for row in records if row.get("id") == task.id]
    assert len(matches) == 1
    assert matches[0]["recovery_attempts"] == 1
    async with graph._driver.session() as session:
        result = await session.run(
            "MATCH (t:Task {id:$id}) RETURN t.status AS status",
            {"id": task.id},
        )
        row = await result.single()
    assert row is not None and row["status"] == "interrupted"
    # Recovery in this test never dispatches the task to a real agent.
    assert all(row.get("id") != task.id for row in await graph.reset_interrupted_tasks())
