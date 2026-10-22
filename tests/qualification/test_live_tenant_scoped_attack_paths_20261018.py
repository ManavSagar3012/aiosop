"""Optional disposable Neo4j verification of all-node/relationship tenant fencing.

This is a synthetic local graph, NOT genuine finding verification or target proof.
"""

import asyncio

import pytest
from neo4j.exceptions import ServiceUnavailable
from neo4j import AsyncGraphDatabase

from ai_osop.memory.graph_memory import GraphMemory
from tests.qualification.joined_redis_graph_fixture_20261018 import disposable_redis_graph_services


@pytest.mark.asyncio
async def test_disposable_graph_blocks_foreign_bridge_and_foreign_relation(
    disposable_redis_graph_services,
):
    driver = AsyncGraphDatabase.driver(disposable_redis_graph_services.graph_url, auth=None)
    graph = GraphMemory()
    graph._driver = driver
    try:
        for attempt in range(30):
            try:
                await driver.verify_connectivity()
                break
            except ServiceUnavailable:
                if attempt == 29:
                    raise
                await asyncio.sleep(0.5)
        async with driver.session() as session:
            await session.run(
                "CREATE (a:Asset {id:'tenant-path-a', engagement_id:'eng-graph-a'}) "
                "CREATE (b:Endpoint {id:'tenant-path-b', engagement_id:'eng-graph-a'}) "
                "CREATE (c:Vulnerability {id:'tenant-path-c', engagement_id:'eng-graph-a', impact:'rce'}) "
                "CREATE (foreign:Endpoint {id:'tenant-path-foreign', engagement_id:'eng-graph-b'}) "
                "CREATE (a)-[:HAS_ENDPOINT {engagement_id:'eng-graph-a'}]->(b) "
                "CREATE (b)-[:HAS_VULNERABILITY {engagement_id:'eng-graph-a'}]->(c) "
                "CREATE (a)-[:HAS_ENDPOINT {engagement_id:'eng-graph-a'}]->(foreign) "
                "CREATE (foreign)-[:HAS_VULNERABILITY {engagement_id:'eng-graph-a'}]->(c)"
            )
        first = await graph.find_tenant_attack_paths(
            engagement_id="eng-graph-a", entry_node_id="tenant-path-a", goal_types=["rce"]
        )
        assert len(first) == 1
        assert first[0].node_ids == ["tenant-path-a", "tenant-path-b", "tenant-path-c"]
        assert first[0].validated is False
        async with driver.session() as session:
            await session.run(
                "MATCH (:Endpoint {id:'tenant-path-b'})-[r:HAS_VULNERABILITY]->(:Vulnerability {id:'tenant-path-c'}) "
                "SET r.engagement_id='eng-graph-b'"
            )
        second = await graph.find_tenant_attack_paths(
            engagement_id="eng-graph-a", entry_node_id="tenant-path-a", goal_types=["rce"]
        )
        assert second == []
        foreign = await graph.find_tenant_attack_paths(
            engagement_id="eng-graph-b", entry_node_id="tenant-path-a", goal_types=["rce"]
        )
        assert foreign == []
    finally:
        await driver.close()
