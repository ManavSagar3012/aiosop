"""Tenant-scoped path traversal source contract and fail-closed API wiring."""

import inspect

from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.api.routers import intelligence


def test_all_nodes_and_relationships_scoped_in_cypher():
    src = inspect.getsource(GraphMemory.find_tenant_attack_paths)
    assert "all(n IN nodes(p) WHERE n.engagement_id = $sid)" in src
    assert "all(r IN relationships(p) WHERE r.engagement_id = $sid)" in src
    assert "goal.engagement_id = $sid" in src
    assert "length(p) <= $max_depth" in src
    assert "LIMIT 11" in src
    assert "apoc." not in src


def test_route_never_calls_unscoped_traversal():
    src = inspect.getsource(intelligence.get_attack_paths)
    assert '"find_tenant_attack_paths"' in src
    assert "find_attack_paths(" not in src
    assert "p.engagement_id != session_id" in src
    assert "_recheck_graph_authority(session_id, operator, authority)" in src
