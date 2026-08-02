"""
Attack Graph MCP reality gate.
Proves attack-graph-mcp executes real Neo4j Cypher queries and paths.
"""

import uuid

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def test_attack_graph_flow():
    base = require_server("attack_graph")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "get_asset_neighbors" in tools
    assert "get_attack_paths" in tools
    assert "upsert_verified_finding" in tools
    assert "get_graph_summary" in tools

    # Unique per run so the reality gate is hermetic: it must not depend on — or
    # collide with — Vulnerability nodes left by prior runs in the persistent
    # graph. (A fixed id + persistent Neo4j is what made this test flaky.)
    run = uuid.uuid4().hex[:12]
    engagement_id = f"test-eng-attack-graph-{run}"
    finding = {
        "id": f"vuln-test-attack-graph-{run}",
        "title": "SQL Injection in Search parameter",
        "vuln_type": "sqli",
        "severity": "high",
        "cvss_score": 8.5,
        "description": "SQL Injection found via automated check.",
        "evidence": [{"type": "sqlmap", "payload": "Canned SQLMap payload."}],
        "tool_source": "mcp-test",
        "confidence": 1.0,
        "endpoint_id": f"ep-test-target-{run}",
        "created_at": "2026-07-15T00:00:00",
    }

    # Add a verified finding to the Neo4j graph.
    res = mcp_execute(
        base,
        "upsert_verified_finding",
        {"engagement_id": engagement_id, "finding": finding},
    )
    # Assert on the RETURNED id, not the supplied one: on an id-clash the server
    # legitimately mints a fresh id to preserve the unique-id invariant, so the
    # persisted id is authoritative for downstream lookups.
    vuln_id = res.get("vulnerability_id")
    assert vuln_id, f"upsert returned no vulnerability_id: {res}"

    # Verify graph summary stats
    summary = mcp_execute(base, "get_graph_summary", {"engagement_id": engagement_id})
    assert summary.get("vulnerabilities", 0) > 0

    # Verify asset neighbors, using the id the server actually persisted.
    neighbors = mcp_execute(
        base,
        "get_asset_neighbors",
        {"engagement_id": engagement_id, "node_id": vuln_id},
    )
    assert "neighbors" in neighbors
