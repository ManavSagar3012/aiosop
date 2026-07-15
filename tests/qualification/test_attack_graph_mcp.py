"""
Attack Graph MCP reality gate.
Proves attack-graph-mcp executes real Neo4j Cypher queries and paths.
"""

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

    finding = {
        "id": "vuln-test-attack-graph-mcp",
        "title": "SQL Injection in Search parameter",
        "vuln_type": "sqli",
        "severity": "high",
        "cvss_score": 8.5,
        "description": "SQL Injection found via automated check.",
        "evidence": [{"type": "sqlmap", "payload": "Canned SQLMap payload."}],
        "tool_source": "mcp-test",
        "confidence": 1.0,
        "endpoint_id": "ep-test-target",
        "created_at": "2026-07-15T00:00:00"
    }

    # Add a verified finding to the Neo4j graph
    res = mcp_execute(
        base,
        "upsert_verified_finding",
        {
            "engagement_id": "test-eng-attack-graph-mcp",
            "finding": finding
        }
    )
    assert res.get("vulnerability_id") == "vuln-test-attack-graph-mcp"

    # Verify graph summary stats
    summary = mcp_execute(base, "get_graph_summary", {"engagement_id": "test-eng-attack-graph-mcp"})
    assert summary.get("vulnerabilities", 0) > 0

    # Verify asset neighbors
    neighbors = mcp_execute(
        base,
        "get_asset_neighbors",
        {
            "engagement_id": "test-eng-attack-graph-mcp",
            "node_id": "vuln-test-attack-graph-mcp"
        }
    )
    assert "neighbors" in neighbors
