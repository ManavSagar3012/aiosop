"""A graph analyst flag is never independent target authorization proof."""

from ai_osop.api.routers.findings import _vuln_node_to_finding


def test_graph_validated_does_not_promote_public_finding() -> None:
    result = _vuln_node_to_finding(
        {
            "id": "vuln-graph-only",
            "title": "Provider-supplied vulnerability hypothesis",
            "validated": True,
            "confidence": 1.0,
            "severity": "critical",
            "engagement_id": "eng-tenant-1",
        }
    )
    assert result["status"] == "hypothesis"
    assert result["graph_review_status"] == "reviewed"
    assert result["source_authenticity_verified"] is False
    assert result["independent_target_effect_verified"] is False
    assert result["authorization_violation_verified"] is False


def test_unreviewed_graph_is_also_only_hypothesis() -> None:
    result = _vuln_node_to_finding({"validated": False})
    assert result["status"] == "hypothesis"
    assert result["graph_review_status"] == "unreviewed"
