"""Offline contract tests for M5 attack paths, M6 logic, and M7 aggregation."""

from ai_osop.core.capability_benchmarks import (
    aggregate_benchmark_results,
    evaluate_attack_path_contract,
    evaluate_business_logic_scenario,
)
from ai_osop.core.models import AttackPath


def test_m5_requires_structural_and_evidence_proof():
    path = AttackPath(
        id="path-m5-001",
        node_ids=["vuln-sqli", "asset-db", "goal-sensitive-data"],
        edge_ids=["edge-1", "edge-2"],
        confidence=0.9,
        risk_score=9.0,
        validated=True,
        entry_node_id="vuln-sqli",
        goal_node_id="goal-sensitive-data",
        engagement_id="eng-m5",
    )
    expected = {
        "id": "M5-PATH-001",
        "entry_node_id": "vuln-sqli",
        "goal_node_id": "goal-sensitive-data",
        "required_node_ids": ["asset-db"],
        "minimum_confidence": 0.8,
        "requires_validated": True,
        "required_evidence_types": ["sqlmap_injection", "impact_confirmation"],
    }

    result = evaluate_attack_path_contract(path, expected, [{"type": "sqlmap_injection"}])

    assert result["matched"] is False
    assert result["missing_evidence_types"] == ["impact_confirmation"]
    assert result["checks"]["required_nodes"] is True


def test_m5_marks_a_fully_evidenced_path_as_matched():
    path = AttackPath(
        node_ids=["vuln-1", "asset-1", "goal-1"],
        edge_ids=["edge-1", "edge-2"],
        confidence=0.8,
        risk_score=8.0,
        validated=True,
        entry_node_id="vuln-1",
        goal_node_id="goal-1",
        engagement_id="eng-m5",
    )
    expected = {
        "entry_node_id": "vuln-1",
        "goal_node_id": "goal-1",
        "required_node_ids": ["asset-1"],
        "minimum_confidence": 0.8,
        "requires_validated": True,
        "required_evidence_types": ["scanner_validation", "impact_confirmation"],
    }

    result = evaluate_attack_path_contract(
        path,
        expected,
        [{"type": "scanner_validation"}, {"type": "impact_confirmation"}],
    )

    assert result["matched"] is True
    assert result["missing_evidence_types"] == []


def test_m6_detects_an_observed_illegal_state_transition():
    expected = {
        "id": "M6-ORDER-001",
        "initial_state": "created",
        "allowed_transitions": [["created", "paid"], ["paid", "shipped"]],
        "expected_violation": True,
        "required_evidence_types": ["request_response_pair"],
    }
    observed = {
        "initial_state": "created",
        "transitions": [["created", "shipped"]],
        "evidence": [{"type": "request_response_pair"}],
    }

    result = evaluate_business_logic_scenario(expected, observed)

    assert result["passed"] is True
    assert result["observed_violation"] is True
    assert result["invalid_transitions"] == [["created", "shipped"]]


def test_m7_refuses_a_generalization_claim_for_one_small_benchmark():
    result = aggregate_benchmark_results(
        [
            {
                "benchmark_id": "ginandjuice-m3-real-sqlmap",
                "metrics": {
                    "total_expected": 1,
                    "true_positives": 1,
                    "false_positives": 0,
                    "false_negatives": 0,
                    "precision": 1.0,
                    "recall": 1.0,
                },
                "coverage_confidence": {"average_evidence_confidence": 50.0},
            }
        ]
    )

    assert result["micro_recall"] == 1.0
    assert result["generalization_ready"] is False
    assert len(result["generalization_blockers"]) == 2
