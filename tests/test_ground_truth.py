"""Regression tests for parameter-aware M4 ground-truth scoring."""

from ai_osop.core.ground_truth import GroundTruthEngine


def _evaluate(expected, actual):
    return GroundTruthEngine(expected).evaluate_engagement(
        actual_findings=actual,
        tasks_list=[],
        skipped_scans=[],
        endpoints_list=[],
    )


def test_matches_persisted_sqlmap_evidence_by_parameter():
    expected = [
        {
            "vuln_class": "sqli",
            "path": "/catalog",
            "parameter": "category",
            "description": "SQL injection in category",
        }
    ]
    actual = [
        {
            "id": "vuln-real-sqlmap",
            "vuln_type": "sqli",
            "evidence": '[{"provenance":"sqlmap","url":"https://ginandjuice.shop/catalog?category=Accessories","parameter":"category (GET)"}]',
        }
    ]

    result = _evaluate(expected, actual)

    assert result["metrics"] == {
        "total_expected": 1,
        "total_found": 1,
        "true_positives": 1,
        "false_positives": 0,
        "false_negatives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "f1_score": 1.0,
    }
    trace = result["traces"][0]
    assert trace["matched_finding_id"] == "vuln-real-sqlmap"
    assert trace["matched_parameter"] == "category"


def test_does_not_credit_a_finding_to_a_different_parameter_on_same_endpoint():
    expected = [
        {
            "vuln_class": "sqli",
            "path": "/catalog",
            "parameter": "category",
            "description": "SQL injection in category",
        },
        {
            "vuln_class": "sqli",
            "path": "/catalog",
            "parameter": "sort",
            "description": "SQL injection in sort",
        },
    ]
    actual = [
        {
            "id": "vuln-category",
            "type": "sqli",
            "url": "https://example.test/catalog?category=Accessories",
            "parameter": "category (GET)",
        }
    ]

    result = _evaluate(expected, actual)

    assert result["metrics"]["true_positives"] == 1
    assert result["metrics"]["false_negatives"] == 1
    assert result["metrics"]["recall"] == 0.5
    assert result["traces"][1]["status"] == "missed"


def test_duplicate_reports_are_counted_as_false_positives():
    expected = [
        {
            "vuln_class": "xss",
            "path": "/search",
            "parameter": "q",
            "description": "Reflected XSS in search",
        }
    ]
    actual = [
        {
            "id": "vuln-1",
            "type": "xss",
            "url": "https://example.test/search?q=one",
            "parameter": "q",
        },
        {
            "id": "vuln-2",
            "type": "xss",
            "url": "https://example.test/search?q=two",
            "parameter": "q",
        },
    ]

    result = _evaluate(expected, actual)

    assert result["metrics"]["true_positives"] == 1
    assert result["metrics"]["false_positives"] == 1
    assert result["metrics"]["precision"] == 0.5


def test_manifest_contract_reports_missing_method_without_inflating_recall():
    expected = [
        {
            "id": "M4-SQLI-001",
            "vuln_class": "sqli",
            "path": "/catalog",
            "method": "GET",
            "parameter": "category",
            "scanner": "sqlmap",
            "expected_db": "H2",
            "expected_technique": "boolean-based blind",
            "minimum_confidence": 50,
            "requires_replay": False,
            "requires_attack_chain": False,
            "description": "SQL injection in category",
        }
    ]
    actual = [
        {
            "id": "vuln-category",
            "vuln_type": "sqli",
            "tool_source": "sqlmap",
            "validated": True,
            "evidence": [
                {
                    "url": "https://example.test/catalog?category=Accessories",
                    "parameter": "category (GET)",
                    "dbms": "H2",
                    "techniques": ["boolean-based blind"],
                }
            ],
        }
    ]

    result = _evaluate(expected, actual)

    assert result["metrics"]["recall"] == 1.0
    assert result["coverage_confidence"] == {
        "expected": 1,
        "execution_observed": 1,
        "verified": 1,
        "persisted": 1,
        "contract_satisfied": 0,
        "average_evidence_confidence": 50.0,
    }
    trace = result["traces"][0]
    assert trace["evidence_contract"]["method"]["status"] == "failed"
    assert trace["evidence_contract"]["scanner"]["status"] == "passed"
    assert trace["evidence_contract"]["dbms"]["status"] == "passed"
    assert trace["evidence_contract"]["techniques"]["status"] == "passed"
    assert trace["contract_satisfied"] is False
