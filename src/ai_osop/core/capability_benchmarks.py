"""Evidence-gated benchmark evaluators for M5, M6, and M7.

These pure evaluators consume recorded artefacts. They never execute an attack,
change target state, or infer a positive result from an unverified hypothesis.
"""

from typing import Any, Dict, List, Mapping, Sequence, Set

from ai_osop.core.models import AttackPath


def evaluate_attack_path_contract(
    path: AttackPath, expected: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]
) -> Dict[str, Any]:
    """Evaluate an M5 path against a manifest contract and supplied evidence.

    Required evidence is declared as ``required_evidence_types``. A path can be
    structurally correct but remain unconfirmed until every required evidence
    item has been recorded.
    """
    required_nodes = set(expected.get("required_node_ids", []))
    required_evidence = set(expected.get("required_evidence_types", []))
    observed_evidence = {str(item.get("type")) for item in evidence if item.get("type")}
    checks = {
        "entry_node": path.entry_node_id == expected.get("entry_node_id"),
        "goal_node": path.goal_node_id == expected.get("goal_node_id"),
        "required_nodes": required_nodes.issubset(set(path.node_ids)),
        "minimum_confidence": path.confidence >= float(expected.get("minimum_confidence", 0.0)),
        "validated": not bool(expected.get("requires_validated", False)) or path.validated,
        "evidence": required_evidence.issubset(observed_evidence),
    }
    return {
        "contract_id": expected.get("id"),
        "matched": all(checks.values()),
        "checks": checks,
        "missing_evidence_types": sorted(required_evidence - observed_evidence),
    }


def evaluate_business_logic_scenario(
    expected: Mapping[str, Any], observed: Mapping[str, Any]
) -> Dict[str, Any]:
    """Evaluate a recorded M6 state-machine scenario without replaying it.

    ``allowed_transitions`` contains two-element ``[from_state, to_state]``
    pairs. Any observed transition outside that set is an invariant violation.
    The manifest declares whether a violation is the expected ground truth.
    """
    allowed = {tuple(pair) for pair in expected.get("allowed_transitions", [])}
    transitions = [tuple(pair) for pair in observed.get("transitions", [])]
    invalid = [pair for pair in transitions if pair not in allowed]
    expected_violation = bool(expected.get("expected_violation", False))
    observed_violation = bool(observed.get("violation_observed", False)) or bool(invalid)
    required_evidence = set(expected.get("required_evidence_types", []))
    evidence_types = {
        str(item.get("type")) for item in observed.get("evidence", []) if item.get("type")
    }
    checks = {
        "initial_state": observed.get("initial_state") == expected.get("initial_state"),
        "violation_classification": observed_violation == expected_violation,
        "evidence": required_evidence.issubset(evidence_types),
    }
    return {
        "scenario_id": expected.get("id"),
        "passed": all(checks.values()),
        "checks": checks,
        "invalid_transitions": [list(pair) for pair in invalid],
        "observed_violation": observed_violation,
        "missing_evidence_types": sorted(required_evidence - evidence_types),
    }


def aggregate_benchmark_results(
    results: Sequence[Mapping[str, Any]],
    minimum_expected: int = 10,
    minimum_benchmarks: int = 2,
) -> Dict[str, Any]:
    """Produce M7 macro/micro metrics and a conservative generalization gate."""
    benchmark_ids: Set[str] = set()
    total_tp = total_fp = total_fn = total_expected = 0
    precision_values: List[float] = []
    recall_values: List[float] = []
    confidence_values: List[float] = []

    for result in results:
        benchmark_id = str(result.get("benchmark_id") or "")
        if not benchmark_id:
            raise ValueError("Each benchmark result requires benchmark_id")
        if benchmark_id in benchmark_ids:
            raise ValueError(f"Duplicate benchmark_id: {benchmark_id}")
        benchmark_ids.add(benchmark_id)

        metrics = result.get("metrics")
        if not isinstance(metrics, Mapping):
            raise ValueError(f"Benchmark {benchmark_id} is missing metrics")
        total_tp += int(metrics.get("true_positives", 0))
        total_fp += int(metrics.get("false_positives", 0))
        total_fn += int(metrics.get("false_negatives", 0))
        total_expected += int(metrics.get("total_expected", 0))
        precision_values.append(float(metrics.get("precision", 0.0)))
        recall_values.append(float(metrics.get("recall", 0.0)))

        coverage = result.get("coverage_confidence", {})
        if isinstance(coverage, Mapping) and "average_evidence_confidence" in coverage:
            confidence_values.append(float(coverage["average_evidence_confidence"]))

    micro_precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 1.0
    micro_recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 1.0
    reasons: List[str] = []
    if len(benchmark_ids) < minimum_benchmarks:
        reasons.append(f"requires at least {minimum_benchmarks} independent benchmarks")
    if total_expected < minimum_expected:
        reasons.append(f"requires at least {minimum_expected} expected findings")

    return {
        "benchmarks": len(benchmark_ids),
        "total_expected": total_expected,
        "micro_precision": round(micro_precision, 3),
        "micro_recall": round(micro_recall, 3),
        "macro_precision": (
            round(sum(precision_values) / len(precision_values), 3) if precision_values else 0.0
        ),
        "macro_recall": round(sum(recall_values) / len(recall_values), 3) if recall_values else 0.0,
        "average_evidence_confidence": (
            round(sum(confidence_values) / len(confidence_values), 1) if confidence_values else 0.0
        ),
        "generalization_ready": not reasons,
        "generalization_blockers": reasons,
    }
