"""Ground Truth Engine — benchmark precision & recall validation.

Maps the actual findings generated during an engagement against a known
expected vulnerability manifest to calculate security engineering metrics and
produce evidence-backed execution traces for missed findings.
"""

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qsl, urlparse

from ai_osop.core.finding_confidence import score_finding


def _get_field(obj: Any, field: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(field, default)
    try:
        return getattr(obj, field, default)
    except AttributeError:
        return default


def _normalise_class(value: Any) -> str:
    """Return the canonical vulnerability-class key used by the evaluator."""
    return str(value or "").lower().replace("_", "").replace("-", "")


def _normalise_path(value: Any) -> str:
    """Return a comparable URL path, ignoring scheme, host, and query string."""
    parsed = urlparse(str(value or "").lower())
    path = parsed.path or str(value or "").split("?", 1)[0].lower()
    return path.rstrip("/") or "/"


def _normalise_parameter(value: Any) -> str:
    """Normalise tool-specific parameter labels such as ``category (GET)``."""
    name = str(value or "").strip().lower()
    return re.sub(r"\s*\([^)]*\)\s*$", "", name)


def _as_json(value: Any) -> Any:
    """Decode serialized evidence when possible, otherwise return the input."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _collect_evidence_values(value: Any, keys: List[str]) -> List[Any]:
    """Collect selected keys from nested evidence without assuming its shape."""
    decoded = _as_json(value)
    if isinstance(decoded, dict):
        values = [decoded[key] for key in keys if key in decoded]
        for child in decoded.values():
            values.extend(_collect_evidence_values(child, keys))
        return values
    if isinstance(decoded, list):
        list_values: List[Any] = []
        for child in decoded:
            list_values.extend(_collect_evidence_values(child, keys))
        return list_values
    return []


def _extract_parameters(finding: Dict[str, Any]) -> List[str]:
    """Extract parameter names from finding fields and structured evidence."""
    values: List[Any] = []
    for key in ("parameter", "affected_parameter", "parameter_name", "parameters"):
        if key in finding:
            values.append(finding[key])
    values.extend(
        _collect_evidence_values(
            finding.get("evidence"),
            ["parameter", "affected_parameter", "parameter_name", "parameters"],
        )
    )

    parameters = set()
    for value in values:
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, dict):
                    parameters.update(_extract_parameters(item))
                else:
                    normalised = _normalise_parameter(item)
                    if normalised:
                        parameters.add(normalised)
        elif isinstance(value, dict):
            parameters.update(_extract_parameters(value))
        else:
            normalised = _normalise_parameter(value)
            if normalised:
                parameters.add(normalised)
    return sorted(parameters)


def _extract_urls(finding: Dict[str, Any]) -> List[str]:
    """Extract target URLs from top-level fields and persisted evidence."""
    values: List[Any] = [finding.get(key) for key in ("url", "endpoint_url", "target")]
    values.extend(
        _collect_evidence_values(finding.get("evidence"), ["url", "endpoint_url", "target"])
    )
    return sorted({_normalise_path(value) for value in values if value})


def _flatten_values(values: List[Any]) -> List[str]:
    """Flatten scalar or list-shaped evidence values into comparable strings."""
    flattened: List[str] = []
    for value in values:
        decoded = _as_json(value)
        if isinstance(decoded, (list, tuple, set)):
            flattened.extend(_flatten_values(list(decoded)))
        elif decoded is not None and not isinstance(decoded, dict):
            rendered = str(decoded).strip()
            if rendered:
                flattened.append(rendered)
    return flattened


def _extract_values(
    finding: Dict[str, Any], top_level_keys: List[str], evidence_keys: List[str]
) -> List[str]:
    """Extract selected values from a finding and its structured evidence."""
    values = [finding[key] for key in top_level_keys if key in finding]
    values.extend(_collect_evidence_values(finding.get("evidence"), evidence_keys))
    return _flatten_values(values)


def _evaluate_contract(
    expected: Dict[str, Any], actual: Dict[str, Any], confidence_score: int
) -> Dict[str, Dict[str, Any]]:
    """Evaluate optional manifest requirements without changing recall matching.

    Identity is class/path/parameter. Tool, DBMS, technique, method, and
    replay/attack-path requirements are reported separately so an absent field
    is visible evidence debt, not a silently inflated true positive.
    """
    method = str(expected.get("method") or "").upper()
    scanner = str(expected.get("scanner") or "").lower()
    expected_db = str(expected.get("expected_db") or "").lower()
    raw_techniques = expected.get("expected_techniques")
    if raw_techniques is None:
        raw_techniques = [expected.get("expected_technique")]
    elif isinstance(raw_techniques, str):
        raw_techniques = [raw_techniques]
    expected_techniques = [str(value).lower() for value in raw_techniques if value]
    actual_methods = {value.upper() for value in actual["methods"]}
    actual_scanners = {value.lower() for value in actual["scanners"]}
    actual_dbs = {value.lower() for value in actual["dbms"]}
    actual_techniques = {value.lower() for value in actual["techniques"]}

    checks: Dict[str, Dict[str, Any]] = {}

    def add_check(name: str, required: bool, expected_value: Any, passed: bool) -> None:
        checks[name] = {
            "required": required,
            "expected": expected_value,
            "status": "passed" if not required or passed else "failed",
        }

    add_check("method", bool(method), method or None, method in actual_methods)
    add_check("scanner", bool(scanner), scanner or None, scanner in actual_scanners)
    add_check("dbms", bool(expected_db), expected_db or None, expected_db in actual_dbs)
    add_check(
        "techniques",
        bool(expected_techniques),
        expected_techniques,
        all(technique in actual_techniques for technique in expected_techniques),
    )
    minimum_confidence = expected.get("minimum_confidence")
    add_check(
        "minimum_confidence",
        minimum_confidence is not None,
        minimum_confidence,
        minimum_confidence is not None and confidence_score >= int(minimum_confidence),
    )
    requires_replay = bool(expected.get("requires_replay", False))
    add_check(
        "manual_replay",
        requires_replay,
        requires_replay,
        bool(actual["finding"].get("manual_replay_succeeds")),
    )
    requires_attack_chain = bool(expected.get("requires_attack_chain", False))
    add_check(
        "attack_path",
        requires_attack_chain,
        requires_attack_chain,
        bool(actual["finding"].get("attack_path_confirmed")),
    )
    return checks


class GroundTruthEngine:
    """Evaluates scan findings against a target's expected vulnerability manifest."""

    def __init__(self, expected_findings: List[Dict[str, Any]]):
        """Initialize with expected findings list, e.g.:
        [
          {
            "vuln_class": "sqli",
            "path": "/catalog/product",
            "parameter": "productId",
            "description": "SQL Injection in productId parameter"
          }
        ]
        """
        self.expected = expected_findings

    def evaluate_engagement(
        self,
        actual_findings: List[Dict[str, Any]],
        tasks_list: List[Any],
        skipped_scans: List[Dict[str, Any]],
        endpoints_list: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute coverage, precision, recall, and missed vulnerability traces."""

        # 1. Map expected findings and check their status in the pipeline
        traces: List[Dict[str, Any]] = []
        tp = 0
        fn = 0

        # Normalize actual findings for lookup. Evidence is deliberately included:
        # Neo4j vulnerability nodes preserve the tool URL and parameter in evidence
        # rather than duplicating those fields at the top level.
        actual_lookup: List[Dict[str, Any]] = []
        for f in actual_findings:
            actual_lookup.append(
                {
                    "type": _normalise_class(f.get("vuln_type") or f.get("type")),
                    "paths": _extract_urls(f),
                    "parameters": _extract_parameters(f),
                    "methods": _extract_values(
                        f, ["method", "http_method"], ["method", "http_method"]
                    ),
                    "scanners": _extract_values(
                        f, ["tool_source", "scanner"], ["provenance", "scanner"]
                    ),
                    "dbms": _extract_values(f, ["dbms"], ["dbms"]),
                    "techniques": _extract_values(f, ["techniques"], ["techniques"]),
                    "finding": f,
                }
            )
        matched_actual_indexes: Set[int] = set()

        for exp in self.expected:
            vuln_class = _normalise_class(exp["vuln_class"])
            path = _normalise_path(exp["path"])
            param = _normalise_parameter(exp.get("parameter"))

            trace = {
                "expected": exp,
                "endpoint_discovered": False,
                "parameter_extracted": False,
                "scanner_scheduled": False,
                "task_status": None,
                "task_error": None,
                "task_id": None,
                "is_skipped": False,
                "skip_reason": None,
                "matched_finding_id": None,
                "matched_parameter": None,
                "confidence_assessment": None,
                "evidence_contract": {},
                "contract_satisfied": False,
                "status": "missed",
            }

            # Step 1: Was the endpoint path discovered?
            matching_endpoints = []
            for ep in endpoints_list:
                ep_url = ep.get("url") or ""
                if _normalise_path(ep_url) == path:
                    trace["endpoint_discovered"] = True
                    matching_endpoints.append(ep)

            # Step 2: Was the parameter extracted?
            if trace["endpoint_discovered"] and param:
                for ep in matching_endpoints:
                    query_keys = ep.get("query_keys") or []
                    # Also parse from URL query string if present
                    ep_url = ep.get("url") or ""
                    ep_parsed = urlparse(ep_url.lower())
                    if ep_parsed.query:
                        from urllib.parse import parse_qsl

                        query_keys.extend([k for k, _ in parse_qsl(ep_parsed.query)])

                    if any(str(k).lower() == param for k in query_keys):
                        trace["parameter_extracted"] = True
                        break
            elif trace["endpoint_discovered"] and not param:
                trace["parameter_extracted"] = True

            # Step 3: Was the scanner scheduled?
            # We match tasks by type (e.g. sqli_scan) and target url matching the path
            matching_tasks = []
            for t in tasks_list:
                t_type = _get_field(t, "type", "")
                # Normalise type (e.g. jwt_scan)
                if _normalise_class(t_type.removesuffix("_scan")) == vuln_class:
                    # Check if task payload target URL matches our expected path
                    payload = _get_field(t, "payload", {})
                    if isinstance(payload, str):
                        try:
                            payload = json.loads(payload)
                        except (TypeError, ValueError):
                            payload = {}
                    t_url = payload.get("url") or payload.get("target") or ""
                    if _normalise_path(t_url) == path:
                        trace["scanner_scheduled"] = True
                        matching_tasks.append(t)

            # Step 4: Was the task executed? What's the status/error?
            if trace["scanner_scheduled"] and matching_tasks:
                # Get the latest/most advanced task
                latest_task = matching_tasks[-1]
                t_status = _get_field(latest_task, "status")
                t_id = _get_field(latest_task, "id")

                trace["task_id"] = t_id
                trace["task_status"] = t_status

                # Check for error in result
                t_res = _get_field(latest_task, "result")
                if isinstance(t_res, str):
                    try:
                        t_res = json.loads(t_res)
                    except (TypeError, ValueError):
                        pass
                if isinstance(t_res, dict):
                    trace["task_error"] = t_res.get("error") or t_res.get("reason")
                else:
                    trace["task_error"] = _get_field(latest_task, "error")

            # Step 5: Check if the scan was skipped by the Applicability Engine
            for s in skipped_scans:
                s_class = _normalise_class(s.get("vuln_class"))
                s_url = s.get("endpoint_url") or ""
                if s_class == vuln_class and _normalise_path(s_url) == path:
                    trace["is_skipped"] = True
                    trace["skip_reason"] = s.get("reason")
                    trace["status"] = "skipped"
                    break

            # Step 6: Verify if actually found in findings
            is_found = False
            for index, al in enumerate(actual_lookup):
                if index in matched_actual_indexes:
                    continue
                parameter_matches = not param or param in al["parameters"]
                if al["type"] == vuln_class and path in al["paths"] and parameter_matches:
                    is_found = True
                    matched_actual_indexes.add(index)
                    trace["status"] = "found"
                    trace["matched_finding_id"] = al["finding"].get("id")
                    trace["matched_parameter"] = param or None
                    assessment = score_finding(al["finding"], {"ground_truth_match": True})
                    trace["confidence_assessment"] = assessment
                    checks = _evaluate_contract(exp, al, assessment["score"])
                    trace["evidence_contract"] = checks
                    trace["contract_satisfied"] = all(
                        check["status"] == "passed" for check in checks.values()
                    )
                    tp += 1
                    break

            if not is_found and trace["status"] != "skipped":
                fn += 1

            traces.append(trace)

        # Calculate False Positives (actual findings that were not expected)
        # One real finding may satisfy only one expected entry. Any additional
        # unmatched finding is a false positive, including duplicate reports.
        fp = len(actual_lookup) - len(matched_actual_indexes)

        total_expected = len(self.expected)
        total_found = len(actual_findings)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        found_traces: List[Dict[str, Any]] = [
            trace for trace in traces if trace["status"] == "found"
        ]
        findings_by_id = {
            str(actual["finding"].get("id")): actual["finding"] for actual in actual_lookup
        }
        confidence_scores: List[int] = []
        execution_observed = 0
        verified = 0
        persisted = 0
        contract_satisfied = 0
        for trace in found_traces:
            trace_assessment = trace.get("confidence_assessment")
            if not isinstance(trace_assessment, dict):
                continue
            score = trace_assessment.get("score")
            if isinstance(score, int):
                confidence_scores.append(score)
            if "tool_validation" in trace_assessment.get("verified_signals", []):
                execution_observed += 1
            finding_id = trace.get("matched_finding_id")
            if finding_id:
                persisted += 1
                if findings_by_id.get(str(finding_id), {}).get("validated"):
                    verified += 1
            if trace.get("contract_satisfied"):
                contract_satisfied += 1
        coverage_confidence = {
            "expected": total_expected,
            "execution_observed": execution_observed,
            "verified": verified,
            "persisted": persisted,
            "contract_satisfied": contract_satisfied,
            "average_evidence_confidence": (
                round(sum(confidence_scores) / len(confidence_scores), 1)
                if confidence_scores
                else 0.0
            ),
        }

        return {
            "metrics": {
                "total_expected": total_expected,
                "total_found": total_found,
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
            },
            "coverage_confidence": coverage_confidence,
            "traces": traces,
        }

    def generate_markdown_report(self, results: Dict[str, Any]) -> str:
        """Format the evaluation metrics and traces into a clean Markdown audit report."""
        m = results["metrics"]

        md = []
        md.append("# AI-OSOP Capability Coverage & Ground Truth Audit")
        md.append(f"**Generated:** {datetime.utcnow().isoformat()}Z\n")

        md.append("## Executive Summary\n")
        md.append("| Metric | Value | Description |")
        md.append("| :--- | :---: | :--- |")
        md.append(
            f"| **Ground Truth Expected** | {m['total_expected']} | Total vulnerabilities expected on this benchmark target |"
        )
        md.append(f"| **Total Found** | {m['total_found']} | Vulnerabilities reported by AI-OSOP |")
        md.append(
            f"| **True Positives** | {m['true_positives']} | Valid expected vulnerabilities found |"
        )
        md.append(
            f"| **False Positives** | {m['false_positives']} | Reported findings not in ground truth (potential noise) |"
        )
        md.append(
            f"| **False Negatives (Missed)** | {m['false_negatives']} | Expected vulnerabilities AI-OSOP failed to find |"
        )
        md.append(
            f"| **Precision Score** | {m['precision'] * 100:.1f}% | Ratio of valid findings to total reported |"
        )
        md.append(
            f"| **Recall Score** | {m['recall'] * 100:.1f}% | Ratio of valid findings to total expected |"
        )
        md.append(
            f"| **F1 Score** | {m['f1_score'] * 100:.1f}% | Harmonic mean of Precision and Recall |"
        )
        md.append("\n")

        coverage = results.get("coverage_confidence", {})
        if coverage:
            md.append("## Coverage Confidence\n")
            md.append("| Stage | Count |")
            md.append("| :--- | ---: |")
            md.append(f"| Expected | {coverage['expected']} |")
            md.append(f"| Tool execution observed | {coverage['execution_observed']} |")
            md.append(f"| Validated | {coverage['verified']} |")
            md.append(f"| Persisted | {coverage['persisted']} |")
            md.append(f"| Evidence contract satisfied | {coverage['contract_satisfied']} |")
            md.append(
                f"| Average evidence confidence | {coverage['average_evidence_confidence']:.1f}/100 |"
            )
            md.append("\n")

        md.append("## Missed Vulnerability Execution Traces\n")
        md.append("Detailed analysis of why expected vulnerabilities were missed:\n")

        for t in results["traces"]:
            exp = t["expected"]
            status_emoji = {
                "found": "✅ **FOUND**",
                "skipped": "⏩ **SKIPPED**",
                "missed": "❌ **MISSED**",
            }.get(t["status"], "❓ **UNKNOWN**")

            md.append(f"### Expected: {exp['description']}")
            md.append(f"- **Vulnerability Class:** `{exp['vuln_class'].upper()}`")
            md.append(
                f"- **Target Path:** `{exp['path']}` (Param: `{exp.get('parameter', 'none')}`)"
            )
            md.append(f"- **Pipeline Status:** {status_emoji}")

            if t["status"] == "found":
                md.append(
                    "  - *Vulnerability was successfully discovered and verified in the graph.*"
                )
                if not t["contract_satisfied"]:
                    failed_checks = [
                        name
                        for name, check in t["evidence_contract"].items()
                        if check["status"] == "failed"
                    ]
                    md.append("  - **Evidence contract incomplete:** " + ", ".join(failed_checks))
            elif t["status"] == "skipped":
                md.append(
                    f"  - **Skip Reason:** {t['skip_reason']} (filtered by Applicability Engine)"
                )
            else:
                # Detail the exact stage where it was lost
                stages = []
                stages.append(
                    f"  - [Step 1] Endpoint Discovered: {'✅ YES' if t['endpoint_discovered'] else '❌ NO'}"
                )
                stages.append(
                    f"  - [Step 2] Parameter Extracted: {'✅ YES' if t['parameter_extracted'] else '❌ NO'}"
                )
                stages.append(
                    f"  - [Step 3] Scanner Scheduled: {'✅ YES' if t['scanner_scheduled'] else '❌ NO'}"
                )

                t_status = t.get("task_status")
                t_id = t.get("task_id")

                if t_id:
                    stages.append(f"  - [Step 4] Task Started: ✅ YES (`{t_id}`)")
                    stages.append(f"  - [Step 5] Task Execution Status: `{t_status}`")
                    if t_status in ("pending", "scheduled"):
                        stages.append(
                            "    - ⚠️ **Root Cause:** Queue timeout (task remained stalled in queue due to concurrency limits)."
                        )
                    elif t_status == "failed":
                        stages.append(
                            f"    - ⚠️ **Root Cause:** Scanner failed. Error: `{t['task_error']}`"
                        )
                else:
                    stages.append("  - [Step 4] Task Started: ❌ NO")
                    # Deduce the pipeline failure stage
                    if not t["endpoint_discovered"]:
                        stages.append(
                            "    - ⚠️ **Root Cause:** Recon/crawler failed to discover target endpoint."
                        )
                    elif not t["parameter_extracted"]:
                        stages.append(
                            "    - ⚠️ **Root Cause:** Parameter extractor failed to locate target parameter."
                        )
                    else:
                        stages.append(
                            "    - ⚠️ **Root Cause:** Planner skipped scanner / task never generated."
                        )

                md.append("\n".join(stages))
            md.append("\n" + "-" * 40 + "\n")

        return "\n".join(md)
