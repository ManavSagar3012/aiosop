"""Ground Truth Engine — benchmark precision & recall validation.

Maps the actual findings generated during an engagement against a known
expected vulnerability manifest to calculate security engineering metrics and
produce evidence-backed execution traces for missed findings.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _get_field(obj: Any, field: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(field, default)
    try:
        return getattr(obj, field, default)
    except AttributeError:
        return default


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
        traces = []
        tp = 0
        fn = 0

        # Normalize actual findings for lookup
        # Actual finding shape: {'title': '...', 'vuln_type': 'csrf', 'endpoint_id': '...'}
        # Or from /findings: {'title': '...', 'type': 'csrf', 'url': '...'}
        actual_lookup = []
        for f in actual_findings:
            f_type = str(f.get("vuln_type") or f.get("type") or "").lower().replace("_", "")
            f_url = str(f.get("url") or "").lower()
            actual_lookup.append({"type": f_type, "url": f_url, "finding": f})

        for exp in self.expected:
            vuln_class = exp["vuln_class"].lower().replace("_", "")
            path = exp["path"].lower()
            param = exp.get("parameter", "").lower()

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
                "status": "missed",
            }

            # Step 1: Was the endpoint path discovered?
            matching_endpoints = []
            for ep in endpoints_list:
                ep_url = ep.get("url") or ""
                ep_parsed = urlparse(ep_url.lower())
                if ep_parsed.path == path or ep_parsed.path.rstrip("/") == path.rstrip("/"):
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
            task_type_key = f"{vuln_class}_scan"
            for t in tasks_list:
                t_type = _get_field(t, "type", "")
                # Normalise type (e.g. jwt_scan)
                if t_type.lower() == task_type_key:
                    # Check if task payload target URL matches our expected path
                    payload = _get_field(t, "payload", {})
                    if isinstance(payload, str):
                        try:
                            payload = json.loads(payload)
                        except Exception:
                            payload = {}
                    t_url = payload.get("url") or payload.get("target") or ""
                    t_parsed = urlparse(t_url.lower())
                    if t_parsed.path == path or t_parsed.path.rstrip("/") == path.rstrip("/"):
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
                    except Exception:
                        pass
                if isinstance(t_res, dict):
                    trace["task_error"] = t_res.get("error") or t_res.get("reason")
                else:
                    trace["task_error"] = _get_field(latest_task, "error")

            # Step 5: Check if the scan was skipped by the Applicability Engine
            for s in skipped_scans:
                s_class = s.get("vuln_class", "").lower().replace("_", "")
                s_url = s.get("endpoint_url") or ""
                s_parsed = urlparse(s_url.lower())
                if s_class == vuln_class and (
                    s_parsed.path == path or s_parsed.path.rstrip("/") == path.rstrip("/")
                ):
                    trace["is_skipped"] = True
                    trace["skip_reason"] = s.get("reason")
                    trace["status"] = "skipped"
                    break

            # Step 6: Verify if actually found in findings
            is_found = False
            for al in actual_lookup:
                if al["type"] == vuln_class:
                    al_parsed = urlparse(al["url"])
                    if al_parsed.path == path or al_parsed.path.rstrip("/") == path.rstrip("/"):
                        is_found = True
                        trace["status"] = "found"
                        tp += 1
                        break

            if not is_found and trace["status"] != "skipped":
                fn += 1

            traces.append(trace)

        # Calculate False Positives (actual findings that were not expected)
        fp = 0
        for al in actual_lookup:
            matched_expected = False
            for exp in self.expected:
                exp_class = exp["vuln_class"].lower().replace("_", "")
                exp_path = exp["path"].lower()
                al_parsed = urlparse(al["url"])
                if exp_class == al["type"] and (
                    al_parsed.path == exp_path or al_parsed.path.rstrip("/") == exp_path.rstrip("/")
                ):
                    matched_expected = True
                    break
            if not matched_expected:
                fp += 1

        total_expected = len(self.expected)
        total_found = len(actual_findings)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

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
