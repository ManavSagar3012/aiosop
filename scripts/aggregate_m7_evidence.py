"""Aggregate persisted Gin & Juice and Juice Shop benchmark evidence for M7.

The script is read-only with respect to targets. It queries the existing M3
Neo4j finding and reads a Juice Shop result file; it then writes one local M7
evidence summary. Any unstable run remains visible in that summary.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_osop.core.capability_benchmarks import aggregate_benchmark_results
from ai_osop.core.ground_truth import GroundTruthEngine
from ai_osop.memory.graph_memory import GraphMemory


REPO = Path(__file__).resolve().parents[1]
GIN_MANIFEST = REPO / "benchmarks" / "manifests" / "ginandjuice_m3.json"
JUICE_RESULTS = REPO / "benchmarks" / "juiceshop" / "results"
OUTPUT_DIR = REPO / "benchmarks" / "results"
GIN_ENGAGEMENT_ID = "eng-m3-real-sqlmap"


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return payload


def _latest_juice_result() -> Path:
    results = sorted(JUICE_RESULTS.glob("bench-*.json"))
    if not results:
        raise FileNotFoundError("No Juice Shop benchmark result found")
    return results[-1]


def _juice_envelope(report: Dict[str, Any]) -> Dict[str, Any]:
    scoreboard = report["scored_scoreboard"]
    tp = int(scoreboard["true_positive"])
    fn = int(scoreboard["false_negative"])
    positive_confidences = [
        float(check["confidence"])
        for check in report["per_check"].values()
        if check["scored"] and check["expected_exploitable"] and check["validated"]
    ]
    average_confidence = (
        round(sum(positive_confidences) * 100 / len(positive_confidences), 1)
        if positive_confidences
        else 0.0
    )
    return {
        "benchmark_id": "owasp-juiceshop-core-v1",
        "metrics": {
            "total_expected": tp + fn,
            "true_positives": tp,
            "false_positives": int(scoreboard["false_positive"]),
            "false_negatives": fn,
            "precision": float(scoreboard["precision"] or 0.0),
            "recall": float(scoreboard["recall"] or 0.0),
        },
        "coverage_confidence": {
            "average_evidence_confidence": average_confidence,
            "stable": bool(report["stability"]["stable"]),
        },
    }


async def _gin_envelope() -> Dict[str, Any]:
    manifest = _load_json(GIN_MANIFEST)
    graph = GraphMemory()
    await graph.connect()
    try:
        findings = await graph.get_vulnerabilities_by_engagement(GIN_ENGAGEMENT_ID)
    finally:
        await graph.close()
    evaluation = GroundTruthEngine(manifest["expected_findings"]).evaluate_engagement(
        findings, [], [], []
    )
    return {
        "benchmark_id": manifest["benchmark_id"],
        "metrics": evaluation["metrics"],
        "coverage_confidence": evaluation["coverage_confidence"],
    }


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--juice-result", type=Path, default=None)
    args = parser.parse_args()
    juice_path = args.juice_result or _latest_juice_result()
    juice = _juice_envelope(_load_json(juice_path))
    gin = await _gin_envelope()
    aggregate = aggregate_benchmark_results([gin, juice])
    aggregate["inputs"] = {
        "ginandjuice_engagement_id": GIN_ENGAGEMENT_ID,
        "juiceshop_result": str(juice_path.relative_to(REPO)),
        "juiceshop_stable": juice["coverage_confidence"]["stable"],
    }
    OUTPUT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output = OUTPUT_DIR / f"m7-{stamp}.json"
    output.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    print(json.dumps(aggregate, sort_keys=True))
    print(f"evidence_written={output.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
