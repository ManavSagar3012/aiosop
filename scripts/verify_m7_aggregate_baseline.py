"""Aggregate the available M4 result without claiming cross-benchmark validity.

This runner is intentionally read-only. With only one scoped manifest it must
report ``generalization_ready=false``; it becomes an M7 proof only after more
independent benchmark manifests and recorded results are supplied.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_osop.core.capability_benchmarks import aggregate_benchmark_results
from ai_osop.core.ground_truth import GroundTruthEngine
from ai_osop.memory.graph_memory import GraphMemory


ENGAGEMENT_ID = "eng-m3-real-sqlmap"
MANIFEST_PATH = (
    Path(__file__).resolve().parents[1] / "benchmarks" / "manifests" / "ginandjuice_m3.json"
)


def _load_manifest() -> Dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


async def main() -> int:
    manifest = _load_manifest()
    graph = GraphMemory()
    await graph.connect()
    try:
        findings = await graph.get_vulnerabilities_by_engagement(ENGAGEMENT_ID)
    finally:
        await graph.close()

    result = GroundTruthEngine(manifest["expected_findings"]).evaluate_engagement(
        findings, [], [], []
    )
    aggregate = aggregate_benchmark_results(
        [
            {
                "benchmark_id": manifest["benchmark_id"],
                "metrics": result["metrics"],
                "coverage_confidence": result["coverage_confidence"],
            }
        ]
    )
    print(json.dumps(aggregate, sort_keys=True))
    return 0 if not aggregate["generalization_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
