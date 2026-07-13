"""Evaluate the persisted M3 finding against its versioned, scoped manifest.

This is an offline read of Neo4j. It performs no scanning and does not claim
general recall: the manifest currently covers one authorized SQLi scenario.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_osop.core.finding_confidence import score_finding
from ai_osop.core.ground_truth import GroundTruthEngine
from ai_osop.memory.graph_memory import GraphMemory


ENGAGEMENT_ID = "eng-m3-real-sqlmap"
MANIFEST_PATH = (
    Path(__file__).resolve().parents[1] / "benchmarks" / "manifests" / "ginandjuice_m3.json"
)


def _load_manifest() -> Dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest.get("expected_findings"), list):
        raise ValueError("Manifest must contain an expected_findings list")
    return manifest


async def main() -> int:
    manifest = _load_manifest()
    graph = GraphMemory()
    await graph.connect()
    try:
        findings = await graph.get_vulnerabilities_by_engagement(ENGAGEMENT_ID)
    finally:
        await graph.close()

    engine = GroundTruthEngine(manifest["expected_findings"])
    result = engine.evaluate_engagement(findings, [], [], [])
    metrics = result["metrics"]
    print(f"benchmark={manifest['benchmark_id']}")
    print(f"scope={manifest['scope']}")
    print(json.dumps(metrics, sort_keys=True))
    print(json.dumps(result["coverage_confidence"], sort_keys=True))

    if metrics["true_positives"] != len(manifest["expected_findings"]):
        return 1

    assessment = score_finding(findings[0], {"ground_truth_match": True})
    print(f"finding_confidence_score={assessment['score']}/100")
    print(f"evidence_contract_satisfied={result['traces'][0]['contract_satisfied']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
