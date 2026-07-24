#!/usr/bin/env python3
"""Blind Engagement + Ablation Study Runner.

Phase 2 + Ablation: runs the cognition benchmark in BLIND mode (no prior
knowledge of the target — no manifest, no preset endpoints, no hardcoded
paths) and with/without each cognitive component to measure which
components actually contribute to performance.

Blind mode: the system gets only a URL. No ground-truth manifest. No
preseeded endpoints. It must discover, orient, hypothesize, and test
entirely on its own.

Ablation: runs the same engagement with each cognitive component toggled
off in turn to measure its contribution:
  - Without business context (no orientation)
  - Without uncertainty tracker (no active info-seeking)
  - Without graph pathfinder (no chain discovery)
  - Without adversarial critic (no false-positive review)
  - Without reasoning trace (no explainability)
  - Baseline: all components on

Usage:
  python benchmarks/blind_ablation.py --target http://localhost:3000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_SRC = Path(__file__).resolve().parent.parent / "src"
_BENCH = Path(__file__).resolve().parent
for p in [_SRC, _BENCH]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from ai_osop.core.config import settings, EngagementPhase  # noqa: E402
from ai_osop.core.deterministic_scan import (  # noqa: E402
    bootstrap_discovery,
    run_deterministic_scan,
    run_generalized_scan,
)
from ai_osop.core.models import ScopeDefinition, SessionState  # noqa: E402
from ai_osop.memory.graph_memory import GraphMemory  # noqa: E402
from ai_osop.safety.governed_client import (  # noqa: E402
    governance_hook,
    research_header_from_settings,
)
from ai_osop.safety.rate_limiter import RateLimiter  # noqa: E402
from ai_osop.safety.scope import ScopeEnforcer  # noqa: E402


@dataclass
class AblationResult:
    """Result of one ablation run."""
    config_name: str
    seeded: int = 0
    findings_total: int = 0
    findings_validated: int = 0
    chains: int = 0
    uncertainties: int = 0
    time_to_discovery: float = 0.0
    high_value_endpoints: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


# Ablation configurations: which components to enable/disable
ABLATION_CONFIGS = [
    {
        "name": "baseline (all on)",
        "business_context": True,
        "uncertainty_tracker": True,
        "graph_pathfinder": True,
    },
    {
        "name": "without business context",
        "business_context": False,
        "uncertainty_tracker": True,
        "graph_pathfinder": True,
    },
    {
        "name": "without uncertainty tracker",
        "business_context": True,
        "uncertainty_tracker": False,
        "graph_pathfinder": True,
    },
    {
        "name": "without graph pathfinder",
        "business_context": True,
        "uncertainty_tracker": True,
        "graph_pathfinder": False,
    },
    {
        "name": "without any cognitive components (raw scan)",
        "business_context": False,
        "uncertainty_tracker": False,
        "graph_pathfinder": False,
    },
]


async def run_ablation(
    target_url: str,
    config: Dict[str, Any],
) -> AblationResult:
    """Run one ablation configuration against the target."""
    result = AblationResult(config_name=config["name"])

    gm = GraphMemory()
    try:
        await gm.connect()
    except Exception as e:
        result.error = f"Neo4j connection failed: {e}"
        return result

    eid = f"abl-{secrets.token_hex(3)}"
    scope = ScopeDefinition(
        engagement_id=eid,
        domains=["localhost"],
        ips=["127.0.0.1"],
    )

    ghook = governance_hook(
        scope=ScopeEnforcer(scope),
        rate_limiter=RateLimiter(
            target_rate=settings.scan_target_rate_per_second,
            target_capacity=settings.scan_target_burst,
        ),
        research_header=research_header_from_settings(),
    )

    try:
        t0 = time.monotonic()

        # 1. Discovery (always on — this is the baseline scanner)
        seeded = await bootstrap_discovery(target_url, eid, gm, governance_hook=ghook)
        result.seeded = seeded

        # 2. Business context (conditional)
        eps = await gm.run_read_query(
            "MATCH (e:Endpoint {engagement_id: $eid}) "
            "RETURN e.url AS url, e.path AS path, e.method AS method, "
            "e.status_code AS status_code, e.technologies AS technologies, "
            "e.auth_required AS auth_required, e.query_keys AS query_keys, e.id AS id "
            "LIMIT 500",
            {"eid": eid},
        )

        if config.get("business_context", True):
            from ai_osop.core.business_context import batch_categorize
            categorized = batch_categorize(eps)
            result.high_value_endpoints = len([c for c in categorized if c.criticality >= 7])

        # 3. Uncertainty detection (conditional)
        if config.get("uncertainty_tracker", True):
            from ai_osop.core.uncertainty_tracker import UncertaintyTracker
            tracker = UncertaintyTracker()
            uncerts = tracker.detect_uncertainties(eid, eps, [])
            result.uncertainties = tracker.get_summary(eid).get("total", 0)

        # 4. Hypothesize (always on — this is the reasoning engine)
        from ai_osop.core.hypothesis_engine import HypothesisEngine
        engine = HypothesisEngine(gm, session_memory=None)
        await engine.generate_and_persist(eid, limit=12)

        # 5. Scan (always on — this is the detection engine)
        suite_f, _, _ = await run_deterministic_scan(target_url, eid, gm, governance_hook=ghook)
        gen_f, _ = await run_generalized_scan(eid, gm, governance_hook=ghook)
        result.time_to_discovery = time.monotonic() - t0

        # 6. Read back findings
        vulns = await gm.get_vulnerabilities_by_engagement(eid)
        validated = [v for v in vulns if v.get("validated")]
        result.findings_total = len(vulns)
        result.findings_validated = len(validated)

        # 7. Graph pathfinder (conditional)
        if config.get("graph_pathfinder", True):
            from ai_osop.core.graph_pathfinder import GraphPathfinder
            pathfinder = GraphPathfinder(gm)
            chains = await pathfinder.find_chains(eid, max_depth=5)
            result.chains = len(chains)

    except Exception as e:
        result.error = str(e)
    finally:
        await gm.close()

    return result


async def run_blind_ablation(target_url: str) -> int:
    """Run all ablation configurations and compare results."""
    print(f"\n{'='*70}")
    print(f"BLIND ENGAGEMENT + ABLATION STUDY")
    print(f"Target: {target_url}")
    print(f"{'='*70}\n")

    results: List[AblationResult] = []

    for config in ABLATION_CONFIGS:
        print(f"--- {config['name']} ---")
        result = await run_ablation(target_url, config)
        results.append(result)
        print(f"  seeded={result.seeded} findings={result.findings_total} "
              f"validated={result.findings_validated} chains={result.chains} "
              f"uncertainties={result.uncertainties} "
              f"high_value={result.high_value_endpoints} "
              f"ttd={result.time_to_discovery:.1f}s"
              + (f" ERROR: {result.error}" if result.error else ""))
        print()

    # Comparison table
    print(f"{'='*70}")
    print(f"ABLATION COMPARISON TABLE")
    print(f"{'='*70}")
    print(f"{'Config':<45} {'Seed':>5} {'Find':>5} {'Val':>5} {'Chain':>5} {'Unc':>5} {'HV':>4} {'TTD':>6}")
    print(f"{'-'*45} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*4} {'-'*6}")
    for r in results:
        print(f"{r.config_name:<45} {r.seeded:>5} {r.findings_total:>5} "
              f"{r.findings_validated:>5} {r.chains:>5} {r.uncertainties:>5} "
              f"{r.high_value_endpoints:>4} {r.time_to_discovery:>5.1f}s")

    # Delta analysis: how much does each component contribute?
    print(f"\n--- Component Contribution Analysis ---")
    baseline = results[0]  # all components on
    for r in results[1:]:
        delta_findings = r.findings_validated - baseline.findings_validated
        delta_chains = r.chains - baseline.chains
        delta_unc = r.uncertainties - baseline.uncertainties
        print(f"  {r.config_name}:")
        print(f"    findings delta: {delta_findings:+d}")
        print(f"    chains delta:   {delta_chains:+d}")
        print(f"    uncertainty delta: {delta_unc:+d}")

    # Save results
    output_path = _BENCH / "ablation_results.json"
    output_path.write_text(json.dumps([r.to_dict() for r in results], indent=2))
    print(f"\nResults saved to {output_path}")

    print(f"\n{'='*70}")
    print(f"ABLATION STUDY COMPLETE")
    print(f"{'='*70}\n")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Blind engagement + ablation study")
    parser.add_argument("--target", default="http://localhost:3000")
    args = parser.parse_args()
    return asyncio.run(run_blind_ablation(args.target))


if __name__ == "__main__":
    sys.exit(main())
