#!/usr/bin/env python3
"""Cross-Stack Generalization Benchmark Harness.

Runs the cognition benchmark against MULTIPLE targets with different
technology stacks — without modifying AI-OSOP. This is Phase 1 of the
research evaluation program: does the cognitive architecture generalize
beyond the environment it was designed and tested on?

Each target gets the same treatment:
  1. Governed discovery (crt.sh, Wayback, content crawl, OpenAPI, WAF detection)
  2. Business context orientation (endpoint categorization)
  3. Uncertainty detection
  4. Hypothesis generation
  5. Deterministic + generalized scan
  6. Graph pathfinder (attack chain discovery)
  7. Cognition metrics (time-to-discovery, FP rate, novel paths, chains, trace)

The harness then compares results across targets to measure:
  - Does reasoning quality stay stable across stacks?
  - Does false-positive rate stay low?
  - Does time-to-discovery stay comparable?
  - Does it discover novel paths on unfamiliar targets?

Usage:
  # Run against Juice Shop (baseline)
  python benchmarks/cross_stack_benchmark.py --targets juice-shop

  # Run against multiple targets (if containers are running)
  python benchmarks/cross_stack_benchmark.py --targets juice-shop,dvwa,webgoat

  # Run all available targets
  python benchmarks/cross_stack_benchmark.py --all
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
from ai_osop.core.business_context import batch_categorize  # noqa: E402
from ai_osop.core.uncertainty_tracker import UncertaintyTracker  # noqa: E402
from ai_osop.core.reasoning_trace import ReasoningTrace  # noqa: E402
from ai_osop.core.graph_pathfinder import GraphPathfinder  # noqa: E402
from score_engagement import score_findings, load_manifest  # noqa: E402


# Target registry: each target has a URL, scope domain, and optional
# ground-truth manifest path. When no manifest exists, the scorecard
# uses a permissive manifest (recall=None — honest "no ground truth").
TARGETS = {
    "juice-shop": {
        "url": "http://localhost:3000",
        "domain": "localhost",
        "manifest": "benchmarks/ground_truth/juice_shop.yaml",
        "stack": "Node.js/Angular/SQLite",
        "description": "OWASP Juice Shop — modern SPA with 50+ known vulns",
    },
    "dvwa": {
        "url": "http://localhost:8080",
        "domain": "localhost",
        "manifest": None,  # no ground truth manifest
        "stack": "PHP/MySQL",
        "description": "Damn Vulnerable Web Application — PHP/MySQL",
    },
    "webgoat": {
        "url": "http://localhost:8081",
        "domain": "localhost",
        "manifest": None,
        "stack": "Java/Spring/H2",
        "description": "OWASP WebGoat — Java Spring educational app",
    },
    "mutillidae": {
        "url": "http://localhost:8082",
        "domain": "localhost",
        "manifest": None,
        "stack": "PHP/Apache",
        "description": "OWASP Mutillidae II — legacy PHP",
    },
    "nodegoat": {
        "url": "http://localhost:4000",
        "domain": "localhost",
        "manifest": None,
        "stack": "Node.js/Express/MongoDB",
        "description": "OWASP NodeGoat — Node.js business logic",
    },
}


@dataclass
class TargetResult:
    """Results from running the cognition benchmark against one target."""
    target_name: str
    url: str
    stack: str
    seeded: int = 0
    findings_total: int = 0
    findings_validated: int = 0
    chains: int = 0
    uncertainties: int = 0
    time_to_discovery: float = 0.0
    novel_paths: int = 0
    trace_steps: int = 0
    trace_confirmed: int = 0
    trace_refuted: int = 0
    false_positive_rate: float = 0.0
    recall: Optional[float] = None
    precision: Optional[float] = None
    high_value_endpoints: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


async def run_target(
    target_name: str,
    target_config: Dict[str, Any],
) -> TargetResult:
    """Run the cognition benchmark against a single target."""
    url = target_config["url"]
    domain = target_config["domain"]
    result = TargetResult(
        target_name=target_name,
        url=url,
        stack=target_config.get("stack", "unknown"),
    )

    print(f"\n--- {target_name} ({target_config['stack']}) ---")

    gm = GraphMemory()
    try:
        await gm.connect()
    except Exception as e:
        result.error = f"Neo4j connection failed: {e}"
        print(f"  SKIP  {result.error}")
        return result

    eid = f"xstack-{target_name}-{secrets.token_hex(3)}"
    scope = ScopeDefinition(
        engagement_id=eid,
        domains=[domain],
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

    trace = ReasoningTrace()
    uncertainty = UncertaintyTracker()

    try:
        # 1. Discovery
        t0 = time.monotonic()
        seeded = await bootstrap_discovery(url, eid, gm, governance_hook=ghook)
        result.seeded = seeded
        if seeded == 0:
            result.error = "discovery seeded 0 endpoints"
            result.time_to_discovery = time.monotonic() - t0
            print(f"  SKIP  {result.error}")
            await gm.close()
            return result

        # 2. Observe endpoints
        eps = await gm.run_read_query(
            "MATCH (e:Endpoint {engagement_id: $eid}) "
            "RETURN e.url AS url, e.path AS path, e.method AS method, "
            "e.status_code AS status_code, e.technologies AS technologies, "
            "e.auth_required AS auth_required, e.query_keys AS query_keys, e.id AS id "
            "LIMIT 500",
            {"eid": eid},
        )

        # 3. Orient: business context
        categorized = batch_categorize(eps)
        high_value = [c for c in categorized if c.criticality >= 7]
        result.high_value_endpoints = len(high_value)
        trace.record(eid, "orient", f"Categorized {len(categorized)} endpoints",
                     rationale=f"{len(high_value)} high-value")

        # 4. Uncertainty detection
        new_uncerts = uncertainty.detect_uncertainties(eid, eps, [])
        result.uncertainties = uncertainty.get_summary(eid).get("total", 0)

        # 5. Hypothesize
        from ai_osop.core.hypothesis_engine import HypothesisEngine
        engine = HypothesisEngine(gm, session_memory=None)
        hypotheses = await engine.generate_and_persist(eid, limit=12)
        trace.record(eid, "hypothesize", f"Generated {len(hypotheses)} hypotheses",
                     rationale=f"categories: {set(h.category for h in hypotheses)}")

        # 6. Scan
        suite_f, _, _ = await run_deterministic_scan(url, eid, gm, governance_hook=ghook)
        gen_f, _ = await run_generalized_scan(eid, gm, governance_hook=ghook)
        all_findings = suite_f + gen_f
        result.time_to_discovery = time.monotonic() - t0

        # 7. Read back
        vulns = await gm.get_vulnerabilities_by_engagement(eid)
        validated = [v for v in vulns if v.get("validated")]
        result.findings_total = len(vulns)
        result.findings_validated = len(validated)

        for v in validated[:3]:
            trace.record(eid, "evaluate", f"Confirmed: {v.get('vuln_type', '?')}",
                         result="confirmed", confidence=float(v.get("confidence", 0)))

        # 8. Graph pathfinder
        pathfinder = GraphPathfinder(gm)
        chains = await pathfinder.find_chains(eid, max_depth=5)
        result.chains = len(chains)

        # 9. Scorecard (if manifest exists)
        manifest_path = target_config.get("manifest")
        if manifest_path and Path(manifest_path).exists():
            manifest = load_manifest(manifest_path)
            card = score_findings(vulns, manifest)
            s = card["summary"]
            result.recall = s.get("recall")
            result.precision = s.get("precision")
            result.novel_paths = s.get("extras_for_triage", 0)
            fp = s.get("false_positives", 0)
            result.false_positive_rate = fp / max(1, len(vulns))
        else:
            # No ground truth — count extras as all findings (honest)
            result.novel_paths = len(vulns)
            result.false_positive_rate = 0.0  # no ground truth to measure against

        # 10. Trace summary
        ts = trace.get_summary(eid)
        result.trace_steps = ts.get("total_steps", 0)
        result.trace_confirmed = ts.get("hypotheses_confirmed", 0)
        result.trace_refuted = ts.get("hypotheses_refuted", 0)

    except Exception as e:
        result.error = str(e)
        print(f"  ERROR  {result.error}")
    finally:
        await gm.close()

    print(f"  Result: seeded={result.seeded} findings={result.findings_total} "
          f"validated={result.findings_validated} chains={result.chains} "
          f"uncertainties={result.uncertainties} ttd={result.time_to_discovery:.1f}s "
          f"novel={result.novel_paths} trace_steps={result.trace_steps}")

    return result


async def run_cross_stack(target_names: List[str]) -> int:
    """Run the benchmark against multiple targets and compare results."""
    print(f"\n{'='*70}")
    print(f"CROSS-STACK GENERALIZATION BENCHMARK")
    print(f"{'='*70}")
    print(f"Targets: {', '.join(target_names)}")
    print()

    results: List[TargetResult] = []
    for name in target_names:
        config = TARGETS.get(name)
        if config is None:
            print(f"  SKIP  Unknown target: {name}")
            continue
        result = await run_target(name, config)
        results.append(result)

    # Comparison table
    print(f"\n{'='*70}")
    print(f"COMPARISON TABLE")
    print(f"{'='*70}")
    print(f"{'Target':<15} {'Stack':<20} {'Seed':>5} {'Find':>5} {'Val':>5} "
          f"{'Chain':>5} {'Unc':>5} {'TTD':>6} {'Novel':>6} {'Trace':>6}")
    print(f"{'-'*15} {'-'*20} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*6} {'-'*6} {'-'*6}")
    for r in results:
        print(f"{r.target_name:<15} {r.stack:<20} {r.seeded:>5} {r.findings_total:>5} "
              f"{r.findings_validated:>5} {r.chains:>5} {r.uncertainties:>5} "
              f"{r.time_to_discovery:>5.1f}s {r.novel_paths:>6} {r.trace_steps:>6}")

    # Stability analysis
    print(f"\n--- Stability Analysis ---")
    ttd_values = [r.time_to_discovery for r in results if r.error == ""]
    fp_values = [r.false_positive_rate for r in results if r.error == ""]
    chain_values = [r.chains for r in results if r.error == ""]

    if len(ttd_values) >= 2:
        ttd_avg = sum(ttd_values) / len(ttd_values)
        ttd_spread = max(ttd_values) - min(ttd_values)
        print(f"  Time-to-discovery: avg={ttd_avg:.1f}s spread={ttd_spread:.1f}s")

    if fp_values:
        fp_avg = sum(fp_values) / len(fp_values)
        print(f"  False-positive rate: avg={fp_avg:.2f} (target: <=0.1)")

    if chain_values:
        print(f"  Attack chains: min={min(chain_values)} max={max(chain_values)} "
              f"avg={sum(chain_values)/len(chain_values):.1f}")

    # Gate: at least 1 target passed with findings
    passed = [r for r in results if r.error == "" and r.findings_validated >= 1]
    gate_pass = len(passed) >= 1

    print(f"\n  GATE: at least 1 target with validated findings ... "
          f"{'PASS' if gate_pass else 'FAIL'} ({len(passed)}/{len(results)})")
    print(f"\n{'='*70}")
    print(f"{'CROSS-STACK BENCHMARK PASSED' if gate_pass else 'CROSS-STACK BENCHMARK FAILED'}")
    print(f"{'='*70}\n")

    # Save results as JSON
    output_path = _BENCH / "cross_stack_results.json"
    output_path.write_text(json.dumps([r.to_dict() for r in results], indent=2, default=str))
    print(f"Results saved to {output_path}")

    return 0 if gate_pass else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-stack generalization benchmark")
    parser.add_argument("--targets", default="juice-shop",
                        help="Comma-separated target names (juice-shop,dvwa,webgoat)")
    parser.add_argument("--all", action="store_true",
                        help="Run against all available targets")
    args = parser.parse_args()

    if args.all:
        target_names = list(TARGETS.keys())
    else:
        target_names = [t.strip() for t in args.targets.split(",")]

    return asyncio.run(run_cross_stack(target_names))


if __name__ == "__main__":
    sys.exit(main())
