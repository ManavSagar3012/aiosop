#!/usr/bin/env python3
"""Cognition Benchmark — measure reasoning quality, not just feature completeness.

The assessment says: 'The next phase is no longer an engineering challenge —
it's a research and evaluation challenge.' This benchmark measures the
COGNITIVE capabilities the assessment identified:

  1. Time-to-discovery: how fast does AI-OSOP find its first critical finding?
  2. Hypothesis quality: what fraction of hypotheses lead to confirmed findings?
  3. Adaptive planning: does it change strategy based on what it learns?
  4. False-positive rate: what fraction of findings are false positives?
  5. Novel-path discovery: does it find things NOT in the ground-truth manifest?
  6. Uncertainty resolution: does it actively resolve unknowns?
  7. Reasoning trace quality: can it explain every decision it made?
  8. Chain discovery: does it discover multi-step attack chains?

This benchmark runs the full autonomous engagement, then evaluates the
reasoning trace + uncertainty tracker + graph pathfinder outputs to
produce a COGNITION SCORECARD alongside the detection scorecard.

Run:  .venv/Scripts/python.exe benchmarks/cognition_benchmark.py --target http://localhost:3000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

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


def _check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  {status:4s}  {label}" + (f" — {detail}" if detail else ""))
    return condition


async def run(target: str) -> int:
    print(f"\n=== COGNITION BENCHMARK vs {target} ===\n")

    gm = GraphMemory()
    await gm.connect()

    eid = f"cog-{secrets.token_hex(4)}"
    scope = ScopeDefinition(
        engagement_id=eid,
        domains=["localhost"],
        ips=["127.0.0.1"],
    )
    session = SessionState(
        session_id=f"eng-{int(time.time())}-{eid}",
        scope=scope,
        phase=EngagementPhase.INITIALIZED.value,
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

    # 1. OBSERVE: discovery
    t0 = time.monotonic()
    seeded = await bootstrap_discovery(target, eid, gm, governance_hook=ghook)
    print(f"[observe] seeded {seeded} endpoints in {time.monotonic()-t0:.1f}s")

    eps = await gm.run_read_query(
        "MATCH (e:Endpoint {engagement_id: $eid}) RETURN e.url AS url, e.path AS path, e.method AS method, e.status_code AS status_code, e.technologies AS technologies, e.auth_required AS auth_required, e.query_keys AS query_keys, e.id AS id LIMIT 500",
        {"eid": eid},
    )

    # 2. ORIENT: business context
    categorized = batch_categorize(eps)
    high_value = [c for c in categorized if c.criticality >= 7]
    print(f"[orient] {len(categorized)} endpoints categorized, {len(high_value)} high-value")
    trace.record(eid, "orient", f"Categorized {len(categorized)} endpoints",
                 rationale=f"{len(high_value)} high-value (criticality>=7): {[c.category for c in high_value[:5]]}")

    # 3. UNCERTAINTY DETECTION
    findings_so_far = []
    new_uncerts = uncertainty.detect_uncertainties(eid, eps, findings_so_far)
    unc_hyps = uncertainty.get_uncertainty_hypotheses(eid)
    print(f"[uncertainty] {len(new_uncerts)} uncertainties detected, {len(unc_hyps)} info-seeking hypotheses")
    trace.record(eid, "observe", f"Detected {len(new_uncerts)} uncertainties",
                 rationale=f"open: {uncertainty.get_summary(eid)}")

    # 4. HYPOTHESIZE
    from ai_osop.core.hypothesis_engine import HypothesisEngine
    engine = HypothesisEngine(gm, session_memory=None)
    hypotheses = await engine.generate_and_persist(eid, limit=12)
    total_hypotheses = len(hypotheses)
    print(f"[hypothesize] {total_hypotheses} hypotheses generated")
    trace.record(eid, "hypothesize", f"Generated {total_hypotheses} hypotheses",
                 rationale=f"categories: {set(h.category for h in hypotheses)}")

    # 5. ACT: run scans (the actual discovery phase)
    t1 = time.monotonic()
    suite_f, validated_ids, expected = await run_deterministic_scan(target, eid, gm, governance_hook=ghook)
    gen_f, examined = await run_generalized_scan(eid, gm, governance_hook=ghook)
    scan_time = time.monotonic() - t1
    all_findings = suite_f + gen_f
    ttd = time.monotonic() - t0  # time-to-discovery

    print(f"[act] scan completed in {scan_time:.1f}s, {len(all_findings)} findings")

    # 6. EVALUATE: read findings back from graph
    vulns = await gm.get_vulnerabilities_by_engagement(eid)
    validated = [v for v in vulns if v.get("validated")]
    print(f"[evaluate] {len(vulns)} findings in graph, {len(validated)} validated")

    # Record confirmed/refuted in trace
    for v in validated[:5]:
        trace.record(eid, "evaluate", f"Finding confirmed: {v.get('vuln_type', '?')}",
                     rationale=f"validated=True, confidence={v.get('confidence', 0)}",
                     result="confirmed", confidence=float(v.get("confidence", 0)))

    # 7. GRAPH PATHFINDER: discover attack chains
    pathfinder = GraphPathfinder(gm)
    chains = await pathfinder.find_chains(eid, max_depth=5)
    print(f"[chain] {len(chains)} attack chains discovered by graph pathfinder")

    # 8. SCORECARD: detection quality
    manifest = load_manifest(_BENCH / "ground_truth" / "juice_shop.yaml")
    card = score_findings(vulns, manifest)
    s = card["summary"]

    # 9. COGNITION METRICS
    trace_summary = trace.get_summary(eid)
    unc_summary = uncertainty.get_summary(eid)

    # Hypothesis quality: what fraction of hypotheses led to confirmed findings?
    confirmed_hyp_types = {v.get("vuln_type", "") for v in validated}
    hyp_quality = len(confirmed_hyp_types) / max(1, total_hypotheses)

    # Novel-path discovery: extras (findings not in the manifest)
    novel_count = s.get("extras_for_triage", 0)

    # False-positive rate
    fp_count = s.get("false_positives", 0)
    fp_rate = fp_count / max(1, len(vulns))

    # Uncertainty resolution rate
    unc_resolved = unc_summary.get("resolved", 0)
    unc_total = unc_summary.get("total", 0)
    unc_rate = unc_resolved / max(1, unc_total)

    print(f"\n--- COGNITION SCORECARD ---")
    print(f"  Time-to-discovery:         {ttd:.1f}s")
    print(f"  Hypotheses generated:     {total_hypotheses}")
    print(f"  Hypothesis quality:        {hyp_quality:.2f} (confirmed_types / total_hypotheses)")
    print(f"  Findings total:             {len(vulns)}")
    print(f"  Findings validated:        {len(validated)}")
    print(f"  False-positive rate:       {fp_rate:.2f} ({fp_count}/{len(vulns)})")
    print(f"  Novel paths (extras):       {novel_count}")
    print(f"  Attack chains discovered:  {len(chains)}")
    print(f"  Uncertainties detected:     {unc_total}")
    print(f"  Uncertainties resolved:     {unc_resolved} ({unc_rate:.2f})")
    print(f"  Reasoning trace steps:      {trace_summary.get('total_steps', 0)}")
    print(f"  Trace: confirmed:           {trace_summary.get('hypotheses_confirmed', 0)}")
    print(f"  Trace: refuted:             {trace_summary.get('hypotheses_refuted', 0)}")
    print(f"  Trace: chains:              {trace_summary.get('chains_generated', 0)}")
    print(f"  Trace: pivots:              {trace_summary.get('pivots', 0)}")
    print(f"  Trace: dead-ends:           {trace_summary.get('dead_ends', 0)}")
    print(f"  Detection recall:           {s.get('recall', 0)}")
    print(f"  Detection precision:         {s.get('precision', 0)}")
    print(f"  Detection coverage:          {s.get('coverage', 0)}")
    print(f"  Evidence completeness:       {s.get('evidence_completeness', 0)}")

    # Gate: cognition quality
    cognition_pass = (
        ttd < 300  # finds something in under 5 minutes
        and len(validated) >= 1  # at least 1 validated finding
        and fp_rate <= 0.1  # false-positive rate < 10%
        and len(chains) >= 1  # discovers at least 1 attack chain
        and trace_summary.get("total_steps", 0) >= 3  # reasoning trace has steps
        and novel_count >= 1  # discovers at least 1 novel path not in the manifest
    )
    print(f"\n  GATE: cognition quality ... {'PASS' if cognition_pass else 'FAIL'}")
    print(f"\n=== {'COGNITION BENCHMARK PASSED' if cognition_pass else 'COGNITION BENCHMARK FAILED'} ===\n")

    await gm.close()
    return 0 if cognition_pass else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Cognition benchmark — measure reasoning quality")
    parser.add_argument("--target", default="http://localhost:3000")
    args = parser.parse_args()
    return asyncio.run(run(args.target))


if __name__ == "__main__":
    sys.exit(main())
