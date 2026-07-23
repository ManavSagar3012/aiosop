#!/usr/bin/env python3
"""Score the live autonomous engagement against the ground-truth manifest.

Runs the autonomous engagement against Juice Shop, then scores the persisted
findings against benchmarks/ground_truth/juice_shop.yaml. Emits a scorecard
with recall, precision, false-negatives, and evidence completeness.

Run:  .venv/Scripts/python.exe benchmarks/score_autonomous.py --target http://localhost:3000
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
from score_engagement import score_findings, load_manifest  # noqa: E402


async def run(target: str) -> int:
    print(f"\n=== AUTONOMOUS ENGAGEMENT SCORECARD vs {target} ===\n")

    gm = GraphMemory()
    await gm.connect()

    eid = f"score-{secrets.token_hex(4)}"
    scope = ScopeDefinition(
        engagement_id=eid,
        domains=["localhost"],
        ips=["127.0.0.1"],
        exclusions=[],
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

    # Run the full pipeline
    seeded = await bootstrap_discovery(target, eid, gm, governance_hook=ghook)
    print(f"[recon] seeded {seeded} endpoints")

    suite_f, _, _ = await run_deterministic_scan(target, eid, gm, governance_hook=ghook)
    gen_f, _ = await run_generalized_scan(eid, gm, governance_hook=ghook)

    # Read findings from graph
    vulns = await gm.get_vulnerabilities_by_engagement(eid)
    print(f"[scan] {len(vulns)} findings in graph ({len(suite_f + gen_f)} persisted)")

    # Score against manifest
    manifest = load_manifest(_BENCH / "ground_truth" / "juice_shop.yaml")
    card = score_findings(vulns, manifest)

    s = card["summary"]
    print(f"\n--- Scorecard ---")
    print(f"  Manifest positives:     {s['manifest_positives']}")
    print(f"  Manifest neg controls:  {s['manifest_negative_controls']}")
    print(f"  Findings total:         {s['findings_total']}")
    print(f"  Findings real:          {s['findings_real']}")
    print(f"  Simulated dropped:      {s['findings_simulated_dropped']}")
    print(f"  True positives:        {s['true_positives']}")
    print(f"  False negatives:        {s['false_negatives']}")
    print(f"  False positives:        {s['false_positives']}")
    print(f"  Extras (triage):       {s['extras_for_triage']}")
    print(f"  Recall:                 {s['recall']}")
    print(f"  Precision:              {s['precision']}")
    print(f"  Coverage:               {s['coverage']}")
    print(f"  Evidence completeness:  {s['evidence_completeness']}")
    print(f"  Mock LLM flag:          {s['mock_llm']}")

    if card["false_negatives"]:
        print(f"\n  False negatives:")
        for fn in card["false_negatives"]:
            print(f"    - {fn.get('gt_id')}: {fn.get('type')} @ {fn.get('endpoint')}")

    if card["false_positives"]:
        print(f"\n  False positives:")
        for fp in card["false_positives"]:
            print(f"    - {fp.get('gt_id')}: {fp.get('type')} @ {fp.get('endpoint')}")

    if card["extras"]:
        print(f"\n  Extras (real but unlisted in manifest):")
        for ex in card["extras"][:10]:
            print(f"    - {ex.get('type')} @ {ex.get('endpoint')} (conf={ex.get('confidence')})")

    # Gate: recall must be >= 0.8 (4/5 positives found)
    recall = s["recall"] or 0
    passed = recall >= 0.8
    print(f"\n  GATE: recall >= 0.8 ... {'PASS' if passed else 'FAIL'} ({recall})")
    print(f"\n=== {'SCORECARD PASSED' if passed else 'SCORECARD FAILED'} ===\n")

    await gm.close()
    return 0 if passed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Score autonomous engagement vs ground truth")
    parser.add_argument("--target", default="http://localhost:3000")
    args = parser.parse_args()
    return asyncio.run(run(args.target))


if __name__ == "__main__":
    sys.exit(main())
