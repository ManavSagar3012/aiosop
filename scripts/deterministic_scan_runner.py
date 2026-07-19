"""CLI wrapper for the deterministic detection backbone.

Runs core.deterministic_scan against a target, persists findings through a real
graph_memory, then READS THEM BACK to prove the detect -> persist -> retrieve
path end to end. No LLM, no MCP fleet, no agent lifecycle.

    python scripts/deterministic_scan_runner.py [target] [engagement_id]
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_osop.core.deterministic_scan import run_deterministic_scan  # noqa: E402
from ai_osop.memory.graph_memory import GraphMemory  # noqa: E402


async def main(base: str, engagement_id: str) -> bool:
    gm = GraphMemory()
    await gm.connect()
    t0 = time.monotonic()
    persisted, validated, expected = await run_deterministic_scan(base, engagement_id, gm)
    dt = time.monotonic() - t0
    readback = await gm.get_vulnerabilities_by_engagement(engagement_id)

    for v in persisted:
        print(f"  [PERSIST] {v.vuln_type.value:24s} {v.severity.value:8s} {v.cwe:8s} -> {v.id}")
    recall = len(validated) / expected if expected else 0.0
    print("\n================ DETERMINISTIC ENGAGEMENT ================")
    print(f"  target           {base}")
    print(f"  engagement_id    {engagement_id}")
    print(f"  validated        {len(validated)}/{expected}  (recall={recall:.2f})")
    print(f"  persisted        {len(persisted)}   in {dt:.1f}s")
    print(f"  graph read-back  {len(readback)}  <- proves detect->persist->retrieve")
    ok = len(persisted) > 0 and len(readback) >= len(persisted)
    print(f"  RESULT           {'PASS - findings detected AND persisted' if ok else 'FAIL'}")
    return ok


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
    eid = sys.argv[2] if len(sys.argv) > 2 else f"det-scan-{int(time.time())}"
    raise SystemExit(0 if asyncio.run(main(base, eid)) else 1)
