"""Live end-to-end proof: governed discovery -> governed scan -> persist -> report.

Proves the post-fix pipeline works against a real target with real infra:
  * live Neo4j (endpoint discovery + finding persistence read back)
  * live OWASP Juice Shop on :3000 (the target)
  * a single governance hook (scope + bounty-safe rate + research header) threaded
    through bootstrap_discovery AND run_generalized_scan (the BLK-2/M1 seam)

It asserts: endpoints were discovered into the graph, at least one VALIDATED
finding was persisted by the generalized oracles through the governed client,
and a bounty report renders from those findings. Out-of-scope egress would raise
(governance is fail-closed), so a clean run also proves scope held.

Run:  .venv/Scripts/python.exe benchmarks/live_e2e_governed_scan.py --target http://localhost:3000
Exit 0 + "LIVE E2E PASSED" on success.
"""
from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
from pathlib import Path
from typing import List, Optional

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ai_osop.core.deterministic_scan import (  # noqa: E402
    bootstrap_discovery,
    run_generalized_scan,
)
from ai_osop.core.report_generator import generate_bounty_report  # noqa: E402
from ai_osop.memory.graph_memory import GraphMemory  # noqa: E402
from ai_osop.safety.governed_client import governance_hook, research_header_from_settings  # noqa: E402
from ai_osop.safety.rate_limiter import RateLimiter  # noqa: E402
from ai_osop.safety.scope import ScopeEnforcer  # noqa: E402
from ai_osop.core.models import ScopeDefinition  # noqa: E402


async def _endpoint_count(gm: GraphMemory, eid: str) -> int:
    async with gm._driver.session() as s:
        res = await s.run(
            "MATCH (e:Endpoint {engagement_id:$eid}) RETURN count(e) AS n", eid=eid
        )
        rec = await res.single()
        return int(rec["n"]) if rec else 0


async def _cleanup(gm: GraphMemory, eid: str) -> None:
    try:
        async with gm._driver.session() as s:
            await s.run(
                "MATCH (n {engagement_id:$eid}) DETACH DELETE n", eid=eid
            )
    except Exception:
        pass


async def run(target: str) -> int:
    from urllib.parse import urlparse

    host = urlparse(target).hostname or "localhost"
    engagement_id = f"live-e2e-{secrets.token_hex(4)}"

    gm = GraphMemory()
    await gm.connect()

    # ONE governance hook, scoped to the target host, bounty-safe rate, research header.
    ghook = governance_hook(
        scope=ScopeEnforcer(ScopeDefinition(engagement_id=engagement_id, domains=[host])),
        rate_limiter=RateLimiter(target_rate=5.0, target_capacity=10),
        research_header=research_header_from_settings(),
    )

    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        ok = ok and cond

    try:
        # 1. Governed discovery.
        seeded = await bootstrap_discovery(
            target, engagement_id, gm, governance_hook=ghook
        )
        eps = await _endpoint_count(gm, engagement_id)
        print(f"[discovery] seeded={seeded} endpoints_in_graph={eps}")
        check("governed discovery populated the graph", eps > 0)

        # 2. Governed generalized scan (SQLi/mass-assign/injection/JWT/IDOR).
        persisted, examined = await run_generalized_scan(
            engagement_id, gm, governance_hook=ghook
        )
        print(f"[scan] examined={examined} persisted_findings={len(persisted)}")
        check("generalized scan examined discovered endpoints", examined > 0)
        check("generalized scan persisted >=1 validated finding", len(persisted) > 0)

        # 3. Read findings back from the graph (persistence round-trip).
        vulns = await gm.get_vulnerabilities_by_engagement(engagement_id)
        validated = [v for v in (vulns or []) if v.get("validated")]
        print(f"[persist] read_back={len(vulns or [])} validated={len(validated)}")
        check("validated findings round-trip from Neo4j", len(validated) > 0)

        # 4. Render a bounty report from the persisted findings.
        report = await generate_bounty_report(engagement_id, gm, target=target)
        has_report = bool(report) and "Security Assessment Report" in report
        print(f"[report] length={len(report or '')} chars")
        check("bounty report renders from persisted findings", has_report)
        if has_report:
            # show the finding titles the report surfaced
            for line in (report or "").splitlines():
                if line.startswith("| ") and "SEVERITY" not in line and "---" not in line:
                    print("    " + line.strip()[:120])
    finally:
        await _cleanup(gm, engagement_id)
        try:
            await gm.close()
        except Exception:
            pass

    print("\n" + ("LIVE E2E PASSED" if ok else "LIVE E2E FAILED"))
    return 0 if ok else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default="http://localhost:3000")
    args = ap.parse_args(argv)
    return asyncio.run(run(args.target))


if __name__ == "__main__":
    raise SystemExit(main())
