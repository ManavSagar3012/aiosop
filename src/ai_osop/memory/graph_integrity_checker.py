"""Graph integrity checker — schema-drift and orphan-node detection.

Two entry points:

1. ``run_integrity_check(gm)`` — returns a structured ``IntegrityReport``
   describing every orphan / ghost class. Used both by the CLI ``__main__``
   block (pretty-prints the report) and by the orchestrator's background
   integrity sweep (records metrics, never blocks startup).
2. ``cleanup_orphan_vulnerabilities(gm)`` — archives (soft-deletes) orphan
   Vulnerability and ghost Workflow nodes. Never hard-deletes.

The orchestrator wires (1) into a periodic background task at startup so
schema drift is detected at runtime, not only by a manual CLI run. The
report is intentionally a typed dict (``IntegrityReport``) so callers can
assert on it in tests without parsing stdout.
"""

import asyncio
import logging
from typing import Any, Dict, Optional, TypedDict

from ai_osop.memory.graph_memory import GraphMemory

logger = logging.getLogger("ai_osop.memory.graph_integrity")


class IntegrityReport(TypedDict):
    """Structured result of ``run_integrity_check``.

    Each field is the count of orphan / ghost nodes of that class. A clean
    graph has every field == 0. The orchestrator's periodic sweep exports
    these as Prometheus gauges (see orchestrator wiring).
    """

    ghost_workflows: int
    orphan_steps: int
    orphan_evidence: int
    orphan_vulnerabilities: int
    orphan_diff_auth_findings: int
    orphan_exploits: int
    orphan_replay_results: int
    orphan_authorization_tests: int
    orphan_workflow_bound_api_endpoints: int
    archived_node_groups: int
    total_issues: int


# Each (label, predicate) pair: a Cypher fragment that identifies orphan nodes
# of that label. Centralised so a new label is one row, not a copy-pasted
# 10-line query block. The `archived IS NULL OR archived = false` guard means
# soft-deleted nodes are NOT flagged (they are intentionally detached).
_ORPHAN_QUERIES: Dict[str, str] = {
    "ghost_workflows": """
    MATCH (w:Workflow)
    WHERE NOT (w)-[:HAS_STEP]->() AND NOT (w)-[:CALLED]->()
      AND (w.archived IS NULL OR w.archived = false)
    RETURN count(w) AS c
    """,
    "orphan_steps": """
    MATCH (s:Step)
    WHERE NOT ()-[:HAS_STEP]->(s) AND (s.archived IS NULL OR s.archived = false)
    RETURN count(s) AS c
    """,
    "orphan_evidence": """
    MATCH (e:Evidence)
    WHERE NOT ()-[:HAS_EVIDENCE]->(e) AND (e.archived IS NULL OR e.archived = false)
    RETURN count(e) AS c
    """,
    "orphan_vulnerabilities": """
    MATCH (v:Vulnerability)
    WHERE NOT ()-[:HAS_VULNERABILITY]->(v) AND (v.archived IS NULL OR v.archived = false)
    RETURN count(v) AS c
    """,
    # PATCH (AIOSOP-AUDIT-2026-06-16): the previous REL-011 patch checked only
    # `HAS_FINDING`, but live data shows DiffAuthFindings are linked via
    # `PRODUCED` (AuthorizationTest->finding, 26/27) and `HAS_DIFF_AUTH_FINDING`
    # (26/27); only 1/27 used `HAS_FINDING`. A finding is non-orphan if it
    # has ANY of the three canonical inbound links. NOTE: HAS_FINDING has no
    # producer in src/; kept in the filter to avoid breaking legacy paths.
    "orphan_diff_auth_findings": """
    MATCH (d:DiffAuthFinding)
    WHERE NOT ()-[:PRODUCED]->(d)
      AND NOT ()-[:HAS_DIFF_AUTH_FINDING]->(d)
      AND NOT ()-[:HAS_FINDING]->(d)
      AND (d.archived IS NULL OR d.archived = false)
    RETURN count(d) AS c
    """,
    "orphan_exploits": """
    MATCH (x:Exploit)
    WHERE NOT ()-[:EXPLOITED_BY]->(x) AND (x.archived IS NULL OR x.archived = false)
    RETURN count(x) AS c
    """,
    "orphan_replay_results": """
    MATCH (rr:ReplayResult)
    WHERE NOT ()-[:HAS_REPLAY]->(rr) AND (rr.archived IS NULL OR rr.archived = false)
    RETURN count(rr) AS c
    """,
    "orphan_authorization_tests": """
    MATCH (t:AuthorizationTest)
    WHERE NOT ()-[:HAS_AUTH_TEST]->(t) AND (t.archived IS NULL OR t.archived = false)
    RETURN count(t) AS c
    """,
    "orphan_workflow_bound_api_endpoints": """
    MATCH (a:Endpoint {type: "api"})
    WHERE a.workflow_id IS NOT NULL AND a.workflow_id <> ''
      AND NOT ()-[:CALLED]->(a)
      AND (a.archived IS NULL OR a.archived = false)
    RETURN count(a) AS c
    """,
}


async def run_integrity_check(
    gm: Optional[GraphMemory] = None,
    *,
    emit_prints: bool = False,
) -> IntegrityReport:
    """Run every orphan-class query against the graph and return a structured
    report.

    ``emit_prints=True`` preserves the legacy CLI behaviour (pretty-prints the
    report to stdout). The orchestrator's background sweep passes
    ``emit_prints=False`` and consumes the typed dict instead — no stdout
    parsing, no log noise on a healthy graph.

    Safe to call against a graph with zero nodes: every query is a COUNT, so
    a cold DB returns 0 for every field without raising.
    """
    close_gm = False
    if gm is None:
        gm = GraphMemory()
        await gm.connect()
        close_gm = True

    if emit_prints:
        print("=== AI-OSOP Graph Integrity Report ===")

    report: Dict[str, Any] = {}
    for key, q in _ORPHAN_QUERIES.items():
        try:
            rows = await gm.run_read_query(q)
            count = int(rows[0]["c"]) if rows else 0
        except Exception as e:
            # A query failure (e.g. label missing on a fresh DB) must not sink
            # the whole check — record -1 so the metric is visibly anomalous
            # rather than silently zero.
            logger.warning("graph_integrity_query_failed key=%s err=%s", key, e)
            count = -1
        report[key] = count
        if emit_prints:
            print(f"\n[!] {key}: {count}")

    # Archived-node groups (informational; not an orphan count).
    try:
        archived_rows = await gm.run_read_query(
            """
            MATCH (n) WHERE n.archived = true
            RETURN labels(n) AS labels, count(n) AS c
            """
        )
        archived_groups = sum(int(r["c"]) for r in archived_rows) if archived_rows else 0
    except Exception:
        archived_groups = 0
    report["archived_node_groups"] = archived_groups

    # Sum only non-negative counts so a -1 (query failure) does not subtract
    # from the total — it surfaces in its own field instead.
    total = sum(
        v for k, v in report.items() if k != "archived_node_groups" and isinstance(v, int) and v > 0
    )
    report["total_issues"] = total

    if emit_prints:
        print(f"\n=======================================")
        print(f"Total graph integrity issues: {total}")

    if close_gm:
        await gm.close()

    return report  # type: ignore[return-value]


async def cleanup_orphan_vulnerabilities(gm: Optional[GraphMemory] = None):
    """Archive orphans: vulnerabilities AND ghost workflows. Never deletes."""
    if emit_prints := True:  # legacy callers expect prints
        print("=== Archiving Orphan Vulnerabilities + Ghost Workflows ===")
    close_gm = False
    if gm is None:
        gm = GraphMemory()
        await gm.connect()
        close_gm = True

    cleaned_vulns = 0
    cleaned_workflows = 0
    try:
        res = await gm.run_write_query(
            """
            MATCH (v:Vulnerability)
            WHERE NOT ()-[:HAS_VULNERABILITY]->(v) AND (v.archived IS NULL OR v.archived = false)
            SET v.archived = true,
                v.cleanup_reason = 'orphan_vulnerability_no_endpoint_link',
                v.cleanup_timestamp = datetime()
            RETURN count(v) as cleaned_count
            """
        )
        cleaned_vulns = res[0]["cleaned_count"] if res else 0
        if emit_prints:
            print(f"[+] Archived {cleaned_vulns} orphan vulnerabilities.")

        res = await gm.run_write_query(
            """
            MATCH (w:Workflow)
            WHERE NOT (w)-[:HAS_STEP]->() AND NOT (w)-[:CALLED]->()
              AND (w.archived IS NULL OR w.archived = false)
            SET w.archived = true,
                w.cleanup_reason = 'ghost_workflow_no_steps_or_called_edges',
                w.cleanup_timestamp = datetime()
            RETURN count(w) as cleaned_count
            """
        )
        cleaned_workflows = res[0]["cleaned_count"] if res else 0
        if emit_prints:
            print(f"[+] Archived {cleaned_workflows} ghost workflows.")
    except Exception as e:
        if emit_prints:
            print(f"[!] Error during cleanup: {e}")
        raise

    if close_gm:
        await gm.close()

    if emit_prints:
        print("=== Cleanup Complete ===")
    return cleaned_vulns, cleaned_workflows


if __name__ == "__main__":
    asyncio.run(run_integrity_check(emit_prints=True))
