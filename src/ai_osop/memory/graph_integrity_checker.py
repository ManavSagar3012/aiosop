import asyncio
import sys

from ai_osop.memory.graph_memory import GraphMemory


async def run_integrity_check(gm: GraphMemory = None):
    close_gm = False
    if gm is None:
        gm = GraphMemory()
        await gm.connect()
        close_gm = True

    print("=== AI-OSOP Graph Integrity Report ===")

    async with gm._driver.session() as session:
        # 1. Ghost Workflows
        # A Workflow is a ghost only if it has NEITHER a HAS_STEP (mapping) NOR a
        # CALLED (API-inventory) edge. Checking HAS_STEP alone false-positives on
        # inventory-only workflows that legitimately have only CALLED->APIEndpoint.
        ghost_wf_query = """
        MATCH (w:Workflow)
        WHERE NOT (w)-[:HAS_STEP]->() AND NOT (w)-[:CALLED]->()
          AND (w.archived IS NULL OR w.archived = false)
        RETURN w.id as id, w.name as name, w.engagement_id as engagement_id
        """
        res = await session.run(ghost_wf_query)
        ghost_wfs = [dict(r) async for r in res]
        print(f"\n[!] Ghost Workflows (No Steps, Non-Archived): {len(ghost_wfs)}")
        for w in ghost_wfs[:10]:
            print(f"    - ID: {w['id']} | Name: {w['name']} | Engagement: {w['engagement_id']}")
        if len(ghost_wfs) > 10:
            print(f"    ... and {len(ghost_wfs) - 10} more")

        # 2. Orphan Steps
        orphan_step_query = """
        MATCH (s:Step)
        WHERE NOT ()-[:HAS_STEP]->(s) AND (s.archived IS NULL OR s.archived = false)
        RETURN s.id as id, s.engagement_id as engagement_id
        """
        res = await session.run(orphan_step_query)
        orphan_steps = [dict(r) async for r in res]
        print(f"\n[!] Orphan Steps (No parent Workflow, Non-Archived): {len(orphan_steps)}")
        for s in orphan_steps[:10]:
            print(f"    - ID: {s['id']} | Engagement: {s['engagement_id']}")
        if len(orphan_steps) > 10:
            print(f"    ... and {len(orphan_steps) - 10} more")

        # 3. Orphan Evidence
        orphan_ev_query = """
        MATCH (e:Evidence)
        WHERE NOT ()-[:HAS_EVIDENCE]->(e) AND (e.archived IS NULL OR e.archived = false)
        RETURN e.id as id, e.type as type, e.path as path
        """
        res = await session.run(orphan_ev_query)
        orphan_evs = [dict(r) async for r in res]
        print(f"\n[!] Orphan Evidence (No parent Step, Non-Archived): {len(orphan_evs)}")
        for e in orphan_evs[:10]:
            print(f"    - ID: {e['id']} | Type: {e['type']} | Path: {e['path']}")
        if len(orphan_evs) > 10:
            print(f"    ... and {len(orphan_evs) - 10} more")

        # 4. Orphan Vulnerabilities
        orphan_vuln_query = """
        MATCH (v:Vulnerability)
        WHERE NOT ()-[:HAS_VULNERABILITY]->(v) AND (v.archived IS NULL OR v.archived = false)
        RETURN v.id as id, v.title as title, v.engagement_id as engagement_id
        """
        res = await session.run(orphan_vuln_query)
        orphan_vulns = [dict(r) async for r in res]
        print(f"\n[!] Orphan Vulnerabilities (No Endpoint link, Non-Archived): {len(orphan_vulns)}")
        for v in orphan_vulns[:10]:
            print(f"    - ID: {v['id']} | Title: {v['title']} | Engagement: {v['engagement_id']}")
        if len(orphan_vulns) > 10:
            print(f"    ... and {len(orphan_vulns) - 10} more")

        # 5. Orphan DiffAuthFindings
        # PATCH (AIOSOP-AUDIT-2026-06-16): the previous REL-011 patch checked only
        # `HAS_FINDING`, but live data shows DiffAuthFindings are linked via
        # `PRODUCED` (AuthorizationTest->finding, 26/27) and `HAS_DIFF_AUTH_FINDING`
        # (26/27); only 1/27 used `HAS_FINDING`. Checking HAS_FINDING alone produced
        # 26 FALSE-POSITIVE orphans (runtime-verified). A finding is non-orphan if it
        # has ANY of the three canonical inbound links.
        # NOTE: HAS_FINDING has no producer in src/ (no persist method creates it);
        # it is currently producer-less. Kept in the filter rather than removed to
        # avoid breaking any out-of-tree/legacy path that may still emit it.
        orphan_diff_query = """
        MATCH (d:DiffAuthFinding)
        WHERE NOT ()-[:PRODUCED]->(d)
          AND NOT ()-[:HAS_DIFF_AUTH_FINDING]->(d)
          AND NOT ()-[:HAS_FINDING]->(d)
          AND (d.archived IS NULL OR d.archived = false)
        RETURN d.id as id, d.category as category, d.engagement_id as engagement_id
        """
        res = await session.run(orphan_diff_query)
        orphan_diffs = [dict(r) async for r in res]
        print(
            f"\n[!] Orphan DiffAuthFindings (No Endpoint/Resource link, Non-Archived): {len(orphan_diffs)}"
        )
        for d in orphan_diffs[:10]:
            print(
                f"    - ID: {d['id']} | Category: {d['category']} | Engagement: {d['engagement_id']}"
            )
        if len(orphan_diffs) > 10:
            print(f"    ... and {len(orphan_diffs) - 10} more")

        # 5b. Orphan Exploits (no inbound EXPLOITED_BY from a Vulnerability)
        orphan_exploit_query = """
        MATCH (x:Exploit)
        WHERE NOT ()-[:EXPLOITED_BY]->(x) AND (x.archived IS NULL OR x.archived = false)
        RETURN x.id as id, x.type as type, x.engagement_id as engagement_id
        """
        res = await session.run(orphan_exploit_query)
        orphan_exploits = [dict(r) async for r in res]
        print(
            f"\n[!] Orphan Exploits (No Vulnerability link, Non-Archived): {len(orphan_exploits)}"
        )
        for x in orphan_exploits[:10]:
            print(f"    - ID: {x['id']} | Type: {x['type']} | Engagement: {x['engagement_id']}")
        if len(orphan_exploits) > 10:
            print(f"    ... and {len(orphan_exploits) - 10} more")

        # 5c. Orphan ReplayResults (no inbound HAS_REPLAY from an APIEndpoint)
        orphan_replay_query = """
        MATCH (rr:ReplayResult)
        WHERE NOT ()-[:HAS_REPLAY]->(rr) AND (rr.archived IS NULL OR rr.archived = false)
        RETURN rr.id as id, rr.endpoint_id as endpoint_id, rr.engagement_id as engagement_id
        """
        res = await session.run(orphan_replay_query)
        orphan_replays = [dict(r) async for r in res]
        print(
            f"\n[!] Orphan ReplayResults (No APIEndpoint link, Non-Archived): {len(orphan_replays)}"
        )
        for rr in orphan_replays[:10]:
            print(
                f"    - ID: {rr['id']} | Endpoint: {rr['endpoint_id']} | Engagement: {rr['engagement_id']}"
            )
        if len(orphan_replays) > 10:
            print(f"    ... and {len(orphan_replays) - 10} more")

        # 5d. Orphan AuthorizationTests (no inbound HAS_AUTH_TEST from an APIEndpoint)
        orphan_authtest_query = """
        MATCH (t:AuthorizationTest)
        WHERE NOT ()-[:HAS_AUTH_TEST]->(t) AND (t.archived IS NULL OR t.archived = false)
        RETURN t.id as id, t.endpoint_id as endpoint_id, t.engagement_id as engagement_id
        """
        res = await session.run(orphan_authtest_query)
        orphan_authtests = [dict(r) async for r in res]
        print(
            f"\n[!] Orphan AuthorizationTests (No APIEndpoint link, Non-Archived): {len(orphan_authtests)}"
        )
        for t in orphan_authtests[:10]:
            print(
                f"    - ID: {t['id']} | Endpoint: {t['endpoint_id']} | Engagement: {t['engagement_id']}"
            )
        if len(orphan_authtests) > 10:
            print(f"    ... and {len(orphan_authtests) - 10} more")

        # 5e. Workflow-bound APIEndpoints missing their CALLED edge.
        # Only flag endpoints that claim a workflow (non-empty workflow_id) yet have
        # no inbound CALLED — these lost their edge (parent Workflow absent at persist
        # time). Inventory-only APIEndpoints (engagement_id set, no workflow_id) are
        # legitimate and intentionally NOT flagged.
        orphan_api_query = """
        MATCH (a:Endpoint {type: "api"})
        WHERE a.workflow_id IS NOT NULL AND a.workflow_id <> ''
          AND NOT ()-[:CALLED]->(a)
          AND (a.archived IS NULL OR a.archived = false)
        RETURN a.id as id, a.workflow_id as workflow_id, a.engagement_id as engagement_id
        """
        res = await session.run(orphan_api_query)
        orphan_apis = [dict(r) async for r in res]
        print(
            f"\n[!] Workflow-bound API Endpoints missing CALLED (Non-Archived): {len(orphan_apis)}"
        )
        for a in orphan_apis[:10]:
            print(
                f"    - ID: {a['id']} | Workflow: {a['workflow_id']} | Engagement: {a['engagement_id']}"
            )
        if len(orphan_apis) > 10:
            print(f"    ... and {len(orphan_apis) - 10} more")

        # 6. Archived count
        archived_query = """
        MATCH (n)
        WHERE n.archived = true
        RETURN labels(n) as labels, count(n) as count
        """
        res = await session.run(archived_query)
        archived_nodes = [dict(r) async for r in res]
        print(f"\n[+] Archived Nodes Count:")
        for a in archived_nodes:
            print(f"    - Labels: {a['labels']} | Count: {a['count']}")

    if close_gm:
        await gm.close()

    total_issues = (
        len(ghost_wfs)
        + len(orphan_steps)
        + len(orphan_evs)
        + len(orphan_vulns)
        + len(orphan_diffs)
        + len(orphan_exploits)
        + len(orphan_replays)
        + len(orphan_authtests)
        + len(orphan_apis)
    )
    print(f"\n=======================================")
    print(f"Total graph integrity issues: {total_issues}")
    return total_issues


async def cleanup_orphan_vulnerabilities(gm: GraphMemory = None):
    """Archive orphans: vulnerabilities AND ghost workflows. Never deletes."""
    print("=== Archiving Orphan Vulnerabilities + Ghost Workflows ===")
    close_gm = False
    if gm is None:
        gm = GraphMemory()
        await gm.connect()
        close_gm = True

    cleaned_vulns = 0
    cleaned_workflows = 0
    try:
        async with gm._driver.session() as session:
            res = await session.run(
                """
                MATCH (v:Vulnerability)
                WHERE NOT ()-[:HAS_VULNERABILITY]->(v) AND (v.archived IS NULL OR v.archived = false)
                SET v.archived = true,
                    v.cleanup_reason = 'orphan_vulnerability_no_endpoint_link',
                    v.cleanup_timestamp = datetime()
                RETURN count(v) as cleaned_count
                """
            )
            record = await res.single()
            cleaned_vulns = record["cleaned_count"] if record else 0
            print(f"[+] Archived {cleaned_vulns} orphan vulnerabilities.")

            res = await session.run(
                """
                MATCH (w:Workflow)
                WHERE NOT (w)-[:HAS_STEP]->() AND NOT (w)-[:CALLED]->()
                  AND (w.archived IS NULL OR w.archived = false)
                SET w.archived = true,
                    w.cleanup_reason = 'ghost_workflow_no_steps_no_called',
                    w.cleanup_timestamp = datetime()
                RETURN count(w) as cleaned_count
                """
            )
            record = await res.single()
            cleaned_workflows = record["cleaned_count"] if record else 0
            print(f"[+] Archived {cleaned_workflows} ghost workflows.")

        return {"vulnerabilities": cleaned_vulns, "workflows": cleaned_workflows}
    finally:
        if close_gm:
            await gm.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(run_integrity_check()))
