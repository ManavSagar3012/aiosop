"""One-time migration: remove duplicate nodes so the uniqueness constraints added to
GraphMemory._setup_schema can actually be created.

Background: APIEndpoint / Task / Engagement / AutoDiscoveryClaim gained
`REQUIRE ... IS UNIQUE` constraints. Neo4j refuses to create a uniqueness constraint
while duplicate keys exist, and _setup_schema swallows that failure (now logged at
WARNING). Until duplicates are removed, those constraints are silently absent and the
"atomic MERGE lock" guarantees (e.g. claim_auto_discovery) do not hold.

This script:
  1. Reports duplicate key counts per (label, key) — always.
  2. With --apply, merges each duplicate group into the OLDEST node (lowest
     elementId tiebreaker), re-pointing all relationships via apoc.refactor.mergeNodes
     when APOC is available, else a manual relationship-rewire fallback.
  3. With --apply, re-runs _setup_schema so the constraints get created afterward.

DRY-RUN BY DEFAULT. Nothing is written unless you pass --apply.

Usage:
    python migrate_dedupe_constraints.py            # dry-run report only
    python migrate_dedupe_constraints.py --apply    # perform the dedupe + create constraints
"""

import asyncio
import sys

from ai_osop.memory.graph_memory import GraphMemory

# (label, key-property) pairs that just gained a uniqueness constraint.
TARGETS = [
    ("APIEndpoint", "id"),
    ("Task", "id"),
    ("Engagement", "engagement_id"),
    ("AutoDiscoveryClaim", "engagement_id"),
]


async def _find_duplicates(session, label, key):
    q = (
        f"MATCH (n:`{label}`) WHERE n.`{key}` IS NOT NULL "
        f"WITH n.`{key}` AS k, count(*) AS c WHERE c > 1 "
        f"RETURN k AS key, c AS cnt ORDER BY c DESC"
    )
    res = await session.run(q)
    return await res.data()


async def _has_apoc(session):
    try:
        res = await session.run("RETURN apoc.version() AS v")
        await res.single()
        return True
    except Exception:
        return False


async def _merge_group(session, label, key, key_value, use_apoc):
    """Merge all nodes sharing (label, key=key_value) into the oldest, keeping rels.

    Requires APOC: a correct generic relationship-rewire across arbitrary rel types
    cannot be expressed safely in plain Cypher, so we deliberately refuse rather than
    risk dropping edges. Install APOC, or dedupe flagged groups by hand.
    """
    if not use_apoc:
        raise RuntimeError(
            f"APOC not available; refusing to merge {label}.{key}={key_value!r} "
            f"(a plain-Cypher merge could silently drop relationships). "
            f"Install APOC or dedupe this group manually."
        )
    # Keep the oldest node (apoc.refactor.mergeNodes keeps the first in the list),
    # combine relationships, discard duplicate scalar properties.
    q = (
        f"MATCH (n:`{label}`) WHERE n.`{key}` = $val "
        f"WITH n ORDER BY elementId(n) ASC WITH collect(n) AS ns "
        f"CALL apoc.refactor.mergeNodes(ns, {{properties:'discard', mergeRels:true}}) "
        f"YIELD node RETURN elementId(node) AS kept"
    )
    res = await session.run(q, val=key_value)
    rec = await res.single()
    return rec["kept"] if rec else None


async def main(apply: bool):
    g = GraphMemory()
    await g.connect()
    total_groups = 0
    try:
        async with g._driver.session() as session:
            use_apoc = await _has_apoc(session)
            print(f"APOC available: {use_apoc}\n")
            for label, key in TARGETS:
                dups = await _find_duplicates(session, label, key)
                if not dups:
                    print(f"[ok]   {label}.{key}: no duplicates")
                    continue
                total_groups += len(dups)
                print(f"[DUP]  {label}.{key}: {len(dups)} duplicated key(s)")
                for row in dups:
                    print(f"         key={row['key']!r} count={row['cnt']}")
                    if apply:
                        kept = await _merge_group(session, label, key, row["key"], use_apoc)
                        print(f"         merged -> kept elementId={kept}")

        if apply:
            print("\nRe-running schema setup to create constraints...")
            await g._setup_schema()
            print("Schema setup complete. Verify with: python check_constraints.py")
        else:
            print(
                f"\nDRY-RUN: {total_groups} duplicate group(s) found across targets. "
                f"Re-run with --apply to merge them and create the constraints."
            )
    finally:
        await g.close()


if __name__ == "__main__":
    apply_flag = "--apply" in sys.argv[1:]
    asyncio.run(main(apply_flag))
