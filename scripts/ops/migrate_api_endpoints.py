"""Neo4j Migration: APIEndpoint → Endpoint

Migrate existing :APIEndpoint nodes to :Endpoint with type="api".
Also migrates all relationships from :APIEndpoint to :Endpoint.

Usage:
    python scripts/ops/migrate_api_endpoints.py

Requires: Neo4j running and accessible.
"""

import asyncio
import sys

from ai_osop.memory.graph_memory import GraphMemory


MIGRATION_CYPHER = """
// Step 1: Copy all APIEndpoint properties to Endpoint nodes
MATCH (a:APIEndpoint)
MERGE (e:Endpoint {id: a.id})
SET e.url = a.url,
    e.method = a.method,
    e.type = "api",
    e.host = a.host,
    e.path = a.path,
    e.query_keys = a.query_keys,
    e.has_body = a.has_body,
    e.content_type = a.content_type,
    e.body_schema_keys = a.body_schema_keys,
    e.auth_class = a.auth_class,
    e.request_headers_sample = a.request_headers_sample,
    e.status_codes_seen = a.status_codes_seen,
    e.response_size_avg = a.response_size_avg,
    e.response_content_type = a.response_content_type,
    e.user_label = a.user_label,
    e.engagement_id = a.engagement_id,
    e.workflow_id = a.workflow_id,
    e.observations = a.observations,
    e.first_seen = a.first_seen,
    e.last_seen = a.last_seen
WITH a, e
// Step 2: Migrate all relationships from APIEndpoint to Endpoint
MATCH (a)-[r]->(target)
WHERE NOT target:APIEndpoint
CALL apoc.refactor.cloneRelationships(e, [r], {standinNode: a}) YIELD input, output
WITH a, e
MATCH (source)-[r2]->(a)
WHERE NOT source:APIEndpoint
CALL apoc.refactor.cloneRelationships(e, [r2], {standinNode: a}) YIELD input, output
WITH a
// Step 3: Remove old APIEndpoint nodes
DELETE a
"""

FALLBACK_CYPHER = """
// Without APOC: manual relationship migration
MATCH (a:APIEndpoint)
MERGE (e:Endpoint {id: a.id})
SET e.url = a.url,
    e.method = a.method,
    e.type = "api",
    e.host = a.host,
    e.path = a.path,
    e.query_keys = a.query_keys,
    e.has_body = a.has_body,
    e.content_type = a.content_type,
    e.body_schema_keys = a.body_schema_keys,
    e.auth_class = a.auth_class,
    e.request_headers_sample = a.request_headers_sample,
    e.status_codes_seen = a.status_codes_seen,
    e.response_size_avg = a.response_size_avg,
    e.response_content_type = a.response_content_type,
    e.user_label = a.user_label,
    e.engagement_id = a.engagement_id,
    e.workflow_id = a.workflow_id,
    e.observations = a.observations,
    e.first_seen = a.first_seen,
    e.last_seen = a.last_seen
WITH a, e
// Migrate outgoing relationships
MATCH (a)-[r]->(target)
WHERE NOT target:APIEndpoint
WITH a, e, r, target, type(r) as rel_type
DELETE r
WITH e, target, rel_type
CALL apoc.create.relationship(e, rel_type, {}, target) YIELD rel as rel_out
WITH e, a
// Migrate incoming relationships
MATCH (source)-[r2]->(a)
WHERE NOT source:APIEndpoint
WITH e, a, r2, source, type(r2) as rel_type2
DELETE r2
WITH e, source, rel_type2
CALL apoc.create.relationship(source, rel_type2, {}, e) YIELD rel as rel_in
WITH a
DELETE a
"""

NO_APOC_CYPHER = """
// Without APOC at all: copy properties, drop old node, relationships will be lost
MATCH (a:APIEndpoint)
MERGE (e:Endpoint {id: a.id})
SET e.url = a.url,
    e.method = a.method,
    e.type = "api",
    e.host = a.host,
    e.path = a.path,
    e.query_keys = a.query_keys,
    e.has_body = a.has_body,
    e.content_type = a.content_type,
    e.body_schema_keys = a.body_schema_keys,
    e.auth_class = a.auth_class,
    e.request_headers_sample = a.request_headers_sample,
    e.status_codes_seen = a.status_codes_seen,
    e.response_size_avg = a.response_size_avg,
    e.response_content_type = a.response_content_type,
    e.user_label = a.user_label,
    e.engagement_id = a.engagement_id,
    e.workflow_id = a.workflow_id,
    e.observations = a.observations,
    e.first_seen = a.first_seen,
    e.last_seen = a.last_seen
DELETE a
"""


async def count_api_endpoints(gm: GraphMemory) -> int:
    async with gm._driver.session() as session:
        result = await session.run("MATCH (a:APIEndpoint) RETURN count(a) as n")
        record = await result.single()
        return record["n"] if record else 0


async def has_apoc(gm: GraphMemory) -> bool:
    try:
        async with gm._driver.session() as session:
            result = await session.run(
                "CALL apoc.help('refactor.cloneRelationships') YIELD name RETURN name LIMIT 1"
            )
            record = await result.single()
            return record is not None
    except Exception:
        return False


async def migrate(gm: GraphMemory) -> dict:
    before = await count_api_endpoints(gm)
    if before == 0:
        return {"before": 0, "after": 0, "migrated": 0, "note": "No APIEndpoint nodes found"}

    apoc = await has_apoc(gm)
    if apoc:
        cypher = MIGRATION_CYPHER
    else:
        cypher = NO_APOC_CYPHER

    async with gm._driver.session() as session:
        await session.run(cypher)

    after = await count_api_endpoints(gm)
    return {
        "before": before,
        "after": after,
        "migrated": before - after,
        "apoc": apoc,
        "note": "Relationships preserved with APOC" if apoc else "Relationships may have been lost without APOC",
    }


async def main():
    print("=" * 60)
    print("Neo4j Migration: APIEndpoint → Endpoint")
    print("=" * 60)

    gm = GraphMemory()
    await gm.connect()
    try:
        result = await migrate(gm)
        print(f"\nBefore: {result['before']} APIEndpoint nodes")
        print(f"After:  {result['after']} APIEndpoint nodes")
        print(f"Migrated: {result['migrated']} nodes → :Endpoint with type='api'")
        print(f"APOC available: {result['apoc']}")
        print(f"Note: {result['note']}")
        if result['after'] > 0:
            print("\nWARNING: Some APIEndpoint nodes remain. Check for errors.")
            sys.exit(1)
        print("\nMigration complete.")
    finally:
        await gm.close()


if __name__ == "__main__":
    asyncio.run(main())
