"""End-to-end verification for Issues 12 + 13: DiffAuth pipeline + Neo4j schema."""

import asyncio
import sys
import uuid

sys.path.insert(0, "src")

from ai_osop.core.models import DiffAuthFinding
from ai_osop.memory.graph_memory import GraphMemory


async def main() -> int:
    gm = GraphMemory()
    await gm.connect()
    print("[1] connected to Neo4j (constraints/indexes ensured)")

    engagement_id = f"verify-{uuid.uuid4().hex[:8]}"
    finding = DiffAuthFinding(
        category="horizontal_pe",
        resource_id=f"ep-test-{uuid.uuid4().hex[:8]}",
        test_identity_id="user_b",
        expected_result="403 Forbidden",
        observed_result="200 OK",
        evidence_diff={"baseline_status": 403, "test_status": 200, "delta_keys": ["records"]},
        confidence=0.95,
        engagement_id=engagement_id,
    )

    persisted_id = await gm.add_diff_auth_finding(finding)
    print(f"[2] add_diff_auth_finding returned id={persisted_id}")
    assert persisted_id == finding.id, f"id mismatch: {persisted_id} vs {finding.id}"

    async with gm._driver.session() as session:
        result = await session.run(
            "MATCH (d:DiffAuthFinding {id: $id}) RETURN d",
            {"id": finding.id},
        )
        record = await result.single()
        if not record:
            print("FAIL: finding not persisted")
            return 1
        d = dict(record["d"])
        print(f"[3] read back: category={d.get('category')} confidence={d.get('confidence')} "
              f"engagement_id={d.get('engagement_id')}")
        assert d.get("category") == "horizontal_pe"
        assert d.get("confidence") == 0.95
        assert d.get("engagement_id") == engagement_id

        result = await session.run(
            "SHOW CONSTRAINTS YIELD name WHERE name IN ['diff_auth_id', 'evidence_id'] RETURN collect(name) AS names",
        )
        names_record = await result.single()
        names = names_record["names"] if names_record else []
        print(f"[4] constraints present: {names}")

        cleanup = await session.run(
            "MATCH (d:DiffAuthFinding {id: $id}) DETACH DELETE d",
            {"id": finding.id},
        )
        await cleanup.consume()
        print(f"[5] cleanup deleted test finding")

    if "diff_auth_id" not in names:
        print("FAIL: diff_auth_id constraint missing")
        return 1
    if "evidence_id" not in names:
        print("WARN: evidence_id constraint missing")

    print("PASS: DiffAuth pipeline + schema verified")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
