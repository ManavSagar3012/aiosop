"""Integration regression test for add_vulnerability idempotency (AIOSOP-UPSERT-IDEMPOTENT).

A caller-supplied finding id (upsert_verified_finding MCP tool, restart-recovery,
re-import) can collide with an existing node that has a *different* content-based
dedup_key. The old Cypher did ``ON CREATE SET v.id = $id`` unconditionally, so the
collision violated the unique-id constraint and aborted the whole upsert — the
attack_graph reality gate crashed with ConstraintValidationFailed on re-runs.

These tests run the real Cypher against a live Neo4j (skipped when unreachable, so
local dev without the data tier does not see false failures; CI provides Neo4j).
They assert:
  * idempotency  — same content twice -> one node, same id, duplicate_count bumped
  * clash-safety — same forced id + different content -> no crash, fresh id minted
"""

from __future__ import annotations

import uuid

import pytest

from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability
from ai_osop.memory.graph_memory import GraphMemory


def _vuln(engagement: str, title: str, url: str, vid: str | None = None) -> Vulnerability:
    v = Vulnerability(
        cwe="CWE-89",
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        title=title,
        description="idempotency itest",
        tool_source="itest",
        evidence=[{"type": "itest", "url": url}],
        confidence=0.9,
        validated=True,
        exploitability="high",
        impact="high",
        engagement_id=engagement,
    )
    if vid:
        v.id = vid
    return v


@pytest.fixture
async def graph_memory():
    gm = GraphMemory()
    try:
        await gm.connect()
    except Exception as e:  # noqa: BLE001 - Neo4j not available in this environment
        pytest.skip(f"Neo4j unavailable: {e}")
    yield gm
    if gm._driver is not None:
        await gm._driver.close()


async def _cleanup(gm: GraphMemory, engagement: str) -> None:
    async with gm._driver.session() as s:
        await s.run("MATCH (v:Vulnerability {engagement_id: $e}) DETACH DELETE v", e=engagement)


@pytest.mark.asyncio
async def test_same_content_is_idempotent(graph_memory):
    eng = f"itest-idem-{uuid.uuid4().hex[:8]}"
    try:
        id1 = await graph_memory.add_vulnerability(_vuln(eng, "dup", "http://t/a"))
        id2 = await graph_memory.add_vulnerability(_vuln(eng, "dup", "http://t/a"))
        assert id1 == id2  # dedup collapsed on content, id preserved
        async with graph_memory._driver.session() as s:
            rec = await (
                await s.run(
                    "MATCH (v:Vulnerability {engagement_id: $e}) "
                    "RETURN count(v) AS c, collect(v.duplicate_count) AS dc",
                    e=eng,
                )
            ).single()
        assert rec["c"] == 1  # one node, not two
        assert rec["dc"] == [1]  # ON MATCH bumped duplicate_count
    finally:
        await _cleanup(graph_memory, eng)


@pytest.mark.asyncio
async def test_id_clash_with_different_content_does_not_crash(graph_memory):
    eng = f"itest-clash-{uuid.uuid4().hex[:8]}"
    forced = f"vuln-forced-{uuid.uuid4().hex[:8]}"
    try:
        id1 = await graph_memory.add_vulnerability(_vuln(eng, "one", "http://t/one", vid=forced))
        assert id1 == forced  # clean create keeps the supplied id
        # Same forced id, different content => different dedup_key => used to crash.
        id2 = await graph_memory.add_vulnerability(
            _vuln(eng, "two DIFFERENT", "http://t/two", vid=forced)
        )
        assert id2 != forced  # a fresh id was minted to dodge the unique-id clash
        async with graph_memory._driver.session() as s:
            rec = await (
                await s.run(
                    "MATCH (v:Vulnerability {engagement_id: $e}) RETURN count(v) AS c",
                    e=eng,
                )
            ).single()
        assert rec["c"] == 2  # both findings persisted, neither lost to a crash
    finally:
        await _cleanup(graph_memory, eng)
