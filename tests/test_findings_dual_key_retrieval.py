"""Regression test for AIOSOP-FINDINGS-KEY-2026-07-20.

An engagement is addressable by two id forms: the SHORT operator-supplied
``engagement_id`` (juice-e2e-xxx) and the FULL generated ``session_id``
(eng-{timestamp}-juice-e2e-xxx). Writers persist Vulnerability.engagement_id
under different forms (the deterministic scan uses scope.engagement_id; some
agents use ctx.session_id). The findings API read path used ONLY the URL
session_id, so a scan that persisted 7 findings under the short engagement_id
was retrieved as 0 via GET /engagements/{id}/findings — findings stranded in
the graph, invisible to the dashboard and bounty report.

The fix makes get_vulnerabilities_by_engagement match ANY provided id form
(``WHERE v.engagement_id IN $ids``) and threads both forms from the findings
router. These tests pin that behavior:

  * unit  — the Cypher is an IN-list over every non-empty, de-duped id form
            (runs everywhere, no data tier needed)
  * live  — a finding written under the SHORT id is retrievable when the read
            passes the FULL id + short alias (skipped without Neo4j)
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import Severity, VulnClass
from ai_osop.core.models import Vulnerability
from ai_osop.memory.graph_memory import GraphMemory


class _FakeResult:
    def __init__(self, records):
        self._records = records

    async def data(self):
        return self._records


class _FakeSession:
    """Captures the Cypher params passed to session.run for assertions."""

    def __init__(self, records, sink):
        self._records = records
        self._sink = sink

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def run(self, cypher, params=None):
        self._sink["cypher"] = cypher
        self._sink["params"] = params or {}
        return _FakeResult(self._records)


def _gm_with_capture(records):
    gm = GraphMemory()
    sink: dict = {}
    driver = MagicMock()
    driver.session = MagicMock(return_value=_FakeSession(records, sink))
    gm._driver = driver
    return gm, sink


@pytest.mark.asyncio
async def test_query_matches_any_id_form_and_dedupes():
    gm, sink = _gm_with_capture([{"v": {"id": "x", "engagement_id": "short"}}])
    # full + short + a duplicate of full; empty/None must be dropped
    out = await gm.get_vulnerabilities_by_engagement("full", "short", "full", "", None)  # type: ignore[arg-type]
    assert [r["id"] for r in out] == ["x"]
    # IN-list, not equality — this is the crux of the fix
    assert "v.engagement_id IN $ids" in sink["cypher"]
    # de-duped, order preserved, falsy values removed
    assert sink["params"]["ids"] == ["full", "short"]


@pytest.mark.asyncio
async def test_single_id_form_still_works():
    gm, sink = _gm_with_capture([])
    await gm.get_vulnerabilities_by_engagement("only-one")
    assert sink["params"]["ids"] == ["only-one"]


# --------------------------------------------------------------------------
# live integration: prove the stranded-findings bug is actually fixed
# --------------------------------------------------------------------------
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


async def _cleanup(gm: GraphMemory, *engagements: str) -> None:
    async with gm._driver.session() as s:
        for eid in engagements:
            await s.run("MATCH (v:Vulnerability {engagement_id:$e}) DETACH DELETE v", e=eid)


@pytest.mark.asyncio
async def test_finding_written_short_is_read_via_both_forms(graph_memory):
    gm = graph_memory
    short = f"dk-{uuid.uuid4().hex[:10]}"
    full = f"eng-20260720120000-{short}"
    await _cleanup(gm, short, full)
    try:
        v = Vulnerability(
            cwe="CWE-89",
            vuln_type=VulnClass.SQLI,
            severity=Severity.HIGH,
            title="dual-key regression finding",
            description="written under the SHORT engagement_id, like the deterministic scan does",
            tool_source="dual_key_itest",
            evidence=[{"type": "itest"}],
            confidence=0.9,
            validated=True,
            exploitability="high",
            impact="high",
            engagement_id=short,  # writer uses the short form
        )
        await gm.add_vulnerability(v)

        # OLD read path (full session_id only) missed it entirely
        only_full = await gm.get_vulnerabilities_by_engagement(full)
        assert len(only_full) == 0

        # NEW read path (both forms) retrieves it
        both = await gm.get_vulnerabilities_by_engagement(full, short)
        assert len(both) == 1
        assert both[0]["title"] == "dual-key regression finding"
    finally:
        await _cleanup(gm, short, full)
