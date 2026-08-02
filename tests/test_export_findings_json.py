"""Unit tests for GraphMemory.export_findings_json — the seam between a real
engagement's persisted findings and benchmarks/score_engagement.py.

These patch get_vulnerabilities_by_engagement (the DB boundary) so they run
without a live Neo4j, and assert the export's own logic: stable
confidence-descending ordering, optional file write, and scorer-ready shape.
"""

import json
from unittest.mock import AsyncMock

import pytest

from ai_osop.memory.graph_memory import GraphMemory


def _make_gm(records):
    gm = GraphMemory()
    gm.get_vulnerabilities_by_engagement = AsyncMock(return_value=records)
    return gm


@pytest.mark.asyncio
async def test_export_returns_findings_sorted_by_confidence_desc():
    gm = _make_gm(
        [
            {"id": "b", "vuln_type": "xss", "confidence": 0.5},
            {"id": "a", "vuln_type": "sqli", "confidence": 0.95},
            {"id": "c", "vuln_type": "idor", "confidence": 0.7},
        ]
    )
    out = await gm.export_findings_json("eng-1")
    assert [f["id"] for f in out] == ["a", "c", "b"]


@pytest.mark.asyncio
async def test_export_ties_broken_by_id_for_stable_output():
    gm = _make_gm(
        [
            {"id": "z", "vuln_type": "xss", "confidence": 0.8},
            {"id": "a", "vuln_type": "sqli", "confidence": 0.8},
        ]
    )
    out = await gm.export_findings_json("eng-1")
    # same confidence -> id ascending, so runs are byte-stable
    assert [f["id"] for f in out] == ["a", "z"]


@pytest.mark.asyncio
async def test_export_handles_missing_or_none_confidence():
    gm = _make_gm(
        [
            {"id": "has", "vuln_type": "xss", "confidence": 0.6},
            {"id": "none", "vuln_type": "sqli", "confidence": None},
            {"id": "absent", "vuln_type": "idor"},
        ]
    )
    out = await gm.export_findings_json("eng-1")
    # 0.6 first; None and absent both coerce to 0.0, then id-ascending
    assert [f["id"] for f in out] == ["has", "absent", "none"]


@pytest.mark.asyncio
async def test_export_writes_file_when_path_given(tmp_path):
    gm = _make_gm([{"id": "a", "vuln_type": "sqli", "confidence": 0.9}])
    out_file = tmp_path / "findings.json"
    out = await gm.export_findings_json("eng-1", path=str(out_file))
    assert out_file.exists()
    on_disk = json.loads(out_file.read_text(encoding="utf-8"))
    assert on_disk == out
    assert on_disk[0]["vuln_type"] == "sqli"


@pytest.mark.asyncio
async def test_export_no_path_does_not_write(tmp_path):
    gm = _make_gm([{"id": "a", "vuln_type": "sqli", "confidence": 0.9}])
    out = await gm.export_findings_json("eng-1")
    assert isinstance(out, list) and len(out) == 1
    # nothing created in tmp_path
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_export_empty_engagement_yields_empty_list(tmp_path):
    gm = _make_gm([])
    out_file = tmp_path / "empty.json"
    out = await gm.export_findings_json("eng-empty", path=str(out_file))
    assert out == []
    assert json.loads(out_file.read_text(encoding="utf-8")) == []
