"""Unit tests for ValidationLedger: recording, state transitions, and precision/gates."""

from datetime import timedelta
from typing import Any, Dict

import pytest

from ai_osop.core.enums import Severity, VulnClass
from ai_osop.core.models import Endpoint, Vulnerability
from ai_osop.core.validation_ledger import ValidatedFindingEvent, ValidationLedger


class _FakeSessionMemory:
    def __init__(self) -> None:
        self.writes = []
        self.reads = []

    async def run_write(self, query: str, *params) -> None:
        self.writes.append((query, params))

    async def run_read(self, query: str, *params) -> list:
        # The real driver returns list[dict] with keys from the SELECT; the summarize
        # method expects "suspicious_ids" present when manual_review exists.
        if "summarize" in query or "GROUP BY" in query:
            return [
                {
                    "state": "validated",
                    "count": 3,
                    "avg_trust": 0.9,
                    "suspicious_ids": [],
                },
                {
                    "state": "manual_review",
                    "count": 2,
                    "avg_trust": 0.4,
                    "suspicious_ids": ["f-3"],
                },
                {
                    "state": "escalated",
                    "count": 1,
                    "avg_trust": 0.95,
                    "suspicious_ids": [],
                },
            ]
        return []


@pytest.mark.asyncio
async def test_ledger_records_finding_lifecycle():
    mem = _FakeSessionMemory()
    ledger = ValidationLedger(mem)
    await ledger.initialize()

    assert any("CREATE TABLE" in w[0] for w in mem.writes)

    finding = ValidatedFindingEvent(
        id="f-1",
        vuln_id="vuln-1",
        endpoint_id="ep-1",
        state="validated",
        evidence_summary="SQLi on login",
        trust_score=0.92,
    )
    await ledger.record(finding)
    assert len(mem.writes) == 2  # TABLE + insert
    assert "INSERT INTO" in mem.writes[-1][0]
    assert mem.writes[-1][1][:4] == ("f-1", "vuln-1", "ep-1", "validated")

    await ledger.transition("f-1", "manual_review", "oracle failed to confirm payload")
    assert "UPDATE" in mem.writes[-1][0]
    assert "manual_review" in mem.writes[-1][1][1]
    assert "oracle failed" in mem.writes[-1][1][2]

    summary = await ledger.summarize(engagement_id="eng")
    states = {s[0]: s[1] for s in summary["states"]}
    assert states["validated"] == 3
    assert states["manual_review"] == 2
    assert states["escalated"] == 1


@pytest.mark.asyncio
async def test_precision_gate_counts_confirmed_vs_flagged():
    mem = _FakeSessionMemory()
    ledger = ValidationLedger(mem)
    await ledger.initialize()

    # Confirmed finding path (SQLi hallmarks)
    confirmed = ValidatedFindingEvent(
        id="f-2",
        vuln_id="vuln-sql-1",
        endpoint_id="ep-login",
        state="validated",
        evidence_summary="boolean confirmation",
        trust_score=0.98,
    )
    await ledger.record(confirmed)

    # Flagged but invalidated by oracle
    needs_review = ValidatedFindingEvent(
        id="f-3",
        vuln_id="vuln-sus-1",
        endpoint_id="ep-login",
        state="manual_review",
        evidence_summary="",
        trust_score=0.3,
    )
    await ledger.record(needs_review)

    assert len(mem.writes) == 3  # setup + two records
    summary = await ledger.summarize()
    assert "manual_review" in {s[0] for s in summary["states"]}
    assert summary["needs_review_sample"] is not None
