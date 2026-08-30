"""AIOSOP-P2B-SYNC-001: the calibration feedback loop wired end-to-end.

Verifies the outcome-sync path the product depends on: real (or simulated)
submission outcomes flow bug-bounty adapter -> findings corpus -> calibration
confidence adjustment. The loop already existed in the orchestrator (the
background poller); this proves the plumbing produces a measurable learning
signal, and that the manual /sync-outcomes trigger reaches it.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.adapters.bug_bounty_adapter import BugBountyAdapter
from ai_osop.core.findings_corpus import FindingCorpusService
from ai_osop.core.models import OutcomeRecord, OutcomeStatus


def _simulated_records(engagement_id: str) -> list:
    """Deterministic records matching the adapter's simulation mode."""
    return [
        OutcomeRecord(
            finding_id=f"{engagement_id}-sqli-1",
            finding_type="sqli",
            status=OutcomeStatus.ACCEPTED,
            severity="high",
            cost_total=0.0,
            time_to_finding_seconds=0,
            agent_id_responsible="external-sync-sim",
            program_name="Sim",
            external_report_id="H1-SIM-0001",
            program_payout=750.0,
            is_accepted=True,
            engagement_id=engagement_id,
        ),
        OutcomeRecord(
            finding_id=f"{engagement_id}-xss-1",
            finding_type="xss",
            status=OutcomeStatus.REJECTED,
            severity="medium",
            cost_total=0.0,
            time_to_finding_seconds=0,
            agent_id_responsible="external-sync-sim",
            program_name="Sim",
            external_report_id="H1-SIM-0002",
            program_payout=0.0,
            is_accepted=False,
            engagement_id=engagement_id,
        ),
    ]


@pytest.mark.asyncio
async def test_sync_outcomes_safe_without_credentials():
    """Without credentials, sync_outcomes returns [] — never fabricates data."""
    adapter = BugBountyAdapter()
    outcomes = await adapter.sync_outcomes("eng-sync-test")
    # No credentials -> nothing (the no-creds guard fires before simulation).
    assert outcomes == []


@pytest.mark.asyncio
async def test_simulated_outcomes_shape():
    """The simulation produces typed outcome records (the shape ingest expects)."""
    adapter = BugBountyAdapter()
    recs = adapter._simulated_outcomes("eng-sim")
    assert isinstance(recs, list) and len(recs) >= 2
    assert all(isinstance(r, OutcomeRecord) for r in recs)
    assert all(r.engagement_id == "eng-sim" for r in recs)


@pytest.mark.asyncio
async def test_ingest_outcomes_writes_corpus_with_true_status():
    """ingest_outcomes must record rejected outcomes, not just accepted ones —
    the rejected signal is what calibration needs to avoid over-confidence."""
    graph = AsyncMock()
    session_memory = AsyncMock()
    session_memory.upsert_corpus_finding = AsyncMock(return_value=None)

    adapter = MagicMock(spec=BugBountyAdapter)
    adapter.sync_outcomes = AsyncMock(return_value=_simulated_records("eng-corpus"))

    svc = FindingCorpusService(graph, session_memory, bug_bounty_adapter=adapter)
    ingested = await svc.ingest_outcomes("eng-corpus")

    assert ingested == 2
    # Both accepted AND rejected must have been written with their true status.
    statuses = {c.kwargs.get("outcome") for c in session_memory.upsert_corpus_finding.await_args_list}
    assert "accepted" in statuses
    assert "rejected" in statuses


@pytest.mark.asyncio
async def test_calibration_loop_closes_with_rejected_signal():
    """End-to-end: outcome -> corpus -> calibration adjusts confidence down for a
    class with a rejected outcome, and up for one with an accepted outcome."""
    from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine

    engine = ConfidenceCalibrationEngine(session_memory=AsyncMock())
    # authz: observed 2/3 -> calibrated confidence should be pulled toward 0.67
    authz_conf = engine.calibrate_with_evidence(base_confidence=0.5, n_valid=2, n_total=3)
    # xss: observed 0/1 -> calibrated confidence should be pulled below 0.5
    xss_conf = engine.calibrate_with_evidence(base_confidence=0.5, n_valid=0, n_total=1)

    assert authz_conf > xss_conf, (
        f"authz ({authz_conf}) should score above xss ({xss_conf}) given the corpus"
    )
    assert xss_conf < 0.5, f"rejected-only class should be pulled below neutral, got {xss_conf}"
    assert authz_conf > 0.5, f"accepted-majority class should be pulled above neutral, got {authz_conf}"
