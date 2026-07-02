"""P2b: orchestrator outcome-ingestion poller tests.

Covers the write half of the calibration loop that was previously orphaned — the
orchestrator now folds real submission outcomes into the corpus for every active
engagement. Exercised hermetically via Orchestrator.__new__ (no real construction,
no DB), so we test only the ingestion-tick logic in isolation.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.orchestrator.orchestrator import Orchestrator


def _orch(sessions, corpus_service):
    orch = Orchestrator.__new__(Orchestrator)  # skip heavy __init__
    orch.state = SimpleNamespace(sessions=sessions)
    orch.finding_corpus_service = corpus_service
    return orch


@pytest.mark.asyncio
async def test_ingest_once_sums_across_active_engagements():
    svc = MagicMock()
    svc.ingest_outcomes = AsyncMock(side_effect=[2, 3])  # one call per engagement
    orch = _orch({"eng-1": object(), "eng-2": object()}, svc)

    total = await orch._ingest_outcomes_once()

    assert total == 5
    assert svc.ingest_outcomes.await_count == 2
    called = {c.args[0] for c in svc.ingest_outcomes.await_args_list}
    assert called == {"eng-1", "eng-2"}


@pytest.mark.asyncio
async def test_ingest_once_noop_without_service():
    orch = _orch({"eng-1": object()}, None)
    assert await orch._ingest_outcomes_once() == 0


@pytest.mark.asyncio
async def test_ingest_once_noop_with_no_active_engagements():
    svc = MagicMock()
    svc.ingest_outcomes = AsyncMock(return_value=1)
    orch = _orch({}, svc)
    assert await orch._ingest_outcomes_once() == 0
    svc.ingest_outcomes.assert_not_awaited()


@pytest.mark.asyncio
async def test_ingest_once_isolates_per_engagement_failure():
    """One engagement raising must not abort ingestion of the others."""
    svc = MagicMock()
    svc.ingest_outcomes = AsyncMock(side_effect=[RuntimeError("boom"), 4])
    orch = _orch({"eng-bad": object(), "eng-ok": object()}, svc)

    total = await orch._ingest_outcomes_once()

    assert total == 4  # the good engagement still counted; the bad one swallowed
    assert svc.ingest_outcomes.await_count == 2
