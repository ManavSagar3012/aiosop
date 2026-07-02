"""Tests for the P2b confidence-calibration wiring in HypothesisEngine.

These prove that HypothesisEngine._calibrate() reorders hypotheses by *learned*
confidence: it recalibrates each hypothesis against the empirical per-category
success rate, but only when that rate is a real signal (!= neutral 0.5).

Hermetic: no DB, no network. session_memory and graph_memory are mocked.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from ai_osop.core.hypothesis_engine import HypothesisEngine
from ai_osop.core.models import Hypothesis


def _hyp(title: str, category: str, confidence: float) -> Hypothesis:
    """Hand-build a minimal Hypothesis with the fields the calibrator touches."""
    return Hypothesis(
        title=title,
        description=f"{title} description",
        category=category,
        target_id="ep-1",
        confidence=confidence,
        engagement_id="eng-1",
    )


def _make_session_memory(rates: dict[str, float]) -> MagicMock:
    """A mock session_memory whose get_historical_success_rate returns a
    dict-driven per-category rate (defaulting to neutral 0.5)."""
    sm = MagicMock()

    async def _rate(finding_type, workflow_intent=None):
        return rates.get(finding_type, 0.5)

    sm.get_historical_success_rate = AsyncMock(side_effect=_rate)
    return sm


@pytest.mark.asyncio
async def test_calibrate_is_noop_without_session_memory():
    """When no session_memory is wired, _calibrate must not touch confidence."""
    engine = HypothesisEngine(graph_memory=MagicMock())
    assert engine._calibrator is None

    hyps = [
        _hyp("workflow hyp", "workflow", 0.60),
        _hyp("cloud hyp", "cloud", 0.70),
    ]
    originals = [h.confidence for h in hyps]

    await engine._calibrate(hyps)

    assert [h.confidence for h in hyps] == originals


@pytest.mark.asyncio
async def test_calibrate_recalibrates_signal_category_toward_history():
    """A category with a real historical signal (0.9) is pulled toward it via
    the historical*0.6 + base*0.4 formula."""
    session_memory = _make_session_memory({"workflow": 0.9})
    engine = HypothesisEngine(graph_memory=MagicMock(), session_memory=session_memory)
    assert engine._calibrator is not None

    base = 0.60
    hyps = [_hyp("workflow hyp", "workflow", base)]

    await engine._calibrate(hyps)

    expected = 0.9 * 0.6 + base * 0.4  # = 0.78
    assert hyps[0].confidence != base
    assert hyps[0].confidence == pytest.approx(expected)


@pytest.mark.asyncio
async def test_calibrate_leaves_neutral_category_unchanged():
    """A category whose historical rate is neutral (0.5) keeps its raw
    heuristic confidence untouched."""
    session_memory = _make_session_memory({"workflow": 0.9})  # cloud -> 0.5 default
    engine = HypothesisEngine(graph_memory=MagicMock(), session_memory=session_memory)

    base_cloud = 0.70
    hyps = [_hyp("cloud hyp", "cloud", base_cloud)]

    await engine._calibrate(hyps)

    assert hyps[0].confidence == pytest.approx(base_cloud)


@pytest.mark.asyncio
async def test_calibration_reorders_hypotheses_by_learned_confidence():
    """The core proof: a formerly-lower workflow hypothesis outranks a
    formerly-higher neutral one after learned calibration + sort.

    Before calibration:  cloud (0.70) > workflow (0.60)
    After  calibration:  workflow (0.78) > cloud (0.70)
    """
    session_memory = _make_session_memory({"workflow": 0.9})  # cloud stays neutral 0.5
    engine = HypothesisEngine(graph_memory=MagicMock(), session_memory=session_memory)

    workflow_hyp = _hyp("workflow hyp", "workflow", 0.60)
    cloud_hyp = _hyp("cloud hyp", "cloud", 0.70)
    hyps = [workflow_hyp, cloud_hyp]

    # Sanity: pre-calibration order has the neutral one on top.
    assert cloud_hyp.confidence > workflow_hyp.confidence

    await engine._calibrate(hyps)

    # Neutral category unchanged; signal category raised above it.
    assert cloud_hyp.confidence == pytest.approx(0.70)
    assert workflow_hyp.confidence == pytest.approx(0.9 * 0.6 + 0.60 * 0.4)  # 0.78
    assert workflow_hyp.confidence > cloud_hyp.confidence

    # The same sort used at the end of generate_hypotheses now reorders them.
    hyps.sort(key=lambda h: -h.confidence)
    assert hyps[0] is workflow_hyp
    assert hyps[1] is cloud_hyp
