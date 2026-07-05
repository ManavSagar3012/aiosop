"""Closed-loop calibration feedback tests (real outcomes -> adjusted confidence).

Proves the ConfidenceCalibrationEngine public API that closes the P2b loop:

  record_outcome(finding, real_verdict)          # RECORD ground truth
      -> durable corpus (here: an in-memory fake standing in for Postgres)
      -> calibrate_for_class / calibrate_with_evidence   # LEARN from it

All offline and deterministic: a fake store implements the same public methods
(``upsert_corpus_finding`` write, ``get_historical_outcome_counts`` read) that
the real ``SessionMemory`` exposes, so recording accepts/rejects for a class and
then calibrating exercises the whole loop with no Postgres and no network.
"""
import pytest

from ai_osop.core.calibration_engine import (
    DEFAULT_PRIOR_STRENGTH,
    POSITIVE_OUTCOMES,
    ConfidenceCalibrationEngine,
)


# --------------------------------------------------------------------------- #
# Fake durable store: implements the SessionMemory surface the engine uses.    #
# record_outcome writes through upsert_corpus_finding; calibrate_for_class     #
# reads back through get_historical_outcome_counts. This is the real loop.     #
# --------------------------------------------------------------------------- #
class _FakeStore:
    def __init__(self):
        # keyed by finding id so a re-verdict upserts (corrects) rather than dupes
        self._rows = {}

    async def upsert_corpus_finding(self, finding_data, outcome="accepted"):
        self._rows[finding_data["id"]] = {
            "category": finding_data.get("category"),
            "outcome": outcome,
        }

    async def get_historical_outcome_counts(self, finding_type, workflow_intent=None):
        n_valid = n_total = 0
        for row in self._rows.values():
            if row["category"] != finding_type:
                continue
            if row["outcome"] in POSITIVE_OUTCOMES:
                n_valid += 1
                n_total += 1
            else:  # rejected / na / informative are decided-but-invalid
                n_total += 1
        return n_valid, n_total


async def _record(engine, category, outcome, n, start=0):
    """Record ``n`` findings of ``category`` with a fixed real ``outcome``."""
    for i in range(start, start + n):
        await engine.record_outcome(
            {"id": f"{category}-{outcome}-{i}", "category": category}, outcome
        )


# --------------------------------------------------------------------------- #
# (a) recording accepts/rejects moves calibrated confidence in the right way   #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_accepts_raise_and_rejects_lower_confidence():
    base = 0.5

    # Mostly-accepted class -> confidence should rise above base.
    hot = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    await _record(hot, "authz", "accepted", 9)
    await _record(hot, "authz", "rejected", 1)
    hot_conf = await hot.calibrate_for_class(base, "authz")
    assert hot_conf > base

    # Mostly-rejected class -> confidence should fall below base.
    cold = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    await _record(cold, "authz", "accepted", 1)
    await _record(cold, "authz", "rejected", 9)
    cold_conf = await cold.calibrate_for_class(base, "authz")
    assert cold_conf < base

    # duplicate counts as a true positive (detection was correct).
    dup = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    await _record(dup, "authz", "duplicate", 10)
    assert await dup.calibrate_for_class(base, "authz") > base


# --------------------------------------------------------------------------- #
# (b) a class with no recorded outcomes returns confidence ~unchanged          #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_no_outcomes_returns_base_unchanged():
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    for base in (0.2, 0.5, 0.85):
        # Nothing recorded for this class at all.
        assert await engine.calibrate_for_class(base, "never_seen") == pytest.approx(base)
    # And the pure evidence function with zero counts is a strict no-op.
    assert engine.calibrate_with_evidence(0.73, n_valid=0, n_total=0) == pytest.approx(0.73)


@pytest.mark.asyncio
async def test_recording_other_class_does_not_move_this_class():
    """Outcomes are keyed per class — a hot 'authz' must not bleed into 'ssrf'."""
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    await _record(engine, "authz", "accepted", 20)
    assert await engine.calibrate_for_class(0.4, "ssrf") == pytest.approx(0.4)


# --------------------------------------------------------------------------- #
# (c) monotonicity — more accepts => strictly higher calibrated confidence     #
# --------------------------------------------------------------------------- #
def test_monotonic_in_accept_count_fixed_total():
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    base, total = 0.5, 20
    confs = [
        engine.calibrate_with_evidence(base, n_valid=k, n_total=total)
        for k in range(0, total + 1)
    ]
    assert confs == sorted(confs)
    assert len(set(confs)) > 1  # actually varies, not clamped flat
    # symmetric endpoints around a 0.5 prior: all-reject < base < all-accept
    assert confs[0] < base < confs[-1]


@pytest.mark.asyncio
async def test_more_accumulated_accepts_raise_confidence():
    """Recording additional accepts (loop truly accumulating) lifts confidence."""
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    base = 0.5
    await _record(engine, "authz", "accepted", 2)
    after_2 = await engine.calibrate_for_class(base, "authz")
    await _record(engine, "authz", "accepted", 18, start=2)
    after_20 = await engine.calibrate_for_class(base, "authz")
    assert after_20 > after_2 > base


# --------------------------------------------------------------------------- #
# Sample-size awareness: a thin class barely moves; a thick one converges.     #
# --------------------------------------------------------------------------- #
def test_prior_strength_controls_shrinkage():
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    base = 0.5
    # 100% observed accept-rate, but only 1 sample vs 200 samples.
    thin = engine.calibrate_with_evidence(base, n_valid=1, n_total=1)
    thick = engine.calibrate_with_evidence(base, n_valid=200, n_total=200)
    assert base < thin < thick
    # thin stays near the prior; thick nears the observed rate (clamped ceiling).
    assert thin < 0.65
    assert thick > 0.95
    # closed form check: (1 + k*0.5)/(1 + k) with default k
    expected_thin = (1 + DEFAULT_PRIOR_STRENGTH * 0.5) / (1 + DEFAULT_PRIOR_STRENGTH)
    assert thin == pytest.approx(expected_thin)


# --------------------------------------------------------------------------- #
# RECORD side: validation + durable write-through.                             #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_record_outcome_persists_and_normalizes():
    store = _FakeStore()
    engine = ConfidenceCalibrationEngine(session_memory=store)
    got = await engine.record_outcome({"id": "f1", "category": "xss"}, "ACCEPTED")
    assert got == "accepted"  # normalized
    assert store._rows["f1"] == {"category": "xss", "outcome": "accepted"}


@pytest.mark.asyncio
async def test_record_outcome_rejects_unknown_verdict():
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    with pytest.raises(ValueError):
        await engine.record_outcome({"id": "f1", "category": "xss"}, "maybe-later")


@pytest.mark.asyncio
async def test_reverdict_corrects_ground_truth_not_double_counts():
    """An initial 'triaged' later flipped to 'rejected' must overwrite, not add."""
    engine = ConfidenceCalibrationEngine(session_memory=_FakeStore())
    finding = {"id": "same-finding", "category": "authz"}
    await engine.record_outcome(finding, "triaged")
    conf_positive = await engine.calibrate_for_class(0.5, "authz")
    assert conf_positive > 0.5
    await engine.record_outcome(finding, "rejected")  # same id -> upsert
    conf_negative = await engine.calibrate_for_class(0.5, "authz")
    assert conf_negative < 0.5


# --------------------------------------------------------------------------- #
# Fallback path: store exposes only a rate (real SessionMemory today).         #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_calibrate_for_class_falls_back_to_rate_blend():
    class _RateOnlyStore:
        async def get_historical_success_rate(self, finding_type, workflow_intent=None):
            return 1.0  # hot class

    engine = ConfidenceCalibrationEngine(session_memory=_RateOnlyStore())
    # No counts method -> legacy blend: 1.0*0.6 + 0.4*0.4 = 0.76
    assert await engine.calibrate_for_class(0.4, "authz") == pytest.approx(0.76)
