"""P2b calibration feedback-loop tests.

Proves the loop that lets confidence self-correct from real submission outcomes:

  sync_outcomes (real accept/reject/duplicate)  ->  FindingCorpusService.ingest_outcomes
      ->  finding_corpus (true status per finding type)
      ->  SessionMemory.get_historical_success_rate  ->  ConfidenceCalibrationEngine

Everything runs offline: the reader is exercised against a fake async session, and
the writer against the deterministic bug-bounty simulator — no Postgres, no network.
"""
import pytest

from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine
from ai_osop.core.findings_corpus import FindingCorpusService
from ai_osop.memory.session_memory import SessionMemory


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #
class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    """Async-context session whose execute() yields pre-grouped (outcome, count) rows."""

    def __init__(self, rows):
        self._rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def execute(self, query):
        return _FakeResult(self._rows)


def _session_factory(rows):
    """Mimic SessionMemory._async_session: a callable returning an async-ctx session."""
    return lambda: _FakeSession(rows)


def _grouped_rows(store, finding_type):
    """Group a {id: {category, outcome}} store into [(outcome, count)] for one category,
    exactly as the real GROUP BY would return it."""
    counts = {}
    for row in store.values():
        if row["category"] == finding_type:
            counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    return list(counts.items())


def _reader_with_rows(rows):
    sm = SessionMemory()
    sm._async_session = _session_factory(rows)
    return sm


def _sim_adapter():
    from ai_osop.adapters.bug_bounty_adapter import BugBountyAdapter

    adapter = BugBountyAdapter()
    adapter.h1_api_key = "test-key"      # so sync_outcomes doesn't early-return []
    adapter.simulation_mode = True       # deterministic synthetic outcomes
    return adapter


# --------------------------------------------------------------------------- #
# Reader: get_historical_success_rate                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_success_rate_neutral_when_no_data():
    """Cold start returns the neutral 0.5 the calibration engine treats as 'no signal'."""
    sm = _reader_with_rows([])
    assert await sm.get_historical_success_rate("ssrf") == 0.5


@pytest.mark.asyncio
async def test_success_rate_all_valid():
    sm = _reader_with_rows([("accepted", 3), ("paid", 2)])
    assert await sm.get_historical_success_rate("idor") == 1.0


@pytest.mark.asyncio
async def test_success_rate_mixed_outcomes():
    # valid = accepted(3) + duplicate(1) = 4 ; invalid = rejected(1) + informative(1) = 2
    sm = _reader_with_rows(
        [("accepted", 3), ("duplicate", 1), ("rejected", 1), ("informative", 1)]
    )
    assert await sm.get_historical_success_rate("xss") == pytest.approx(4 / 6)


@pytest.mark.asyncio
async def test_success_rate_neutral_when_disconnected():
    sm = SessionMemory()  # _async_session is None
    assert await sm.get_historical_success_rate("xss") == 0.5


@pytest.mark.asyncio
async def test_success_rate_neutral_on_db_error():
    class _Boom:
        def __call__(self):
            raise RuntimeError("db down")

    sm = SessionMemory()
    sm._async_session = _Boom()
    assert await sm.get_historical_success_rate("xss") == 0.5


# --------------------------------------------------------------------------- #
# Ingestion: FindingCorpusService.ingest_outcomes                             #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_ingest_outcomes_records_true_status():
    """Simulated outcomes land in the corpus keyed by finding type with real status."""
    from unittest.mock import MagicMock

    store = {}

    async def fake_upsert(finding_data, outcome="accepted"):
        store[finding_data["id"]] = {
            "category": finding_data["category"],
            "outcome": outcome,
        }

    sm = MagicMock()
    sm.upsert_corpus_finding = fake_upsert
    svc = FindingCorpusService(MagicMock(), sm, bug_bounty_adapter=_sim_adapter())

    n = await svc.ingest_outcomes("eng-1")
    assert n == 2
    # Simulator yields idor/triaged and xss/paid — captured with their real status.
    outcomes = {v["category"]: v["outcome"] for v in store.values()}
    assert outcomes == {"idor": "triaged", "xss": "paid"}


@pytest.mark.asyncio
async def test_ingest_outcomes_noop_without_adapter():
    from unittest.mock import MagicMock

    svc = FindingCorpusService(MagicMock(), MagicMock(), bug_bounty_adapter=None)
    assert await svc.ingest_outcomes("eng-1") == 0


# --------------------------------------------------------------------------- #
# Capstone: full loop, real classification logic end-to-end                    #
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_full_loop_ingest_then_calibrate():
    """sync -> ingest (true status) -> reader -> calibration engine, with a rejection
    in the mix so the rate is a genuine fraction, not a trivial 1.0."""
    from unittest.mock import MagicMock

    store = {}

    async def fake_upsert(finding_data, outcome="accepted"):
        store[finding_data["id"]] = {
            "category": finding_data["category"],
            "outcome": outcome,
        }

    writer = MagicMock()
    writer.upsert_corpus_finding = fake_upsert
    svc = FindingCorpusService(MagicMock(), writer, bug_bounty_adapter=_sim_adapter())
    await svc.ingest_outcomes("eng-1")  # idor/triaged (valid), xss/paid (valid)

    # A real-world rejection for xss enters the corpus too.
    store["xss-reject-1"] = {"category": "xss", "outcome": "rejected"}

    # Reader over the accumulated ground truth (real classification logic).
    reader = _reader_with_rows(_grouped_rows(store, "xss"))
    xss_rate = await reader.get_historical_success_rate("xss")
    assert xss_rate == pytest.approx(0.5)  # 1 paid / (1 paid + 1 rejected)

    reader_idor = _reader_with_rows(_grouped_rows(store, "idor"))
    assert await reader_idor.get_historical_success_rate("idor") == 1.0

    # Calibration engine consumes the rate: a hot finding type pulls a weak base
    # confidence up; the engine no longer AttributeErrors on the missing method.
    engine = ConfidenceCalibrationEngine(session_memory=reader_idor)
    calibrated = await engine.calibrate_confidence(
        base_confidence=0.4, finding_type="idor"
    )
    # historical(1.0)*0.6 + base(0.4)*0.4 = 0.76 — learning lifted confidence above base.
    assert calibrated == pytest.approx(0.76)
    assert calibrated > 0.4
