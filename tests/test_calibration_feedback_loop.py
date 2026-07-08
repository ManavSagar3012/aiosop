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
    adapter.h1_api_key = "test-key"  # so sync_outcomes doesn't early-return []
    adapter.simulation_mode = True  # deterministic synthetic outcomes
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
    sm = _reader_with_rows([("accepted", 3), ("duplicate", 1), ("rejected", 1), ("informative", 1)])
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
    # Simulator yields idor/triaged and xss/paid. Ingest normalizes the concrete
    # finding type onto the hypothesis-category vocabulary (idor->authz,
    # xss->client_side) so calibration lookups match; the real status is preserved.
    outcomes = {v["category"]: v["outcome"] for v in store.values()}
    assert outcomes == {"authz": "triaged", "client_side": "paid"}


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
    await svc.ingest_outcomes("eng-1")  # idor->authz/triaged, xss->client_side/paid

    # A real-world rejection for a client_side (xss-class) finding enters too.
    store["xss-reject-1"] = {"category": "client_side", "outcome": "rejected"}

    # Reader over the accumulated ground truth (real classification logic). Note the
    # lookup key is the hypothesis CATEGORY (client_side / authz), which is exactly
    # what the hypothesis engine passes — proving the taxonomy now aligns end-to-end.
    reader = _reader_with_rows(_grouped_rows(store, "client_side"))
    cs_rate = await reader.get_historical_success_rate("client_side")
    assert cs_rate == pytest.approx(0.5)  # 1 paid / (1 paid + 1 rejected)

    reader_authz = _reader_with_rows(_grouped_rows(store, "authz"))
    assert await reader_authz.get_historical_success_rate("authz") == 1.0

    # Calibration engine consumes the rate: a hot category pulls a weak base
    # confidence up; the engine no longer AttributeErrors on the missing method.
    engine = ConfidenceCalibrationEngine(session_memory=reader_authz)
    calibrated = await engine.calibrate_confidence(base_confidence=0.4, finding_type="authz")
    # historical(1.0)*0.6 + base(0.4)*0.4 = 0.76 — learning lifted confidence above base.
    assert calibrated == pytest.approx(0.76)
    assert calibrated > 0.4


# --------------------------------------------------------------------------- #
# Regression lock: real VulnClass emitters must map to hypothesis categories.  #
# Guards against the taxonomy silently reverting to synonym-only keys that no   #
# emitter produces (which would make calibration a no-op for those categories). #
# --------------------------------------------------------------------------- #
def test_real_vulnclass_emitters_map_to_hypothesis_categories():
    from ai_osop.core.taxonomy import HYPOTHESIS_CATEGORIES, category_for_finding_type

    # (emitted VulnClass.value  ->  expected hypothesis category)
    expected = {
        "idor": "authz",
        "mass_assignment": "authz",
        "broken_access_control": "authz",
        "privilege_escalation": "authz",
        "xss": "client_side",
        "csrf": "client_side",
        "request_smuggling": "client_side",
        "ssrf": "ssrf_redirect",
        "graphql_security": "graphql",  # the value the GraphQL agent actually emits
        "race_condition": "workflow",
        "cloud_vuln": "cloud",
        "kubernetes_security": "cloud",
        "jwt_abuse": "session",  # the value emitted, not the "jwt" synonym
        "oauth2": "session",
        "authentication_weakness": "session",
    }
    for finding_type, category in expected.items():
        got = category_for_finding_type(finding_type)
        assert got == category, f"{finding_type} -> {got}, expected {category}"
        assert got in HYPOTHESIS_CATEGORIES

    # Injection-family types intentionally have no hypothesis category and must
    # pass through unchanged (documented design — they don't participate yet).
    for injection in ("sqli", "rce", "lfi", "xxe", "deserialization", "ssti"):
        assert category_for_finding_type(injection) == injection
        assert injection not in HYPOTHESIS_CATEGORIES
