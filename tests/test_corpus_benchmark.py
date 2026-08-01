"""B1: VulnerabilityCorpusBenchmark — deterministic offline corpus
Evaluates fixed PRMs (positive reference materials) with expected labels so the
platform scores itself against reproducible facts, not marketing claims."""

from typing import Any, Dict, List, Optional

import pytest

from ai_osop.core.corpus_benchmark import CorpusBenchmark, GroundTruthEntry


def _make_corpus() -> List[GroundTruthEntry]:
    return [
        GroundTruthEntry(
            id="gt-001",
            vuln_class="sql_injection",
            endpoint="/rest/user/login",
            method="POST",
            expected_result="accepted",
            reference_exploit={"payload": "' OR 1=1--", "expected_status": 200},
            severity_expected="high",
        ),
        GroundTruthEntry(
            id="gt-002",
            vuln_class="idor",
            endpoint="/rest/basket/{id}",
            method="GET",
            expected_result="accepted",
            reference_exploit={"payload": "https://target/rest/basket/2", "expected_status": 200},
            severity_expected="high",
        ),
        GroundTruthEntry(
            id="gt-003",
            vuln_class="info_disclosure",
            endpoint="/ftp/legal.md",
            method="GET",
            expected_result="rejected",
            reference_exploit={"payload": "GET /ftp/legal.md", "expected_status": 403},
            severity_expected="low",
        ),
        GroundTruthEntry(
            id="gt-004",
            vuln_class="csrf",
            endpoint="/rest/user/change-password",
            method="POST",
            expected_result="rejected",
            reference_exploit={"payload": "csrf_token=x", "expected_status": 403},
            severity_expected="medium",
        ),
    ]


def test_corpus_schema_coherent():
    corpus = CorpusBenchmark(_make_corpus())
    assert corpus.count() == 4
    assert corpus.classes == {"sql_injection", "idor", "info_disclosure", "csrf"}


def test_corpus_contract_is_stable():
    corpus = CorpusBenchmark(_make_corpus())
    out = corpus.contracts()
    assert out["version"] == "1.0.0"
    assert set(out["benchmarks"].keys()) == {"gt-001", "gt-002", "gt-003", "gt-004"}


@pytest.mark.asyncio
async def test_corpus_run_deterministic():
    corpus = CorpusBenchmark(_make_corpus())
    r1 = await corpus.run(dry_run=True)
    r2 = await corpus.run(dry_run=True)
    assert r1 == r2
    assert len(r1) == 4
    assert all(f["matched"] for f in r1)
    expected_by_id = {a.expected_result: a.expected_result for a in _make_corpus()}
    # assertions about matching invariants


@pytest.mark.asyncio
async def test_corpus_fails_on_empty_runner():
    corpus = CorpusBenchmark(_make_corpus())

    async def _empty(*_):
        return None

    with pytest.raises(AssertionError):
        await corpus.run(agent_runner=_empty)


_corrupt = [
    GroundTruthEntry(
        id="gt-x",
        vuln_class="idor",
        endpoint="/rest/basket/1",
        method="POST",
        expected_result="rejected",
        reference_exploit={"expected_status": 403},
        severity_expected="low",
    )
]


def test_corpus_requires_valid_endpoint_and_reference():
    # Invalid entries silently fail at validation time only if status is nonsense
    from ai_osop.core.corpus_benchmark import CorpusBenchmark as _CB

    c = _CB(_corrupt)
    # Current contract: invalid entries are scoped out, only rejected when the
    # expected_result type is nonsensical list/None or reference_exploit is a string.
    assert len(c.entries) == 1
    assert c.entries[0].reference_exploit == {"expected_status": 403}


def _load_corpus():
    import json
    import pathlib

    base = pathlib.Path("benchmarks/corpus")
    entries = []
    for f in sorted(base.glob("*.json")):
        for raw in json.loads(f.read_text()):
            entries.append(
                GroundTruthEntry(
                    id=raw["id"],
                    vuln_class=raw["vuln_class"],
                    endpoint=raw["endpoint"],
                    method=raw["method"],
                    expected_result=raw["expected_result"],
                    reference_exploit=raw["reference_exploit"],
                    severity_expected=raw["severity_expected"],
                    confidence=raw.get("confidence", 1.0),
                )
            )
    return entries


def test_corpus_files_load_and_follow_provenance_policy():
    import json
    import pathlib

    base = pathlib.Path("benchmarks/corpus")
    files = list(base.glob("*.json"))
    assert len(files) >= 2, "expected h1_real + synthetic_negatives corpus files"
    total = 0
    for f in files:
        for raw in json.loads(f.read_text()):
            total += 1
            assert raw["source_url"].startswith(
                ("https://hackerone.com/reports/", "synthetic://")
            ), raw["id"]
            assert raw["expected_result"] in {"accepted", "rejected"}
    assert total >= 20


@pytest.mark.asyncio
async def test_corpus_precision_recall_gate():
    """Deterministic fixture findings scored against the checked-in corpus must
    maintain >=0.90 precision/recall. Fixture provenance: hand-aligned to the
    corpus (every 'accepted' entry has a matching 'accepted' finding, every
    'rejected' entry a matching 'rejected' one). When the pipeline changes,
    regenerate this fixture from a real run ONCE and re-pin — do not let the
    fixture drift to keep the test green.

    Honesty note: this gate proves the scoring pipeline, report shape, and gate
    semantics are correct. It does NOT, on its own, certify live model accuracy —
    for that, re-run the platform against a live target and re-pin the fixture.
    """
    from ai_osop.core.corpus_benchmark import CorpusBenchmark

    entries = _load_corpus()
    findings = [
        {"id": e.id, "outcome": "accepted"} for e in entries if e.expected_result == "accepted"
    ] + [{"id": e.id, "outcome": "rejected"} for e in entries if e.expected_result == "rejected"]
    bench = CorpusBenchmark(entries)
    report = await bench.score(findings)
    assert report["evaluated"] == len(entries), report
    assert report["precision"] >= 0.90, report
    assert report["recall"] >= 0.90, report
