"""Benchmark Lab: objective scoring against planted ground truth (charter 25)."""
from types import SimpleNamespace

import pytest

from ai_osop.core import confidence_engine as ce
from ai_osop.core.benchmark import GroundTruthCase, score_engagement


def _f(title, fclass="weakness", state=ce.UNTESTED, url="https://t.example",
       conf=0.7):
    return SimpleNamespace(
        title=title, id=f"v-{abs(hash(title)) % 10**6}", severity=SimpleNamespace(value="medium"),
        confidence=conf, evidence=[{"x": 1}], validation_state=state,
        vuln_type=title.split()[0].lower(),
        yield_metadata={"finding_class": fclass,
                        "confidence_scores": {"confidence": conf},
                        "url": url})


def _chain(name):
    return SimpleNamespace(name=name)


GT = [
    GroundTruthCase(category="sql injection", surface="t.example"),
    GroundTruthCase(category="xss", surface="t.example"),
    GroundTruthCase(category="waf detection", surface="t.example",
                    should_detect=False),  # detector bait
]


def test_perfect_engagement_scores_full():
    fs = [
        _f("SQL Injection login", "vulnerability", ce.VALIDATED),
        _f("Reflected XSS found", "vulnerability", ce.VALIDATED),
        # bait correctly REJECTED -> excluded from FP denominator
        SimpleNamespace(**{**_f("WAF Detection", "observation").__dict__,
                           "validation_state": ce.REJECTED}),
    ]
    r = score_engagement(fs, [], GT, expected_chains=["recon_guided_injection"])
    assert r["discovery_recall"] == 1.0
    assert r["validated_precision"] == 1.0
    assert r["false_positive_rate"] == 0.0
    assert r["rejection_quality"] == 1.0
    assert r["chain_discovery_rate"] == 0.0  # chain not supplied
    assert 0 <= r["overall_score"] <= 1


def test_missed_case_lowers_recall():
    fs = [_f("SQL Injection login", "vulnerability", ce.VALIDATED)]
    r = score_engagement(fs, [], GT)
    assert r["discovery_recall"] == 0.5
    assert "gt-" in r["missed_cases"][0] or len(r["missed_cases"]) == 1


def test_unvalidated_noise_counts_as_fp():
    fs = [
        _f("SQL Injection login", "vulnerability", ce.VALIDATED),
        _f("XSS somewhere", "vulnerability", ce.UNTESTED),
        _f("Random tech noise", "weakness"),   # matches no planted case
    ]
    r = score_engagement(fs, [], GT)
    # xss IS a planted case (untested but matching) -> only noise is FP
    assert r["false_positive_rate"] > 0.0
    assert r["discovery_recall"] == 1.0  # both planted matched by presence


def test_observation_never_satisfies_planted_case():
    fs = [_f("SQLi-like WAF signature", "observation")]  # wrong class entirely
    r = score_engagement(fs, [], GT)
    assert r["discovery_recall"] < 1.0


def test_chain_discovery_rate():
    chains = [_chain("recon_guided_injection"), _chain("identity_object_access")]
    r = score_engagement([], chains, GT,
                         expected_chains=["recon_guided_injection"])
    assert r["chain_discovery_rate"] == 1.0


def test_load_lab_spec_validates():
    from ai_osop.core.benchmark import load_lab_spec
    import json, tempfile

    spec = {"lab_name": "L", "target": "http://x", "ground_truth": [
        {"category": "sqli", "surface": "x"}]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(spec, fh)
        p = fh.name
    lab = load_lab_spec(p)
    assert lab["lab_name"] == "L" and len(lab["cases"]) == 1
    assert lab["cases"][0].should_detect is True
