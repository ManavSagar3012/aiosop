"""Benchmark CI gate (charter section 25): regression guard.

Every change to intelligence layers must maintain minimum scores against a
fixed ground-truth fixture. If any metric drops below threshold, this test
FAILS — preventing silent capability regressions from reaching production.
"""

import pytest
from types import SimpleNamespace

from ai_osop.core import confidence_engine as ce
from ai_osop.core.benchmark import GroundTruthCase, score_engagement


def _f(title, fclass, state, url="https://lab.example", conf=0.9):
    return SimpleNamespace(
        title=title, id=f"v-{abs(hash(title)) % 10**6}",
        severity=SimpleNamespace(value="high"),
        confidence=conf, evidence=[{"x": 1}], validation_state=state,
        yield_metadata={"finding_class": fclass, "confidence_scores":
                        {"confidence": conf}, "url": url})


# Fixed ground truth for regression testing
LAB_GT = [
    GroundTruthCase(category="sql injection", surface="lab.example"),
    GroundTruthCase(category="xss", surface="lab.example"),
    GroundTruthCase(category="idor", surface="lab.example"),
    GroundTruthCase(category="waf detection", surface="lab.example",
                    should_detect=False),
]

EXPECTED_CHAINS = ["recon_guided_injection", "identity_object_access"]

MINIMUM_SCORES = {
    "discovery_recall": 0.60,
    "validated_precision": 0.75,
    "false_positive_rate": 0.40,   # must stay BELOW
    "rejection_quality": 0.90,
}


def _ideal_findings():
    return [
        _f("SQL Injection on /login", "vulnerability", ce.VALIDATED),
        _f("Reflected XSS on search", "vulnerability", ce.VALIDATED),
        _f("IDOR on /api/order/123", "vulnerability", ce.VALIDATED),
        SimpleNamespace(**{**_f("WAF Detection", "observation", ce.REJECTED).__dict__,
                           "validation_state": ce.REJECTED}),
    ]


class TestBenchmarkCIGate:
    def test_ideal_engagement_meets_all_thresholds(self):
        r = score_engagement(_ideal_findings(), [], LAB_GT,
                             expected_chains=EXPECTED_CHAINS)
        assert r["discovery_recall"] >= MINIMUM_SCORES["discovery_recall"]
        assert r["validated_precision"] >= MINIMUM_SCORES["validated_precision"]
        assert r["false_positive_rate"] <= MINIMUM_SCORES["false_positive_rate"]
        assert r["rejection_quality"] >= MINIMUM_SCORES["rejection_quality"]
        assert r["overall_score"] >= 0.70

    def test_regression_detection_works(self):
        """Simulate losing XSS detection -> recall drops below gate."""
        fs = [v for v in _ideal_findings() if "XSS" not in v.title]
        r = score_engagement(fs, [], LAB_GT)
        assert r["discovery_recall"] < 1.0  # regression detected

    def test_fp_leak_detected(self):
        """A non-rejected observation counts as FP -> rate increases."""
        fs = _ideal_findings() + [
            _f("Random noise finding", "weakness", ce.APPLICABLE)]
        r = score_engagement(fs, [], LAB_GT)
        assert r["false_positive_rate"] > 0.0
