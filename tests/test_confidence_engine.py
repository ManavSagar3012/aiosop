"""Confidence Engine + validation lifecycle (charter 12/17)."""
import pytest

from ai_osop.core import confidence_engine as ce
from ai_osop.core.finding_intelligence import deduplicate_findings
from ai_osop.core.models import Severity, Vulnerability, VulnClass


def _v(title, cls_sev=Severity.INFO, conf=0.5, ev=None):
    v = Vulnerability(title=title, description=title, vuln_type=VulnClass.UNKNOWN,
                      severity=cls_sev, tool_source="nuclei",
                      engagement_id="eng-ce", confidence=conf, evidence=ev or [])
    v.yield_metadata = {"detector": "nuclei", "url": "http://t.example"}
    return v


def test_unvalidated_ceiling():
    """Even rich evidence cannot exceed 0.75 without the Validation Engine."""
    s = ce.score_finding("vulnerability", evidence_count=10)
    assert s.confidence <= 0.75 and s.validation_state == ce.UNTESTED
    assert s.false_positive_probability >= 0.02


def test_fp_flags_suppress_applicability():
    clean = ce.score_finding("weakness", evidence_count=2)
    flagged = ce.score_finding("weakness", evidence_count=2, fp_flags=1)
    assert flagged.applicability_score < clean.applicability_score


def test_validation_dominates_and_is_terminal():
    v = ce.score_finding("vulnerability", validated=True)
    r = ce.score_finding("vulnerability", rejected=True)
    assert v.validation_state == ce.VALIDATED and v.confidence >= 0.9
    assert r.validation_state == ce.REJECTED and r.confidence <= 0.05
    with pytest.raises(ValueError):
        ce.assert_transition(ce.VALIDATED, ce.UNTESTED)
    assert ce.can_transition(ce.REJECTED, ce.UNTESTED)  # new-observation revival


def test_fit_output_carries_scores():
    raw = [_v("Missing Security Headers", ev=[{"a": 1}]),
           _v("Missing Security Headers", ev=[{"b": 2}])]
    canonical, _ = deduplicate_findings(raw)
    meta = canonical[0].yield_metadata["confidence_scores"]
    assert set(meta) >= {"confidence", "evidence_score",
                         "applicability_score", "false_positive_probability",
                         "validation_state"}
    # weakness class enters as APPLICABLE (its applicability pre-check ran)
    assert canonical[0].validation_state == ce.APPLICABLE


def test_report_sections_truthful_grouping():
    """Charter 21: one finding per section; headline counts only CONFIRMED."""
    from ai_osop.core.finding_intelligence import build_report_sections

    def mk(title, fclass, state):
        v = _v(title)
        v.yield_metadata = {"finding_class": fclass}
        v.validation_state = state
        return v

    fs = [
        mk("SQLi reproduced", "vulnerability", ce.VALIDATED),
        mk("SSRF hypothesis", "vulnerability", ce.UNTESTED),
        mk("Missing headers", "weakness", ce.APPLICABLE),
        mk("AWS detected", "observation", ce.UNTESTED),
        mk("WAF detection FP", "observation", ce.REJECTED),
    ]
    out = build_report_sections(fs)
    c = out["counts"]
    assert c["confirmed_vulnerabilities"] == 1
    assert c["candidate_vulnerabilities"] == 1
    assert c["security_weaknesses"] == 1
    assert c["informational"] == 1
    assert c["rejected"] == 1
    assert c["headline_vulnerability_count"] == 1  # NOT inflated by noise
