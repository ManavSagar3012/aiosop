"""Tests for benchmarks/score_engagement.py — the platform-level scorer.

These lock the *honest ground-truth* semantics that make the scorecard
trustworthy:

  * recall is measured over manifest positives (a missed entry => false neg),
  * precision is measured ONLY against explicit negative controls, and is None
    when none are defined (never a fake 1.0),
  * findings unmapped to any manifest entry are "extras" for triage, NOT
    false positives (an incomplete manifest must not punish real discovery),
  * simulated/mock findings are dropped before scoring and can never be a TP,
  * type aliasing (jwt<->jwt_abuse, idor<->broken_access_control) works,
  * endpoint matching tolerates full URLs vs paths.
"""

from __future__ import annotations

import importlib.util
import json

# Import the scorer module by path — benchmarks/ is not a package.
import sys as _sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "score_engagement",
    Path(__file__).resolve().parents[1] / "benchmarks" / "score_engagement.py",
)
score_engagement = importlib.util.module_from_spec(_SPEC)
# Register before exec so dataclass forward-ref resolution (which looks the
# module up in sys.modules by __module__) works for GroundTruthEntry etc.
_sys.modules["score_engagement"] = score_engagement
_SPEC.loader.exec_module(score_engagement)

score_findings = score_engagement.score_findings
GroundTruthEntry = score_engagement.GroundTruthEntry
load_manifest = score_engagement.load_manifest


def _gt(id, type, endpoint="", expected=True, expected_evidence=None):
    return GroundTruthEntry(
        id=id,
        type=type,
        endpoint=endpoint,
        expected=expected,
        expected_evidence=expected_evidence or [],
    )


def _finding(id, vuln_type, endpoint="", confidence=0.9, evidence=None, tool_source="sqlmap"):
    return {
        "id": id,
        "vuln_type": vuln_type,
        "endpoint_id": endpoint,
        "confidence": confidence,
        "evidence": evidence if evidence is not None else [{"type": "request"}],
        "tool_source": tool_source,
        "title": f"{vuln_type} finding",
    }


# --------------------------------------------------------------------------- #
# Recall
# --------------------------------------------------------------------------- #
def test_perfect_recall_when_all_positives_matched():
    manifest = [
        _gt("JS-001", "SQLi", "/rest/user/login"),
        _gt("JS-004", "JWT", "/rest/user/login"),
    ]
    findings = [
        _finding("f1", "sqli", "/rest/user/login"),
        _finding("f2", "jwt_abuse", "/rest/user/login"),
    ]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["true_positives"] == 2
    assert s["false_negatives"] == 0
    assert s["recall"] == 1.0
    assert s["coverage"] == 1.0


def test_missing_positive_is_false_negative():
    manifest = [
        _gt("JS-001", "SQLi", "/rest/user/login"),
        _gt("JS-002", "SQLi", "/rest/products/search"),
    ]
    findings = [_finding("f1", "sqli", "/rest/user/login")]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["true_positives"] == 1
    assert s["false_negatives"] == 1
    assert s["recall"] == 0.5
    assert card["false_negatives"][0]["gt_id"] == "JS-002"


# --------------------------------------------------------------------------- #
# Precision & the honest-ground-truth policy
# --------------------------------------------------------------------------- #
def test_precision_is_none_without_negative_controls():
    """No negative controls => precision is undefined, not a fake 1.0."""
    manifest = [_gt("JS-001", "SQLi", "/rest/user/login")]
    findings = [_finding("f1", "sqli", "/rest/user/login")]
    card = score_findings(findings, manifest)
    assert card["summary"]["precision"] is None


def test_extra_finding_is_triage_not_false_positive():
    """A real finding not in the manifest must NOT count against precision."""
    manifest = [_gt("JS-001", "SQLi", "/rest/user/login")]
    findings = [
        _finding("f1", "sqli", "/rest/user/login"),
        _finding("f2", "xss", "/rest/products/search"),  # real, but unlisted
    ]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["false_positives"] == 0
    assert s["extras_for_triage"] == 1
    assert card["extras"][0]["finding_id"] == "f2"
    assert s["recall"] == 1.0  # the manifest positive was still found


def test_negative_control_match_is_false_positive():
    manifest = [
        _gt("JS-001", "SQLi", "/rest/user/login"),
        _gt("NEG-1", "SQLi", "/rest/products/reviews", expected=False),
    ]
    findings = [
        _finding("f1", "sqli", "/rest/user/login"),
        _finding("f2", "sqli", "/rest/products/reviews"),  # hits negative control
    ]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["true_positives"] == 1
    assert s["false_positives"] == 1
    assert s["precision"] == 0.5
    assert card["false_positives"][0]["gt_id"] == "NEG-1"


# --------------------------------------------------------------------------- #
# Simulated findings
# --------------------------------------------------------------------------- #
def test_simulated_finding_dropped_and_never_a_true_positive():
    manifest = [_gt("JS-001", "SQLi", "/rest/user/login")]
    findings = [
        _finding("f1", "sqli", "/rest/user/login", tool_source="mock-sqlmap"),
    ]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["findings_simulated_dropped"] == 1
    assert s["true_positives"] == 0
    assert s["false_negatives"] == 1  # the real one is now missing
    assert s["recall"] == 0.0


def test_simulated_by_evidence_provenance_dropped():
    manifest = [_gt("JS-001", "SQLi", "/rest/user/login")]
    findings = [
        _finding(
            "f1",
            "sqli",
            "/rest/user/login",
            evidence=[{"type": "request", "provenance": "simulated"}],
        )
    ]
    card = score_findings(findings, manifest)
    assert card["summary"]["findings_simulated_dropped"] == 1
    assert card["summary"]["true_positives"] == 0


# --------------------------------------------------------------------------- #
# Type aliasing & endpoint matching
# --------------------------------------------------------------------------- #
def test_idor_matches_broken_access_control_alias():
    manifest = [_gt("JS-003", "IDOR", "/rest/basket/")]
    findings = [_finding("f1", "broken_access_control", "/rest/basket/1")]
    card = score_findings(findings, manifest)
    assert card["summary"]["true_positives"] == 1


def test_endpoint_full_url_matches_manifest_path():
    manifest = [_gt("JS-002", "SQLi", "/rest/products/search")]
    findings = [_finding("f1", "sqli", "http://localhost:3000/rest/products/search?q=1")]
    card = score_findings(findings, manifest)
    assert card["summary"]["true_positives"] == 1


def test_wrong_type_does_not_match():
    manifest = [_gt("JS-001", "SQLi", "/rest/user/login")]
    findings = [_finding("f1", "xss", "/rest/user/login")]
    card = score_findings(findings, manifest)
    assert card["summary"]["true_positives"] == 0
    assert card["summary"]["false_negatives"] == 1


# --------------------------------------------------------------------------- #
# Evidence completeness
# --------------------------------------------------------------------------- #
def test_evidence_completeness_scored():
    manifest = [
        _gt(
            "JS-001",
            "SQLi",
            "/rest/user/login",
            expected_evidence=["request", "response", "payload"],
        )
    ]
    # finding only carries request+response, missing payload
    findings = [
        _finding(
            "f1", "sqli", "/rest/user/login", evidence=[{"type": "request"}, {"type": "response"}]
        )
    ]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["true_positives"] == 1
    assert s["evidence_completeness"] == 0.0
    assert "payload" in card["matched"][0]["missing_evidence"]


def test_evidence_complete_when_all_present():
    manifest = [
        _gt("JS-001", "SQLi", "/rest/user/login", expected_evidence=["request", "response"])
    ]
    findings = [
        _finding(
            "f1", "sqli", "/rest/user/login", evidence=[{"type": "request"}, {"type": "response"}]
        )
    ]
    card = score_findings(findings, manifest)
    assert card["summary"]["evidence_completeness"] == 1.0


# --------------------------------------------------------------------------- #
# Duplicate findings / greedy matching
# --------------------------------------------------------------------------- #
def test_two_findings_one_positive_best_confidence_wins_rest_are_extras():
    manifest = [_gt("JS-001", "SQLi", "/rest/user/login")]
    findings = [
        _finding("weak", "sqli", "/rest/user/login", confidence=0.4),
        _finding("strong", "sqli", "/rest/user/login", confidence=0.95),
    ]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["true_positives"] == 1
    assert card["matched"][0]["finding_id"] == "strong"
    # the weaker duplicate is an extra (same endpoint+type, dedup should ideally
    # have collapsed it upstream, but the scorer must not double-count it as TP)
    assert s["extras_for_triage"] == 1


# --------------------------------------------------------------------------- #
# Real manifest loads and scores against the shipped ground truth
# --------------------------------------------------------------------------- #
def test_real_juice_shop_manifest_loads_and_scores():
    manifest_path = (
        Path(__file__).resolve().parents[1] / "benchmarks" / "ground_truth" / "juice_shop.yaml"
    )
    manifest = load_manifest(manifest_path)
    assert len(manifest) >= 5
    # empty findings -> full recall miss, no crash
    card = score_findings([], manifest)
    s = card["summary"]
    assert s["true_positives"] == 0
    assert s["recall"] == 0.0
    assert s["false_negatives"] == len([g for g in manifest if g.expected])
    assert s["precision"] is None  # no negative controls in shipped manifest


def test_empty_manifest_yields_none_metrics_not_crash():
    card = score_findings([_finding("f1", "sqli", "/x")], [])
    s = card["summary"]
    assert s["recall"] is None
    assert s["coverage"] is None
    assert s["extras_for_triage"] == 1


# --------------------------------------------------------------------------- #
# Regression: persisted findings store `evidence` as a JSON STRING and carry NO
# top-level endpoint field — the real Vulnerability export shape. Before the fix
# the scorer read a non-existent top-level endpoint (=> "" => type-only match,
# mis-attributing JS-002's SQLi to JS-001) and iterated the evidence string as
# characters (=> evidence_kinds always []). These lock both behaviours.
# --------------------------------------------------------------------------- #
_SQLMAP_EV = [
    {
        "type": "sqlmap_injection",
        "provenance": "sqlmap",
        "url": "http://localhost:3000/rest/products/search?q=test",
        "parameter": "q (GET)",
        "dbms": "SQLite",
        "techniques": ["boolean-based blind", "time-based blind"],
        "payloads": ["q=test%' AND 9942=9942 AND 'XBfi%'='XBfi"],
    }
]


def _persisted_finding(id, vuln_type, evidence_dicts, confidence=0.9, tool_source="sqlmap"):
    """Finding shaped like the real JSON export: evidence is a JSON-encoded
    string and there is NO top-level endpoint/url field."""
    return {
        "id": id,
        "vuln_type": vuln_type,
        "confidence": confidence,
        "evidence": json.dumps(evidence_dicts),
        "tool_source": tool_source,
        "title": f"{vuln_type} finding",
    }


def test_stringified_evidence_recovers_endpoint_for_correct_attribution():
    """The products/search SQLi must be credited to JS-002 — not greedily
    claimed by the first SQLi in manifest order (JS-001/login)."""
    manifest = [
        _gt("JS-001", "SQLi", "/rest/user/login"),
        _gt("JS-002", "SQLi", "/rest/products/search"),
    ]
    findings = [_persisted_finding("vuln-sqli", "sqli", _SQLMAP_EV, confidence=0.98)]
    card = score_findings(findings, manifest)
    s = card["summary"]
    assert s["true_positives"] == 1
    assert card["matched"][0]["gt_id"] == "JS-002"  # correct attribution
    assert card["matched"][0]["endpoint"]  # endpoint recovered from evidence, not ""
    assert card["false_negatives"][0]["gt_id"] == "JS-001"  # login SQLi genuinely missed


def test_stringified_evidence_registers_evidence_kinds():
    """evidence_completeness must reflect real artifacts: url->request and
    payloads->payload are present; response is honestly absent."""
    manifest = [
        _gt(
            "JS-002",
            "SQLi",
            "/rest/products/search",
            expected_evidence=["request", "response", "payload"],
        )
    ]
    findings = [_persisted_finding("vuln-sqli", "sqli", _SQLMAP_EV, confidence=0.98)]
    card = score_findings(findings, manifest)
    m = card["matched"][0]
    assert "request" in m["evidence_kinds"]  # aliased from url
    assert "payload" in m["evidence_kinds"]  # aliased from payloads
    assert "response" in m["missing_evidence"]  # genuinely not captured -> honest gap
    assert m["evidence_complete"] is False


def test_stringified_simulated_provenance_still_dropped():
    """The honest-stub guard must see through the stringified evidence too."""
    manifest = [_gt("JS-002", "SQLi", "/rest/products/search")]
    sim_ev = [
        {
            "type": "sqlmap_injection",
            "provenance": "simulated",
            "url": "http://localhost:3000/rest/products/search?q=test",
        }
    ]
    findings = [_persisted_finding("vuln-sim", "sqli", sim_ev)]
    card = score_findings(findings, manifest)
    assert card["summary"]["findings_simulated_dropped"] == 1
    assert card["summary"]["true_positives"] == 0
