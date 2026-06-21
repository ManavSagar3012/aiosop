"""Tests for the submittability triage engine (core/triage.py)."""

from ai_osop.core.triage import rank_findings, score_finding


def _finding(**kw):
    base = {
        "id": "diff-x",
        "category": "horizontal_pe",
        "resource_id": "/api/v2/widget/42",
        "test_identity_id": "user_b",
        "expected_result": "403 Forbidden",
        "observed_result": "200 OK",
        "confidence": 0.9,
        "evidence_diff": {"body": "differs"},
    }
    base.update(kw)
    return base


def test_clean_authz_break_scores_high():
    r = score_finding(_finding(category="vertical_pe"))
    assert r.score >= 70
    assert r.tier == "submit_now"
    assert r.severity in ("high", "critical")


def test_crown_jewel_outranks_generic_idor():
    vertical = score_finding(_finding(category="vertical_pe", resource_id="/admin/settings"))
    horizontal = score_finding(_finding(category="horizontal_pe", resource_id="/api/v1/user/1"))
    assert vertical.score > horizontal.score


def test_low_confidence_drops_score():
    high = score_finding(_finding(confidence=0.95))
    low = score_finding(_finding(confidence=0.2))
    assert high.score > low.score


def test_ambiguous_evidence_scores_below_clean_break():
    clean = score_finding(_finding(expected_result="403 Forbidden", observed_result="200 OK"))
    ambiguous = score_finding(
        _finding(expected_result="200 OK", observed_result="200 OK", evidence_diff={})
    )
    assert clean.score > ambiguous.score


def test_duplicate_risk_penalizes_anonymous_common_endpoint():
    rare = score_finding(
        _finding(category="tenant_escape", test_identity_id="user_b", resource_id="/org/9/ledger")
    )
    duped = score_finding(
        _finding(
            category="horizontal_pe", test_identity_id="anonymous", resource_id="/api/v1/user/1"
        )
    )
    assert duped.duplicate_risk > rare.duplicate_risk
    assert rare.score > duped.score


def test_noise_tier_for_weak_finding():
    r = score_finding(
        _finding(
            category="workflow_bypass",
            confidence=0.15,
            expected_result="200 OK",
            observed_result="200 OK",
            evidence_diff={},
        )
    )
    assert r.tier in ("noise", "likely_duplicate")
    assert r.score < 45


def test_rank_findings_orders_best_first():
    findings = [
        _finding(
            id="weak",
            category="horizontal_pe",
            confidence=0.3,
            expected_result="200 OK",
            observed_result="200 OK",
            evidence_diff={},
        ),
        _finding(
            id="strong",
            category="vertical_pe",
            confidence=0.95,
            resource_id="/admin/users",
            test_identity_id="user_b",
        ),
        _finding(id="mid", category="horizontal_pe", confidence=0.7),
    ]
    ranked = rank_findings(findings)
    assert [f["id"] for f in ranked] == ["strong", "mid", "weak"]
    assert all("triage" in f for f in ranked)
    assert ranked[0]["triage"]["tier"] == "submit_now"


def test_score_is_deterministic():
    f = _finding(category="vertical_pe")
    assert score_finding(f).score == score_finding(f).score


def test_bounty_band_present_and_consistent_with_severity():
    r = score_finding(_finding(category="vertical_pe"))
    assert r.bounty_band
    if r.severity == "critical":
        assert "10k" in r.bounty_band


def test_score_bounded_0_100():
    for cat in ("vertical_pe", "tenant_escape", "horizontal_pe", "workflow_bypass", "unknown"):
        for conf in (0.0, 0.5, 1.0):
            r = score_finding(_finding(category=cat, confidence=conf))
            assert 0.0 <= r.score <= 100.0
