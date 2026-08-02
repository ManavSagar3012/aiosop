"""Tests for the independent-evidence confidence rubric."""

import pytest

from ai_osop.core.finding_confidence import score_finding, score_signals


def test_full_independent_evidence_scores_one_hundred():
    result = score_signals(
        {
            "tool_validation": True,
            "payload_reproduced": True,
            "evidence_stored": True,
            "ground_truth_match": True,
            "manual_replay_succeeds": True,
            "attack_path_confirmed": True,
        }
    )

    assert result["score"] == 100
    assert result["confidence"] == 1.0
    assert result["missing_signals"] == []


def test_persisted_payload_is_not_treated_as_a_reproduction():
    result = score_finding(
        {
            "validated": True,
            "tool_source": "sqlmap",
            "evidence": [{"payloads": ["category=Accessories' AND 1=1"]}],
        },
        {"ground_truth_match": True},
    )

    assert result["score"] == 50
    assert result["verified_signals"] == [
        "tool_validation",
        "evidence_stored",
        "ground_truth_match",
    ]
    assert "payload_reproduced" in result["missing_signals"]


def test_unknown_signal_is_rejected():
    with pytest.raises(ValueError, match="Unknown confidence"):
        score_signals({"tool_validation": True, "magic": True})
