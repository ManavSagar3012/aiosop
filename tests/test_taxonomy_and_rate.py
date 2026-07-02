"""Focused, hermetic unit tests for the calibration taxonomy and rate math.

Covers:
  * ai_osop.core.taxonomy.category_for_finding_type
  * ai_osop.core.calibration_engine.ConfidenceCalibrationEngine.calibrate_from_rate

Both units are pure/sync. The calibration engine is constructed with a
MagicMock() session_memory so no DB/Redis connection is ever established.
"""

from unittest.mock import MagicMock

import pytest

from ai_osop.core.taxonomy import (
    HYPOTHESIS_CATEGORIES,
    _FINDING_TYPE_TO_CATEGORY,
    category_for_finding_type,
)
from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine


# ---------------------------------------------------------------------------
# taxonomy.category_for_finding_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "finding_type,expected",
    [
        ("idor", "authz"),
        ("xss", "client_side"),
        ("ssrf", "ssrf_redirect"),
        ("graphql", "graphql"),
        ("jwt", "session"),
        ("race_condition", "workflow"),
        ("s3", "cloud"),
    ],
)
def test_known_mappings(finding_type, expected):
    assert category_for_finding_type(finding_type) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("IDOR", "authz"),
        ("Idor", "authz"),
        ("XSS", "client_side"),
        ("SSRF", "ssrf_redirect"),
        ("GraphQL", "graphql"),
        ("JWT", "session"),
        ("RACE_CONDITION", "workflow"),
        ("S3", "cloud"),
    ],
)
def test_case_insensitivity(raw, expected):
    assert category_for_finding_type(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("  idor  ", "authz"),
        ("\txss\n", "client_side"),
        (" SSRF ", "ssrf_redirect"),
        ("  Race_Condition  ", "workflow"),
    ],
)
def test_whitespace_trimming(raw, expected):
    assert category_for_finding_type(raw) == expected


@pytest.mark.parametrize("empty", ["", None])
def test_empty_or_none_returns_unknown(empty):
    assert category_for_finding_type(empty) == "unknown"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("sqli", "sqli"),
        ("rce", "rce"),
        ("SQLi", "sqli"),
        ("  RCE  ", "rce"),
        ("some_novel_type", "some_novel_type"),
    ],
)
def test_unmapped_pass_through_lowercased(raw, expected):
    """Unmapped types fall through to their lowercased+trimmed value unchanged."""
    assert category_for_finding_type(raw) == expected


def test_every_mapped_value_is_a_hypothesis_category():
    """Every VALUE the map produces must be a member of HYPOTHESIS_CATEGORIES.

    The map is the single reconciliation point between concrete finding types
    and the hypothesis-category vocabulary. If a value ever drifts outside
    HYPOTHESIS_CATEGORIES, calibration lookups keyed on that category silently
    never match recorded outcomes.
    """
    for finding_type, category in _FINDING_TYPE_TO_CATEGORY.items():
        assert category in HYPOTHESIS_CATEGORIES, (
            f"mapping {finding_type!r} -> {category!r} is not a hypothesis category"
        )


def test_known_mappings_land_in_hypothesis_categories():
    """The public function's output for mapped types is a hypothesis category."""
    for finding_type in _FINDING_TYPE_TO_CATEGORY:
        assert category_for_finding_type(finding_type) in HYPOTHESIS_CATEGORIES


# ---------------------------------------------------------------------------
# calibration_engine.ConfidenceCalibrationEngine.calibrate_from_rate
# ---------------------------------------------------------------------------


def _engine(skill_engine=None):
    """Construct the engine with a mock session_memory (never connects)."""
    return ConfidenceCalibrationEngine(session_memory=MagicMock(), skill_engine=skill_engine)


def test_neutral_rate_returns_base_confidence():
    """rate == 0.5 is the neutral sentinel: base confidence passes through (clamped)."""
    engine = _engine()
    assert engine.calibrate_from_rate(0.42, 0.5) == pytest.approx(0.42)


@pytest.mark.parametrize("base", [0.05, 0.1, 0.5, 0.99, 1.5])
def test_neutral_rate_still_clamped(base):
    """Even at the neutral sentinel the result stays within [0.1, 0.99]."""
    result = _engine().calibrate_from_rate(base, 0.5)
    assert 0.1 <= result <= 0.99


def test_high_rate_known_value():
    """rate=1.0, base=0.4 -> (1.0*0.6)+(0.4*0.4) = 0.76."""
    engine = _engine()
    assert engine.calibrate_from_rate(0.4, 1.0) == pytest.approx(0.76)


def test_zero_rate_drives_down_and_clamps_low():
    """rate=0.0 pulls confidence down; a small base clamps to the 0.1 floor."""
    engine = _engine()
    # (0.0*0.6) + (0.2*0.4) = 0.08 -> clamped up to 0.1
    assert engine.calibrate_from_rate(0.2, 0.0) == pytest.approx(0.1)
    # (0.0*0.6) + (0.05*0.4) = 0.02 -> clamped up to 0.1
    assert engine.calibrate_from_rate(0.05, 0.0) == pytest.approx(0.1)


def test_zero_rate_reduces_confidence_below_base():
    """With a moderate base the zero-rate result is below base but above floor."""
    engine = _engine()
    # (0.0*0.6) + (0.8*0.4) = 0.32
    result = engine.calibrate_from_rate(0.8, 0.0)
    assert result == pytest.approx(0.32)
    assert result < 0.8


@pytest.mark.parametrize("base", [0.0, 0.05, 0.1, 0.3, 0.5, 0.7, 0.99, 1.0, 1.5])
@pytest.mark.parametrize("rate", [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0])
def test_result_always_within_bounds(base, rate):
    """Result is always clamped to [0.1, 0.99] across a grid of inputs."""
    result = _engine().calibrate_from_rate(base, rate)
    assert 0.1 <= result <= 0.99


def test_skill_bonus_path_boosts_confidence():
    """A stub skill_engine with effectiveness 0.9 adds a (0.9-0.5)*0.5 = 0.2 bonus."""
    skill_engine = MagicMock()
    skill_engine.get_skill_effectiveness.return_value = 0.9
    engine = _engine(skill_engine=skill_engine)

    # Neutral rate: base + bonus. base=0.4, bonus=0.2 -> 0.6
    result = engine.calibrate_from_rate(0.4, 0.5, used_skill_id="skill-123")
    assert result == pytest.approx(0.6)
    skill_engine.get_skill_effectiveness.assert_called_once_with("skill-123")


def test_skill_bonus_on_history_path():
    """Skill bonus is additive on the Bayesian-update branch as well."""
    skill_engine = MagicMock()
    skill_engine.get_skill_effectiveness.return_value = 0.9
    engine = _engine(skill_engine=skill_engine)

    # rate=1.0, base=0.4 -> 0.76; + 0.2 bonus = 0.96
    result = engine.calibrate_from_rate(0.4, 1.0, used_skill_id="skill-xyz")
    assert result == pytest.approx(0.96)


def test_skill_bonus_ignored_without_skill_id():
    """No used_skill_id means the skill engine is never consulted."""
    skill_engine = MagicMock()
    skill_engine.get_skill_effectiveness.return_value = 0.9
    engine = _engine(skill_engine=skill_engine)

    result = engine.calibrate_from_rate(0.4, 1.0, used_skill_id=None)
    assert result == pytest.approx(0.76)
    skill_engine.get_skill_effectiveness.assert_not_called()


def test_low_effectiveness_grants_no_bonus():
    """Effectiveness <= 0.5 yields no skill bonus."""
    skill_engine = MagicMock()
    skill_engine.get_skill_effectiveness.return_value = 0.5
    engine = _engine(skill_engine=skill_engine)

    result = engine.calibrate_from_rate(0.4, 1.0, used_skill_id="skill-weak")
    assert result == pytest.approx(0.76)
