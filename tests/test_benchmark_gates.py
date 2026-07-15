"""
tests/test_benchmark_gates.py -- CI gates for the Juice Shop benchmark.

These tests use saved result files in benchmarks/juiceshop/results/ and
never run the live benchmark (which requires Juice Shop running). CI on a
fresh checkout skips gracefully if no result files exist.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Add repo root to sys.path so we can import compare_baseline without installing.
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "benchmarks"))

from compare_baseline import compare  # noqa: E402

RESULTS_DIR = REPO / "benchmarks" / "juiceshop" / "results"


def _all_results() -> list[Path]:
    """Return result JSON files sorted oldest-first."""
    if not RESULTS_DIR.exists():
        return []
    return sorted(RESULTS_DIR.glob("bench-*.json"))


def _latest() -> dict | None:
    files = _all_results()
    if not files:
        return None
    return json.loads(files[-1].read_text())


def _two_most_recent() -> tuple[dict, dict] | None:
    files = _all_results()
    if len(files) < 2:
        return None
    a = json.loads(files[-2].read_text())
    b = json.loads(files[-1].read_text())
    # inject _path for compare() compat
    a["_path"] = str(files[-2])
    b["_path"] = str(files[-1])
    return a, b


# ---------------------------------------------------------------------------
# Gate tests
# ---------------------------------------------------------------------------

def test_latest_bench_meets_recall_gate():
    result = _latest()
    if result is None:
        pytest.skip("No benchmark result files found -- run bench.py first")
    recall = result["scored_scoreboard"]["recall"]
    if recall is None:
        pytest.skip("recall is None (insufficient scored checks)")
    assert recall >= 0.8, f"Recall {recall:.3f} < 0.80 minimum acceptable gate"


def test_latest_bench_meets_precision_gate():
    result = _latest()
    if result is None:
        pytest.skip("No benchmark result files found")
    precision = result["scored_scoreboard"]["precision"]
    # None = no TPs or FPs scored yet -- acceptable on a fresh bench
    if precision is None:
        return
    assert precision >= 0.8, f"Precision {precision:.3f} < 0.80 minimum acceptable gate"


def test_latest_bench_zero_false_positives():
    result = _latest()
    if result is None:
        pytest.skip("No benchmark result files found")
    fp = result["scored_scoreboard"]["false_positive"]
    assert fp == 0, f"false_positive count = {fp}, expected 0"


def test_latest_bench_stable():
    result = _latest()
    if result is None:
        pytest.skip("No benchmark result files found")
    # Re-derive stability from per_check data so we are immune to the old
    # bench.py bug that counted unscored (informational) TIMEOUT checks against
    # stability. The gate only cares about *scored* checks timing out.
    per_check = result.get("per_check", {})
    scored_timeouts = [
        cid for cid, v in per_check.items()
        if v.get("scored", True) and v.get("status") == "TIMEOUT"
    ]
    assert scored_timeouts == [], (
        f"Scored benchmark checks timed out: {scored_timeouts}. "
        "Investigate infra or increase --timeout when running bench.py."
    )


def test_regression_vs_previous():
    pair = _two_most_recent()
    if pair is None:
        pytest.skip("Fewer than 2 benchmark result files -- need at least 2 runs to compare")
    baseline, current = pair
    report = compare(baseline, current)
    assert report["passed"] is True, (
        "Regression vs previous run detected!\n"
        + "\n".join(
            f"  FAIL gate={k}: baseline={v.get('baseline')} current={v.get('current')}"
            for k, v in report["gates"].items()
            if not v["passed"]
        )
    )


def test_generalization_gate():
    """Minimum ground-truth coverage: need >=5 scored entries for recall to be meaningful."""
    result = _latest()
    if result is None:
        pytest.skip("No benchmark result files found")
    sb = result["scored_scoreboard"]
    total_scored = sb["true_positive"] + sb["false_negative"]
    if total_scored == 0:
        pytest.skip("Zero scored positive entries -- no ground truth coverage to check")
    assert total_scored >= 5, (
        f"Only {total_scored} ground-truth positive entries (TP+FN); "
        f"need >= 5 for a meaningful recall score"
    )
