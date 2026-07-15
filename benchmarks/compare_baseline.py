"""
compare_baseline.py -- regression comparator for bench.py JSON outputs.

Usage:
    python benchmarks/compare_baseline.py --baseline old.json --current new.json
    python benchmarks/compare_baseline.py --baseline a.json --current b.json --output report.json

Exit c 0=passed, 1=gate failed, 2=IO/usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def compare(baseline: dict, current: dict, recall_threshold: float = 0.02) -> dict:
    """Pure comparison function -- no IO. Can be imported and called from tests."""
    bsb = baseline["scored_scoreboard"]
    csb = current["scored_scoreboard"]
    gates: dict = {}

    # Recall gate
    if bsb["recall"] is not None and csb["recall"] is not None:
        regressed = csb["recall"] < bsb["recall"] - recall_threshold
        gates["recall"] = {
            "passed": not regressed,
            "baseline": bsb["recall"],
            "current": csb["recall"],
            "threshold": recall_threshold,
            "delta": round(csb["recall"] - bsb["recall"], 4),
        }
    else:
        gates["recall"] = {"passed": True, "note": "insufficient data (None)"}

    # Precision gate
    if bsb["precision"] is not None and csb["precision"] is not None:
        regressed = csb["precision"] < bsb["precision"] - recall_threshold
        gates["precision"] = {
            "passed": not regressed,
            "baseline": bsb["precision"],
            "current": csb["precision"],
            "threshold": recall_threshold,
            "delta": round(csb["precision"] - bsb["precision"], 4),
        }
    else:
        gates["precision"] = {"passed": True, "note": "insufficient data (None)"}

    # False-positive gate
    fp_regressed = csb["false_positive"] > bsb["false_positive"]
    gates["false_positive"] = {
        "passed": not fp_regressed,
        "baseline": bsb["false_positive"],
        "current": csb["false_positive"],
    }

    # Stability gate -- WARNING only (infra flakiness can cause instability)
    b_stable = baseline.get("stability", {}).get("stable", True)
    c_stable = current.get("stability", {}).get("stable", True)
    stability_warn = b_stable and not c_stable
    gates["stability"] = {
        "passed": True,  # never a hard FAIL
        "warning": stability_warn,
        "baseline_stable": b_stable,
        "current_stable": c_stable,
        "note": "WARNING: baseline was stable but current run is not" if stability_warn else None,
    }

    # Per-check deltas
    b_checks = baseline.get("per_check", {})
    c_checks = current.get("per_check", {})
    check_deltas = []
    for cid, bval in b_checks.items():
        b_verdict = bval.get("verdict", "n/a")
        c_verdict = c_checks.get(cid, {}).get("verdict", "MISSING")
        if b_verdict == c_verdict:
            continue
        kind = "neutral"
        if b_verdict == "TRUE_POSITIVE" and c_verdict == "FALSE_NEGATIVE":
            kind = "regression"
        elif b_verdict == "FALSE_NEGATIVE" and c_verdict == "TRUE_POSITIVE":
            kind = "improvement"
        check_deltas.append({
            "check_id": cid,
            "baseline_verdict": b_verdict,
            "current_verdict": c_verdict,
            "kind": kind,
        })

    overall_passed = all(g["passed"] for g in gates.values())
    return {
        "passed": overall_passed,
        "gates": gates,
        "check_deltas": check_deltas,
        "baseline_path": baseline.get("_path"),
        "current_path": current.get("_path"),
        "baseline_generated_at": baseline.get("generated_at"),
        "current_generated_at": current.get("generated_at"),
    }


def _load(path: str) -> dict:
    p = Path(path)
    data = json.loads(p.read_text())
    data["_path"] = str(p)
    return data


def _print_summary(report: dict) -> None:
    print("=== compare_baseline summary ===", file=sys.stderr)
    print(f"  baseline : {report['baseline_generated_at']}", file=sys.stderr)
    print(f"  current  : {report['current_generated_at']}", file=sys.stderr)
    for name, g in report["gates"].items():
        status = "PASS" if g["passed"] else "FAIL"
        warn = "  [WARN]" if g.get("warning") else ""
        note = f"  {g['note']}" if g.get("note") else ""
        delta = f"  delta={g['delta']}" if "delta" in g else ""
        print(f"  [{status}] {name}{warn}{delta}{note}", file=sys.stderr)
    if report["check_deltas"]:
        print("  --- per-check deltas ---", file=sys.stderr)
        for d in report["check_deltas"]:
            print(
                f"    {d['check_id']}: {d['baseline_verdict']} -> "
                f"{d['current_verdict']}  ({d['kind']})",
                file=sys.stderr,
            )
    verdict = "PASSED" if report["passed"] else "FAILED"
    print(f"\n  Overall: {verdict}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="Regression comparator for bench.py JSON outputs")
    ap.add_argument("--baseline", required=True, help="Path to baseline bench JSON")
    ap.add_argument("--current", required=True, help="Path to current bench JSON")
    ap.add_argument(
        "--recall-threshold", type=float, default=0.02,
        help="Max allowed recall/precision drop (default 0.02)",
    )
    ap.add_argument("--output", help="Write JSON report to file instead of stdout")
    args = ap.parse_args()

    try:
        baseline = _load(args.baseline)
        current = _load(args.current)
    except Exception as e:
        print(f"ERROR loading files: {e}", file=sys.stderr)
        return 2

    report = compare(baseline, current, args.recall_threshold)
    _print_summary(report)

    out = json.dumps(report, indent=2, default=str)
    if args.output:
        try:
            Path(args.output).write_text(out)
        except Exception as e:
            print(f"ERROR writing output: {e}", file=sys.stderr)
            return 2
    else:
        print(out)

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
