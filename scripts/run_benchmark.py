"""One-command benchmark runner (charter section 25).

Usage:
    poetry run python scripts/run_benchmark.py \
        --spec benchmarks/lab_spec.example.json \
        --findings findings_export.json \
        [--out benchmark.json]

findings_export.json: array of finding dicts as produced by the platform
(Vulnerability.model_dump() shape — title, severity, yield_metadata,
validation_state, evidence, engagement_id...). Chains may be supplied via
--chains chains_export.json (AttackChain.to_dict() list).
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai_osop.core.benchmark import load_lab_spec, score_engagement  # noqa: E402


def _load_findings(path: str):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    # Rehydrate minimal duck-typed objects the scorer needs.
    from types import SimpleNamespace

    out = []
    for d in raw:
        ym = d.get("yield_metadata") or {}
        out.append(
            SimpleNamespace(
                id=d.get("id", ""),
                title=d.get("title", ""),
                severity=SimpleNamespace(value=str(d.get("severity", "info")).lower()),
                confidence=float(d.get("confidence", 0.5)),
                evidence=d.get("evidence") or [],
                validation_state=d.get("validation_state", "UNTESTED"),
                yield_metadata=ym,
            )
        )
    return out


def _load_chains(path):
    if not path:
        return []
    # allow inline JSON (e.g. '[]') as well as a file path
    if path.strip().startswith("["):
        raw = json.loads(path)
    else:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    from types import SimpleNamespace

    return [SimpleNamespace(**c) for c in raw]


async def main() -> int:
    ap = argparse.ArgumentParser(description="AI-OSOP benchmark scorer")
    ap.add_argument("--spec", required=True, help="lab spec JSON")
    ap.add_argument("--findings", required=True, help="findings export JSON")
    ap.add_argument("--chains", default=None, help="chains export JSON")
    ap.add_argument("--out", default="benchmark.json")
    args = ap.parse_args()

    lab = load_lab_spec(args.spec)
    findings = _load_findings(args.findings)
    chains = _load_chains(args.chains)

    report = score_engagement(
        findings, chains, lab["cases"], expected_chains=lab["expected_chains"]
    )
    report["lab_name"] = lab["lab_name"]
    report["target"] = lab["target"]
    report["authorization"] = lab["authorization"]

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"benchmark written -> {args.out}")
    for k in (
        "discovery_recall",
        "validated_precision",
        "false_positive_rate",
        "rejection_quality",
        "chain_discovery_rate",
        "overall_score",
    ):
        print(f"  {k}: {report.get(k)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
