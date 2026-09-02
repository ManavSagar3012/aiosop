"""Benchmark Lab (charter section 25) — objective capability measurement.

A benchmark declares PLANTED TRUTH for an authorized lab target:

    GroundTruthCase(category, surface, should_detect=True)   # must be found
    GroundTruthCase(..., should_detect=False)                # detector bait:
        observations the platform MUST NOT elevate (e.g., catch-all WAF)

score_engagement() then measures exactly what the charter demands:
    discovery_recall          found / planted
    validated_precision       validated-correct / total validated claims
    false_positive_rate       unmatched findings / all canonical findings
    rejection_quality         bait findings landing in REJECTED / all bait
    chain_discovery_rate      correlated chains / expected chains

Pure functions over already-produced artifacts (findings + chains), so the same
scorer works against unit fixtures, staging runs, and live engagements.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ai_osop.core import confidence_engine as ce
from ai_osop.core.chain_engine import AttackChain


@dataclass
class GroundTruthCase:
    category: str  # e.g. "sqli", "xss", "weak_headers", "waf_fp_bait"
    surface: str  # host (normalized) the case lives on
    should_detect: bool = True
    requires_validation: bool = False  # counts toward validated_precision only
    id: str = ""

    def __post_init__(self):
        if not self.id:
            raw = f"{self.category}|{self.surface}".encode()
            self.id = "gt-" + hashlib.sha256(raw).hexdigest()[:10]


def _norm_surface(raw: str) -> str:
    import re
    from urllib.parse import urlparse

    raw = (raw or "").strip().lower()
    if "://" in raw:
        host = urlparse(raw).hostname or ""
    else:
        host = raw.split("/")[0]
    return re.sub(r"^www\.|:\d+$", "", host)


def _finding_matches_case(v, case: GroundTruthCase) -> bool:
    meta = v.yield_metadata or {}
    fclass = meta.get("finding_class")
    if case.should_detect and fclass == "observation":
        return False  # elevated observations never satisfy planted vulnerabilities
    vtype = getattr(v, "vuln_type", "")
    vtype = getattr(vtype, "value", vtype)
    text = f"{v.title} {meta.get('issue_id', '')} {vtype}".lower()
    cat = _normalize_seps_local(case.category)
    return cat in _normalize_seps_local(text)


def _normalize_seps_local(text: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower())


def score_engagement(
    findings: List[Any],
    chains: List[AttackChain],
    ground_truth: List[GroundTruthCase],
    expected_chains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Score a completed engagement against planted truth."""
    positives = [c for c in ground_truth if c.should_detect]
    baits = [c for c in ground_truth if not c.should_detect]

    # --- discovery recall: each planted case matched by >=1 non-rejected finding
    hits, misses = [], []
    for case in positives:
        matched = any(
            (getattr(v, "validation_state", ce.UNTESTED) != ce.REJECTED)
            and _surface_of_finding(v) == _norm_surface(case.surface)
            and _finding_matches_case(v, case)
            for v in findings
        )
        (hits if matched else misses).append(case.id)

    # --- validated precision: of VALIDATED findings, how many map to real cases
    validated = [v for v in findings if getattr(v, "validation_state", ce.UNTESTED) == ce.VALIDATED]
    vp_hits = sum(
        1
        for v in validated
        if any(
            _finding_matches_case(v, c) and _surface_of_finding(v) == _norm_surface(c.surface)
            for c in positives
        )
    )

    # --- false-positive rate over ALL canonical (non-rejected) findings
    candidates = [v for v in findings if getattr(v, "validation_state", ce.UNTESTED) != ce.REJECTED]
    fp = sum(
        1
        for v in candidates
        if not any(
            _finding_matches_case(v, c) and _surface_of_finding(v) == _norm_surface(c.surface)
            for c in positives
        )
    )
    fp_rate = round(fp / len(candidates), 3) if candidates else 0.0

    # --- rejection quality: baits must end REJECTED (not reported as findings)
    rejected_ids = {
        id(v) for v in findings if getattr(v, "validation_state", ce.UNTESTED) == ce.REJECTED
    }
    bait_rejected = sum(
        1 for b in baits for v in findings if id(v) in rejected_ids and _finding_matches_case(v, b)
    )
    bait_total = len(baits)

    # --- chain discovery
    expected_chain_names = expected_chains or []
    chain_names = {c.name for c in chains}
    chains_found = sum(1 for n in expected_chain_names if n in chain_names)

    report = {
        "planted": len(positives),
        "discovered": len(hits),
        "missed_cases": misses,
        "discovery_recall": round(len(hits) / len(positives), 3) if positives else None,
        "validated_claims": len(validated),
        "validated_precision": (round(vp_hits / len(validated), 3) if validated else None),
        "false_positive_rate": fp_rate,
        "bait_rejected": bait_rejected,
        "bait_total": bait_total,
        "rejection_quality": (round(bait_rejected / bait_total, 3) if bait_total else None),
        "expected_chains": len(expected_chain_names),
        "chains_found": chains_found,
        "chain_discovery_rate": (
            round(chains_found / len(expected_chain_names), 3) if expected_chain_names else None
        ),
    }
    report["overall_score"] = _overall(report)
    return report


def _surface_of_finding(v) -> str:
    meta = v.yield_metadata or {}
    return _norm_surface(meta.get("url") or meta.get("host") or getattr(v, "asset_id", ""))


def _overall(r: Dict[str, Any]) -> float:
    """Weighted composite: recall & precision dominate; FP-rate penalizes."""
    recall = r.get("discovery_recall") or 0.0
    precision = r.get("validated_precision")
    precision = precision if precision is not None else 0.5
    fp_penalty = r.get("false_positive_rate", 0.0)
    rejection = r.get("rejection_quality")
    rejection = rejection if rejection is not None else 0.5
    score = 0.40 * recall + 0.30 * precision + 0.20 * rejection - 0.20 * fp_penalty
    return round(max(0.0, min(1.0, score)), 3)


def load_lab_spec(path: str) -> Dict[str, Any]:
    """Load and validate a lab specification JSON (charter section 25)."""
    import json

    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    for req in ("ground_truth",):
        if req not in raw:
            raise ValueError(f"lab spec missing required field '{req}'")
    cases = [GroundTruthCase(
        category=c["category"],
        surface=c["surface"],
        should_detect=bool(c.get("should_detect", True)),
        requires_validation=bool(c.get("requires_validation", False)),
        id=c.get("id", ""),
    ) for c in raw["ground_truth"]]
    return {
        "lab_name": raw.get("lab_name", "unnamed-lab"),
        "target": raw.get("target", ""),
        "authorization": raw.get("authorization", ""),
        "cases": cases,
        "expected_chains": raw.get("expected_chains", []),
    }
