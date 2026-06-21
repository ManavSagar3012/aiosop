"""Submittability triage for authorization findings.

The diff-auth engine emits DiffAuthFinding records, but a hunter still has to decide
*which to submit first*. Returning them in creation order buries a cross-tenant
privilege escalation under a pile of low-signal horizontal cases. This module scores
each finding for submittability so the highest-value, lowest-duplicate-risk findings
surface first.

Pure, deterministic, dependency-free: score is a function of the finding alone, so it
is trivially testable and stable across runs (no model calls, no clock, no I/O).

Score (0-100) = impact * confidence * evidence_strength, minus a duplicate-risk
penalty. Each finding also gets a tier, a human rationale, a CVSS-ish severity label,
and an estimated bounty band — the signals a researcher uses to triage a queue.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Per-category base impact (0-1). Vertical privilege escalation and cross-tenant escape
# are the crown-jewel bugs; horizontal access is strong; workflow bypass varies.
CATEGORY_IMPACT: Dict[str, float] = {
    "vertical_pe": 1.00,  # low-priv identity reaching admin/high-priv resource
    "tenant_escape": 1.00,  # crossing an organization/tenant boundary
    "horizontal_pe": 0.80,  # accessing a peer's resource (classic IDOR/BOLA)
    "workflow_bypass": 0.70,  # skipping a required step / state-machine abuse
}
_DEFAULT_IMPACT = 0.55

# Tier thresholds on the final 0-100 score.
TIER_SUBMIT = 70.0
TIER_REVIEW = 45.0
TIER_DUP = 25.0

SEVERITY_BANDS = [
    (85.0, "critical"),
    (70.0, "high"),
    (45.0, "medium"),
    (0.0, "low"),
]

# Rough bounty bands by severity — directional, for queue prioritization only.
BOUNTY_BANDS: Dict[str, str] = {
    "critical": "$2k-$10k+",
    "high": "$750-$3k",
    "medium": "$250-$900",
    "low": "$0-$250",
}


@dataclass
class TriageResult:
    finding_id: str
    score: float  # 0-100 submittability
    tier: str  # submit_now | review | likely_duplicate | noise
    severity: str  # critical | high | medium | low
    bounty_band: str
    confidence: float
    duplicate_risk: float  # 0-1, higher = more likely already reported
    rationale: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "score": round(self.score, 1),
            "tier": self.tier,
            "severity": self.severity,
            "bounty_band": self.bounty_band,
            "confidence": round(self.confidence, 3),
            "duplicate_risk": round(self.duplicate_risk, 3),
            "rationale": self.rationale,
        }


def _evidence_strength(finding: Dict[str, Any]) -> tuple[float, Optional[str]]:
    """How cleanly does the observed result contradict the expected one?

    A denied->allowed transition (e.g. 403 Forbidden -> 200 OK) is an unambiguous
    authorization break and scores full strength. A weaker/ambiguous diff scores less.
    Returns (multiplier 0..1, reason-or-None).
    """
    expected = str(finding.get("expected_result", "")).lower()
    observed = str(finding.get("observed_result", "")).lower()

    def _denied(s: str) -> bool:
        return any(code in s for code in ("401", "403", "forbidden", "unauthor", "denied"))

    def _allowed(s: str) -> bool:
        return any(code in s for code in ("200", "201", "204", "ok", "success"))

    if _denied(expected) and _allowed(observed):
        return (
            1.0,
            f"clean authz break ({finding.get('expected_result')} -> {finding.get('observed_result')})",
        )
    if _allowed(observed) and expected and expected != observed:
        return (
            0.8,
            f"unexpected access ({finding.get('expected_result')} -> {finding.get('observed_result')})",
        )
    if expected and observed and expected != observed:
        return 0.55, "results differ but transition is ambiguous"
    # Evidence diff present but no clear status transition.
    if finding.get("evidence_diff"):
        return 0.4, "body/diff signal only, no status transition"
    return 0.25, "weak evidence"


def _duplicate_risk(finding: Dict[str, Any]) -> tuple[float, Optional[str]]:
    """Heuristic likelihood the finding is already-reported (lowers submittability).

    Generic, unauthenticated, root-collection IDOR on common paths is the most-duplicated
    class on public programs; deep, tenant-specific, or multi-step findings are rarer.
    """
    category = str(finding.get("category", ""))
    resource = str(finding.get("resource_id", "")).lower()
    identity = str(finding.get("test_identity_id", "")).lower()

    risk = 0.2
    reasons: List[str] = []

    if "anon" in identity or "guest" in identity or "unauth" in identity:
        risk += 0.25
        reasons.append("anonymous-accessible (heavily fuzzed by others)")
    if category == "horizontal_pe":
        risk += 0.15  # classic IDOR is the most-reported class
    if any(
        common in resource for common in ("/user", "/profile", "/order", "/account", "/api/v1/")
    ):
        risk += 0.15
        reasons.append("common high-traffic endpoint")
    if category in ("tenant_escape", "vertical_pe"):
        risk -= 0.15  # higher-impact, harder to stumble on -> less duplicated
        reasons.append("high-impact class, lower duplicate likelihood")
    if "workflow" in category:
        risk -= 0.1
        reasons.append("multi-step logic, rarely duplicated")

    risk = max(0.0, min(1.0, risk))
    return risk, ("; ".join(reasons) if reasons else None)


def score_finding(finding: Dict[str, Any]) -> TriageResult:
    """Score a single DiffAuthFinding-shaped dict for submittability."""
    fid = str(finding.get("id") or finding.get("finding_id") or "unknown")
    category = str(finding.get("category", ""))
    confidence = float(finding.get("confidence") or 0.0)
    confidence = max(0.0, min(1.0, confidence))

    impact = CATEGORY_IMPACT.get(category, _DEFAULT_IMPACT)
    ev_mult, ev_reason = _evidence_strength(finding)
    dup_risk, dup_reason = _duplicate_risk(finding)

    # Base submittability before duplicate penalty.
    base = impact * confidence * ev_mult * 100.0
    # Duplicate risk discounts up to 40% of the score.
    score = base * (1.0 - 0.4 * dup_risk)
    score = max(0.0, min(100.0, score))

    if score >= TIER_SUBMIT:
        tier = "submit_now"
    elif score >= TIER_REVIEW:
        tier = "review"
    elif score >= TIER_DUP:
        tier = "likely_duplicate"
    else:
        tier = "noise"

    severity = next(label for threshold, label in SEVERITY_BANDS if score >= threshold)

    rationale: List[str] = [
        f"category '{category or 'unknown'}' base impact {impact:.2f}",
        f"engine confidence {confidence:.2f}",
    ]
    if ev_reason:
        rationale.append(f"evidence: {ev_reason} (x{ev_mult:.2f})")
    if dup_reason:
        rationale.append(f"duplicate risk {dup_risk:.2f}: {dup_reason}")

    return TriageResult(
        finding_id=fid,
        score=score,
        tier=tier,
        severity=severity,
        bounty_band=BOUNTY_BANDS[severity],
        confidence=confidence,
        duplicate_risk=dup_risk,
        rationale=rationale,
    )


def rank_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Score and sort findings best-first. Returns each input dict augmented with a
    'triage' block, ordered by descending submittability score."""
    scored = []
    for f in findings:
        result = score_finding(f)
        enriched = dict(f)
        enriched["triage"] = result.to_dict()
        scored.append((result.score, enriched))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [enriched for _, enriched in scored]
