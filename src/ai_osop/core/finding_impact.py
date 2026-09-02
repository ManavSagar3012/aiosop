"""Deterministic per-finding impact scoring (charter section 13).

COMPLEMENTS the existing ImpactQuantificationEngine (LLM-based, chain-level
CVSS). This module provides instant, auditable, no-LLN per-finding impact
scores used by the report renderer, adaptive planner, and risk engine.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

_CLASS_WEIGHTS: Dict[str, float] = {
    "rce": 10.0,
    "sqli": 9.0,
    "ssti": 8.5,
    "deserialization": 8.5,
    "xxe": 7.5,
    "ssrf": 7.0,
    "idor": 7.0,
    "bola": 7.0,
    "broken_access_control": 7.0,
    "authentication_weakness": 6.5,
    "lfi": 6.5,
    "command_injection": 9.0,
    "jwt_abuse": 6.0,
    "oauth2": 6.0,
    "xss": 5.5,
    "csrf": 4.5,
    "race_condition": 5.0,
    "mass_assignment": 5.0,
    "subdomain_takeover": 6.0,
    "exposed_secret": 7.0,
    "graphql": 4.5,
    "prototype_pollution": 5.5,
}

_AUTH_BONUS_UNAUTH = 1.5
_ENTRY_POINT_BONUS = 0.8
_CHAIN_BONUS_PER = 0.5
_CHAIN_CAP = 2.0
_VALIDATED_MULT = 1.15


@dataclass
class FindingImpact:
    score: float
    narrative: str
    data_access_risk: str
    privilege_risk: str
    chain_potential: int
    drivers: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


def _weight(vuln_type, fclass):
    vt = str(getattr(vuln_type, "value", vuln_type)).lower().replace(" ", "_")
    if vt in _CLASS_WEIGHTS:
        return _CLASS_WEIGHTS[vt]
    return {"observation": 1.0, "weakness": 3.0}.get(fclass, 4.0)


def quantify_finding(v) -> FindingImpact:
    meta = getattr(v, "yield_metadata", None) or {}
    fclass = meta.get("finding_class", "weakness")
    entry = bool(getattr(v, "entry_point", False))
    auth_req = bool(getattr(v, "requires_auth", False))
    exploitable = str(getattr(v, "exploitability", "unknown")).lower()
    validated = bool(getattr(v, "validated", False))
    correlated = list(getattr(v, "correlated_ids", None) or [])

    score = _weight(getattr(v, "vuln_type", ""), fclass)
    drivers = {"base": score}
    parts = []

    if not auth_req:
        score += _AUTH_BONUS_UNAUTH
        drivers["unauth_bonus"] = _AUTH_BONUS_UNAUTH
        parts.append("reachable without authentication")

    if entry:
        score += _ENTRY_POINT_BONUS
        drivers["entry_point"] = True
        parts.append("internet-facing entry point")

    cb = min(len(correlated) * _CHAIN_BONUS_PER, _CHAIN_CAP)
    score += cb
    if correlated:
        parts.append(f"chains with {len(correlated)} finding(s)")
        drivers["chain_bonus"] = cb

    if exploitable == "high":
        score *= 1.1
        parts.append("exploitability high")
    elif exploitable == "low":
        score *= 0.7

    if validated:
        score *= _VALIDATED_MULT
        parts.append("VALIDATED")

    if fclass == "observation":
        score = min(score, 2.0)

    score = round(max(0.0, min(10.0, score)), 1)
    narrative = f"Impact {score}/10: {'; '.join(parts)}." if parts else f"Impact {score}/10."

    da = "none"
    if fclass != "observation":
        if score >= 8:
            da = "critical"
        elif score >= 6:
            da = "high"
        elif score >= 4:
            da = "medium"
        elif score >= 2:
            da = "low"

    pr = "none"
    if not auth_req and score >= 6:
        pr = "critical"
    elif auth_req and score >= 7:
        pr = "high"
    elif score >= 5:
        pr = "medium"
    elif score >= 3:
        pr = "low"

    return FindingImpact(
        score=score,
        narrative=narrative,
        data_access_risk=da,
        privilege_risk=pr,
        chain_potential=len(correlated),
        drivers=drivers,
    )


def quantify_batch(findings):
    return {v.id: quantify_finding(v) for v in findings}


def top_impact(findings, limit=10):
    scored = [(quantify_finding(v).score, v) for v in findings]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [v for _, v in scored[:limit]]
