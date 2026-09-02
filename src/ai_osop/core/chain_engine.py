"""Attack-Chain Correlation Engine (charter section 14).

Answers continuously: 'Can separate findings combine into something more
significant than their parts?' Chains are first-class outputs with member
findings, evidence inheritance, and composed confidence:

    chain_confidence = min(member confidences) x role_coverage
    chain_severity   = max(member severities), escalated one level only when
                       EVERY member is individually VALIDATED

Rules fire only across DISTINCT findings on the SAME normalized surface;
REJECTED findings are never eligible; OBSERVATION-class members may serve as
reconnaissance steps but cannot alone satisfy a terminal role.
"""

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ai_osop.core import confidence_engine as ce
from ai_osop.core.finding_intelligence import (
    _sev_rank,
    CLASS_OBSERVATION,
    CLASS_VULNERABILITY,
    CLASS_WEAKNESS,
)
from ai_osop.core.models import AttackPath, Vulnerability

# --- role classification ------------------------------------------------------

_ROLE_PATTERNS: List[Tuple[str, tuple]] = [
    (
        "injection",
        (r"sqli|sql[-_]?injection", r"xss", r"ssrf", r"\brce\b", r"ssti", r"command[-_]?injection"),
    ),
    (
        "authz_bypass",
        (r"idor|bola", r"broken[-_]?access", r"auth[-_]?bypass", r"privilege[-_]?escalation"),
    ),
    (
        "info_disclosure",
        (
            r"source[-_]?map",
            r"directory[-_]?listing",
            r"information[-_]?disclosure",
            r"exposed[-_]?secret",
            r"osint[-_]?leak",
            r"server[-_]?info",
        ),
    ),
    (
        "exposure",
        (
            r"subdomain[-_]?takeover",
            r"admin[-_]?panel",
            r"console|dashboard|exposed[-_]?service|open[-_]?dashboard",
            r"kubernetes|docker[-_]?api",
        ),
    ),
    (
        "session_weakness",
        (
            r"jwt[-_]?",
            r"session[-_]?(fixation|prediction)",
            r"weak[-_]?cookie|cookie.*(secure|httponly)",
            r"oauth2|authentication[-_]?weakness",
        ),
    ),
]


def classify_chain_role(vuln: Vulnerability) -> Optional[str]:
    """Map a finding to ONE attack-chain role (most specific wins by order)."""
    if getattr(vuln, "validation_state", None) == ce.REJECTED:
        return None
    meta = vuln.yield_metadata or {}
    fclass = meta.get("finding_class")
    if fclass not in (CLASS_WEAKNESS, CLASS_VULNERABILITY):
        return None  # observations are recon color, never chain members
    haystack = f"{vuln.title} {meta.get('issue_id', '')}".lower()
    for role, patterns in _ROLE_PATTERNS:
        if any(_search(p, haystack) for p in patterns):
            return role
    return None


def _search(pattern: str, text: str) -> bool:
    import re

    t1 = text.lower()
    t2 = re.sub(r"[^a-z0-9]+", "-", t1)
    return bool(re.search(pattern, t1) or re.search(pattern, t2))


def _surface_of(vuln: Vulnerability) -> str:
    """Normalized host for cross-finding association."""
    import re
    from urllib.parse import urlparse

    meta = vuln.yield_metadata or {}
    raw = meta.get("url") or meta.get("host") or getattr(vuln, "asset_id", "") or ""
    raw = raw.strip().lower()
    if "://" in raw:
        return urlparse(raw).hostname or ""
    return re.sub(r":\d+$|^www\.", "", raw.split("/")[0])


# --- chain rules ----------------------------------------------------------------

_CHAIN_RULES: List[Dict[str, Any]] = [
    {
        "name": "recon_guided_injection",
        "roles": ["info_disclosure", "injection"],
        "title": "Disclosed internals guided successful injection surface",
        "impact": "Information disclosure reduced attacker uncertainty, "
        "increasing injection reliability against the same surface.",
    },
    {
        "name": "identity_object_access",
        "roles": ["authz_bypass", "info_disclosure"],
        "title": "Enumerated object identifiers combined with broken access control",
        "impact": "Unauthorized cross-user/cross-tenant data access.",
    },
    {
        "name": "session_hijack_via_injection",
        "roles": ["injection", "session_weakness"],
        "title": "Injection primitive paired with session/token weakness",
        "impact": "Potential account compromise via token theft or fixation.",
    },
    {
        "name": "exposed_admin_with_session_flaw",
        "roles": ["exposure", "session_weakness"],
        "title": "Exposed administrative surface reachable through session weakness",
        "impact": "Unauthenticated path toward privileged functionality.",
    },
]

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass
class AttackChain:
    id: str
    name: str
    title: str
    impact: str
    surface: str
    steps: List[Dict[str, Any]]  # ordered role -> finding ref/evidence
    member_ids: List[str]
    confidence: float
    severity: str
    validated_steps: int
    status: str = "HYPOTHESIZED"  # HYPOTHESIZED -> CONFIRMED (P3)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def correlate_chains(findings: List[Vulnerability]) -> Tuple[List[AttackChain], Dict[str, Any]]:
    """Correlate classified findings into candidate attack chains."""
    # bucket eligible findings by (surface, role)
    buckets: Dict[Tuple[str, str], List[Vulnerability]] = {}
    stats: Dict[str, Any] = {"eligible": 0, "chains": 0, "rejected_excluded": 0}
    for v in findings:
        vstate = getattr(v, "validation_state", ce.UNTESTED)
        if vstate == ce.REJECTED:
            stats["rejected_excluded"] += 1
            continue
        role = classify_chain_role(v)
        if role is None:
            continue
        stats["eligible"] += 1
        buckets.setdefault((_surface_of(v), role), []).append(v)

    chains: List[AttackChain] = []
    for rule in _CHAIN_RULES:
        need = rule["roles"]
        surfaces = {surf for surf, _role in buckets}
        for surface in surfaces:
            # pick best finding per required role on this surface
            picks: List[Vulnerability] = []
            seen_ids = set()
            ok = True
            for role in need:
                cands = [v for v in buckets.get((surface, role), []) if v.id not in seen_ids]
                if not cands:
                    ok = False
                    break
                best = max(cands, key=lambda x: (x.confidence,))
                picks.append(best)
                seen_ids.add(best.id)
            if not ok:
                continue

            confidences = []
            for m in picks:
                cs = (m.yield_metadata or {}).get("confidence_scores", {})
                confidences.append(float(cs.get("confidence", m.confidence)))
            coverage = 1.0  # all required roles present by construction
            confidence = round(min(confidences) * coverage, 3)

            sevs = [_sev_rank(m) for m in picks]
            sev_idx = max(sevs)
            if all(getattr(m, "validation_state", ce.UNTESTED) == ce.VALIDATED for m in picks):
                sev_idx = min(sev_idx + 1, len(_SEV_ORDER) - 1)
            severity = _SEV_ORDER[max(sev_idx, 1)]

            raw_id = f"{rule['name']}|{surface}|{'|'.join(sorted(seen_ids))}"
            cid = "chain-" + hashlib.sha256(raw_id.encode()).hexdigest()[:12]

            steps = [
                {
                    "order": i + 1,
                    "role": role,
                    "finding_id": m.id,
                    "title": m.title,
                    "validated": getattr(m, "validation_state", ce.UNTESTED) == ce.VALIDATED,
                }
                for i, (m, role) in enumerate(zip(picks, need))
            ]

            chains.append(
                AttackChain(
                    id=cid,
                    name=rule["name"],
                    title=rule["title"],
                    impact=rule["impact"],
                    surface=surface,
                    steps=steps,
                    member_ids=list(seen_ids),
                    confidence=confidence,
                    severity=severity,
                    validated_steps=sum(1 for s in steps if s["validated"]),
                )
            )
            stats["chains"] += 1

    chains.sort(key=lambda c: (c.confidence, len(c.member_ids)), reverse=True)
    return chains, stats


async def persist_chains(graph_memory, chains: List[AttackChain],
                         engagement_id: str) -> List[str]:
    """Persist chains as first-class graph entities.

    Uses the EXISTING add_attack_path API (charter 28: no duplicate plumbing):
      * node_ids   = member finding IDs (Vulnerability nodes already in graph)
      * LEADS_TO edges carry chain confidence as probability
    Returns persisted path IDs; failures are logged, never raised (chains are
    derived intelligence — a persistence hiccup must not break engagements).
    """
    import logging

    logger = logging.getLogger(__name__)
    persisted: List[str] = []
    for chain in chains:
        sev_rank = {"info": 1, "low": 3, "medium": 5,
                    "high": 7.5, "critical": 10}.get(chain.severity, 5)
        path = AttackPath(
            id=chain.id,
            node_ids=list(chain.member_ids),
            edge_ids=[],
            confidence=chain.confidence,
            risk_score=round(sev_rank * max(chain.confidence, 0.05), 2),
            detection_risk=round(1.0 - chain.confidence, 3),
            validation_state=(ce.VALIDATED if chain.validated_steps == len(chain.steps)
                              else ce.UNTESTED),
            validated=chain.validated_steps == len(chain.steps),
            entry_node_id=chain.steps[0]["finding_id"] if chain.steps else "",
            goal_node_id=chain.steps[-1]["finding_id"] if chain.steps else "",
            engagement_id=engagement_id,
        )
        try:
            await graph_memory.add_attack_path(path)
            persisted.append(path.id)
        except Exception as e:  # noqa: BLE001 - derived intelligence is best-effort
            logger.warning(f"chain_persist_failed chain={chain.id} error={e}")
    return persisted
