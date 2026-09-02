"""Finding Intelligence Layer (charter Phase 1) — RECONSTRUCTED 2026-08-24b.

Core rule (operator directive): NO scanner output becomes a real finding until
AI-OSOP can explain why it matters, prove the condition exists on the correct
surface, validate impact, and determine whether an existing observation already
represents the same root cause.

Deterministic core: classify -> fingerprint -> deduplicate (evidence-preserving)
-> confidence scoring -> truth-telling report sections.
"""

import hashlib
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from ai_osop.core import confidence_engine as ce
from ai_osop.core.models import Vulnerability

CLASS_OBSERVATION = "observation"  # tech/infra/cert/network metadata
CLASS_WEAKNESS = "weakness"  # configuration/hardening deficiency
CLASS_VULNERABILITY = "vulnerability"  # exploitable condition requiring validation

_OBSERVATION_PATTERNS = (
    r"waf",
    r"wappalyzer",
    r"technology",
    r"tech-detect",
    r"\btls\b|ssl[-_]?version|certificate",
    r"dns",
    r"cname",
    r"mx\b|spf\b|dmarc",
    r"aws|s3|cloudfront|azure|gcp",
    r"service[-_]?detection",
    r"favicon",
    r"http[-_]?options|method[-_]?detect",
    r"ip[-_]?geo|asn",
    # FIX (fit-obs-tuning-2026-08-24): environmental metadata surfaced by the
    # qosmos engagement that previously fell to the WEAKNESS default.
    r"analytics|gtag|gtm\b|tracking[-_]?pixel",
    r"payment|razorpay|stripe|paypal",
    r"external[-_]?resource",
    r"storage[-_]?usage",
    r"console[-_]?hostname",
    r"generic[-_]?technology",
)
_WEAKNESS_PATTERNS = (
    r"security[-_]?headers|missing[-_]?header",
    r"csp|content[-_]?security[-_]?policy",
    r"subresource[-_]?integrity|\bsri\b",
    r"cookie.*(secure|httponly|samesite)",
    r"cache[-_]?control|referrer[-_]?policy|hsts|strict[-_]?transport",
    r"cors|access[-_]?control[-_]?allow[-_]?origin",
    r"clickjacking|x[-_]?frame|frame[-_]?ancestors",
    r"information[-_]?disclosure|source[-_]?map|directory[-_]?listing",
)
_VULNERABILITY_PATTERNS = (
    r"sqli|sql[-_]?injection",
    r"xss|cross[-_]?site[-_]?scripting",
    r"ssrf|server[-_]?side[-_]?request",
    r"idor|bola",
    # FIX: \brce\b — "subresource" previously matched bare "rce"
    r"\brce\b|\bremote[-_]?code\b",
    r"ssti|template[-_]?injection",
    r"lfi|rfi|path[-_]?traversal|directory[-_]?traversal",
    r"auth[-_]?(bypass|zig)|broken[-_]?access",
    r"deserialization",
    r"xxe|xml[-_]?external",
    r"open[-_]?redirect",
    r"jwt[-_]?(none|confusion|weak)",
    r"upload|webshell",
    r"csrf",
    r"command[-_]?injection",
)


def _normalize_seps(text: str) -> str:
    """Collapse non-alphanumeric runs to '-' so 'SQL Injection' matches
    patterns written as sql[-_]?injection (FIX fit-separators: space-separated
    titles previously matched NOTHING)."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower())


def _match_any(text: str, patterns) -> bool:
    t1 = text.lower()
    t2 = _normalize_seps(t1)
    return any(re.search(p, t1) or re.search(p, t2) for p in patterns)


def classify_finding(vuln: Vulnerability) -> str:
    """Classify into observation / weakness / vulnerability."""
    haystack = " ".join(
        filter(
            None,
            [
                vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type),
                getattr(vuln, "title", "") or "",
                (vuln.yield_metadata or {}).get("detector", ""),
                (vuln.yield_metadata or {}).get("template_id", ""),
            ],
        )
    )
    if _match_any(haystack, _VULNERABILITY_PATTERNS):
        return CLASS_VULNERABILITY  # explicit exploit patterns win precedence
    if _match_any(haystack, _WEAKNESS_PATTERNS):
        return CLASS_WEAKNESS
    if _match_any(haystack, _OBSERVATION_PATTERNS):
        return CLASS_OBSERVATION
    return CLASS_WEAKNESS  # conservative default for unmapped detectors


def _normalize_url_target(url_or_host: str) -> str:
    """Canonical surface identity: scheme-less host + normalized path."""
    raw = (url_or_host or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        path = parsed.path or "/"
    else:
        parts = raw.split("/", 1)
        host = parts[0].split(":")[0]
        path = "/" + parts[1] if len(parts) > 1 else "/"
    host = re.sub(r":\d+$", "", host.split("/")[0])
    path = re.sub(r"/+$", "", path) or "/"
    return f"{host}{path}"


def _evidence_key(ev: Dict[str, Any]) -> str:
    try:
        blob = str(sorted((k, str(v)[:400]) for k, v in ev.items()))
    except Exception:  # noqa: BLE001 - any weird evidence still gets a key
        blob = repr(ev)[:500]
    return hashlib.sha256(blob.encode("utf-8", "ignore")).hexdigest()[:16]


def finding_fingerprint(vuln: Vulnerability) -> str:
    """Canonical root-cause identity for deduplication."""
    meta = vuln.yield_metadata or {}
    endpoint = getattr(vuln, "endpoint_id", None) or meta.get("url") or meta.get("host") or ""
    surface = _normalize_url_target(str(endpoint))
    detector = (meta.get("template_id") or meta.get("detector") or vuln.tool_source or "").lower()
    vtype = vuln.vuln_type.value if hasattr(vuln.vuln_type, "value") else str(vuln.vuln_type)
    root_cause = meta.get("root_cause") or vuln.title or ""
    cause_token = re.sub(r"[^a-z0-9]+", "-", root_cause.lower())[:40]
    raw = f"{vuln.engagement_id}|{surface}|{vtype}|{detector}|{cause_token}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _sev_rank(v: Vulnerability) -> int:
    sev = str(v.severity.value if hasattr(v.severity, "value") else v.severity)
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, -1)


def deduplicate_findings(
    vulns: List[Vulnerability],
) -> Tuple[List[Vulnerability], Dict[str, Any]]:
    """Merge observations sharing a root-cause fingerprint.

    representative = highest (severity, confidence); evidence UNIONED with
    content-hash dedup; all member IDs preserved via correlated_ids.
    Evidence is NEVER discarded - counts reflect distinct root causes.
    """
    groups: Dict[str, List[Vulnerability]] = {}
    for v in vulns:
        groups.setdefault(finding_fingerprint(v), []).append(v)

    canonical: List[Vulnerability] = []
    stats: Dict[str, Any] = {
        "observations_in": len(vulns),
        "canonical_out": 0,
        "merged_away": 0,
        "by_class": {CLASS_OBSERVATION: 0, CLASS_WEAKNESS: 0, CLASS_VULNERABILITY: 0},
    }

    for members in groups.values():
        members.sort(key=lambda v: (_sev_rank(v), v.confidence), reverse=True)
        rep = members[0]
        fclass = classify_finding(rep)
        stats["by_class"][fclass] += 1

        seen_keys = set()
        merged_evidence = []
        for m in members:
            for ev in m.evidence or []:
                key = _evidence_key(ev if isinstance(ev, dict) else {"raw": ev})
                if key not in seen_keys:
                    seen_keys.add(key)
                    merged_evidence.append(ev)

        rep.evidence = merged_evidence
        rep.correlated_ids = sorted({m.id for m in members} | set(rep.correlated_ids or []))
        meta = dict(rep.yield_metadata or {})
        meta.update(
            {
                "finding_class": fclass,
                "fingerprint": finding_fingerprint(rep),
                "observation_count": len(members),
                "merged_observation_ids": [m.id for m in members[1:]],
            }
        )
        if fclass == CLASS_OBSERVATION:
            meta["report_section"] = "informational"
            rep.confidence = min(rep.confidence, 0.30)

        # Confidence Engine (charter 17): deterministic, auditable scores.
        score = ce.score_finding(
            finding_class=fclass,
            evidence_count=len(rep.evidence or []),
            fp_flags=1 if meta.get("_invalid_signature") else 0,
            detection_level=meta.get("detection_level", "detected"),
            applicable=fclass in (CLASS_WEAKNESS, CLASS_VULNERABILITY),
        )
        rep.validation_state = score.validation_state
        meta["confidence_scores"] = score.to_dict()
        rep.yield_metadata = meta
        canonical.append(rep)
        stats["merged_away"] += len(members) - 1

    stats["canonical_out"] = len(canonical)
    canonical.sort(key=lambda v: (_sev_rank(v), v.confidence), reverse=True)
    return canonical, stats


def build_report_sections(findings: List[Vulnerability]) -> Dict[str, Any]:
    """Charter section 21: reports must separate reality from noise.

    Sections are mutually exclusive; a finding appears in exactly one:
      confirmed_vulnerabilities  VALIDATED vulnerability-class
      security_weaknesses        weakness-class not rejected
      candidate_vulnerabilities  vulnerability-class awaiting validation
      informational              observation-class
      rejected                   REJECTED (fixed or false positive)
    The headline 'vulnerability count' = len(confirmed_vulnerabilities) ONLY.
    """
    sections: Dict[str, List[Vulnerability]] = {
        "confirmed_vulnerabilities": [],
        "security_weaknesses": [],
        "candidate_vulnerabilities": [],
        "informational": [],
        "rejected": [],
    }
    for v in findings:
        meta = v.yield_metadata or {}
        fclass = meta.get("finding_class", CLASS_WEAKNESS)
        vstate = getattr(v, "validation_state", ce.UNTESTED)
        if vstate == ce.REJECTED:
            sections["rejected"].append(v)
        elif fclass == CLASS_VULNERABILITY:
            if vstate == ce.VALIDATED:
                sections["confirmed_vulnerabilities"].append(v)
            else:
                sections["candidate_vulnerabilities"].append(v)
        elif fclass == CLASS_OBSERVATION:
            sections["informational"].append(v)
        else:
            sections["security_weaknesses"].append(v)

    counts = {k: len(v) for k, v in sections.items()}
    counts["headline_vulnerability_count"] = counts["confirmed_vulnerabilities"]
    return {"sections": sections, "counts": counts}
