"""Finding Validation Engine (P0 remediation, 2026-09-02).

External review verdict on the generated report: raw scanner observations
were rendered as "Verified Vulnerabilities" — including findings whose OWN
EVIDENCE said out_of_scan_scope / catch_all / fingerprint-only. The
intelligence existed in the evidence but never gated the final status.

This module is the deterministic stage between scanners and reporting:

    scanner result
      -> (existing) finding_intelligence dedup/classification
      -> THIS: scope validation
             false-positive gating
             evidence-vs-claim consistency (header claims checked against
               the actual response captured in evidence)
             security classification (vulnerability / hardening / fingerprint)
             finding-aware remediation (no more generic fallback)
             honest taxonomy (fingerprints get NO fake ATT&CK/OWASP)
      -> report (grouped sections + honest funnel)

No LLM anywhere in this chain: validation must happen BEFORE narrative.
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ai_osop.safety.rule_factory import DefensiveRuleFactory

# ---------------------------------------------------------------------------
# Security classes — the report's top-level sections
# ---------------------------------------------------------------------------
C_VALIDATED = "validated_vulnerability"  # a real, evidence-backed security issue
C_HARDENING = "hardening_item"  # config deficiency worth fixing, not a vuln per se
C_FINGERPRINT = "fingerprint_observation"  # tech/infra/cert metadata, informational
C_OUT_OF_SCOPE = "out_of_scope"  # evidence host/port outside engagement scope
C_FALSE_POSITIVE = "false_positive"  # scanner signal its own evidence refutes

SECTION_ORDER = [C_VALIDATED, C_HARDENING, C_FINGERPRINT, C_OUT_OF_SCOPE, C_FALSE_POSITIVE]

# ---------------------------------------------------------------------------
# Template families (matched against title/template text, lowercased)
# ---------------------------------------------------------------------------
_FINGERPRINT_PATTERNS = (
    "aws", "cloudfront", "s3 bucket", "wappalyzer", "tech-detect", "tech detect",
    "ssl certificate issuer", "ssl dns names", "ns record", "nameserver",
    "dns saas", "waf detection", "detect websites", "amazon-s3", "bucket storage",
    "tls version", "certificate issuer", "service detection", "detect amazon",
)
_HARDENING_PATTERNS = (
    "missing security headers", "missing-security-headers",
    "missing subresource integrity", "missing-sri",
    "weak content security policy", "weak-csp",
)
# A catch-all FP signal on a WAF detection is still a useful OBSERVATION
# (a defensive control exists) — but never a vulnerability.
_WAF_PATTERNS = ("waf", "firewall", "cloudfront")

_HEADER_NAMES = (
    "strict-transport-security", "x-content-type-options", "x-frame-options",
    "referrer-policy", "content-security-policy", "permissions-policy",
    "x-permitted-cross-domain-policies", "cross-origin-embedder-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
)


def _norm_text(finding: Dict[str, Any]) -> str:
    parts = [
        str(finding.get("title", "") or ""),
        str(finding.get("vuln_type", "") or ""),
        str(finding.get("description", "") or "")[:200],
        str((finding.get("yield_metadata") or {}).get("template_id", "") or ""),
        str((finding.get("yield_metadata") or {}).get("detector", "") or ""),
    ]
    ev = finding.get("evidence")
    if isinstance(ev, list):
        for e in ev:
            if isinstance(e, dict):
                parts.append(str(e.get("template", "")))
                parts.append(str(e.get("template_id", "")))
    return " ".join(parts).lower()


def _evidence_entries(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    ev = finding.get("evidence")
    # Graph persistence stores the evidence list as a JSON-encoded string;
    # parse it so the gates see the actual captured responses (found live on
    # the qosmos evidence: an unparsed string read as "no response" and the
    # header check then declared every header missing — the exact
    # evidence-vs-claim inconsistency this engine exists to catch).
    if isinstance(ev, str):
        import json as _json

        try:
            ev = _json.loads(ev)
        except (ValueError, TypeError):
            return []
    if isinstance(ev, list):
        return [e for e in ev if isinstance(e, dict)]
    if isinstance(ev, dict):
        return [ev]
    return []


def _matched_targets(finding: Dict[str, Any]) -> List[str]:
    """Collect host(:port) strings the scanner actually touched."""
    targets: List[str] = []
    for e in _evidence_entries(finding):
        for key in ("matched_at", "url", "host", "target"):
            v = e.get(key)
            if isinstance(v, str) and v:
                targets.append(v)
    t = finding.get("target") or finding.get("url")
    if isinstance(t, str) and t:
        targets.append(t)
    return targets


def _host_in_scope(host_port: str, scope_hosts: List[str]) -> bool:
    """Check a matched 'host:port' (or url) against scope hosts.

    Scope hosts may carry ports ('qosmos.example:443'); a match requires the
    HOST to be in scope AND, when the scope pins a port for that host, the
    matched port to equal it (the :80-vs-:443 problem from the review).
    """
    raw = (host_port or "").strip().lower()
    if raw.startswith("http://") or raw.startswith("https://"):
        p = urlparse(raw)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
    else:
        host = raw.split("/")[0].split(":")[0]
        port_raw = raw.split("/")[0].split(":")
        port = int(port_raw[1]) if len(port_raw) == 2 and port_raw[1].isdigit() else 443
    if not host:
        return True  # nothing to check -> do not reject
    for allowed in scope_hosts:
        a = (allowed or "").strip().lower()
        if not a:
            continue
        if "/" in a:
            a = a.split("/")[0]
        if ":" in a and not a.startswith("["):
            a_host, a_port = a.rsplit(":", 1)
            if a_host == host:
                return port == int(a_port)
        if a == host:
            return True
    return False


# ---------------------------------------------------------------------------
# Gate 1: scope
# ---------------------------------------------------------------------------
def scope_check(finding: Dict[str, Any], scope_hosts: List[str]) -> Tuple[bool, str]:
    """True if every matched target is in scope (and no out_of_scope signal)."""
    for e in _evidence_entries(finding):
        if e.get("out_of_scan_scope") or (e.get("false_positive_signal") or {}).get(
            "out_of_scan_scope"
        ):
            return False, "evidence carries out_of_scan_scope signal"

    def _real(t: str) -> bool:
        # Placeholders must never fabricate a violation: the report path sets
        # target from a missing endpoint_id as "unknown" — found live when all
        # 28 genuinely in-scope findings were discarded on that placeholder.
        return bool(t) and t.strip().lower() not in ("unknown", "n/a", "none")

    matched = [t for t in _matched_targets(finding) if _real(t)]
    if not matched:
        return True, ""  # no real target info -> nothing to violate against
    in_scope = [_host_in_scope(t, scope_hosts) for t in matched]
    if not any(in_scope):
        return False, f"all matched targets outside scope: {matched[0][:80]}"
    return True, ""


# ---------------------------------------------------------------------------
# Gate 2: false-positive signals
# ---------------------------------------------------------------------------
def fp_check(finding: Dict[str, Any]) -> Tuple[bool, str]:
    """True (is FP) when the finding's own evidence refutes/refines the claim."""
    text = _norm_text(finding)
    for e in _evidence_entries(finding):
        if e.get("catch_all") or (e.get("false_positive_signal") or {}).get("catch_all"):
            if any(w in text for w in _WAF_PATTERNS):
                return False, ""  # WAF detection stays a fingerprint observation
            return True, "catch_all response — scanner matched any request"
        fp = e.get("false_positive_signal") or {}
        if fp.get("reason"):
            return True, f"false-positive signal: {str(fp.get('reason'))[:100]}"
    return False, ""


# ---------------------------------------------------------------------------
# Gate 3: evidence-vs-claim consistency (missing security headers)
# ---------------------------------------------------------------------------
def header_claim_check(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """For 'missing security headers' claims: diff the CLAIM against the
    ACTUAL response captured in evidence.

    Returns None when not applicable; else a dict with actually_missing list,
    present list, and a refined claim note. All-headers-present => the claim
    is refuted outright.
    """
    if not any(p in _norm_text(finding) for p in ("missing security headers", "missing-security-headers")):
        return None
    present, missing = [], list(_HEADER_NAMES)
    found_response = False
    for e in _evidence_entries(finding):
        resp = ""
        for key in ("response", "payload", "raw"):
            v = e.get(key)
            if isinstance(v, str) and len(v) > len(resp):
                resp = v
        if not resp:
            continue
        found_response = True
        low = resp.lower()
        for h in _HEADER_NAMES:
            if f"{h}:" in low:
                if h in missing:
                    missing.remove(h)
                if h not in present:
                    present.append(h)
    if not found_response:
        # No parseable response in evidence — the claim can be neither
        # verified nor refuted. Never refine or refute on missing data.
        return None
    return {
        "actual_missing": missing,
        "actual_present": present,
        "claim_refuted": bool(missing) is False,
        "partial": bool(missing) and bool(present),
    }


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def security_class(finding: Dict[str, Any]) -> str:
    text = _norm_text(finding)
    if any(p in text for p in _FINGERPRINT_PATTERNS):
        return C_FINGERPRINT
    if any(p in text for p in _HARDENING_PATTERNS):
        return C_HARDENING
    return C_VALIDATED  # default: a genuine candidate requiring validation


def validate_finding(
    finding: Dict[str, Any], scope_hosts: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Run all gates; annotate the finding dict (in place) with:
    security_class, finding_status, scope_status, fp_probability, notes,
    and (for header claims) the actually-missing list.
    """
    scope_hosts = scope_hosts or []
    notes: List[str] = []

    in_scope, why = scope_check(finding, scope_hosts) if scope_hosts else (True, "")
    is_fp, fp_why = fp_check(finding)
    header = header_claim_check(finding)

    if not in_scope:
        finding["security_class"] = C_OUT_OF_SCOPE
        finding["finding_status"] = "out_of_scope"
        finding["scope_status"] = "out_of_scope"
        finding["fp_probability"] = 0.9
        notes.append(why or "target outside engagement scope")
    elif is_fp:
        finding["security_class"] = C_FALSE_POSITIVE
        finding["finding_status"] = "false_positive"
        finding["scope_status"] = "in_scope"
        finding["fp_probability"] = 0.9
        notes.append(fp_why)
    elif header and header["claim_refuted"]:
        finding["security_class"] = C_FALSE_POSITIVE
        finding["finding_status"] = "false_positive"
        finding["fp_probability"] = 0.95
        notes.append(
            "claim refuted by captured evidence: all checked headers are present"
        )
    else:
        finding["security_class"] = security_class(finding)
        finding["finding_status"] = (
            "verified" if finding["security_class"] == C_VALIDATED else finding["security_class"]
        )
        finding["scope_status"] = "in_scope"
        finding["fp_probability"] = 0.05
        if header and header["partial"]:
            notes.append(
                "claim refined from evidence: partially configured — actually missing: "
                + ", ".join(header["actual_missing"])
            )
            finding["actual_missing_headers"] = header["actual_missing"]

    finding["validation_notes"] = "; ".join(notes) if notes else "passed all validation gates"
    if header and header.get("actual_missing") and not header["claim_refuted"]:
        finding["actual_missing_headers"] = header["actual_missing"]

    if finding.get("security_class") == C_VALIDATED:
        try:
            target_url = str(finding.get("target") or finding.get("endpoint") or "")
            parsed_path = urlparse(target_url).path if target_url else ""
            rule = DefensiveRuleFactory.synthesize_rule(finding, endpoint=parsed_path)
            finding["remediation_rule"] = rule.model_dump()
        except Exception:  # noqa: BLE001 - rule synthesis is best-effort enhancement
            pass

    return finding


# ---------------------------------------------------------------------------
# Finding-aware remediation (replaces the generic fallback)
# ---------------------------------------------------------------------------
def remediation_for(finding: Dict[str, Any]) -> str:
    text = _norm_text(finding)
    cls = finding.get("security_class", C_VALIDATED)

    # Pattern-specific informational remediations win over the generic
    # fingerprint line (e.g. TLS observation gets the verify-baseline advice).
    if "tls version" in text:
        return (
            "Informational protocol observation. Verify TLS 1.0/1.1 are disabled and cipher "
            "suites meet the organization baseline; TLS 1.2/1.3 presence is expected and "
            "requires no action."
        )

    if cls in (C_FINGERPRINT, C_OUT_OF_SCOPE):
        return (
            "Informational asset fingerprint — no remediation required. "
            "Track as attack-surface metadata."
        )
    if cls == C_FALSE_POSITIVE:
        return "None — discarded as a false positive (see validation note)."

    if "missing security headers" in text or "missing-security-headers" in text:
        actual = finding.get("actual_missing_headers")
        if actual:
            return (
                "Add the following response headers (verified absent against the captured "
                f"evidence): {', '.join(actual)}. Example configs — HSTS: "
                "'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'; "
                "X-Content-Type-Options: nosniff; Referrer-Policy: strict-origin-when-cross-origin."
            )
        return (
            "Compare deployed response headers against the organization baseline and add "
            "any verified-missing ones (HSTS, X-Content-Type-Options, X-Frame-Options, "
            "Referrer-Policy, CSP)."
        )
    if "missing subresource integrity" in text or "missing-sri" in text:
        return (
            "Add integrity attributes to externally hosted <script>/<link> tags: "
            "integrity=\"sha384-<hash>\" crossorigin=\"anonymous\". Generate hashes at build "
            "time and cover every third-party origin."
        )
    if "weak content security policy" in text or "weak-csp" in text:
        return (
            "Refine the CSP at directive level: remove 'unsafe-inline' from script-src "
            "(adopt nonces or hashes), restrict default-src/object-src to 'none', and "
            "minimize style-src relaxations. Verify each directive against actual page "
            "requirements before tightening."
        )
    return ""  # fall back to the existing per-vuln_type table (real vulns keep it)


# ---------------------------------------------------------------------------
# Honest taxonomy: fingerprints get NO fake ATT&CK/OWASP
# ---------------------------------------------------------------------------
def taxonomy_gate(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Strip default-mapped ATT&CK/OWASP from non-vulnerability classes so the
    report stops presenting 'uses AWS' as T1190 Exploit Public-Facing App."""
    if finding.get("security_class") in (C_FINGERPRINT, C_OUT_OF_SCOPE, C_FALSE_POSITIVE):
        finding["attack_id"] = None
        finding["attack_name"] = None
        finding["owasp"] = None
    return finding


# ---------------------------------------------------------------------------
# Cross-target correlation (for report presentation)
# ---------------------------------------------------------------------------
def correlate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach affected_targets: same finding family seen on several hosts is
    one issue affecting N targets, not N issues. Merges nothing — only adds
    presentation metadata."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        key = _norm_text(f)[:80]
        groups.setdefault(key, []).append(f)
    for members in groups.values():
        targets = sorted({str(m.get("target") or "") for m in members if m.get("target")})
        for m in members:
            m["affected_targets"] = targets
            m["duplicate_count"] = len(members)
    return findings


# ---------------------------------------------------------------------------
# The honest executive funnel
# ---------------------------------------------------------------------------
def funnel_stats(raw_count: int, findings: List[Dict[str, Any]]) -> Dict[str, int]:
    by_class: Dict[str, int] = {}
    for f in findings:
        c = f.get("security_class", C_VALIDATED)
        by_class[c] = by_class.get(c, 0) + 1
    unique_families = len({ _norm_text(f)[:80] for f in findings })
    return {
        "raw_scanner_signals": raw_count,
        "unique_finding_families": unique_families,
        "validated_vulnerabilities": by_class.get(C_VALIDATED, 0),
        "hardening_items": by_class.get(C_HARDENING, 0),
        "fingerprint_observations": by_class.get(C_FINGERPRINT, 0),
        "out_of_scope": by_class.get(C_OUT_OF_SCOPE, 0),
        "false_positives": by_class.get(C_FALSE_POSITIVE, 0),
    }
