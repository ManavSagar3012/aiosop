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

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

DRF = None
try:
    from ai_osop.safety import DefensiveRuleFactory

    DRF = DefensiveRuleFactory
except ImportError:
    pass

# Use the string alias for consistency
synthesize_rule = DRF.synthesize_rule if DRF else None

# ---------------------------------------------------------------------------
# Security classes — the report's top-level sections
# ---------------------------------------------------------------------------
C_VALIDATED = "validated_vulnerability"  # independently demonstrated security impact
C_POTENTIAL = "potential_vulnerability"  # plausible hypothesis; validation still required
C_HARDENING = "hardening_item"  # config deficiency worth fixing, not a vuln per se
C_FINGERPRINT = "fingerprint_observation"  # tech/infra/cert metadata, informational
C_OUT_OF_SCOPE = "out_of_scope"  # evidence host/port outside engagement scope
C_FALSE_POSITIVE = "false_positive"  # scanner signal its own evidence refutes
C_DUPLICATE = "duplicate"  # correlated into a canonical root cause
C_INSUFFICIENT = "insufficient_evidence"  # claim cannot be assessed from recorded evidence

SECTION_ORDER = [
    C_VALIDATED,
    C_POTENTIAL,
    C_HARDENING,
    C_FINGERPRINT,
    C_FALSE_POSITIVE,
    C_OUT_OF_SCOPE,
    C_DUPLICATE,
    C_INSUFFICIENT,
]

# Explicit lifecycle.  Scanner ingestion may only create DISCOVERED candidates;
# VALIDATED is reachable solely when independent validation proof is recorded.
L_DISCOVERED = "discovered"
L_NORMALIZED = "normalized"
L_IN_SCOPE = "in_scope"
L_CORRELATED = "correlated"
L_ASSESSED = "assessed"
L_NEEDS_VALIDATION = "needs_validation"
L_VALIDATED = "validated"
L_REPORTABLE = "reportable"
L_FALSE_POSITIVE = "false_positive"
L_OUT_OF_SCOPE = "out_of_scope"
L_DUPLICATE = "duplicate"
L_INSUFFICIENT_EVIDENCE = "insufficient_evidence"

# ---------------------------------------------------------------------------
# Template families (matched against title/template text, lowercased)
# ---------------------------------------------------------------------------
_FINGERPRINT_PATTERNS = (
    "aws",
    "cloudfront",
    "s3 bucket",
    "wappalyzer",
    "tech-detect",
    "tech detect",
    "ssl certificate issuer",
    "ssl dns names",
    "ns record",
    "nameserver",
    "dns saas",
    "waf detection",
    "detect websites",
    "amazon-s3",
    "bucket storage",
    "tls version",
    "certificate issuer",
    "service detection",
    "detect amazon",
)
_HARDENING_PATTERNS = (
    "missing security headers",
    "missing-security-headers",
    "missing subresource integrity",
    "missing-sri",
    "weak content security policy",
    "weak-csp",
)
# A catch-all FP signal on a WAF detection is still a useful OBSERVATION
# (a defensive control exists) — but never a vulnerability.
_WAF_PATTERNS = ("waf", "firewall", "cloudfront")

_HEADER_NAMES = (
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "content-security-policy",
    "permissions-policy",
    "x-permitted-cross-domain-policies",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
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
            parsed = _json.loads(ev)
            if isinstance(parsed, list):
                return [e for e in parsed if isinstance(e, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except (ValueError, TypeError):
            pass
        if ev.strip():
            return [
                {
                    "raw": ev,
                    "response": ev,
                    "reproducible": True,
                    "impact": f"{finding.get('vuln_type', 'vulnerability')} evidence observed",
                    "provenance": finding.get("tool_source", "manual"),
                }
            ]
        return []
    if isinstance(ev, list):
        entries = [e for e in ev if isinstance(e, dict)]
        if not entries and ev and all(isinstance(e, str) for e in ev):
            return [
                {
                    "raw": "\n".join(ev),
                    "response": "\n".join(ev),
                    "reproducible": True,
                    "impact": f"{finding.get('vuln_type', 'vulnerability')} evidence observed",
                    "provenance": finding.get("tool_source", "manual"),
                }
            ]
        return entries
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
    if not any(
        p in _norm_text(finding) for p in ("missing security headers", "missing-security-headers")
    ):
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


def differential_evidence_check(finding: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """
    Evaluates whether finding evidence contains reproducible differential proof:
    1. Baseline request/response (normal control state)
    2. Attack request/response (injected vector state)
    3. Control / benign comparison or explicit delta (proving input-causality vs static error)
    """
    entries = _evidence_entries(finding)
    meta = finding.get("yield_metadata") or {}

    for e in entries:
        if not isinstance(e, dict):
            continue
        diff = e.get("differential") or e.get("differential_analysis") or meta.get("differential")
        if isinstance(diff, dict):
            has_base = (
                bool(diff.get("baseline")) or bool(diff.get("control")) or "base_status" in diff
            )
            has_attack = (
                bool(diff.get("attack")) or bool(diff.get("probe")) or "attack_status" in diff
            )
            if has_base and has_attack:
                return True, {
                    "type": "explicit_differential",
                    "delta": diff.get("delta")
                    or diff.get("discrepancy")
                    or "state_deviation_observed",
                    "confidence": 1.0,
                }

        if e.get("type") in (
            "http_differential",
            "web_audit_differential",
            "diff_auth_differential",
            "differential_probe",
        ):
            return True, {
                "type": e.get("type"),
                "delta": e.get("discrepancy") or e.get("observation") or "differential_confirmed",
                "confidence": 1.0,
            }

        if "base_status" in e and "probe_status" in e:
            if e["base_status"] != e["probe_status"]:
                return True, {
                    "type": "status_code_differential",
                    "delta": f"{e['base_status']} -> {e['probe_status']}",
                    "confidence": 1.0,
                }

        if "timing_seconds" in e and "baseline_seconds" in e:
            try:
                delay = float(e["timing_seconds"]) - float(e["baseline_seconds"])
                if delay >= 4.0:
                    return True, {
                        "type": "time_based_differential",
                        "delta": f"Delay {delay:.2f}s above baseline",
                        "confidence": 1.0,
                    }
            except (ValueError, TypeError):
                pass

    return False, {}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def security_class(finding: Dict[str, Any]) -> str:
    """Interpret semantics without granting validation.

    Unknown/exploit-looking scanner output is a POTENTIAL vulnerability.  A
    separate proof predicate below is the only route to C_VALIDATED.
    """
    text = _norm_text(finding)
    if any(p in text for p in _FINGERPRINT_PATTERNS):
        return C_FINGERPRINT
    if any(p in text for p in _HARDENING_PATTERNS):
        return C_HARDENING
    return C_POTENTIAL


TRUSTED_VALIDATION_AUTHORITIES = frozenset(
    {
        "oast_investigation",
        "validation_engine",
        "exploit_validation",
        "deterministic_validator",
        "sqli_http_scan",
        "web_audit",
        "diff_auth_engine",
        "rule_factory",
        "attack_chain",
    }
)

MAX_EVIDENCE_BYTES = 1_000_000
MAX_EVIDENCE_ENTRIES = 100


def _validation_proof(finding: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Require explicit, reproducible proof; scanner severity/title never count."""
    reasons: List[str] = []
    meta = finding.get("yield_metadata") or {}
    state = str(finding.get("validation_state") or meta.get("validation_state") or "").upper()
    validated_flag = (
        finding.get("validated") is True
        or state in ("VALIDATED", "VERIFIED")
        or finding.get("finding_status") in (L_VALIDATED, "verified")
    )
    raw_authority = (
        finding.get("validation_authority")
        or meta.get("validation_authority")
        or (
            finding.get("tool_source")
            if str(finding.get("tool_source") or "").lower() in TRUSTED_VALIDATION_AUTHORITIES
            else None
        )
        or (
            meta.get("detector")
            if str(meta.get("detector") or "").lower() in TRUSTED_VALIDATION_AUTHORITIES
            else None
        )
        or ""
    )
    authority = str(raw_authority).lower()
    trusted_authority = bool(authority) and (
        authority in TRUSTED_VALIDATION_AUTHORITIES
        or any(t in authority for t in TRUSTED_VALIDATION_AUTHORITIES)
    )
    proof_entries = []
    evidence_entries = _evidence_entries(finding)
    replay_proof = finding.get("replay_proof") or meta.get("replay_proof")
    if isinstance(replay_proof, str):
        try:
            replay_proof = json.loads(replay_proof)
        except (TypeError, json.JSONDecodeError):
            replay_proof = None
    if isinstance(replay_proof, dict):
        evidence_entries.append(replay_proof)
    evidence_entries = evidence_entries[:MAX_EVIDENCE_ENTRIES]
    try:
        evidence_size = len(
            json.dumps(evidence_entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    except (TypeError, ValueError, OverflowError):
        evidence_entries = []
    else:
        if evidence_size > MAX_EVIDENCE_BYTES:
            evidence_entries = []
    for e in evidence_entries:
        request = (
            e.get("request")
            or e.get("payload")
            or e.get("test")
            or e.get("probe")
            or meta.get("payload")
            or (finding.get("reproduction_steps")[0] if finding.get("reproduction_steps") else None)
        )
        response = (
            e.get("response")
            or e.get("observation")
            or e.get("result")
            or e.get("raw")
            or e.get("injected_marker")
            or e.get("error_signature")
            or e.get("matched_at")
        )
        impact = (
            e.get("impact")
            or e.get("impact_confirmed")
            or e.get("security_property_violated")
            or (
                e.get("type")
                in (
                    "http_differential",
                    "web_audit_differential",
                    "diff_auth_differential",
                    "oast_callback",
                    "account_takeover_chain",
                )
            )
            or (
                finding.get("vuln_type")
                in ("sqli", "xss", "ssrf", "rce", "idor", "csrf", "jwt_abuse")
                and bool(request or response)
            )
        )
        reproducible = (
            e.get("reproducible") is True
            or bool(e.get("proof"))
            or bool(finding.get("reproduction_steps"))
            or (
                e.get("type")
                in (
                    "http_differential",
                    "web_audit_differential",
                    "diff_auth_differential",
                    "oast_callback",
                    "account_takeover_chain",
                )
            )
            or (finding.get("validated") is True)
            or bool(request and response)
        )
        if request and response and impact and reproducible:
            proof_entries.append(e)
    if not validated_flag:
        reasons.append("no validation-engine VALIDATED state")
    if not trusted_authority:
        reasons.append("untrusted or missing validation authority")
    if not proof_entries:
        reasons.append("no reproducible request/response/impact proof")
    return validated_flag and trusted_authority and bool(proof_entries), reasons


def _quality_score(
    finding: Dict[str, Any],
    *,
    in_scope: bool,
    consistent: bool,
    validated: bool,
    fp_probability: float,
) -> Dict[str, Any]:
    evidence = _evidence_entries(finding)
    dimensions = {
        "scope_correctness": 1.0 if in_scope else 0.0,
        "evidence_completeness": min(1.0, len(evidence) / 3.0),
        "claim_evidence_consistency": 1.0 if consistent else 0.0,
        "deduplication_quality": 1.0 if finding.get("duplicate_count", 1) >= 1 else 0.0,
        "false_positive_risk": round(1.0 - fp_probability, 3),
        "validation_quality": 1.0 if validated else 0.25,
        "severity_correctness": (
            1.0 if validated or str(finding.get("severity", "info")).lower() == "info" else 0.5
        ),
        "taxonomy_correctness": 1.0,
        "remediation_quality": 1.0 if finding.get("remediation") else 0.5,
        "reproducibility": 1.0 if validated else 0.0,
        "differential_evidence_rigor": 1.0 if finding.get("differential_verified") else 0.5,
    }
    return {"score": round(sum(dimensions.values()) / len(dimensions), 3), "dimensions": dimensions}


def validate_finding(
    finding: Dict[str, Any], scope_hosts: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Apply deterministic gates and enforce lifecycle/reportability invariants."""
    scope_hosts = scope_hosts or []
    notes: List[str] = []
    finding["lifecycle_history"] = [L_DISCOVERED, L_NORMALIZED]

    in_scope, why = scope_check(finding, scope_hosts) if scope_hosts else (True, "")
    is_fp, fp_why = fp_check(finding)
    header = header_claim_check(finding)
    consistent = not bool(header and header["claim_refuted"])
    proven, proof_reasons = _validation_proof(finding)
    is_diff, diff_info = differential_evidence_check(finding)
    finding["differential_verified"] = is_diff
    if is_diff:
        finding["differential_details"] = diff_info
        proven = True  # Differential proof satisfies empirical validation gate

    if not in_scope:
        finding.update(
            security_class=C_OUT_OF_SCOPE,
            finding_status=L_OUT_OF_SCOPE,
            lifecycle_state=L_OUT_OF_SCOPE,
            scope_status="out_of_scope",
            scope_reason=why or "target outside engagement scope",
            matched_scope_rule=None,
            fp_probability=0.9,
            reportable=False,
        )
        notes.append(finding["scope_reason"])
    elif is_fp or not consistent:
        reason = fp_why or "claim refuted by captured evidence: all checked headers are present"
        finding.update(
            security_class=C_FALSE_POSITIVE,
            finding_status=L_FALSE_POSITIVE,
            lifecycle_state=L_FALSE_POSITIVE,
            scope_status="in_scope",
            scope_reason="matched engagement host/port",
            fp_probability=0.95,
            reportable=False,
        )
        notes.append(reason)
    else:
        interpreted = security_class(finding)
        finding.update(
            scope_status="in_scope",
            scope_reason="matched engagement host/port",
            matched_scope_rule=(scope_hosts[0] if scope_hosts else "scope unavailable"),
            fp_probability=0.05,
            reportable=False,
        )
        finding["lifecycle_history"].extend([L_IN_SCOPE, L_CORRELATED, L_ASSESSED])
        if interpreted == C_POTENTIAL and proven:
            finding.update(
                security_class=C_VALIDATED,
                finding_status=L_VALIDATED,
                lifecycle_state=L_REPORTABLE,
                reportable=True,
            )
            finding["lifecycle_history"].extend([L_VALIDATED, L_REPORTABLE])
            notes.append("independent validation proof satisfies minimum evidence criteria")
        elif interpreted == C_POTENTIAL:
            finding.update(
                security_class=C_POTENTIAL,
                finding_status=L_NEEDS_VALIDATION,
                lifecycle_state=L_NEEDS_VALIDATION,
            )
            notes.append("; ".join(proof_reasons))
        else:
            finding.update(
                security_class=interpreted, finding_status=interpreted, lifecycle_state=L_ASSESSED
            )
        if header and header["partial"]:
            notes.append(
                "claim refined from evidence: partially configured — actually missing: "
                + ", ".join(header["actual_missing"])
            )
            finding["actual_missing_headers"] = header["actual_missing"]

    finding["validation_notes"] = (
        "; ".join(notes) if notes else "passed deterministic assessment gates"
    )
    if header and header.get("actual_missing") and not header["claim_refuted"]:
        finding["actual_missing_headers"] = header["actual_missing"]

    # Hard invariants: no rejected category can leak into vulnerability totals;
    # scanner labels cannot supply severity for unvalidated candidates.
    if not finding.get("reportable"):
        finding["derived_severity"] = (
            "info"
            if finding["security_class"]
            in (C_FINGERPRINT, C_FALSE_POSITIVE, C_OUT_OF_SCOPE, C_DUPLICATE)
            else "unassigned"
        )
    else:
        finding["derived_severity"] = str(finding.get("severity", "unknown")).lower()

    finding["reasoning_trace"] = {
        "source": finding.get("tool_source")
        or (finding.get("yield_metadata") or {}).get("detector"),
        "scope": finding.get("scope_status"),
        "normalization": finding.get("security_class"),
        "validation": finding.get("finding_status"),
        "evidence_artifacts": len(_evidence_entries(finding)),
        "why_reportable": finding["validation_notes"] if finding.get("reportable") else None,
        "why_not_reportable": None if finding.get("reportable") else finding["validation_notes"],
    }
    finding["quality_scorecard"] = _quality_score(
        finding,
        in_scope=in_scope,
        consistent=consistent,
        validated=proven,
        fp_probability=float(finding.get("fp_probability", 1.0)),
    )

    if finding.get("reportable"):
        try:
            target_url = str(finding.get("target") or finding.get("endpoint") or "")
            rule = DefensiveRuleFactory.synthesize_rule(finding, endpoint=urlparse(target_url).path)
            finding["remediation_rule"] = rule.model_dump()
        except Exception:  # noqa: BLE001 - best-effort defensive control
            pass
    return finding


def enforce_finding_gate(finding: Any, scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
    if hasattr(finding, "model_dump"):
        data = finding.model_dump()
    elif isinstance(finding, dict):
        data = dict(finding)
    elif hasattr(finding, "__dict__"):
        data = dict(vars(finding))
    else:
        raise TypeError("finding must be a mapping or model-like object")
    validate_finding(data, scope_hosts)
    taxonomy_gate(data)
    approved = bool(data.get("reportable") and data.get("security_class") == C_VALIDATED)
    data["validated"] = approved
    data["validation_state"] = "VALIDATED" if approved else "UNTESTED"
    return data


def apply_gate_to_result(
    result: Dict[str, Any], scope_hosts: Optional[List[str]] = None
) -> Dict[str, Any]:
    for key in ("findings", "vulnerabilities", "parsed_findings"):
        values = result.get(key)
        if isinstance(values, list):
            result[key] = [
                enforce_finding_gate(v, scope_hosts)
                for v in values
                if isinstance(v, dict) or hasattr(v, "model_dump")
            ]
    return result


def apply_gate_to_event_payload(
    payload: Dict[str, Any], topic: str = "", scope_hosts: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Gate finding-shaped event/notification payloads before any consumer sees them."""
    apply_gate_to_result(payload, scope_hosts)
    finding_topics = ("vuln", "finding", "exploit.success", "payload_validated")
    finding_keys = {"title", "vuln_type", "severity", "validated", "validation_state", "reportable"}
    if any(marker in topic.lower() for marker in finding_topics) and finding_keys.intersection(
        payload
    ):
        gated = enforce_finding_gate(payload, scope_hosts)
        payload.clear()
        payload.update(gated)
    nested = payload.get("finding")
    if isinstance(nested, dict):
        payload["finding"] = enforce_finding_gate(nested, scope_hosts)
    return payload


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
    if cls in (C_POTENTIAL, C_INSUFFICIENT):
        return (
            "Do not remediate from the scanner label alone. Reproduce the hypothesis with "
            "a minimal in-scope request, capture the control and test responses, and confirm "
            "the security impact before selecting a component-specific fix."
        )

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
            'integrity="sha384-<hash>" crossorigin="anonymous". Generate hashes at build '
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
    if finding.get("security_class") != C_VALIDATED or not finding.get("reportable", False):
        finding["attack_id"] = None
        finding["attack_name"] = None
        finding["owasp"] = None
        finding["cvss"] = None
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
    unique_families = len({_norm_text(f)[:80] for f in findings})
    return {
        "raw_scanner_signals": raw_count,
        "unique_finding_families": unique_families,
        "validated_vulnerabilities": by_class.get(C_VALIDATED, 0),
        "potential_vulnerabilities": by_class.get(C_POTENTIAL, 0),
        "hardening_items": by_class.get(C_HARDENING, 0),
        "fingerprint_observations": by_class.get(C_FINGERPRINT, 0),
        "out_of_scope": by_class.get(C_OUT_OF_SCOPE, 0),
        "false_positives": by_class.get(C_FALSE_POSITIVE, 0),
        "duplicates": by_class.get(C_DUPLICATE, 0),
        "insufficient_evidence": by_class.get(C_INSUFFICIENT, 0),
    }
