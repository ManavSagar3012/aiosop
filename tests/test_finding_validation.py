"""P0 validation-engine tests (external review 2026-09-02).

The review's single biggest finding: the platform's own evidence already
contained out_of_scan_scope / catch_all / fingerprint signals, but raw
scanner observations still rendered as "Verified Vulnerabilities". These
tests pin the new gates:

  - scope: matched host:port outside scope => OUT_OF_SCOPE (the :80-vs-:443 case)
  - scope: in-scope host with different port rejected when scope pins the port
  - fp: catch_all signal => FALSE_POSITIVE
  - fp: WAF detection with catch_all => stays FINGERPRINT (control observed)
  - fp: out_of_scan_scope evidence signal => OUT_OF_SCOPE
  - evidence-vs-claim: "missing headers" with all headers present => FALSE_POSITIVE
  - evidence-vs-claim: partial headers => refined with the actual missing list
  - classification: AWS/Wappalyzer/SSL/DNS/TLS => FINGERPRINT, not vulnerability
  - classification: missing-headers/SRI/CSP => HARDENING
  - taxonomy: fingerprints get NO ATT&CK/OWASP
  - remediation: finding-aware per class/template; no generic fallback
  - correlation: same family across 2 targets => affected_targets=2
  - funnel: raw 28 -> honest per-class counts
"""

from ai_osop.core.finding_validation import (
    C_FALSE_POSITIVE,
    C_FINGERPRINT,
    C_HARDENING,
    C_OUT_OF_SCOPE,
    C_VALIDATED,
    correlate_findings,
    funnel_stats,
    remediation_for,
    taxonomy_gate,
    validate_finding,
)

SCOPE = ["qosmos.example.com:443", "console.qosmos.example.com:443"]


def _evidence_finding(title, matched_at, **ev_extra):
    return {
        "title": title,
        "vuln_type": "unknown",
        "severity": "info",
        "target": matched_at,
        "evidence": [{"type": "nuclei_finding", "matched_at": matched_at, **ev_extra}],
    }


def test_scope_port_violation_discarded():
    f = _evidence_finding("NS Record Detection", "qosmos.example.com:80")
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_OUT_OF_SCOPE
    assert f["finding_status"] == "out_of_scope"
    assert "outside scope" in f["validation_notes"]


def test_scope_in_match_accepted():
    f = _evidence_finding("Some Finding", "qosmos.example.com:443")
    validate_finding(f, SCOPE)
    assert f["security_class"] != C_OUT_OF_SCOPE
    assert f["scope_status"] == "in_scope"


def test_out_of_scan_scope_signal_discarded():
    f = _evidence_finding(
        "NS Record Detection", "qosmos.example.com",
        out_of_scan_scope=True,
    )
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_OUT_OF_SCOPE


def test_catch_all_is_false_positive():
    f = _evidence_finding("Some Template", "qosmos.example.com", catch_all=True)
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_FALSE_POSITIVE
    assert "catch_all" in f["validation_notes"]


def test_waf_detection_stays_fingerprint():
    f = _evidence_finding("WAF Detection: CloudFront", "qosmos.example.com", catch_all=True)
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_FINGERPRINT  # control observed — useful info, not vuln


def test_header_claim_all_present_refuted():
    resp = (
        "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000\r\n"
        "X-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n"
        "Referrer-Policy: strict-origin\r\nContent-Security-Policy: default-src 'self'\r\n"
        "Permissions-Policy: geolocation=()\r\nX-Permitted-Cross-Domain-Policies: none\r\n"
        "Cross-Origin-Embedder-Policy: require-corp\r\nCross-Origin-Opener-Policy: same-origin\r\n"
        "Cross-Origin-Resource-Policy: same-origin\r\n\r\n<body>"
    )
    f = _evidence_finding("HTTP Missing Security Headers", "qosmos.example.com:443")
    f["evidence"][0]["response"] = resp
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_FALSE_POSITIVE
    assert "refuted" in f["validation_notes"]


def test_header_claim_partial_refined():
    resp = (
        "HTTP/1.1 200 OK\r\nX-Content-Type-Options: nosniff\r\n"
        "Content-Security-Policy: default-src 'self'\r\n\r\n<body>"
    )
    f = _evidence_finding("HTTP Missing Security Headers", "qosmos.example.com:443")
    f["evidence"][0]["response"] = resp
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_HARDENING
    assert "strict-transport-security" in f["actual_missing_headers"]
    assert "x-content-type-options" not in f["actual_missing_headers"]
    assert "partially configured" in f["validation_notes"]
    rem = remediation_for(f)
    assert "strict-transport-security" in rem  # lists the verified-absent ones


def test_header_claim_json_string_evidence_parsed():
    """Regression (found live on the qosmos graph): persisted evidence is a
    JSON-encoded STRING. Unparsed, the check read 'no response' and declared
    every header missing — the exact evidence-vs-claim inconsistency this
    engine exists to catch. Here the response contains ALL headers, so the
    claim must be REFUTED through a JSON-string evidence field."""
    import json

    resp = (
        "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000\r\n"
        "X-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\n"
        "Referrer-Policy: strict-origin\r\nContent-Security-Policy: default-src 'self'\r\n"
        "Permissions-Policy: geolocation=()\r\nX-Permitted-Cross-Domain-Policies: none\r\n"
        "Cross-Origin-Embedder-Policy: require-corp\r\nCross-Origin-Opener-Policy: same-origin\r\n"
        "Cross-Origin-Resource-Policy: same-origin\r\n\r\n<body>"
    )
    f = _evidence_finding("HTTP Missing Security Headers", "qosmos.example.com:443")
    f["evidence"] = json.dumps(
        [{"type": "nuclei_finding", "matched_at": "qosmos.example.com:443", "response": resp}]
    )
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_FALSE_POSITIVE
    assert "refuted" in f["validation_notes"]


def test_header_claim_no_response_never_refutes():
    """No parseable response in evidence => the claim is neither refined nor
    refuted (never invent a verdict from missing data). The finding keeps its
    class without an actual_missing list."""
    f = _evidence_finding("HTTP Missing Security Headers", "qosmos.example.com:443")
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_HARDENING
    assert "actual_missing_headers" not in f
    assert "passed all validation gates" in f["validation_notes"]


def test_fingerprint_classification():
    for title in (
        "AWS Cloudfront service detection",
        "Detect websites using AWS bucket storage",
        "Wappalyzer Technology Detection",
        "Detect SSL Certificate Issuer",
        "SSL DNS Names",
        "TLS Version - Detect",
        "NS Record Detection",
    ):
        f = _evidence_finding(title, "qosmos.example.com:443")
        validate_finding(f, SCOPE)
        assert f["security_class"] == C_FINGERPRINT, title


def test_hardening_classification():
    for title in (
        "HTTP Missing Security Headers",
        "Missing Subresource Integrity",
        "Weak Content Security Policy - Detect",
    ):
        f = _evidence_finding(title, "qosmos.example.com:443")
        validate_finding(f, SCOPE)
        assert f["security_class"] == C_HARDENING, title


def test_real_vuln_stays_validated():
    f = _evidence_finding("SQL Injection in login parameter", "qosmos.example.com:443")
    f["vuln_type"] = "sqli"
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_VALIDATED
    assert f["finding_status"] == "verified"


def test_taxonomy_stripped_for_fingerprints():
    f = _evidence_finding("AWS Service - Detect", "qosmos.example.com:443")
    f["attack_id"] = "T1190"
    f["attack_name"] = "Exploit Public-Facing Application"
    f["owasp"] = "A01:2021-Broken Access Control"
    validate_finding(f, SCOPE)
    taxonomy_gate(f)
    assert f["attack_id"] is None
    assert f["owasp"] is None


def test_remediation_finding_aware():
    fp = _evidence_finding("AWS Cloudfront service detection", "qosmos.example.com:443")
    validate_finding(fp, SCOPE)
    assert "no remediation required" in remediation_for(fp).lower()

    sri = _evidence_finding("Missing Subresource Integrity", "qosmos.example.com:443")
    validate_finding(sri, SCOPE)
    assert "integrity=" in remediation_for(sri)

    csp = _evidence_finding("Weak Content Security Policy - Detect", "qosmos.example.com:443")
    validate_finding(csp, SCOPE)
    assert "unsafe-inline" in remediation_for(csp)

    tls = _evidence_finding("TLS Version - Detect", "qosmos.example.com:443")
    validate_finding(tls, SCOPE)
    assert "tls 1.0" in remediation_for(tls).lower()


def test_correlation_across_targets():
    a = _evidence_finding("HTTP Missing Security Headers", "qosmos.example.com:443")
    b = _evidence_finding("HTTP Missing Security Headers", "console.qosmos.example.com:443")
    b["target"] = "console.qosmos.example.com:443"
    validate_finding(a, SCOPE)
    validate_finding(b, SCOPE)
    correlate_findings([a, b])
    assert a["affected_targets"] == sorted(
        ["qosmos.example.com:443", "console.qosmos.example.com:443"]
    )
    assert a["duplicate_count"] == 2


def test_funnel_counts():
    raw = 28
    findings = []
    for _ in range(14):
        findings.append(_evidence_finding("AWS Cloudfront service detection", "qosmos.example.com:443"))
        findings.append(_evidence_finding("HTTP Missing Security Headers", "qosmos.example.com:443"))
    for f in findings:
        validate_finding(f, SCOPE)
    funnel = funnel_stats(raw_count=raw, findings=findings)
    assert funnel["raw_scanner_signals"] == 28
    assert funnel["fingerprint_observations"] == 14
    assert funnel["hardening_items"] == 14
    assert funnel["validated_vulnerabilities"] == 0
    assert funnel["unique_finding_families"] == 2


def test_placeholder_target_never_fabricates_scope_violation():
    """Regression (found live on the qosmos report): the report path sets
    target="unknown" when endpoint_id is missing. The placeholder must not
    read as an out-of-scope match — the finding stays classifiable by its
    evidence."""
    f = _evidence_finding("AWS Cloudfront service detection", "unknown")
    validate_finding(f, SCOPE)
    assert f["security_class"] != C_OUT_OF_SCOPE
    assert f["security_class"] == C_FINGERPRINT


def test_mixed_targets_in_scope_passes():
    """A real in-scope match alongside a placeholder is NOT a violation."""
    f = {
        "title": "HTTP Missing Security Headers",
        "vuln_type": "unknown",
        "target": "unknown",  # report-path placeholder
        "evidence": [
            {"type": "nuclei_finding", "matched_at": "https://qosmos.example.com/"}
        ],
    }
    validate_finding(f, SCOPE)
    assert f["security_class"] == C_HARDENING
    assert f["scope_status"] == "in_scope"
