"""Tests for the Finding Intelligence Layer (Phase 1).

Operator directive: no scanner output becomes a real finding until classified,
deduplicated to a root-cause identity, and evidence-preserving. Proven here:
  * duplicate observations (http/https/trailing-slash variants) collapse to ONE
    canonical finding with UNIONED evidence
  * WAF/TLS/Wappalyzer/AWS detections classify as OBSERVATION
  * missing-header/CSP/SRI classify as WEAKNESS
  * sqli/xss/ssrf classify as VULNERABILITY
  * correlated_ids preserve every merged member (full traceability)
"""

import pytest

from ai_osop.core.config import VulnClass, Severity
from ai_osop.core.models import Vulnerability
from ai_osop.core.finding_intelligence import (
    CLASS_OBSERVATION,
    CLASS_WEAKNESS,
    CLASS_VULNERABILITY,
    classify_finding,
    deduplicate_findings,
    finding_fingerprint,
)


def _vuln(
    title: str,
    vuln_type=VulnClass.UNKNOWN,
    url=None,
    detector="nuclei",
    template_id="",
    severity=Severity.INFO,
    confidence=0.5,
    evidence=None,
) -> Vulnerability:
    v = Vulnerability(
        title=title,
        description=title,
        vuln_type=vuln_type,
        severity=severity,
        tool_source="nuclei",
        engagement_id="eng-fit",
        confidence=confidence,
        evidence=evidence or [],
    )
    v.yield_metadata = {"detector": detector, "template_id": template_id}
    if url:
        v.yield_metadata["url"] = url
    return v


class TestClassification:
    def test_waf_tls_tech_aws_are_observations(self):
        for t in (
            "WAF Detection",
            "TLS Version - Detect",
            "Wappalyzer Technology Detection",
            "AWS S3 Bucket Detection",
            "CloudFront CDN detected",
        ):
            assert classify_finding(_vuln(t)) == CLASS_OBSERVATION, t

    def test_headers_csp_sri_are_weaknesses(self):
        for t in (
            "HTTP Missing Security Headers",
            "Weak CSP policy",
            "Missing Subresource Integrity",
        ):
            assert classify_finding(_vuln(t)) == CLASS_WEAKNESS, t

    def test_exploit_classes_are_vulnerabilities(self):
        for t in (
            "SQL Injection",
            "Reflected XSS",
            "SSRF possible",
            "Broken Access Control / IDOR",
        ):
            assert classify_finding(_vuln(t)) == CLASS_VULNERABILITY, t


class TestFingerprint:
    def test_scheme_port_slash_variants_share_identity(self):
        base = _vuln("Weak CSP", url="http://target.example")
        variants = [
            _vuln("Weak CSP", url="https://target.example"),
            _vuln("Weak CSP", url="https://target.example:443/"),
            _vuln("Weak CSP", url="http://target.example/?utm=x"),
        ]
        fp0 = finding_fingerprint(base)
        for v in variants:
            assert finding_fingerprint(v) == fp0

    def test_different_rootcauses_differ(self):
        a = finding_fingerprint(_vuln("Weak CSP", url="http://t.example"))
        b = finding_fingerprint(_vuln("Missing Security Headers", url="http://t.example"))
        assert a != b


class TestDeduplication:
    def test_duplicates_merge_and_union_evidence(self):
        raw = [
            _vuln(
                "Missing Security Headers",
                url="http://qosmos.qnulabs.com",
                evidence=[{"header": "X-Frame-Options"}],
            ),
            _vuln(
                "Missing Security Headers",
                url="https://qosmos.qnulabs.com/",
                evidence=[{"header": "Content-Security-Policy"}],
            ),
            _vuln(
                "Missing Security Headers",
                url="http://qosmos.qnulabs.com/",
                evidence=[{"header": "X-Frame-Options"}],
            ),  # exact dup evidence
        ]
        canonical, stats = deduplicate_findings(raw)

        assert stats["observations_in"] == 3
        assert stats["canonical_out"] == 1
        assert stats["merged_away"] == 2
        rep = canonical[0]
        assert len(rep.evidence) == 2, "evidence unioned, exact dup dropped"
        assert {h["header"] for h in rep.evidence} == {"X-Frame-Options", "Content-Security-Policy"}
        assert rep.yield_metadata["observation_count"] == 3
        assert len(rep.yield_metadata["merged_observation_ids"]) == 2
        # full traceability: all three original ids present
        assert len(rep.correlated_ids) == 3

    def test_distinct_findings_survive(self):
        raw = [
            _vuln("Missing Security Headers", url="http://t.example"),
            _vuln("Weak CSP", url="http://t.example"),
            _vuln("SQL Injection", url="http://t.example/login", vuln_type=VulnClass.SQLI),
        ]
        canonical, stats = deduplicate_findings(raw)
        assert stats["canonical_out"] == 3

    def test_representative_is_most_severe(self):
        raw = [
            _vuln(
                "SQLi",
                vuln_type=VulnClass.SQLI,
                severity=Severity.MEDIUM,
                confidence=0.6,
                url="http://t.example/p",
            ),
            _vuln(
                "SQLi",
                vuln_type=VulnClass.SQLI,
                severity=Severity.HIGH,
                confidence=0.9,
                url="http://t.example/p",
            ),
        ]
        canonical, _ = deduplicate_findings(raw)
        assert str(canonical[0].severity.value) == "high"
