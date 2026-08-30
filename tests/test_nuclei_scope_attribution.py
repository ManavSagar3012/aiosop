"""Scope-attribution FP triage for nuclei findings (AIOSOP-FP-SCOPE-ATTRIB-001).

Regression coverage for the live 2026-08-30 incident: critical Redis CVE
templates matched a REAL but unscoped sibling service (127.0.0.1:6379 — another
project's Redis) while the engagement target was 127.0.0.1:80, and the findings
were persisted as engagement criticals. The scan loop must now down-rank any
finding whose matched endpoint is not one of the scoped targets' endpoints,
preserving the evidence with a transparent out_of_scan_scope signal.
"""

from ai_osop.agents.vuln_agent import VulnAnalysisAgent
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability


def _agent() -> VulnAnalysisAgent:
    return VulnAnalysisAgent.__new__(VulnAnalysisAgent)


def _vuln(matched_at: str, confidence: float = 0.9) -> Vulnerability:
    return Vulnerability(
        cwe=None,
        vuln_type=VulnClass.RCE,
        severity=Severity.CRITICAL,
        title="Redis < 8.2.1 lua script - Integer Overflow",
        description="Redis CVE description",
        evidence=[
            {
                "type": "nuclei_finding",
                "template": "CVE-2025-46817",
                "matched_at": matched_at,
                "url": matched_at,
            }
        ],
        tool_source="nuclei",
        confidence=confidence,
        exploitability="high",
        engagement_id="eng-test",
    )


# ---- endpoint extraction --------------------------------------------------- #


def test_scoped_endpoints_from_urls_and_bare_hosts():
    a = _agent()
    eps = a._scoped_target_endpoints(["http://127.0.0.1:80", "http://127.0.0.1"])
    assert ("127.0.0.1", 80) in eps
    # bare host normalizes to the http default port
    assert a._scoped_target_endpoints(["127.0.0.1"]) == {("127.0.0.1", 80)}
    assert a._scoped_target_endpoints(["https://example.com"]) == {("example.com", 443)}


def test_scoped_endpoints_ignore_garbage():
    a = _agent()
    assert a._scoped_target_endpoints([None, "", "  ", "http://", "http://[bad"]) == set()


# ---- downrank behavior (the live Redis incident) --------------------------- #


def test_unscoped_service_match_is_downranked():
    """Live incident: scoped target :80, finding matched on :6379 (sibling Redis)."""
    a = _agent()
    scoped = a._scoped_target_endpoints(["http://127.0.0.1:80"])
    v = _vuln("127.0.0.1:6379", confidence=0.9)
    a._apply_out_of_scan_scope_downrank(v, scoped)
    assert v.confidence <= 0.2
    assert v.exploitability == "low"
    signal = v.evidence[0]["false_positive_signal"]
    assert signal["out_of_scan_scope"] is True
    assert signal["matched_endpoint"] == "127.0.0.1:6379"
    assert "127.0.0.1:80" in signal["scoped_endpoints"]


def test_scoped_endpoint_match_is_untouched():
    a = _agent()
    scoped = a._scoped_target_endpoints(["http://127.0.0.1:80"])
    v = _vuln("127.0.0.1:80", confidence=0.9)
    a._apply_out_of_scan_scope_downrank(v, scoped)
    assert v.confidence == 0.9
    assert v.exploitability == "high"
    assert "false_positive_signal" not in v.evidence[0]


def test_scheme_default_port_matches_explicit():
    """http://host (no port) must be treated as host:80 so real matches survive."""
    a = _agent()
    scoped = a._scoped_target_endpoints(["http://127.0.0.1"])
    v = _vuln("127.0.0.1:80", confidence=0.9)
    a._apply_out_of_scan_scope_downrank(v, scoped)
    assert v.confidence == 0.9  # not downranked


def test_no_matched_at_is_untouched():
    a = _agent()
    v = _vuln("")
    a._apply_out_of_scan_scope_downrank(v, {("127.0.0.1", 80)})
    assert v.confidence == 0.9
    assert "false_positive_signal" not in v.evidence[0]


def test_non_numeric_port_does_not_raise():
    """urlparse raises on non-numeric ports; the helper must swallow it."""
    a = _agent()
    v = _vuln("127.0.0.1:notaport")
    a._apply_out_of_scan_scope_downrank(v, {("127.0.0.1", 80)})  # must not raise
    assert v.confidence == 0.9  # unparseable -> untouched, never crashes the scan


def test_empty_evidence_is_untouched():
    a = _agent()
    v = _vuln("127.0.0.1:6379")
    v.evidence = []
    a._apply_out_of_scan_scope_downrank(v, {("127.0.0.1", 80)})  # must not raise


def test_confidence_never_raised_by_downrank():
    """A finding already below the floor stays at its original (lower) value."""
    a = _agent()
    v = _vuln("127.0.0.1:6379", confidence=0.1)
    a._apply_out_of_scan_scope_downrank(v, {("127.0.0.1", 80)})
    assert v.confidence == 0.1
