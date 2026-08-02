"""Vuln-agent coverage tests for the deterministic payload-injection seams."""

import pytest

from ai_osop.agents.vuln_agent import VulnAnalysisAgent


def test_inject_payload_replaces_marker():
    out = VulnAnalysisAgent._inject_payload("http://t?q=OSOPINJECT", "' OR 1=1--")
    assert out == "http://t?q=%27%20OR%201%3D1--"


def test_inject_payload_uses_last_existing_param_when_no_hint():
    """Falls into the last existing query param when no param name is given."""
    out = VulnAnalysisAgent._inject_payload("http://t/search?a=1", "<b>x</b>")
    assert out == "http://t/search?a=%3Cb%3Ex%3C%2Fb%3E"


def test_inject_payload_handles_spa_hash_route():
    """SPA fragment query must stay in the fragment (this is the Juice Shop attack surface)."""
    out = VulnAnalysisAgent._inject_payload("http://t/#/search?q=test", "' OR 1=1--")
    assert "#" in out and "q=" in out
    assert out.startswith("http://t/#/search")


def test_inject_payload_uses_explicit_param_when_given():
    out = VulnAnalysisAgent._inject_payload("http://t?a=1&b=2", "PAYLOAD", param="b")
    parsed = out.split("?", 1)[1]
    assert "b=PAYLOAD" in parsed and "a=1" in parsed


def test_redact_secret_masks_value():
    assert VulnAnalysisAgent._redact_secret("sk_live_abcdefghijklmnop1234") != "sk_live_abcdefghijklmnop1234"
    assert VulnAnalysisAgent._redact_secret("") == ""


def test_vulnerability_model_serializes_for_persistence():
    """A representative scan finding must survive JSON round-trip at the persistence boundary."""
    from ai_osop.core.enums import Severity, VulnClass
    from ai_osop.core.models import Vulnerability

    vuln = Vulnerability(
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        title="SQLi",
        description="d",
        tool_source="sqlmap",
        confidence=0.9,
        engagement_id="eng-1",
        endpoint_id="e-1",
    )
    dump = vuln.model_dump(mode="json")
    assert dump["vuln_type"] == "sqli"
    assert dump["severity"] == "high"
