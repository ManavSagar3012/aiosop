from ai_osop.core.bounty_report import finding_signature, render_bounty_report
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability


def _vuln(**over):
    base = dict(
        vuln_type=VulnClass.SSRF,
        severity=Severity.HIGH,
        cwe="CWE-918",
        title="Blind SSRF via imageUrl",
        description="Server fetched attacker URL.",
        evidence=[
            {
                "type": "ssrf_callback",
                "url": "http://t/profile/image/url",
                "injection": "imageUrl",
                "interaction": {"method": "GET", "path": "/abc"},
            }
        ],
        tool_source="oast_ssrf",
        confidence=0.97,
        validated=True,
        engagement_id="e1",
    )
    base.update(over)
    return Vulnerability(**base)


def test_signature_is_stable_for_same_finding():
    a = _vuln()
    b = _vuln()
    assert finding_signature(a) == finding_signature(b)


def test_signature_differs_by_endpoint():
    a = _vuln(evidence=[{"url": "http://t/a", "injection": "x"}])
    b = _vuln(evidence=[{"url": "http://t/b", "injection": "x"}])
    assert finding_signature(a) != finding_signature(b)


def test_report_has_core_sections():
    md = render_bounty_report(_vuln())
    for section in (
        "# ",
        "## Summary",
        "## Steps to Reproduce",
        "## Impact",
        "## Evidence",
        "## Remediation",
        "Severity",
    ):
        assert section in md, f"missing section: {section}"
    assert "CWE-918" in md


def test_report_redacts_nothing_extra_but_keeps_evidence():
    md = render_bounty_report(_vuln())
    assert "imageUrl" in md  # the injection point should be shown for repro


def test_report_for_secret_uses_redacted_value():
    v = _vuln(
        vuln_type=VulnClass.EXPOSED_SECRET,
        cwe="CWE-798",
        title="Live github credential",
        evidence=[
            {
                "type": "live_credential",
                "provider": "github",
                "secret_redacted": "ghp_...00 (len 40)",
                "verify_status": 200,
            }
        ],
    )
    md = render_bounty_report(v)
    assert "ghp_...00" in md and "github" in md
