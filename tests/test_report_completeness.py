"""M5: report completeness contract (gap-analysis item M5).

The gap audit (docs/BUG_BOUNTY_READINESS_GAPS.md, M5) flagged that
``core/bounty_report.py`` / ``poc_generator.py`` produce reports, but their
COMPLETENESS was the reporting agent's remit and that audit died on quota.
Before trusting report output for submission, pin the contract a triager-
grade report MUST satisfy:

  1. Every validated finding renders a report with the triager-required
     sections: Summary, Steps to Reproduce, PoC, Impact, Evidence,
     Remediation — and a header carrying Title / Severity / CWE / dedup
     signature / validated-status.
  2. The PoC section is non-empty for every confirmed class (a report
     without a copy-pasteable PoC is a report that gets rejected).
  3. The evidence section carries the actual confirmation artifact (the
     objective signal that made the finding CONFIRMED), not an empty list.
  4. A simulated/mock finding renders as the SIMULATED placeholder, never
     as a submittable report — defense-in-depth at the report layer.
  5. CVSS is surfaced in the header (rough representative vector today;
     computed vector when cvss_score is set on the finding).

These tests run hermetically against synthetic Vulnerability fixtures, so a
regression in any report section (a missing template branch, a renamed
field, a PoC generator that returns "") surfaces as a failing test before
it reaches a triager.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from ai_osop.core.bounty_report import finding_signature, render_bounty_report
from ai_osop.core.config import Severity, VulnClass
from ai_osop.core.models import Vulnerability


def _vuln(
    *,
    vtype: VulnClass = VulnClass.SQLI,
    severity: Severity = Severity.HIGH,
    cwe: str = "CWE-89",
    title: str = "SQL Injection in login",
    description: str = "Authenticated SQL injection at /rest/user/login.",
    evidence: List[Dict[str, Any]] | None = None,
    validated: bool = True,
    tool_source: str = "sqlmap",
    confidence: float = 0.95,
    simulated: bool = False,
) -> Vulnerability:
    if evidence is None:
        evidence = [
            {
                "type": "sqlmap_injection",
                "provenance": "sqlmap",
                "url": "http://target.test/rest/user/login",
                "parameter": "email",
                "dbms": "SQLite",
                "payloads": ["' OR 1=1--"],
                "techniques": ["boolean-blind"],
                "request": {"method": "POST", "url": "/rest/user/login", "body": "email=x&password=y"},
                "response": {"status": 200, "body_snippet": "...authenticated..."},
            }
        ]
    return Vulnerability(
        cwe=cwe,
        vuln_type=vtype,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        tool_source=tool_source,
        confidence=confidence,
        validated=validated,
        exploitability="high",
        impact="high",
        engagement_id="juice-e2e-canonical",
        simulated=simulated,
    )


_REQUIRED_SECTIONS = (
    "# ",
    "## Summary",
    "## Steps to Reproduce",
    "## Proof of Concept",
    "## Impact",
    "## Evidence",
    "## Remediation",
)
_REQUIRED_HEADER_KEYS = (
    "**Severity:**",
    "**Weakness:**",
    "**Dedup signature:**",
    "**Status:**",
)


def test_validated_finding_renders_all_triager_sections():
    """A CONFIRMED SQLi finding must render every triager-required section +
    header key. A missing section => a triager rejects the report."""
    report = render_bounty_report(_vuln())
    for section in _REQUIRED_SECTIONS:
        assert section in report, f"report missing section {section!r}"
    for key in _REQUIRED_HEADER_KEYS:
        assert key in report, f"report header missing key {key!r}"
    # The validated status line must reflect the finding's validation state.
    assert "Validated (active confirmation)" in report


@pytest.mark.parametrize(
    "vtype,cwe,evidence",
    [
        (
            VulnClass.SQLI, "CWE-89",
            [{"type": "sqlmap_injection", "provenance": "sqlmap",
              "url": "http://t.test/api/login", "parameter": "email",
              "dbms": "SQLite", "payloads": ["' OR 1=1--"]}],
        ),
        (
            VulnClass.XSS, "CWE-79",
            [{"type": "xss_execution", "provenance": "browser",
              "url": "http://t.test/search", "parameter": "q",
              "method": "browser-eval", "payload": "<script>alert(1)</script>"}],
        ),
        (
            VulnClass.SSRF, "CWE-918",
            [{"type": "ssrf_oast", "provenance": "oast",
              "url": "http://t.test/fetch", "injection": "url",
              "interaction": {"method": "GET", "path": "/probe"}}],
        ),
        (
            VulnClass.JWT_ABUSE, "CWE-347",
            [{"type": "jwt_forgery", "provenance": "jwt_tester",
              "url": "http://t.test/me", "technique": "alg_none",
              "victim": "admin@target.test"}],
        ),
        (
            VulnClass.MASS_ASSIGNMENT, "CWE-915",
            [{"type": "mass_assignment", "provenance": "http",
              "url": "http://t.test/api/Users", "accepted_fields": {"role": "admin"}}],
        ),
        (
            VulnClass.RACE_CONDITION, "CWE-362",
            [{"type": "race_limit", "provenance": "turbo_intruder",
              "url": "http://t.test/api/basket", "limit": 1, "observed_successes": 20}],
        ),
    ],
)
def test_every_confirmed_class_renders_nonempty_poc(vtype, cwe, evidence):
    """Every CONFIRMED vuln class must render a NON-EMPTY PoC section. A report
    with an empty PoC is the textbook 'unreproducible' rejection."""
    vuln = _vuln(vtype=vtype, cwe=cwe, evidence=evidence, title=f"{vtype.value} finding")
    report = render_bounty_report(vuln)
    assert "## Proof of Concept" in report
    # Extract the PoC section body (between the PoC header and the next ## ).
    start = report.index("## Proof of Concept") + len("## Proof of Concept")
    end = report.index("## Impact", start)
    poc_body = report[start:end].strip()
    assert poc_body, f"PoC section is empty for {vtype.value}"
    # The PoC must contain either a curl command, a script, or a concrete
    # reproduction artifact — not just prose.
    assert any(
        marker in poc_body.lower()
        for marker in ("curl", "```", "payload", "request", "step", "send")
    ), f"PoC for {vtype.value} has no copy-pasteable artifact: {poc_body[:200]!r}"


def test_evidence_section_carries_confirmation_artifact():
    """The Evidence section must carry the actual confirmation artifact (the
    objective signal that made the finding CONFIRMED), not an empty list.
    This is the difference between 'I claim this is a bug' and 'here is the
    proof'."""
    ev = [
        {
            "type": "sqlmap_injection",
            "provenance": "sqlmap",
            "url": "http://target.test/rest/user/login",
            "parameter": "email",
            "dbms": "SQLite",
            "payloads": ["' OR 1=1--"],
            "techniques": ["boolean-blind"],
        }
    ]
    report = render_bounty_report(_vuln(evidence=ev))
    # The evidence dict must be JSON-serialized into the Evidence section.
    assert "```json" in report
    assert "' OR 1=1--" in report, "the payload must appear in the evidence block"
    assert "sqlmap" in report.lower()


def test_simulated_finding_renders_placeholder_not_report():
    """A simulated/mock finding must render as the SIMULATED placeholder,
    NEVER as a submittable report. This is the report-layer defense-in-depth
    guard (MIN-2) — even if a simulated finding slips past persistence, it
    cannot reach a triager."""
    sim = _vuln(simulated=True)
    report = render_bounty_report(sim)
    assert "SIMULATED" in report.upper(), (
        "simulated finding must render the SIMULATED placeholder, not a report"
    )
    # And the placeholder must NOT contain the triager sections — it's not a
    # submittable report.
    assert "## Steps to Reproduce" not in report, (
        "simulated placeholder must not contain triager sections"
    )


def test_finding_signature_is_stable_and_distinct():
    """The dedup signature must be stable for the same finding and distinct
    for different endpoints/params — otherwise dup suppression (the #1
    reason good bugs pay $0) fails."""
    v1 = _vuln(evidence=[{
        "type": "sqlmap_injection", "provenance": "sqlmap",
        "url": "http://target.test/rest/user/login", "parameter": "email",
        "payloads": ["x"], "dbms": "SQLite",
    }])
    v2 = _vuln(evidence=[{
        "type": "sqlmap_injection", "provenance": "sqlmap",
        "url": "http://target.test/rest/user/login", "parameter": "email",
        "payloads": ["x"], "dbms": "SQLite",
    }])
    v3 = _vuln(evidence=[{
        "type": "sqlmap_injection", "provenance": "sqlmap",
        "url": "http://target.test/rest/products/search", "parameter": "q",
        "payloads": ["x"], "dbms": "SQLite",
    }])
    sig1 = finding_signature(v1)
    sig2 = finding_signature(v2)
    sig3 = finding_signature(v3)
    assert sig1 == sig2, "same finding must produce the same signature"
    assert sig1 != sig3, "different endpoints must produce distinct signatures"
    assert sig1.startswith("OSOP-"), "signature must carry the OSOP- prefix"


def test_cvss_is_surfaced_in_header():
    """The header must surface CVSS. Today it's a representative vector keyed
    by severity; when cvss_score is set on the finding, the report should
    still carry a CVSS line so a triager sees severity at a glance."""
    report = render_bounty_report(_vuln(severity=Severity.CRITICAL))
    assert "CVSS" in report, "CVSS must appear in the report header"
    # Critical severity must surface the critical vector.
    assert "9.8" in report or "Critical" in report
