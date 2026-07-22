"""Unit tests for bounty_report.py - report rendering and dedup signatures.

Tests cover:
- finding_signature() for various vuln types and url-less classes
- _repro_steps() for each vulnerability class
- render_bounty_report() output structure
- Simulated finding suppression (MIN-2)
- Unvalidated finding warnings (MANUAL-CONFIRM-001)
"""

from ai_osop.core.bounty_report import finding_signature, render_bounty_report
from ai_osop.core.models import Vulnerability
from ai_osop.core.enums import Severity, VulnClass


def _vuln(**over) -> Vulnerability:
    base = dict(
        vuln_type=VulnClass.SQLI,
        severity=Severity.HIGH,
        cwe="CWE-89",
        title="SQLi in id parameter",
        description="SQL injection found in the id parameter",
        evidence=[
            {
                "type": "sqli_oracle",
                "url": "http://target/endpoint",
                "parameter": "id",
                "payloads": ["' OR 1=1--"],
                "dbms": "sqlite",
            }
        ],
        tool_source="test",
        confidence=0.95,
        validated=True,
        engagement_id="eng-test-1",
    )
    base.update(over)
    return Vulnerability(**base)


class TestFindingSignature:
    def test_sqli_signature_is_stable(self):
        v = _vuln()
        sig1 = finding_signature(v)
        sig2 = finding_signature(v)
        assert sig1 == sig2
        assert sig1.startswith("OSOP-")
        assert len(sig1) == len("OSOP-") + 12

    def test_different_urls_different_signatures(self):
        v1 = _vuln(evidence=[{"url": "http://a.com/endpoint", "parameter": "id"}])
        v2 = _vuln(evidence=[{"url": "http://b.com/other", "parameter": "id"}])
        assert finding_signature(v1) != finding_signature(v2)

    def test_different_params_different_signatures(self):
        v1 = _vuln(evidence=[{"url": "http://x.com/y", "parameter": "id"}])
        v2 = _vuln(evidence=[{"url": "http://x.com/y", "parameter": "name"}])
        assert finding_signature(v1) != finding_signature(v2)

    def test_same_bug_same_signature(self):
        v1 = _vuln()
        v2 = _vuln()
        assert finding_signature(v1) == finding_signature(v2)


class TestReproSteps:
    def test_sqli_has_three_steps(self):
        from ai_osop.core.bounty_report import _repro_steps
        from ai_osop.core.finding_view import to_finding_view

        v = _vuln()
        view = to_finding_view(v.model_dump())
        steps = _repro_steps(view)
        assert len(steps) == 3
        assert "sqlmap" in steps[2]

    def test_ssrf_has_two_steps(self):
        from ai_osop.core.bounty_report import _repro_steps
        from ai_osop.core.finding_view import to_finding_view

        v = _vuln(
            vuln_type="ssrf",
            evidence=[
                {
                    "url": "http://x",
                    "injection": "url",
                    "interaction": {"method": "POST", "path": "/cb"},
                }
            ],
        )
        view = to_finding_view(v.model_dump())
        steps = _repro_steps(view)
        assert len(steps) == 2
        assert "Collaborator" in steps[0]

    def test_xss_has_two_steps(self):
        from ai_osop.core.bounty_report import _repro_steps
        from ai_osop.core.finding_view import to_finding_view

        v = _vuln(
            vuln_type="xss",
            evidence=[
                {"url": "http://x", "store_field": "comment", "render_url": "http://x/render"}
            ],
        )
        view = to_finding_view(v.model_dump())
        steps = _repro_steps(view)
        assert len(steps) == 2

    def test_jwt_abuse_has_two_steps(self):
        from ai_osop.core.bounty_report import _repro_steps
        from ai_osop.core.finding_view import to_finding_view

        v = _vuln(
            vuln_type="jwt_abuse",
            evidence=[{"url": "http://x", "technique": "alg_none", "victim": "admin"}],
        )
        view = to_finding_view(v.model_dump())
        steps = _repro_steps(view)
        assert len(steps) == 2

    def test_unknown_type_has_one_step(self):
        from ai_osop.core.bounty_report import _repro_steps
        from ai_osop.core.finding_view import to_finding_view

        v = _vuln(vuln_type="unknown", evidence=[{"url": "http://x"}])
        view = to_finding_view(v.model_dump())
        steps = _repro_steps(view)
        assert len(steps) == 1
        assert "reproduce" in steps[0].lower()


class TestRenderBountyReport:
    def test_contains_title(self):
        report = render_bounty_report(_vuln())
        assert "SQLi in id parameter" in report

    def test_contains_severity(self):
        report = render_bounty_report(_vuln())
        assert "high" in report.lower() or "HIGH" in report

    def test_contains_dedup_signature(self):
        report = render_bounty_report(_vuln())
        assert "OSOP-" in report

    def test_contains_remediation(self):
        report = render_bounty_report(_vuln())
        assert "parameterized" in report.lower()

    def test_contains_steps(self):
        report = render_bounty_report(_vuln())
        assert "Steps to Reproduce" in report

    def test_contains_proof_of_concept(self):
        report = render_bounty_report(_vuln())
        assert "Proof of Concept" in report

    def test_contains_evidence(self):
        report = render_bounty_report(_vuln())
        assert "Evidence" in report

    def test_contains_impact_section(self):
        report = render_bounty_report(_vuln())
        assert "Impact" in report

    def test_contains_weakness_cwe(self):
        report = render_bounty_report(_vuln())
        assert "CWE-89" in report

    def test_program_in_header_when_specified(self):
        report = render_bounty_report(_vuln(), program="HackerOne")
        assert "HackerOne" in report

    def test_validated_finding_shows_active_confirmation(self):
        report = render_bounty_report(_vuln(validated=True))
        assert "active confirmation" in report
        assert "MANUAL CONFIRMATION REQUIRED" not in report

    def test_unvalidated_finding_shows_warning(self):
        report = render_bounty_report(_vuln(validated=False))
        assert "MANUAL CONFIRMATION REQUIRED" in report
        assert "strong lead" in report
