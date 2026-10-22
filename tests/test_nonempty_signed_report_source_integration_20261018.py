"""Nonempty signed reporting must not omit source needed for 0022 readback."""

import inspect

from ai_osop.agents.reporting_agent import ReportingAgent


def test_signed_nonempty_reports_require_source_auth_and_flow_lineage():
    source = inspect.getsource(ReportingAgent._generate_report)
    assert "if require_attestation and findings:" in source
    assert 'finding.get("source_binding") is None' in source
    assert 'generation_binding["authorization_version"]' in source
    assert 'generation_binding["authorization_sha256"]' in source
    assert 'generation_binding["flow_revision"]' in source
    assert "independent 0022 source verification remains UNKNOWN" in source


def test_signing_does_not_claim_verified_effect_or_final_report_release():
    source = inspect.getsource(ReportingAgent._generate_report)
    assert '"source_type": "validated_engagement_graph"' in source
    assert '"source_authenticity_verified": False' in source
    assert "sign_report_attestation(" in source
    assert "report_release_approved=True" not in source
