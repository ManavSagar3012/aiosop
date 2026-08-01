"""Integration tests for GET /engagements/{session_id}/report/bounty.

These prove the real operator path end-to-end: seeded engagement + findings → direct
reporting-mcp call → report output produced. Uses the unittest.mock patching the
*execution surface* (the tool call) while keeping the real HTTP route + task/scope
+middleware stack live.
"""

import pytest
from httpx import AsyncClient

from ai_osop.core.enums import EngagementPhase, Severity, VulnClass
from ai_osop.core.models import (
    Engagement,
    Finding,
    ScopeDefinition,
    Task,
    Vulnerability,
)


@pytest.mark.asyncio
async def test_report_bounty_returns_markdown_for_seeded_engagement(remote_target):
    # Seed the engagement with one finding so the reporter has real material to render.
    await remote_target.graph_memory.save_finding(
        Vulnerability(
            id="vuln-int-1",
            vuln_type=VulnClass.SQLI,
            severity=Severity.HIGH,
            title="SQLi on login",
            confidence=0.97,
            evidence=[{"probe_type": "sqli_oracle"}],
            engagement_id=remote_target.id,
            endpoint_id="/api/login",
            status="verified",
        )
    )

    resp = await remote_target.get(
        "/engagements/{}/report/bounty".format(remote_target.id)
    )
    assert resp.status_code == 200, resp.text[:250]
    payload = resp.json()
    assert payload.get("source") == "reporting-mcp/compile_findings"
    assert isinstance(payload.get("markdown", ""), str)
    assert payload.get("markdown")  # must carry content


@pytest.mark.asyncio
async def test_report_bounty_keeps_shape_across_formats(remote_target):
    """The same engine returns consistent shape regardless of requested format."""
    for fmt in ("markdown", "html"):
        resp = await remote_target.get(
            f"/engagements/{remote_target.id}/report/bounty?format={fmt}"
        )
        assert resp.status_code == 200, resp.text[:250]
        body = resp.json()
        assert "engagement_id" in body
        assert "report_id" in body
        assert "source" in body
        assert body.get("source") == "reporting-mcp/compile_findings"
