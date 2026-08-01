"""Integration test for the bounty-report API path.

This is the REAL test of the report-generation topology, not a stub of the code path:
it proves the report endpoint drives findings off a real graph + session store + the
reporting_mcp tool, and is what the UI's MISSION REPORT button actually requests.
"""

import pytest
from ai_osop.api.main import app


@pytest.mark.asyncio
async def test_report_bounty_returns_report_content(async_client, findings_db):
    """`GET /engagements/{id}/report/bounty` yields a report with content + metadata."""
    sid = findings_db.session_id

    resp = await async_client.get(
        f"/engagements/{sid}/report/bounty",
        headers={"Authorization": "Bearer operator-token"},
    )
    assert resp.status_code == 200, resp.text[:200]
    payload = resp.json()
    assert payload["source"] == "reporting-mcp/compile_findings"
    assert isinstance(payload.get("html", ""), str)
    assert payload.get("body_html") == payload["html"]
    assert payload.get("report_id")


@pytest.mark.asyncio
async def test_report_bounty_404_for_missing_engagement(async_client):
    """Searching for a non-existent engagement returns a 404 (not a 502)."""
    resp = await async_client.get(
        "/engagements/eng-missing-506/report/bounty",
        headers={"Authorization": "Bearer operator-token"},
    )
    assert resp.status_code == 404
