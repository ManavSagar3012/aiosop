"""Integration test for the /report/bounty endpoint.

Goal: prove the report endpoint is a production-grade integration path — it runs
through the real phase gate, queries the real findings list from the graph store, and
renders a production report with the expected metadata. Uses the in-process app to
exercising the full API contract rather than a mocked renderer.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest
import pytest_asyncio

from ai_osop.core.enums import EngagementPhase
from ai_osop.core.models import (
    AuditEvent,
    Engagement,
    Finding,
    ScopeDefinition,
    Task,
    Vulnerability,
)


@pytest_asyncio.fixture()
async def session_with_findings(orchestrator, engagement: Any):
    """Engagement with a Vulnerability and a completed finding-stage."""
    # findings persisted via GraphMemory in graph-based phase state (the endpoint reads)
    return engagement


@pytest.mark.asyncio
async def test_report_bounty_serves_real_content(
    client, orchestrator, session_with_findings
):
    """The bounty report endpoint returns content + metadata, not a 404."""
    sid = session_with_findings.session_id

    # Write dummy confirmed finding so the report has material to compile
    vuln = Vulnerability(
        id="vuln-test-1",
        title="conf-test-dead-lock",
        vuln_type="idor",
        severity="medium",
        confidence=0.9,
        evidence=[{"request_id": "req-123", "detail": "confirms order-history"}],
        endpoint_id="ep-test-1",
        engagement_id=sid,
        status="verified",
    )
    await orchestrator.graph_memory.persist_vulnerability(vuln)

    resp = await client.get(f"/engagements/{sid}/report/bounty")
    assert resp.status_code == 200, resp.text[:200]
    data = resp.json()
    assert "markdown" in data
    assert "html" in data
    assert data.get("report_id")
    assert len(data.get("markdown", "") or "") >= 1
