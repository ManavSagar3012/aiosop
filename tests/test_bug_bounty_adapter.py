from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.adapters.bug_bounty_adapter import BugBountyAdapter
from ai_osop.core.models import OutcomeRecord, OutcomeStatus


@pytest.mark.asyncio
async def test_sync_outcomes_simulated() -> None:
    # Setup. bug_bounty_simulation now defaults to False (OSOP-P1-06 secure default), so
    # this test of SIMULATED behavior must opt into simulation explicitly.
    with (
        patch("ai_osop.core.config.settings.bug_bounty_simulation", True),
        patch("ai_osop.core.config.settings.h1_api_key", "test-key"),
    ):
        adapter = BugBountyAdapter()
        engagement_id = "eng-123"

        # Act
        outcomes = await adapter.sync_outcomes(engagement_id)

        # Assert
        assert len(outcomes) > 0
        assert outcomes[0].engagement_id == engagement_id
        assert outcomes[0].status in [OutcomeStatus.PAID, OutcomeStatus.TRIAGED]
        assert outcomes[0].program_payout >= 0


@pytest.mark.asyncio
async def test_sync_outcomes_no_key() -> None:
    # Setup
    with patch("ai_osop.core.config.settings.h1_api_key", None):
        with patch("ai_osop.core.config.settings.bc_api_key", None):
            adapter = BugBountyAdapter()

            # Act
            outcomes = await adapter.sync_outcomes("eng-123")

            # Assert
            assert len(outcomes) == 0


@pytest.mark.asyncio
async def test_submit_finding() -> None:
    # Simulated submission path (no live HackerOne call). Must opt into simulation now
    # that it defaults off (OSOP-P1-06).
    with patch("ai_osop.core.config.settings.bug_bounty_simulation", True):
        adapter = BugBountyAdapter()
        finding = {"id": "f-1", "title": "Test XSS"}

        result = await adapter.submit_finding(finding, platform="h1")

    assert result["status"] == "submitted"
    assert "H1-" in result["external_id"]


def test_parse_finding_type_from_h1_report() -> None:
    adapter = BugBountyAdapter()

    # Case 1: Parse from weakness CWE
    report_cwe = {"relationships": {"weakness": {"data": {"attributes": {"cwe": "CWE-79"}}}}}
    assert adapter._parse_finding_type_from_h1_report(report_cwe) == "xss"

    # Case 2: Parse from weakness name
    report_name = {
        "relationships": {
            "weakness": {
                "data": {"attributes": {"name": "Insecure Direct Object Reference (IDOR)"}}
            }
        }
    }
    assert adapter._parse_finding_type_from_h1_report(report_name) == "idor"

    # Case 3: Parse from title/content keywords
    report_kw = {
        "attributes": {
            "title": "Possible SSRF in pdf generator",
            "vulnerability_information": "The server-side request forgery can be triggered by...",
        }
    }
    assert adapter._parse_finding_type_from_h1_report(report_kw) == "ssrf"

    # Case 4: Unmapped fallback
    report_unknown = {
        "attributes": {
            "title": "Some random issue",
            "vulnerability_information": "no keywords here",
        }
    }
    assert adapter._parse_finding_type_from_h1_report(report_unknown) == "unknown"
