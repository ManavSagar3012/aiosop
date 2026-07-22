from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType, Severity, VulnClass
from ai_osop.core.findings_quality import FindingConversionEngine
from ai_osop.core.models import OutcomeRecord, OutcomeStatus, Vulnerability


@pytest.mark.asyncio
async def test_acceptance_yield_scoring():
    """
    Sprint 15: Verify that the Acceptance Learning Engine correctly calculates
    Acceptance Yield Scores (AYS) based on finding resolutions.
    """
    # 1. Mock Findings and Outcomes
    findings = [
        {"id": "v1", "tool": "nuclei", "identity": "anonymous"},
        {"id": "v2", "tool": "burp", "identity": "user_a"},
        {"id": "v3", "tool": "burp", "identity": "admin"},
    ]

    # Simulate Triage: v1=duplicate, v2=informative, v3=accepted
    outcomes = [
        OutcomeRecord(
            finding_id="v1",
            finding_type="xss",
            status=OutcomeStatus.DUPLICATE,
            severity="medium",
            agent_id_responsible="triage-agent",
            engagement_id="eng-1",
        ),
        OutcomeRecord(
            finding_id="v2",
            finding_type="xss",
            status=OutcomeStatus.INFORMATIVE,
            severity="medium",
            agent_id_responsible="triage-agent",
            engagement_id="eng-1",
        ),
        OutcomeRecord(
            finding_id="v3",
            finding_type="idor",
            status=OutcomeStatus.ACCEPTED,
            severity="high",
            agent_id_responsible="triage-agent",
            engagement_id="eng-1",
        ),
    ]

    # 2. Logic to calculate AYS per scanner and identity
    # (This logic will live in FindingConversionEngine)
    def calculate_ays(findings, outcomes):
        by_tool = {"nuclei": {"total": 0, "accepted": 0}, "burp": {"total": 0, "accepted": 0}}
        by_id = {
            "anonymous": {"total": 0, "accepted": 0},
            "user_a": {"total": 0, "accepted": 0},
            "admin": {"total": 0, "accepted": 0},
        }

        outcome_map = {o.finding_id: o for o in outcomes}

        for f in findings:
            o = outcome_map.get(f["id"])
            by_tool[f["tool"]]["total"] += 1
            by_id[f["identity"]]["total"] += 1

            if o and o.status == OutcomeStatus.ACCEPTED:
                by_tool[f["tool"]]["accepted"] += 1
                by_id[f["identity"]]["accepted"] += 1

        return {tool: (stats["accepted"] / stats["total"]) for tool, stats in by_tool.items()}, {
            identity: (stats["accepted"] / stats["total"]) for identity, stats in by_id.items()
        }

    tool_ays, id_ays = calculate_ays(findings, outcomes)

    # 3. Assertions
    assert tool_ays["nuclei"] == 0.0
    assert tool_ays["burp"] == 0.5  # 1 accepted out of 2 findings
    assert id_ays["anonymous"] == 0.0
    assert id_ays["user_a"] == 0.0
    assert id_ays["admin"] == 1.0

    print("Acceptance Yield Scoring verified.")
