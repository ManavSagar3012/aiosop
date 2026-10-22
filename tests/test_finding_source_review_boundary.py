"""Graph validation and senior review must not impersonate target verification."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.api.deps import state
from ai_osop.api.routers import findings


def test_validated_graph_node_remains_reviewed_not_independently_verified():
    finding = findings._vuln_node_to_finding({
        "id": "vuln-unattributed", "engagement_id": "eng-test",
        "title": "Graph review only", "validated": True,
        "severity": "high", "confidence": 0.98,
    })
    assert finding["status"] == "hypothesis"
    assert finding["graph_review_status"] == "reviewed"
    assert finding["source_authenticity_verified"] is False
    assert finding["authorization_violation_verified"] is False
    assert finding["independent_target_effect_verified"] is False
    assert finding["verification_basis"] == "unattested_graph_review"
    assert findings._vuln_node_to_finding({"validated": False})["status"] == "hypothesis"


@pytest.mark.asyncio
async def test_senior_graph_review_never_returns_proven_vulnerability(monkeypatch):
    validate = AsyncMock()
    monkeypatch.setitem(
        state, "orchestrator", SimpleNamespace(
            graph_memory=SimpleNamespace(validate_vulnerability=validate)
        ),
    )
    monkeypatch.setattr(findings, "assert_engagement_access", AsyncMock())
    monkeypatch.setattr(findings, "_finding_exists", AsyncMock(return_value=True))
    record = await findings.verify_finding(
        "eng-test", "vuln-unattributed", operator={"role": "senior_operator"},
    )
    assert record == {
        "status": "graph_validated_unverified",
        "finding_id": "vuln-unattributed", "session_id": "eng-test",
        "source_authenticity_verified": False,
        "independent_target_effect_verified": False,
        "authorization_violation_verified": False,
    }
    validate.assert_awaited_once_with("vuln-unattributed")
