"""Graph/provider candidate counts cannot become independent verified findings."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.orchestrator.engagement_controller import GoalOrientedEngagementController
from ai_osop.orchestrator.flow_refinement import BoundedFlowRefiner


@pytest.mark.asyncio
async def test_strategic_controller_does_not_infer_verified_findings_from_neo4j():
    async def records(query, params):
        if "Vulnerability" in query:
            return [
                {
                    "v": {
                        "id": "graph-provider-claim",
                        "title": "Unverified private access",
                        "severity": "critical",
                        "validated": True,
                        "finding_status": "verified",
                        "private_response_body": "do-not-expose",
                    }
                }
            ]
        return []

    graph = SimpleNamespace(
        run_read_query=AsyncMock(side_effect=records),
        get_graph_stats=AsyncMock(
            return_value={
                "vulnerabilities": 99,
                "endpoints": 0,
            }
        ),
    )
    orchestrator = SimpleNamespace(
        graph_memory=graph,
        session_memory=SimpleNamespace(),
        _sessions={},
        mcp_registry=None,
    )
    controller = GoalOrientedEngagementController(orchestrator)
    controller.get_or_create_plan = AsyncMock(
        return_value={
            "overall_goal": "Assess signed resources",
            "overall_confidence": 0.0,
            "max_iterations": 3,
            "iterations": 0,
        }
    )
    state = await controller.build_engagement_state_summary("eng-test-candidate")
    assert state["confirmed_findings_count"] == 0
    assert state["candidate_findings_count"] == 99
    assert state["findings_summary"] == [
        {
            "title": "Unverified private access",
            "severity": "critical",
            "verification_state": "candidate_unverified",
        }
    ]
    assert "do-not-expose" not in json.dumps(state)


def test_flow_refinement_strips_provider_self_declared_verification_and_private_claims():
    result = BoundedFlowRefiner._safe_outcome(
        SimpleNamespace(
            result_summary=json.dumps(
                {
                    "findings_count": 3,
                    "confirmed_findings_count": 3,
                    "verified": True,
                    "authorization_violation_verified": True,
                    "private_response_body": "redact-this-body",
                }
            )
        )
    )
    assert result == {"findings_count": 3}
    assert "redact-this-body" not in str(result)


def test_fallback_report_step_never_calls_candidates_verified():
    result = BoundedFlowRefiner._fallback(
        [],
        "task-objective",
        SimpleNamespace(
            result_summary=json.dumps(
                {
                    "findings_count": 3,
                    "verified": True,
                }
            )
        ),
    )
    assert result and result[0].task_type == "generate_report"
    assert "unverified" in result[0].title.lower()
    assert "candidate" in result[0].description.lower()
