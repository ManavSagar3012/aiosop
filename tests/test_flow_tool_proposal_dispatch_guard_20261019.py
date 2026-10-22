"""An inert MCP declaration cannot be smuggled through ordinary Flow dispatch."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.routers import flows
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, SubtaskRecord


FLOW = "flow-inert-mcp-review"
ENG = "eng-inert-mcp-review"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"target": "https://example.test", "tool_name": "navigate", "server_id": "browser_mcp"},
        {"tool_name": "run", "command": "echo dangerous-payload"},
    ],
)
async def test_review_marker_never_dispatches_even_after_approval_or_bogus_parameters(
    monkeypatch, payload
):
    session = SimpleNamespace(
        phase="reconnaissance",
        scope=SimpleNamespace(authorization_ref="signed-roe", domains=["example.test"], ips=[]),
    )
    flow = FlowRecord(
        id=FLOW, engagement_id=ENG, objective="Plan scoped metadata", revision=4, status="pending"
    )
    step = SubtaskRecord(
        id="subtask-inert-review",
        engagement_id=ENG,
        flow_id=FLOW,
        task_id="task-inert-review",
        title="Review a declared MCP tool",
        task_type="operator_mcp_capability_review",
        agent_type=AgentType.HUMAN_OVERSIGHT,
        approval_required=True,
    )
    enqueue = AsyncMock(side_effect=AssertionError("No queue submission is permitted"))
    claim = AsyncMock(side_effect=AssertionError("No durable dispatch claim is permitted"))
    schedule = AsyncMock(side_effect=AssertionError("No tool scheduling is permitted"))
    memory = SimpleNamespace(claim_subtask=claim)
    monkeypatch.setitem(
        flows.state,
        "orchestrator",
        SimpleNamespace(
            session_memory=memory, enqueue_registered_task=enqueue, schedule_task=schedule
        ),
    )
    monkeypatch.setattr(flows, "_owned_flow", AsyncMock(return_value=flow))
    monkeypatch.setattr(flows, "_owned_subtask", AsyncMock(return_value=step))
    monkeypatch.setattr(flows, "assert_engagement_access", AsyncMock(return_value=session))
    with pytest.raises(HTTPException) as exc:
        await flows.dispatch_subtask(
            FLOW,
            step.id,
            flows.DispatchSubtaskRequest(payload=payload, expected_revision=4),
            operator={"sub": "current-owner", "role": "senior_operator"},
        )
    assert exc.value.status_code == 409
    assert "cannot be dispatched" in exc.value.detail
    claim.assert_not_awaited()
    enqueue.assert_not_awaited()
    schedule.assert_not_awaited()


def test_actual_router_contains_both_inert_proposal_and_separate_dispatch_routes():
    from ai_osop.api.main import app

    paths = {route.path for route in app.routes}
    assert "/flows/{flow_id}/tool-proposals" in paths
    assert "/flows/{flow_id}/subtasks/{subtask_id}/dispatch" in paths
