"""Real signed navigation entrypoint must require PG approval and source proof."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.agents.workflow_agent import PlaywrightAgent
from ai_osop.core.config import AgentType
from ai_osop.core.exceptions import WorkflowException
from ai_osop.core.models import ScopeDefinition, SessionState, Task, FlowRecord
from ai_osop.core.signed_replay_execution import (
    authorize_replay_step,
    signed_replay_provider_evidence,
)
from ai_osop.memory.session_memory import SessionMemory


class _Graph:
    def __init__(self, rows):
        self.rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def run(self, query, params):
        assert "HAS_STEP" in query and "TARGETS_ENDPOINT" in query
        assert params == {"wid": "wf-owned", "eid": "eng-owned", "sid": "step-auth"}

        async def entries():
            for row in self.rows:
                yield row

        return entries()


def _setup():
    source = Task(
        id="task-original",
        type="map_workflow",
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-owned",
        status="completed",
        payload={
            "_authorization_version": 4,
            "url": "https://authorized.example/original",
            "user_label": "user_a",
        },
        result={"status": "workflow_recorded", "workflow_id": "wf-owned"},
    )
    parent = Task(
        id="task-parent",
        type="replay_for_diff_auth",
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-owned",
        status="completed",
        flow_id="flow-owned",
        parent_task_id=source.id,
        approval_required=True,
        payload={
            "workflow_id": "wf-owned",
            "source_user_label": "user_a",
            "target_user_label": "user_b",
            "_authorization_version": 4,
            "_flow_revision": 5,
            "operator_approved": True,
            "approval_id": "apr-parent",
        },
    )
    child = Task(
        id="task-child",
        type="navigate",
        agent_type=AgentType.WORKFLOW,
        engagement_id="eng-owned",
        status="running",
        flow_id="flow-owned",
        parent_task_id=parent.id,
        dependencies=[parent.id],
        max_retries=0,
        approval_required=True,
        payload={
            "url": "https://authorized.example/resource",
            "method": "GET",
            "user_label": "user_b",
            "source_user_label": "user_a",
            "step_id": "step-auth",
            "workflow_id": "wf-owned",
            "_authorization_version": 4,
            "_flow_revision": 5,
            "capture_semantics": True,
            "operator_approved": True,
            "approval_id": "apr-child",
        },
    )
    tasks = {t.id: t for t in (source, parent, child)}
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(side_effect=lambda ident: tasks.get(ident))
    memory.load_flow = AsyncMock(
        return_value=FlowRecord(
            id="flow-owned",
            engagement_id="eng-owned",
            status="running",
            objective="Operator reviewed",
            revision=5,
        )
    )
    memory.load_session_state = AsyncMock(
        return_value=SessionState(
            session_id="eng-owned",
            phase="reconnaissance",
            scope=ScopeDefinition(
                engagement_id="eng-owned",
                domains=["authorized.example"],
                authorization_ref="signed-original",
            ),
        )
    )
    memory.is_task_approved = AsyncMock(return_value=True)
    memory.assert_signed_authorization = AsyncMock(return_value=SimpleNamespace(version=4))
    graph_rows = [
        {"role": "user_a", "url": child.payload["url"], "method": "GET", "action": "NAVIGATE"}
    ]
    graph = _Graph(graph_rows)
    ctx = SimpleNamespace(
        current_task=child,
        session_id="eng-owned",
        session_memory=memory,
        graph_memory=SimpleNamespace(_driver=SimpleNamespace(session=lambda: graph)),
        supervision_store=None,
    )
    agent = SimpleNamespace(
        ctx=ctx,
        browser_adapter=SimpleNamespace(
            navigate=AsyncMock(
                return_value={
                    "current_url": child.payload["url"],
                    "status_code": 200,
                }
            )
        ),
        _load_storage_state=AsyncMock(return_value={"cookies": []}),
        observe=AsyncMock(),
    )
    return agent, memory, source, parent, child, graph


@pytest.mark.asyncio
async def test_signed_step_requires_both_pg_human_approvals_and_bound_get():
    agent, memory, source, parent, child, _ = _setup()
    admitted = await authorize_replay_step(agent.ctx, dict(child.payload))
    assert admitted["url"] == child.payload["url"]
    assert admitted["user_label"] == "user_b"
    assert admitted["source_task_id"] == source.id
    assert admitted["replay_parent_task_id"] == parent.id
    assert memory.is_task_approved.await_count == 2
    assert memory.assert_signed_authorization.await_count == 2


@pytest.mark.asyncio
async def test_source_side_replay_observation_is_separately_approved_and_never_claims_a_finding():
    agent, memory, source, parent, child, _ = _setup()
    child.payload["user_label"] = "user_a"
    child.payload["target_user_label"] = "user_b"
    child.payload["_comparison_role"] = "source"
    approved = await authorize_replay_step(agent.ctx, dict(child.payload))
    assert approved["comparison_role"] == "source"
    assert approved["user_label"] == "user_a"
    assert approved["target_user_label"] == "user_b"
    result = await PlaywrightAgent._execute_navigation(agent, dict(child.payload))
    assert result["status"] == "execution_unknown"
    agent.browser_adapter.navigate.assert_awaited_once()
    assert agent.browser_adapter.navigate.await_args.args[1] == "user_a"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        "unapproved_child",
        "unapproved_parent",
        "foreign_graph",
        "unsafe_method",
        "stale_task",
        "revoked",
        "paused_flow",
        "wrong_source",
        "extra_dependency",
    ],
)
async def test_signed_step_bad_authority_never_dispatches_browser(bad):
    agent, memory, source, parent, child, graph = _setup()
    if bad == "unapproved_child":
        child.payload.pop("operator_approved")
    elif bad == "unapproved_parent":
        parent.payload.pop("operator_approved")
    elif bad == "foreign_graph":
        graph.rows[0]["url"] = "https://foreign.example/"
    elif bad == "unsafe_method":
        child.payload["method"] = "POST"
    elif bad == "stale_task":
        original = child.model_copy(deep=True)
        memory.load_task_authoritative.side_effect = lambda ident: (
            original.model_copy(update={"status": "dispatch_unknown"})
            if ident == child.id
            else {source.id: source, parent.id: parent}.get(ident)
        )
    elif bad == "revoked":
        memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    elif bad == "paused_flow":
        memory.load_flow.return_value.status = "paused"
    elif bad == "wrong_source":
        source.payload["user_label"] = "other"
    elif bad == "extra_dependency":
        child.dependencies.append("task-foreign")
    with pytest.raises(WorkflowException):
        await PlaywrightAgent._execute_navigation(agent, dict(child.payload))
    agent.browser_adapter.navigate.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_navigation_without_signed_provider_receipt_stays_unknown():
    agent, _, _, _, child, _ = _setup()
    result = await PlaywrightAgent._execute_navigation(agent, dict(child.payload))
    assert result["status"] == "execution_unknown"
    assert result["reason"] == "provider_origin_unverified"
    agent.browser_adapter.navigate.assert_awaited_once()
    agent.observe.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_navigation_lost_mcp_response_is_unknown_not_retryable_failure():
    agent, _, _, _, child, _ = _setup()
    agent.browser_adapter.navigate.side_effect = OSError("lost MCP acknowledgement")
    result = await PlaywrightAgent._execute_navigation(agent, dict(child.payload))
    assert result == {
        "status": "execution_unknown", "reason": "browser_dispatch_unconfirmed",
    }
    agent.browser_adapter.navigate.assert_awaited_once()
    agent.observe.assert_not_awaited()


@pytest.mark.asyncio
async def test_signed_navigation_only_returns_provider_testimony_not_a_finding(monkeypatch):
    agent, _, _, _, child, _ = _setup()
    import ai_osop.core.signed_replay_execution as signed

    agent.ctx.supervision_store = SimpleNamespace(
        list_mcp_dispatches=AsyncMock(
            return_value=[
                {
                    "server_id": "browser-mcp",
                    "tool_name": "execute",
                    "request_id": "req-verified",
                    "authorization_version": 4,
                    "status": "confirmed_finished",
                }
            ]
        ),
        list_events=AsyncMock(
            return_value=[
                {
                    "id": "evt-signed",
                    "engagement_id": "eng-owned",
                    "task_id": child.id,
                    "kind": "agent.mcp.reconciliation_result",
                    "payload": {
                        "request_id": "req-verified",
                        "status": "confirmed_finished",
                        "provider_receipt_status": "succeeded",
                        "provider_receipt_sha256": "a" * 64,
                    },
                }
            ]
        ),
    )
    monkeypatch.setattr(
        "ai_osop.memory.graph_research_projection.verify_signed_action_event",
        AsyncMock(return_value=True),
    )
    result = await PlaywrightAgent._execute_navigation(agent, dict(child.payload))
    assert result["status"] == "success"
    assert result["verification_status"] == "provider_testimony_only"
    assert result["authorization_violation_verified"] is False
    assert result["findings_count"] == 0
    assert result["source_task_id"] == "task-original"
    assert result["replay_parent_task_id"] == "task-parent"
    assert result["provider_evidence"]["source_authenticity_verified"] is False


@pytest.mark.asyncio
async def test_graph_or_store_failure_never_becomes_signed_provider_proof():
    agent, _, _, _, child, _ = _setup()
    agent.ctx.supervision_store = SimpleNamespace(
        list_mcp_dispatches=AsyncMock(side_effect=OSError("unavailable"))
    )
    assert (
        await signed_replay_provider_evidence(
            agent.ctx, version=4, url=child.payload["url"], scope=SimpleNamespace()
        )
        is None
    )


@pytest.mark.asyncio
async def test_real_agent_entrypoint_denies_stale_signed_step_before_provider_initialize():
    agent, memory, _, _, child, _ = _setup()
    agent.ctx.scope = SimpleNamespace(model_dump=lambda: {"domains": ["authorized.example"]})
    agent.browser_adapter.initialize = AsyncMock()
    memory.assert_signed_authorization.side_effect = PermissionError("revoked")
    with pytest.raises(WorkflowException):
        await PlaywrightAgent._execute(agent, child)
    agent.browser_adapter.initialize.assert_not_awaited()
    agent.browser_adapter.navigate.assert_not_awaited()
