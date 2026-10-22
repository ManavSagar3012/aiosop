"""Declared MCP tool selection creates ONLY a signed native human review step."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import flow_tool_proposals as api
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord
from ai_osop.mcp.protocol import MCPToolDefinition, SideEffectClass

ENG = "eng-tool-planning"
FLOW = "flow-tool-planning"
OBJECTIVE = "task-tool-planning"
ACTOR = {"role": "operator", "sub": "flow-owner", "claims": {"exp": 2000000000}}


def setup(monkeypatch):
    current = FlowRecord(id=FLOW, engagement_id=ENG, objective="Test approved scope", revision=4)
    next_flow = current.model_copy(update={"revision": 5})
    memory = SimpleNamespace(
        assert_signed_authorization=AsyncMock(
            return_value=SimpleNamespace(version=3, policy_sha256="a" * 64)
        ),
        load_session_state=AsyncMock(
            return_value=SimpleNamespace(
                session_id=ENG,
                created_by="flow-owner",
                phase="reconnaissance",
                scope=SimpleNamespace(
                    domains=["example.test"],
                    ips=[],
                    authorization_ref="signed-roe-ref",
                ),
            )
        ),
        load_flow=AsyncMock(side_effect=[current, current, current, next_flow]),
        load_task_authoritative=AsyncMock(
            return_value=SimpleNamespace(
                id=OBJECTIVE,
                flow_id=FLOW,
                engagement_id=ENG,
                type="flow_objective",
                status="planned",
            )
        ),
        list_subtasks=AsyncMock(return_value=[]),
        commit_flow_refinement=AsyncMock(return_value=next_flow),
    )
    declaration = MCPToolDefinition(
        name="inspect_metadata",
        description="PRIVATE: api_key=really-private-secret",
        parameters=[],
        returns={"private_body": "VERY-SENSITIVE"},
        scope_check=True,
        requires_approval=False,
        side_effect_class=SideEffectClass.READ_ONLY,
    )
    forbidden = AsyncMock(side_effect=AssertionError("No remote/provider/network execution"))
    conn = SimpleNamespace(
        server_id="browser_mcp",
        host="backend-secrets.internal",
        port=8091,
        auth_token="Bearer private-value",
        _initialized=True,
        _tools={"inspect_metadata": declaration},
        get_circuit_state=lambda: "closed",
        execute=forbidden,
        initialize=forbidden,
        connect=forbidden,
        ping=forbidden,
    )
    registry = SimpleNamespace(_servers={"browser_mcp": conn})
    monkeypatch.setattr(api, "SessionMemory", SimpleNamespace)
    monkeypatch.setattr(api, "MCPRegistry", SimpleNamespace)
    monkeypatch.setitem(
        api.state,
        "orchestrator",
        SimpleNamespace(session_memory=memory, mcp_registry=registry),
    )
    return memory, registry, forbidden


def input(**overrides):
    return api.CreateToolProposal(
        objective_task_id=OBJECTIVE,
        server_id="browser_mcp",
        tool_name="inspect_metadata",
        expected_flow_revision=4,
        expected_authorization_version=3,
        explicit_human_confirmation=True,
        **overrides,
    )


@pytest.mark.asyncio
async def test_real_cas_refinement_persists_inert_review_only(monkeypatch):
    memory, _, forbidden = setup(monkeypatch)
    response = Response()
    data = await api.propose_declared_flow_tool(FLOW, input(), response, operator=ACTOR)
    assert data["status"] == "proposal_recorded_pending_review"
    assert data["human_approval_still_required"] is True
    assert data["execution_started"] is False
    assert data["runtime_health_verified"] is False
    assert data["target_effect_verified"] is False
    assert data["safe_to_automatically_retry"] is False
    assert response.headers["Cache-Control"] == "private, no-store"
    assert memory.commit_flow_refinement.await_count == 1
    kwargs = memory.commit_flow_refinement.await_args.kwargs
    assert kwargs["activate_flow"] is False
    assert kwargs["expected_subtask_ids"] == []
    assert len(kwargs["additions"]) == 1
    step = kwargs["additions"][0]
    assert step.status == "pending"
    assert step.agent_type is AgentType.HUMAN_OVERSIGHT
    assert step.approval_required is True
    assert step.task_type == "operator_mcp_capability_review"
    assert (step.engagement_id, step.flow_id, step.task_id) == (ENG, FLOW, OBJECTIVE)
    assert "No parameters supplied" in step.description
    for private in ("PRIVATE", "api_key", "internal", "Bearer", "VERY-SENSITIVE", "8091"):
        assert private not in repr(data) + repr(step.model_dump())
    assert memory.assert_signed_authorization.await_count == 3
    forbidden.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "foreign_owner",
        "foreign_scope",
        "foreign_flow",
        "stale_flow",
        "revoked_signer",
        "foreign_objective",
        "already_executing_objective",
        "service_uninitialized",
        "open_circuit",
        "forged_tool",
        "no_scope_check",
        "too_many_subtasks",
        "lost_database_ack",
        "post_commit_revoked",
    ],
)
async def test_denies_stale_cross_tenant_provider_and_unknown_dispatch(monkeypatch, tamper):
    memory, registry, forbidden = setup(monkeypatch)
    if tamper == "foreign_owner":
        memory.load_session_state.return_value.created_by = "foreign"
    elif tamper == "foreign_scope":
        memory.load_session_state.return_value.scope.authorization_ref = None
    elif tamper == "foreign_flow":
        memory.load_flow.side_effect = [
            FlowRecord(id=FLOW, engagement_id="eng-foreign", objective="x", revision=4)
        ]
    elif tamper == "stale_flow":
        memory.load_flow.side_effect = [
            FlowRecord(id=FLOW, engagement_id=ENG, objective="x", revision=5)
        ]
    elif tamper == "revoked_signer":
        memory.assert_signed_authorization.side_effect = PermissionError("SECRET revoked")
    elif tamper == "foreign_objective":
        memory.load_task_authoritative.return_value.engagement_id = "eng-other"
    elif tamper == "already_executing_objective":
        memory.load_task_authoritative.return_value.status = "running"
    elif tamper == "service_uninitialized":
        registry._servers["browser_mcp"]._initialized = False
    elif tamper == "open_circuit":
        registry._servers["browser_mcp"].get_circuit_state = lambda: "open"
    elif tamper == "forged_tool":
        registry._servers["browser_mcp"]._tools["inspect_metadata"] = {
            "name": "inspect_metadata",
            "verified": True,
        }
    elif tamper == "no_scope_check":
        registry._servers["browser_mcp"]._tools["inspect_metadata"].scope_check = False
    elif tamper == "too_many_subtasks":
        memory.list_subtasks.return_value = [
            SimpleNamespace(id=f"subtask-{i}", flow_id=FLOW, engagement_id=ENG) for i in range(15)
        ]
    elif tamper == "lost_database_ack":
        memory.commit_flow_refinement.side_effect = TimeoutError("could have committed")
    elif tamper == "post_commit_revoked":
        memory.assert_signed_authorization.side_effect = [
            SimpleNamespace(version=3, policy_sha256="a" * 64),
            SimpleNamespace(version=3, policy_sha256="a" * 64),
            PermissionError("revoked after commit"),
        ]
    with pytest.raises(HTTPException) as error:
        await api.propose_declared_flow_tool(FLOW, input(), Response(), operator=ACTOR)
    assert error.value.status_code in {409, 503}
    assert "SECRET" not in str(error.value.detail)
    assert "could have" not in str(error.value.detail)
    forbidden.assert_not_awaited()


@pytest.mark.asyncio
async def test_explicit_human_confirmation_required_without_db_or_registry_touch(monkeypatch):
    memory, _, forbidden = setup(monkeypatch)
    with pytest.raises(HTTPException) as error:
        await api.propose_declared_flow_tool(
            FLOW,
            api.CreateToolProposal(
                objective_task_id=OBJECTIVE,
                server_id="browser_mcp",
                tool_name="inspect_metadata",
                expected_flow_revision=4,
                expected_authorization_version=3,
                explicit_human_confirmation=False,
            ),
            Response(),
            operator=ACTOR,
        )
    assert error.value.status_code == 422
    memory.load_flow.assert_not_awaited()
    forbidden.assert_not_awaited()


@pytest.mark.asyncio
async def test_actual_http_route_never_allows_unauthenticated_post():
    import httpx

    from ai_osop.api.main import app

    paths = {route.path for route in app.routes}
    assert "/flows/{flow_id}/tool-proposals" in paths
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            f"/flows/{FLOW}/tool-proposals",
            json=input().model_dump(),
        )
    assert response.status_code == 401
