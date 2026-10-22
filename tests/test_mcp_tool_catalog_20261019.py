"""Real FastAPI tool-catalog route: inert signed Flow metadata, never MCP dispatch."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import mcp_tool_catalog as api
from ai_osop.mcp.protocol import MCPToolDefinition, SideEffectClass


EID = "eng-tool-catalog"
FLOW = "flow-tool-catalog"
OPERATOR = {
    "sub": "tenant-owner",
    "role": "operator",
    "claims": {"exp": 2000000000},
}


def fixtures(monkeypatch):
    memory = SimpleNamespace(
        assert_signed_authorization=AsyncMock(return_value=SimpleNamespace(version=4)),
        load_session_state=AsyncMock(
            return_value=SimpleNamespace(
                session_id=EID,
                created_by="tenant-owner",
                phase="reconnaissance",
                scope=SimpleNamespace(engagement_id=EID),
            )
        ),
        load_flow=AsyncMock(
            return_value=SimpleNamespace(id=FLOW, engagement_id=EID, status="running", revision=7)
        ),
    )
    action = AsyncMock(side_effect=AssertionError("No MCP calls allowed"))
    tool = MCPToolDefinition(
        name="inspect_artifact",
        description="PRIVATE DATA: bearer=never-expose",
        parameters=[],
        returns={"cookie": "super-private"},
        side_effect_class=SideEffectClass.READ_ONLY,
        requires_approval=False,
    )
    server = SimpleNamespace(
        server_id="local_mcp",
        host="private-internal-host",
        port=8091,
        auth_token="Bearer secret-catalog-do-not-return",
        _initialized=True,
        _tools={"inspect_artifact": tool},
        get_circuit_state=lambda: "closed",
        execute=action,
        connect=action,
        initialize=action,
    )
    registry = SimpleNamespace(_servers={"local_mcp": server})
    monkeypatch.setattr(api, "SessionMemory", SimpleNamespace)
    monkeypatch.setattr(api, "MCPRegistry", SimpleNamespace)
    monkeypatch.setitem(
        api.state,
        "orchestrator",
        SimpleNamespace(session_memory=memory, mcp_registry=registry),
    )
    return memory, registry, action


async def read(operator=None):
    response = Response()
    out = await api.read_flow_tool_catalog(
        EID,
        response,
        flow_id=FLOW,
        expected_flow_revision=7,
        expected_authorization_version=4,
        operator=operator or OPERATOR,
    )
    return out, response


@pytest.mark.asyncio
async def test_real_registry_catalog_is_redacted_and_cannot_authorize_execution(monkeypatch):
    memory, _, action = fixtures(monkeypatch)
    result, response = await read()
    assert response.headers["Cache-Control"] == "private, no-store"
    assert result == {
        "engagement_id": EID,
        "flow_id": FLOW,
        "flow_revision": 7,
        "authorization_version": 4,
        "catalog_kind": "declarations_only_unverified",
        "execution_authorized": False,
        "servers": [
            {
                "server_id": "local_mcp",
                "manifest_initialized": True,
                "circuit_state": "closed",
                "runtime_health_verified": False,
                "tools": [
                    {
                        "name": "inspect_artifact",
                        "side_effect_class": "READ_ONLY",
                        "declared_requires_approval": False,
                        "declared_scope_check": True,
                        "signed_task_required_for_execution": True,
                        "execution_authorized": False,
                        "runtime_health_verified": False,
                    }
                ],
            }
        ],
    }
    assert all(
        private not in repr(result)
        for private in ("bearer", "private-internal-host", "super-private", "8091")
    )
    assert memory.assert_signed_authorization.await_count == 2
    assert memory.load_flow.await_count == 2
    assert memory.load_session_state.await_count == 2
    action.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "foreign_owner",
        "foreign_flow",
        "revoked_after_read",
        "flow_paused",
        "provider_token_name",
        "forged_tool",
        "unbounded",
        "senior_unsigned",
    ],
)
async def test_catalog_denies_foreign_stale_tainted_or_unsigned_read(monkeypatch, change):
    memory, registry, action = fixtures(monkeypatch)
    operator = None
    if change == "foreign_owner":
        memory.load_session_state.return_value.created_by = "foreign"
    elif change == "foreign_flow":
        memory.load_flow.return_value.engagement_id = "eng-foreign"
    elif change == "revoked_after_read":
        memory.assert_signed_authorization.side_effect = [
            SimpleNamespace(version=4),
            PermissionError("revoked-private-secret"),
        ]
    elif change == "flow_paused":
        memory.load_flow.return_value.status = "paused"
    elif change == "provider_token_name":
        registry._servers["local_mcp"]._tools = {
            "Bearer private-secret": registry._servers["local_mcp"]._tools["inspect_artifact"]
        }
    elif change == "forged_tool":
        registry._servers["local_mcp"]._tools["inspect_artifact"] = {
            "name": "inspect_artifact",
            "admin": "yes",
        }
    elif change == "unbounded":
        registry._servers = {
            f"server_{i}": SimpleNamespace(server_id=f"server_{i}") for i in range(33)
        }
    elif change == "senior_unsigned":
        operator = {"sub": "global", "role": "senior_operator", "claims": {}}
    with pytest.raises(HTTPException) as error:
        await read(operator=operator)
    assert error.value.status_code in {403, 503}
    assert "private" not in str(error.value.detail)
    action.assert_not_awaited()


@pytest.mark.asyncio
async def test_uninitialized_registry_never_invents_tools(monkeypatch):
    _, registry, action = fixtures(monkeypatch)
    registry._servers["local_mcp"]._initialized = False
    result, _ = await read()
    assert result["servers"][0]["manifest_initialized"] is False
    assert result["servers"][0]["tools"] == []
    action.assert_not_awaited()


@pytest.mark.asyncio
async def test_senior_role_alone_cannot_read_foreign_tenant_catalog(monkeypatch):
    memory, registry, action = fixtures(monkeypatch)
    senior = {
        "sub": "unrelated-senior",
        "role": "senior_operator",
        "claims": {"exp": 2000000000},
    }
    with pytest.raises(HTTPException) as error:
        await read(operator=senior)
    assert error.value.status_code == 503
    assert "private" not in str(error.value.detail)
    action.assert_not_awaited()
    assert memory.load_session_state.await_count == 1


def test_actual_app_mounts_nonexecuting_catalog():
    from ai_osop.api.main import app

    assert "/engagements/{engagement_id}/flow-tool-catalog" in {route.path for route in app.routes}


@pytest.mark.asyncio
async def test_mounted_http_route_requires_a_verified_bearer_before_registry_read():
    import httpx

    from ai_osop.api.main import app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            f"/engagements/{EID}/flow-tool-catalog",
            params={
                "flow_id": FLOW,
                "expected_flow_revision": 7,
                "expected_authorization_version": 4,
            },
        )
    assert response.status_code == 401
    assert "private-internal-host" not in response.text
