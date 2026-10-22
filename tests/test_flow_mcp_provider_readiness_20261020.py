"""Signed Flow read-only provider/Action join; no provider or target contact."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.routers import flow_mcp_readiness as api
from ai_osop.mcp.protocol import MCPToolDefinition, SideEffectClass
from ai_osop.orchestrator.flow_mcp_action_executor import _manifest_sha256


EID = "eng-readiness"
FID = "flow-readiness"
OPERATOR = {"role": "operator", "sub": "owner", "claims": {"exp": 2000000000}}


def _fixture(monkeypatch, *, drift=False):
    tool = MCPToolDefinition(
        name="read_evidence",
        description="inert",
        parameters=[],
        returns={},
        side_effect_class=SideEffectClass.READ_ONLY,
        scope_check=True,
        requires_approval=True,
    )
    conn = SimpleNamespace(
        server_id="browser-mcp",
        _initialized=True,
        _tools={"read_evidence": tool},
        host="private-provider-do-not-serialize",
        auth_token="DO_NOT_LEAK_SECRET",
        get_circuit_state=lambda: "closed",
        execute=AsyncMock(side_effect=AssertionError("No MCP I/O permitted")),
        connect=AsyncMock(side_effect=AssertionError("No MCP I/O permitted")),
        initialize=AsyncMock(side_effect=AssertionError("No MCP I/O permitted")),
    )
    reg = SimpleNamespace(_servers={"browser-mcp": conn})
    sha = _manifest_sha256("browser-mcp", tool)
    store = SimpleNamespace(
        list=AsyncMock(
            return_value={
                "flow_id": FID,
                "actions": [
                    {
                        "server_id": "browser-mcp",
                        "tool_name": "read_evidence",
                        "status": "prepared",
                        "declaration_sha256": "b" * 64 if drift else sha,
                    },
                    {
                        "server_id": "browser-mcp",
                        "tool_name": "read_evidence",
                        "status": "unknown",
                        "declaration_sha256": sha,
                    },
                ],
            }
        )
    )
    svc = SimpleNamespace(
        registry=reg,
        store=store,
        _authority=AsyncMock(return_value=True),
    )
    monkeypatch.setattr(api, "_executor", lambda: svc)
    return svc, conn


async def _read():
    response = Response()
    data = await api.get_flow_mcp_provider_readiness(
        FID,
        response,
        expected_engagement_id=EID,
        expected_revision=3,
        expected_authorization_version=4,
        operator=OPERATOR,
    )
    return data, response


@pytest.mark.asyncio
async def test_all_configured_servers_and_real_action_counts_but_no_false_success(monkeypatch):
    service, conn = _fixture(monkeypatch)
    data, response = await _read()
    assert len(data["servers"]) == 11
    assert data["kind"] == "signed_action_and_process_inventory_unverified"
    assert data["provider_contacted"] is False
    assert data["execution_authorized"] is False
    assert data["independent_target_effect_verified"] is False
    browser = next(s for s in data["servers"] if s["server_id"] == "browser-mcp")
    assert browser["manifest_initialized"] is True
    assert browser["prepared_actions"] == browser["unknown_actions"] == 1
    assert browser["stale_prepared_declarations"] == 0
    assert browser["provider_side_signed_admission_verified"] is False
    assert all(s["runtime_health_verified"] is False for s in data["servers"])
    assert sum(s["registered_in_process"] for s in data["servers"]) == 1
    assert response.headers["Cache-Control"] == "private, no-store"
    assert "DO_NOT_LEAK_SECRET" not in repr(data)
    assert "private-provider" not in repr(data)
    assert service._authority.await_count == 2
    service.store.list.assert_awaited_once()
    for method in (conn.execute, conn.connect, conn.initialize):
        method.assert_not_awaited()


@pytest.mark.asyncio
async def test_stale_approved_manifest_requires_independent_new_preflight(monkeypatch):
    _fixture(monkeypatch, drift=True)
    data, _ = await _read()
    browser = next(s for s in data["servers"] if s["server_id"] == "browser-mcp")
    assert browser["stale_prepared_declarations"] == 1
    assert browser["execution_authorized"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "revoked_before",
        "revoked_after",
        "cross_tenant",
        "unknown_status",
        "untrusted_registry",
        "overlong_actions",
        "missing_ledger",
        "secret_server_id",
    ],
)
async def test_read_fails_closed_for_stale_or_private_data(monkeypatch, fault):
    svc, _ = _fixture(monkeypatch)
    if fault == "revoked_before":
        svc._authority.side_effect = PermissionError("private-db-error")
    elif fault == "revoked_after":
        svc._authority.side_effect = [True, PermissionError("revoked-secret")]
    elif fault == "cross_tenant":
        svc.store.list.return_value["flow_id"] = "flow-foreign"
    elif fault == "unknown_status":
        svc.store.list.return_value["actions"][0]["status"] = "verified"
    elif fault == "untrusted_registry":
        svc.registry._servers["browser-mcp"]._tools["read_evidence"] = {"raw_secret": "hi"}
    elif fault == "overlong_actions":
        svc.store.list.return_value["actions"] *= 51
    elif fault == "missing_ledger":
        svc.store.list.return_value = None
    elif fault == "secret_server_id":
        svc.store.list.return_value["actions"][0]["server_id"] = "foreign-private-host"
    with pytest.raises(HTTPException) as error:
        await _read()
    assert error.value.status_code in {403, 409, 503}
    assert "secret" not in str(error.value.detail)


def test_actual_fastapi_app_mounts_read_only_route():
    from ai_osop.api.main import app

    found = [r for r in app.routes if r.path == "/flows/{flow_id}/mcp-provider-readiness"]
    assert len(found) == 1
    assert found[0].methods == {"GET"}


@pytest.mark.asyncio
async def test_anonymous_http_get_is_denied_before_any_registry_access(monkeypatch):
    import httpx

    from ai_osop.api.main import app

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get(
            f"/flows/{FID}/mcp-provider-readiness",
            params={
                "expected_engagement_id": EID,
                "expected_revision": 3,
                "expected_authorization_version": 4,
            },
        )
    assert response.status_code in {401, 403}
