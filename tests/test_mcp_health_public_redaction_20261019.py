"""System MCP telemetry is not a globally shareable secret-bearing tool registry."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state
from ai_osop.api.routers.system import get_mcp_health


def _fixture(monkeypatch):
    conn = SimpleNamespace(
        server_id="browser_mcp",
        host="sensitive.internal.net",
        port=8091,
        auth_token="Bearer secret-hidden",
        _initialized=True,
        _tools={"leaked_private_tool": {"headers": {"Authorization": "Bearer hidden"}}},
        _failure_count=2,
        _success_count=3,
        _recovery_attempts=1,
        _consecutive_successes=2,
        _last_success_at=None,
        _last_failure_at=None,
        get_circuit_state=lambda: "half_open",
    )
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(mcp_registry=SimpleNamespace(_servers={"browser_mcp": conn})),
    )
    return conn


@pytest.mark.asyncio
async def test_system_health_returns_exact_public_counters_not_private_manifests(monkeypatch):
    _fixture(monkeypatch)
    value = await get_mcp_health(operator={"role": "senior_operator", "sub": "authorized"})
    assert value == {
        "catalog_scope": "process_health_only_unverified",
        "servers": [
            {
                "server_id": "browser_mcp",
                "circuit_state": "half_open",
                "failure_count": 2,
                "success_count": 3,
                "recovery_attempts": 1,
                "consecutive_successes": 2,
                "initialized": True,
                "runtime_health_verified": False,
            }
        ],
    }
    for forbidden in ("8091", "internal.net", "Bearer", "leaked_private_tool", "Authorization"):
        assert forbidden not in repr(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["bad_id", "invalid_circuit", "bad_count", "many_servers"])
async def test_health_rejects_forged_or_unbounded_registry(monkeypatch, fault):
    conn = _fixture(monkeypatch)
    if fault == "bad_id":
        conn.server_id = "other_server"
    elif fault == "invalid_circuit":
        conn.get_circuit_state = lambda: "target_verified"
    elif fault == "bad_count":
        conn._success_count = 2**64
    elif fault == "many_servers":
        state["orchestrator"].mcp_registry._servers = {
            f"test_{i}": SimpleNamespace() for i in range(33)
        }
    with pytest.raises(HTTPException) as error:
        await get_mcp_health(operator={"role": "senior_operator", "sub": "authorized"})
    assert error.value.status_code == 503
    assert "secret" not in str(error.value.detail)


def test_system_health_remains_mounted():
    from ai_osop.api.main import app

    paths = {route.path for route in app.routes}
    assert "/system/mcp/health" in paths
    assert "/engagements/{engagement_id}/flow-tool-catalog" in paths


@pytest.mark.asyncio
async def test_junior_operator_cannot_read_global_cross_tenant_mcp_counters():
    import httpx

    from ai_osop.api.deps import verify_token
    from ai_osop.api.main import app

    async def junior():
        return {"sub": "tenant-operator", "role": "operator", "claims": {"exp": 2000000000}}

    app.dependency_overrides[verify_token] = junior
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            result = await client.get("/system/mcp/health")
            probe = await client.post("/system/mcp/private-server/ping")
        assert result.status_code == 403
        assert probe.status_code == 403
    finally:
        app.dependency_overrides.pop(verify_token, None)
