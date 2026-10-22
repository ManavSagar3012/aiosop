"""All eleven configured MCP services remain visible without invented effects."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state, verify_token
from ai_osop.api.main import app
from ai_osop.api.mcp_fleet_readiness import mcp_fleet_process_visibility
from ai_osop.api.routers.system import get_mcp_fleet_readiness


def _registry(monkeypatch: pytest.MonkeyPatch, service: str = "browser-mcp") -> None:
    record = SimpleNamespace(
        server_id=service,
        host="never-disclose-internal.example",
        auth_token="Bearer do-not-echo-this-secret",
        _tools={"private_tool": "not an authorized target operation"},
        _failure_count=0,
        _success_count=12,
        _recovery_attempts=0,
        _consecutive_successes=12,
        _initialized=True,
        get_circuit_state=lambda: "closed",
    )
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(mcp_registry=SimpleNamespace(_servers={service: record})),
    )


@pytest.mark.asyncio
async def test_mounted_readiness_reports_all_11_without_asserting_target_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _registry(monkeypatch)
    result = await get_mcp_fleet_readiness(operator={"role": "senior_operator", "sub": "senior"})
    assert result["configured_count"] == 11
    assert len(result["services"]) == 11
    assert result["release_decision"] == "NOT PRODUCTION CERTIFIED / NOT READY"
    assert result["production_certified"] is False
    assert result["independently_verified_operations"] is None
    assert {item["server_id"] for item in result["services"]} == {
        "burp-mcp",
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
        "browser-mcp",
        "source-map-mcp",
        "cloud-mcp",
        "turbo-intruder-mcp",
    }
    browser = next(item for item in result["services"] if item["server_id"] == "browser-mcp")
    assert browser["process_registered"] is True
    assert browser["process_initialized"] is True
    assert browser["qualification"] == "process_registration_only"
    unregistered = next(item for item in result["services"] if item["server_id"] == "cloud-mcp")
    assert unregistered["process_registered"] is False
    assert unregistered["qualification"] == "not_verified"
    assert sum(item["importance"] == "critical" for item in result["services"]) == 5
    assert all(
        item["runtime_health_verified"] is False
        and item["current_authorized_operation_verified"] is False
        and item["independent_target_effect_verified"] is False
        and item["production_certified"] is False
        for item in result["services"]
    )
    for private in ("never-disclose", "Bearer", "private_tool", "internal.example", "8091"):
        assert private not in repr(result)


def test_fleet_projection_rejects_unvalidated_process_health() -> None:
    for item in (
        {},
        {"catalog_scope": "target_verified", "servers": []},
        {"catalog_scope": "process_health_only_unverified", "servers": [{}]},
        {
            "catalog_scope": "process_health_only_unverified",
            "servers": [{"server_id": "browser-mcp"}],
        },
    ):
        with pytest.raises(ValueError):
            mcp_fleet_process_visibility(item)


@pytest.mark.asyncio
async def test_unavailable_registry_is_503_and_never_invents_running_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(state, "orchestrator", None)
    with pytest.raises(HTTPException) as exc:
        await get_mcp_fleet_readiness(operator={"role": "senior_operator", "sub": "senior"})
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_fleet_readiness_is_senior_only_and_mounted() -> None:
    assert "/system/mcp/fleet-readiness" in {route.path for route in app.routes}

    async def junior():
        return {"sub": "other-tenant", "role": "operator", "claims": {"exp": 2000000000}}

    app.dependency_overrides[verify_token] = junior
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            result = await client.get("/system/mcp/fleet-readiness")
        assert result.status_code == 403
    finally:
        app.dependency_overrides.pop(verify_token, None)


@pytest.mark.asyncio
async def test_senior_asgi_fleet_readback_never_exposes_provider_or_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _registry(monkeypatch, "nuclei-mcp")

    async def senior():
        return {"sub": "approved-senior", "role": "senior_operator", "claims": {"exp": 2000000000}}

    app.dependency_overrides[verify_token] = senior
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            result = await client.get("/system/mcp/fleet-readiness")
        assert result.status_code == 200
        body = result.json()
        assert body["configured_count"] == 11
        assert body["independently_verified_operations"] is None
        assert body["release_decision"] == "NOT PRODUCTION CERTIFIED / NOT READY"
        nuclei = next(item for item in body["services"] if item["server_id"] == "nuclei-mcp")
        assert nuclei["process_registered"] is True
        assert nuclei["current_authorized_operation_verified"] is False
        assert nuclei["independent_target_effect_verified"] is False
        for sensitive in ("internal.example", "private_tool", "do-not-echo", "8091", "host"):
            assert sensitive not in result.text
    finally:
        app.dependency_overrides.pop(verify_token, None)
