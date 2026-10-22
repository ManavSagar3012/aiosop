"""Production HTTP readiness must not promote an inert/partial MCP fleet.

These tests use only in-process fake health observations. They neither start
provider processes nor claim that a reachable socket proves target effects.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_osop.api import health
from ai_osop.api.deps import state
from ai_osop.api.mcp_fleet_readiness import _FLEET


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["none", "different_server", "wrong_critical"])
async def test_internal_mcp_health_requires_exact_named_fleet_and_correct_risk_roles(
    monkeypatch: pytest.MonkeyPatch, tamper: str
) -> None:
    """No spare fake ID/role may replace a required MCP in a READY roster."""
    bootstrap = {
        name: {
            "critical": role == "critical",
            "status": "initialized",
            "initialized": True,
            "runtime_health_verified": True,
        }
        for name, role in _FLEET
    }
    if tamper == "different_server":
        bootstrap["impostor-mcp"] = bootstrap.pop("burp-mcp")
    elif tamper == "wrong_critical":
        bootstrap["nuclei-mcp"]["critical"] = False
        bootstrap["burp-mcp"]["critical"] = True
    fake_connections = {name: SimpleNamespace(_session=object()) for name in bootstrap}
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(mcp_registry=SimpleNamespace(_servers=fake_connections)),
    )
    monkeypatch.setitem(state, "mcp_bootstrap_readiness", bootstrap)
    result = await health._check_mcp_registry()
    assert result["status"] == ("healthy" if tamper == "none" else "degraded")
    assert result["total_servers"] == 11
    assert result["fleet_runtime_verified"] == 11


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fleet",
    [
        {"status": "healthy", "total_servers": 1},
        {
            "status": "degraded",
            "total_servers": 11,
            "critical_required": 5,
            "critical_initialized": 5,
            "critical_runtime_verified": 0,
        },
        {
            "status": "healthy",
            "total_servers": 11,
            "critical_required": 5,
            "critical_initialized": 4,
            "critical_runtime_verified": 5,
        },
        {
            "status": "healthy",
            "total_servers": 11,
            "critical_required": 5,
            "critical_initialized": 5,
            "critical_runtime_verified": 0,
        },
        {
            "status": "healthy",
            "total_servers": 11,
            "critical_required": 5,
            "critical_initialized": 5,
            "critical_runtime_verified": 5,
            "fleet_initialized": 10,
            "fleet_runtime_verified": 10,
        },
        {
            "status": "healthy",
            "total_servers": 11,
            "critical_required": 4,
            "critical_initialized": 4,
            "critical_runtime_verified": 4,
        },
        {"status": "unknown", "total_servers": 0},
    ],
)
async def test_production_ready_denies_without_eleven_current_runtime_witnesses(
    monkeypatch: pytest.MonkeyPatch, fleet: dict[str, object]
) -> None:
    monkeypatch.setattr(health.settings, "environment", "production")
    monkeypatch.setattr(health, "_check_redis", AsyncMock(return_value={"status": "healthy"}))
    monkeypatch.setattr(health, "_check_neo4j", AsyncMock(return_value={"status": "healthy"}))
    monkeypatch.setattr(health, "_check_postgres", AsyncMock(return_value={"status": "healthy"}))
    monkeypatch.setattr(health, "_check_mcp_registry", AsyncMock(return_value=fleet))
    health._readiness_history.clear()
    app = FastAPI()
    app.include_router(health.router)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.get("/ready")
    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["status"] == "not_ready"
    assert detail["checks"]["mcp_registry"] == fleet
    assert detail["history"][-1]["status"] == "not_ready"


@pytest.mark.asyncio
async def test_production_complete_internal_witness_shape_preserves_other_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only correctly shaped internally checked evidence could clear the fence.

    This deliberately simulated contract does NOT exist in deployed runtime:
    runtime_health_verified remains False for actual registry observations.
    """
    monkeypatch.setattr(health.settings, "environment", "prod")
    for name in ("_check_redis", "_check_neo4j", "_check_postgres"):
        monkeypatch.setattr(health, name, AsyncMock(return_value={"status": "healthy"}))
    monkeypatch.setattr(
        health,
        "_check_mcp_registry",
        AsyncMock(
            return_value={
                "status": "healthy",
                "total_servers": 11,
                "critical_required": 5,
                "critical_initialized": 5,
                "critical_runtime_verified": 5,
                "fleet_initialized": 11,
                "fleet_runtime_verified": 11,
            }
        ),
    )
    result = await health.ready()
    assert result["status"] == "ready"


@pytest.mark.asyncio
async def test_development_keeps_observable_degraded_fleet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(health.settings, "environment", "development")
    for name in ("_check_redis", "_check_neo4j", "_check_postgres"):
        monkeypatch.setattr(health, name, AsyncMock(return_value={"status": "healthy"}))
    monkeypatch.setattr(
        health,
        "_check_mcp_registry",
        AsyncMock(return_value={"status": "degraded", "total_servers": 0}),
    )
    result = await health.ready()
    assert result["status"] == "degraded"
