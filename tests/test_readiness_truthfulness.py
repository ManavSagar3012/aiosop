"""Production probes must not invent a passing release certificate or leak DSNs."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from ai_osop.api import health
from ai_osop.api.deps import state
from ai_osop.api.routers.system import get_trust_score


@pytest.mark.asyncio
@pytest.mark.parametrize("critical", ("postgres", "redis", "neo4j"))
async def test_unknown_critical_dependency_fails_closed(monkeypatch, critical):
    for name in ("postgres", "redis", "neo4j", "mcp_registry"):
        status = "unknown" if name == critical else "healthy"
        monkeypatch.setattr(
            health,
            "_check_" + name,
            AsyncMock(return_value={"status": status}),
        )
    with pytest.raises(HTTPException) as exc:
        await health.ready()
    assert exc.value.status_code == 503
    assert exc.value.detail["status"] == "not_ready"
    assert exc.value.detail["checks"][critical]["status"] == "unknown"


@pytest.mark.asyncio
async def test_unverified_mcp_does_not_misclassify_healthy_critical_stores(monkeypatch):
    for name in ("postgres", "redis", "neo4j"):
        monkeypatch.setattr(
            health,
            "_check_" + name,
            AsyncMock(return_value={"status": "healthy"}),
        )
    monkeypatch.setattr(
        health,
        "_check_mcp_registry",
        AsyncMock(return_value={"status": "unknown"}),
    )
    value = await health.ready()
    assert value["status"] == "degraded"


@pytest.mark.asyncio
async def test_connection_errors_never_reflect_sensitive_driver_text():
    original = state.get("orchestrator")
    orch = MagicMock()
    orch.session_memory._redis = AsyncMock()
    orch.session_memory._redis.ping = AsyncMock(
        side_effect=RuntimeError("redis://user:SECRET@server")
    )
    orch.session_memory._pg_engine.connect.side_effect = RuntimeError(
        "postgresql://user:SECRET@server"
    )
    orch.graph_memory._driver.verify_connectivity = AsyncMock(
        side_effect=RuntimeError("bolt://user:SECRET@server")
    )
    orch.mcp_registry._servers.keys.side_effect = RuntimeError("authorization: SECRET")
    try:
        state["orchestrator"] = orch
        for check in (
            health._check_redis,
            health._check_postgres,
            health._check_neo4j,
            health._check_mcp_registry,
        ):
            status = await check()
            assert status["status"] == "unhealthy"
            assert "SECRET" not in str(status)
            assert "://" not in str(status)
    finally:
        if original is None:
            state.pop("orchestrator", None)
        else:
            state["orchestrator"] = original


@pytest.mark.asyncio
async def test_trust_score_never_returns_fabricated_release_certification():
    status = await get_trust_score({"sub": "signed-owner", "role": "operator"})
    assert status["trust_score"] is None
    assert status["readiness"] == "unverified"
    assert status["last_audited"] is None
    assert status["production_certified"] is False
    assert status["independent_release_verification"] is False
    assert "97" not in str(status)


@pytest.mark.asyncio
@pytest.mark.parametrize("service", ("redis", "neo4j", "postgres"))
async def test_readiness_dependency_probes_have_strict_deadlines(monkeypatch, service):
    monkeypatch.setattr(health, "_DEPENDENCY_TIMEOUT_SECONDS", 0.01)
    previous = state.get("orchestrator")
    orch = MagicMock()

    async def stalled():
        await asyncio.sleep(2)

    orch.session_memory._redis.ping = AsyncMock(side_effect=stalled)
    orch.graph_memory._driver.verify_connectivity = AsyncMock(side_effect=stalled)
    orch.session_memory._pg_engine.connect.return_value.__aenter__ = AsyncMock(
        side_effect=stalled,
    )
    try:
        state["orchestrator"] = orch
        result = await getattr(health, "_check_" + service)()
        assert result["status"] == "unhealthy"
        assert "unavailable" in result["error"]
    finally:
        if previous is None:
            state.pop("orchestrator", None)
        else:
            state["orchestrator"] = previous


@pytest.mark.asyncio
async def test_readiness_probes_start_concurrently_without_serial_deadline_stalls(
    monkeypatch,
):
    started = 0
    all_started = asyncio.Event()

    async def check():
        nonlocal started
        started += 1
        if started == 4:
            all_started.set()
        await asyncio.wait_for(all_started.wait(), timeout=0.3)
        return {"status": "healthy"}

    for name in ("redis", "neo4j", "postgres", "mcp_registry"):
        monkeypatch.setattr(health, "_check_" + name, check)
    result = await health.ready()
    assert started == 4
    assert result["status"] == "ready"
