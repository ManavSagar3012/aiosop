"""AI-OSOP api/health tests — mock state so probes exercise real code without infra."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from ai_osop.api import health as health_mod
from ai_osop.core.metrics import READY_STATUS


@pytest.fixture
def cleanglobal():
    health_mod._readiness_history.clear()
    yield
    health_mod._readiness_history.clear()


def _orchish(mock_sm=None, mock_gm=None, mock_reg=None):
    orch = MagicMock()
    orch.session_memory = mock_sm or MagicMock()
    orch.graph_memory = mock_gm or MagicMock()
    orch.mcp_registry = mock_reg or MagicMock()
    return orch


@pytest.mark.asyncio
async def test_readiness_503_when_redis_down(cleanglobal):
    orch = _orchish()
    orch.session_memory._redis = AsyncMock()
    orch.session_memory._redis.ping = AsyncMock(side_effect=ConnectionError("down"))
    # Healthy postgres + neo4j + mcp_registry to isolate the failure
    orch.session_memory._pg_engine = MagicMock()
    orch.session_memory._pg_engine.connect = AsyncMock()
    orch.graph_memory._driver = AsyncMock()

    with patch.object(health_mod, "state", {"orchestrator": orch}):
        with pytest.raises(Exception) as exc:
            await health_mod.ready()
        assert "503" in str(exc.value) or "not_ready" in str(exc.value)


@pytest.mark.asyncio
async def test_readiness_ready_marks_metric(cleanglobal):
    orch = _orchish()
    orch.session_memory._redis = AsyncMock()
    orch.session_memory._redis.ping = AsyncMock(return_value=True)
    orch.session_memory._pg_engine = MagicMock()
    _ctx = MagicMock()
    _ctx.__aenter__ = AsyncMock()
    _ctx.__aexit__ = AsyncMock()
    orch.session_memory._pg_engine.connect = MagicMock(return_value=_ctx)
    orch.graph_memory._driver = AsyncMock()
    orch.mcp_registry._servers = {}
    with patch.object(health_mod, "state", {"orchestrator": orch}):
        result = await health_mod.ready()
        assert result["status"] == "ready"
        # ready() sets the prometheus gauge to 1.0 on a clean pass
        for fam in READY_STATUS.collect():
            for sample in fam.samples:
                if sample.name == READY_STATUS._name:
                    assert sample.value == 1.0


@pytest.mark.asyncio
async def test_health_platform_reports_three_dep_statuses(cleanglobal):
    orch = _orchish()
    orch.session_memory._redis = AsyncMock()
    orch.session_memory._redis.ping = AsyncMock(return_value=True)
    _ctx = MagicMock()
    _ctx.__aenter__ = AsyncMock()
    _ctx.__aexit__ = AsyncMock()
    orch.session_memory._pg_engine = MagicMock()
    orch.session_memory._pg_engine.connect = MagicMock(return_value=_ctx)
    orch.graph_memory._driver = AsyncMock()

    with patch.object(health_mod, "state", {"orchestrator": orch}):
        out = await health_mod.health_platform()
        assert set(out.keys()) == {"redis", "postgres", "neo4j", "timestamp"}
        assert out["redis"]["status"] == "healthy"
        assert out["neo4j"]["status"] == "healthy"
