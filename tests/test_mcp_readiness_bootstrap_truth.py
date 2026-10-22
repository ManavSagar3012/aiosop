"""A health socket cannot certify the configured MCP execution fleet."""

from types import SimpleNamespace

import pytest

from ai_osop.api.deps import state
from ai_osop.api.health import _check_mcp_registry


@pytest.mark.asyncio
async def test_ready_probe_degrades_uninitialized_critical_fleet(monkeypatch) -> None:
    connection = SimpleNamespace(_session=object())
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(mcp_registry=SimpleNamespace(_servers={"burp-mcp": connection})),
    )
    monkeypatch.setitem(
        state,
        "mcp_bootstrap_readiness",
        {
            "burp-mcp": {"critical": False, "status": "registered", "initialized": False},
            "nuclei-mcp": {
                "critical": True,
                "status": "unavailable",
                "initialized": False,
                "runtime_health_verified": False,
            },
        },
    )

    result = await _check_mcp_registry()

    assert result["status"] == "degraded"
    assert result["healthy_servers"] == 1
    assert result["critical_required"] == 1
    assert result["critical_initialized"] == 0
    assert result["critical_runtime_verified"] == 0
