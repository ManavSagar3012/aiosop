"""Real mounted Cloud static-IaC pre-Pydantic request bounds; no live provider."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest


def _module():
    path = Path(__file__).resolve().parents[1] / "mcp-servers" / "python" / "cloud_mcp.py"
    spec = importlib.util.spec_from_file_location("_cloud_wire_guard_original", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_real_execute_route_is_preparse_bounded_and_duplicate_strict(monkeypatch, tmp_path):
    module = _module()
    assert any(
        isinstance(route, module._BoundedCloudExecuteRoute) and route.path == "/mcp/execute"
        for route in module.app.routes
    )
    token = "t" * 40
    configuration = lambda: (tmp_path, tmp_path / "checkov", token, "a" * 64)
    scanned = AsyncMock(return_value=[])
    config_called = []

    def available():
        config_called.append(True)
        return configuration()

    monkeypatch.setattr(module, "_configuration", available)
    monkeypatch.setattr(module, "_scan", scanned)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app), base_url="http://local-only.invalid"
    ) as client:
        headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        for payload in (
            b'{"tool_name":"scan_local_iac","tool_name":"overwrite","parameters":{}}',
            b'{"tool_name":"scan_local_iac","parameters":{"x":1,"x":2}}',
            b'{"tool_name":"scan_local_iac","parameters":{},"unknown":NaN}',
            b'{"tool_name":"scan_local_iac","parameters":{},"unknown":1e309}',
            b'{"tool_name":"scan_local_iac","parameters":{},"unknown":Infinity}',
            b'{"tool_name":"scan_local_iac","parameters":{},"unknown":"\xff"}',
            b"[]",
            b"{not-json",
        ):
            denied = await client.post("/mcp/execute", content=payload, headers=headers)
            assert denied.status_code == 422
        too_large = await client.post("/mcp/execute", content=b"x" * 50_000, headers=headers)
        assert too_large.status_code == 413
        wrong_type = await client.post(
            "/mcp/execute", content=b"a", headers={"Content-Type": "text/plain"}
        )
        assert wrong_type.status_code == 415

        async def unknown_length():
            for _ in range(20):
                yield b"x" * 1024

        no_length = await client.post("/mcp/execute", content=unknown_length(), headers=headers)
        assert no_length.status_code == 413
        assert config_called == []
        assert scanned.await_count == 0

        accepted = await client.post(
            "/mcp/execute",
            json={
                "tool_name": "scan_local_iac",
                "parameters": {},
                "request_id": "req-inert-local",
            },
            headers={"Authorization": "Bearer " + token},
        )
        assert accepted.status_code == 200
        result = accepted.json()["result"]
        assert result["target_effect_verified"] is False
        assert result["live_cloud_account_verified"] is False
        assert scanned.await_count == 1
        assert len(config_called) == 2
