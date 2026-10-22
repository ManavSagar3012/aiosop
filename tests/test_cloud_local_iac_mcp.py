"""Local Checkov MCP cannot become a live-cloud finding or accept paths."""

import importlib.util
import sys
from pathlib import Path

import httpx
import pytest


def _module():
    path = Path(__file__).resolve().parents[1] / "mcp-servers" / "python" / "cloud_mcp.py"
    spec = importlib.util.spec_from_file_location("_local_iac_cloud_mcp_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_local_iac_checkov_live_mcp_contract(monkeypatch):
    root = Path(__file__).resolve().parent / "fixtures" / "local_iac"
    executable = (
        Path(__file__).resolve().parents[1] / ".runtime" / "checkov-venv" / "Scripts" / "python.exe"
    )
    if not executable.is_file():
        pytest.skip("Isolated local Checkov runtime not installed")
    token = "local-iac-test-only-token-20261021-aaaaaaaa"
    monkeypatch.setenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", "1")
    monkeypatch.setenv("OSOP_CLOUD_MCP_IAC_ROOT", str(root))
    monkeypatch.setenv("OSOP_CLOUD_MCP_CHECKOV_PYTHON", str(executable))
    monkeypatch.setenv("OSOP_CLOUD_MCP_BEARER_TOKEN", token)
    module = _module()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://local-iac.invalid",
        timeout=80.0,
    ) as client:
        health = await client.get("/health")
        assert health.status_code == 200
        declaration = await client.post("/mcp/initialize", json={})
        assert [tool["name"] for tool in declaration.json()["tools"]] == ["scan_local_iac"]
        request = {"tool_name": "scan_local_iac", "parameters": {}, "request_id": "req-local-iac-1"}
        denied = await client.post("/mcp/execute", json=request)
        assert denied.status_code == 401
        forged = await client.post(
            "/mcp/execute",
            json={**request, "parameters": {"path": "C:\\secrets"}},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert forged.status_code == 422
        result = await client.post(
            "/mcp/execute",
            json=request,
            headers={"Authorization": f"Bearer {token}"},
        )
    assert result.status_code == 200, result.json()
    body = result.json()
    assert body["status"] == "success"
    assert body["result"]["findings_count"] > 0
    assert body["result"]["live_cloud_account_verified"] is False
    assert body["result"]["target_effect_verified"] is False
    assert all("code_block" not in item for item in body["result"]["findings"])
    # Checkov emits both CKV_ and CKV2_ IDs for actual Terraform policies.
    # Dropping CKV2_ made a configured local scan return scan_unknown (503).
    identifiers = {item["check_id"] for item in body["result"]["findings"]}
    assert any(value.startswith("CKV_AWS_") for value in identifiers)
    assert any(value.startswith("CKV2_AWS_") for value in identifiers)
