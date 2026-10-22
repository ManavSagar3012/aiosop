"""The fleet probe must never mistake errors or declarations for execution."""

import sys

import httpx
import pytest

from scripts.ops import mcp_validator


@pytest.mark.asyncio
async def test_probe_never_executes_advertised_scanner(monkeypatch):
    monkeypatch.setattr(mcp_validator, "MCP_SERVERS", {"nuclei-mcp": 8084})
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ready"})
        return httpx.Response(
            200,
            json={
                "server_id": "nuclei-mcp",
                "status": "ready",
                "tools": [{"name": "scan"}],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        records = await mcp_validator.validate_mcps(public_intel_smoke=True, client=client)

    assert calls == ["/health", "/mcp/initialize"]
    assert records[0]["initialization"] == "ready"
    assert records[0]["execution"] == "not_attempted"
    assert records[0]["end_to_end_verified"] is False


def test_public_intel_smoke_exit_status_reflects_lookup(monkeypatch, capsys):
    async def failed_probe(**kwargs):
        return [
            {
                "server_id": "threat-intel-mcp",
                "critical": False,
                "execution": "public_lookup_failed",
                "end_to_end_verified": False,
            }
        ]

    monkeypatch.setattr(mcp_validator, "validate_mcps", failed_probe)
    monkeypatch.setattr(sys, "argv", ["mcp_validator.py", "--public-intel-smoke"])
    assert mcp_validator.main() == 1
    capsys.readouterr()

    async def successful_probe(**kwargs):
        return [
            {
                "server_id": "threat-intel-mcp",
                "critical": False,
                "execution": "public_lookup_verified",
                "end_to_end_verified": False,
            }
        ]

    monkeypatch.setattr(mcp_validator, "validate_mcps", successful_probe)
    assert mcp_validator.main() == 0


@pytest.mark.asyncio
async def test_probe_rejects_error_as_execution_success(monkeypatch):
    monkeypatch.setattr(mcp_validator, "MCP_SERVERS", {"threat-intel-mcp": 8086})

    def handler(request):
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ready"})
        if request.url.path == "/mcp/initialize":
            return httpx.Response(
                200,
                json={
                    "server_id": "threat-intel-mcp",
                    "status": "ready",
                    "tools": [{"name": "cve_lookup"}],
                },
            )
        assert request.url.path == "/mcp/execute"
        return httpx.Response(200, json={"status": "error", "error": "unavailable"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        records = await mcp_validator.validate_mcps(public_intel_smoke=True, client=client)

    assert records[0]["execution"] == "public_lookup_failed"
    assert records[0]["end_to_end_verified"] is False
