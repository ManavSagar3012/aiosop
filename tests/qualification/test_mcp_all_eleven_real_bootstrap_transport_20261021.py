"""Genuine loopback HTTP bootstrap for all eleven configured MCP client paths.

The providers are disposable inert fixtures: this qualifies socket/HTTP,
initialize, bounded manifests and bootstrap dispatch, NOT real scanners,
provider-origin signatures, independent target effects or deployed runtime.
"""

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from uuid import uuid4

import pytest
from aiohttp import web

from ai_osop.api import main
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPRegistry


SERVER_SETTINGS = {
    "burp-mcp": "burp_mcp",
    "recon-mcp": "recon_mcp",
    "payload-mcp": "payload_mcp",
    "nuclei-mcp": "nuclei_mcp",
    "shodan-mcp": "shodan_mcp",
    "browser-mcp": "browser_mcp",
    "security-bridge": "security_bridge",
    "threat-intel-mcp": "threat_intel_mcp",
    "source-map-mcp": "source_map_mcp",
    "cloud-mcp": "cloud_mcp",
    "turbo-intruder-mcp": "turbo_intruder_mcp",
}


@asynccontextmanager
async def _local_fleet(
    monkeypatch: pytest.MonkeyPatch, *, bad: str = ""
) -> AsyncIterator[dict[str, list[tuple[str, dict[str, Any]]]]]:
    runners: list[web.AppRunner] = []
    calls: dict[str, list[tuple[str, dict[str, Any]]]] = {name: [] for name in SERVER_SETTINGS}
    try:
        for server_id, setting in SERVER_SETTINGS.items():
            app = web.Application()

            async def health(_: web.Request, name: str = server_id) -> web.Response:
                calls[name].append(("health", {}))
                return web.json_response({"status": "healthy"})

            async def initialize(request: web.Request, name: str = server_id) -> web.Response:
                data = await request.json()
                calls[name].append(("initialize", data))
                tools = (
                    []
                    if name == bad
                    else [
                        {
                            "name": "list_tools",
                            "description": "Fixture-only read-only discovery",
                            "parameters": [],
                            "returns": {"type": "object"},
                            "side_effect_class": "READ_ONLY",
                            "requires_approval": False,
                            "scope_check": True,
                        }
                    ]
                )
                return web.json_response(
                    {
                        "server_id": name,
                        "version": "isolated-fixture",
                        "status": "ready",
                        "capabilities": [],
                        "tools": tools,
                    }
                )

            async def execute(request: web.Request, name: str = server_id) -> web.Response:
                data = await request.json()
                calls[name].append(("execute", data))
                if data.get("tool_name") != "list_tools" or data.get("parameters") != {}:
                    return web.json_response({"status": "denied"}, status=403)
                return web.json_response(
                    {
                        "request_id": data["request_id"],
                        "status": "success",
                        "result": {
                            "count": 1,
                            "target_effect_verified": True,
                            "provider_claim": "not_target_proof",
                        },
                    }
                )

            app.router.add_get("/health", health)
            app.router.add_post("/mcp/initialize", initialize)
            app.router.add_post("/mcp/execute", execute)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            runners.append(runner)
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            assert site._server is not None
            port = int(site._server.sockets[0].getsockname()[1])
            monkeypatch.setattr(main.settings, f"{setting}_host", "127.0.0.1")
            monkeypatch.setattr(main.settings, f"{setting}_port", port)
        yield calls
    finally:
        for runner in reversed(runners):
            await runner.cleanup()


@pytest.mark.asyncio
async def test_all_eleven_actual_http_initialize_and_inert_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main.settings, "environment", "development")
    async with _local_fleet(monkeypatch) as calls:
        registry = MCPRegistry()
        try:
            report = await main.register_optional_mcp_servers(registry)
            assert len(report) == len(registry._servers) == 11
            assert set(report) == set(SERVER_SETTINGS)
            assert all(
                item["registered"]
                and item["initialized"]
                and item["status"] == "initialized"
                and item["runtime_health_verified"] is False
                for item in report.values()
            )
            for name in SERVER_SETTINGS:
                assert [event for event, _ in calls[name]] == ["health", "initialize"]
                assert calls[name][1][1]["scope"] == {}
                assert calls[name][1][1]["auth_credentials"] == {}
                assert calls[name][1][1]["session_id"] == "api-bootstrap"
                RequestContext.bind(engagement_id="api-bootstrap", task_id="task-fixture")
                try:
                    result = await registry.execute_tool(
                        name, "list_tools", {}, request_id="req-" + uuid4().hex
                    )
                finally:
                    RequestContext.clear()
                assert result.status == "success"
                assert result.result == {"count": 1, "provider_claim": "not_target_proof"}
                assert result.provider_provenance.target_effect_verified is False
                assert [event for event, _ in calls[name]] == ["health", "initialize", "execute"]
                assert calls[name][-1][1]["tool_name"] == "list_tools"
        finally:
            await registry.close_all()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["burp-mcp", "cloud-mcp"])
async def test_invalid_optional_or_critical_initialize_stays_unavailable(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    monkeypatch.setattr(main.settings, "environment", "development")
    async with _local_fleet(monkeypatch, bad=bad) as calls:
        registry = MCPRegistry()
        try:
            report = await main.register_optional_mcp_servers(registry)
            assert len(report) == 11
            assert report[bad]["registered"] is True
            assert report[bad]["initialized"] is False
            assert report[bad]["status"] == "unavailable"
            assert registry._servers[bad]._initialized is False
            assert all(
                record["status"] == "initialized" for name, record in report.items() if name != bad
            )
            assert all("execute" not in [kind for kind, _ in seen] for seen in calls.values())
        finally:
            await registry.close_all()


@pytest.mark.asyncio
async def test_production_critical_inert_manifest_denies_app_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main.settings, "environment", "production")
    async with _local_fleet(monkeypatch, bad="cloud-mcp"):
        registry = MCPRegistry()
        try:
            with pytest.raises(RuntimeError, match="Required critical MCP initialization"):
                await main.register_optional_mcp_servers(registry)
        finally:
            await registry.close_all()


@pytest.mark.asyncio
async def test_stalled_optional_handshake_times_out_without_blocking_other_ten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main.settings, "environment", "development")
    monkeypatch.setattr(main, "_MCP_BOOTSTRAP_INIT_TIMEOUT_SECONDS", 0.05)
    async with _local_fleet(monkeypatch) as calls:
        registry = MCPRegistry()
        real_initialize = registry.initialize_server

        async def bounded_initialize(
            server_id: str, scope: dict, credentials: dict, session_id: str
        ):
            if server_id == "burp-mcp":
                import asyncio

                await asyncio.Event().wait()
                raise AssertionError("Cancelled handshake unexpectedly resumed")
            return await real_initialize(server_id, scope, credentials, session_id)

        registry.initialize_server = bounded_initialize  # type: ignore[method-assign]
        try:
            report = await main.register_optional_mcp_servers(registry)
            assert report["burp-mcp"]["status"] == "unavailable"
            assert registry._servers["burp-mcp"]._initialized is False
            assert all(
                record["status"] == "initialized"
                for name, record in report.items()
                if name != "burp-mcp"
            )
            assert calls["burp-mcp"] == [("health", {})]
            assert all(
                [kind for kind, _ in calls[name]] == ["health", "initialize"]
                for name in SERVER_SETTINGS
                if name != "burp-mcp"
            )
        finally:
            await registry.close_all()
