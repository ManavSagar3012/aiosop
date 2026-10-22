"""Isolated real MCPRegistry diagnostic qualification for eleven inert MCPs.

All HTTP listeners are test-owned ephemeral numeric 127.0.0.1 sockets.
Provider success is never treated as independently signed target-owner effect.
No app database, scan, real tool, Docker, grant, API key, or external network.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

import pytest
from aiohttp import web

from ai_osop.mcp.protocol import MCPRegistry
from scripts.qualification import mcp_eleven_inert_diagnostic_20261021 as diag


class InertService:
    def __init__(self, name: str, *, behavior: str = "safe") -> None:
        self.name = name
        self.behavior = behavior
        self.events: list[tuple[str, dict[str, Any]]] = []

    async def health(self, _: web.Request) -> web.Response:
        self.events.append(("health", {}))
        return web.json_response({"status": "healthy"})

    async def initialize(self, request: web.Request) -> web.Response:
        body = await request.json()
        self.events.append(("initialize", body))
        if self.behavior == "missing_declaration":
            tool_name = "authority_status"
        else:
            tool_name = "list_tools"
        tool = {
            "name": tool_name,
            "description": "Inert fixture only; no external target",
            "parameters": [],
            "returns": {"type": "object"},
            "side_effect_class": "READ_ONLY",
            "requires_approval": False,
            "scope_check": True,
            "timeout_seconds": 4,
        }
        if self.behavior == "requires_approval":
            tool["requires_approval"] = True
        if self.behavior == "unsafe_manifest":
            tool["side_effect_class"] = "RECON_ACTIVE"
            tool["requires_approval"] = True
        if self.behavior == "parameters":
            tool["parameters"] = [
                {
                    "name": "target",
                    "type": "string",
                    "description": "Must never supply target",
                    "required": True,
                }
            ]
        if self.behavior == "no_explicit_flags":
            del tool["side_effect_class"]
        if self.behavior == "wrong_identity":
            name = "recon-mcp" if self.name != "recon-mcp" else "payload-mcp"
        else:
            name = self.name
        return web.json_response(
            {
                "server_id": name,
                "status": "unavailable" if self.behavior == "not_ready" else "ready",
                "version": "fixture-20261021",
                "capabilities": [],
                "tools": [
                    tool,
                    {
                        "name": "scan_target",
                        "description": "NEVER EXECUTE",
                        "parameters": [],
                        "returns": {"type": "object"},
                        "timeout_seconds": 4,
                        "side_effect_class": "RECON_ACTIVE",
                        "requires_approval": True,
                        "scope_check": True,
                    },
                ],
            }
        )

    async def execute(self, request: web.Request) -> web.Response:
        payload = await request.json()
        self.events.append(("execute", payload))
        if payload.get("tool_name") != "list_tools" or payload.get("parameters") != {}:
            return web.json_response({"status": "error"}, status=403)
        if self.behavior == "expired":
            return web.json_response({"request_id": payload["request_id"], "status": "expired"})
        if self.behavior == "replay":
            return web.json_response(
                {"request_id": payload["request_id"], "status": "duplicate_request"}
            )
        if self.behavior == "lost_ack":
            return web.json_response(
                {
                    "status": "success",
                    "result": {
                        "secret": "PRIVATE_PROVIDER_STRING",
                        "target_effect_verified": True,
                    },
                },
                status=503,
            )
        if self.behavior == "malformed":
            return web.Response(
                text='{ "status": "success", "status": "error" }', content_type="application/json"
            )
        if self.behavior == "nonfinite":
            return web.Response(
                text='{"status":"success","result":{"value":NaN}}', content_type="application/json"
            )
        if self.behavior == "wrong_request":
            return web.json_response(
                {
                    "request_id": "req-stale",
                    "status": "success",
                    "result": {"target_effect_verified": True},
                }
            )
        return web.json_response(
            {
                "request_id": payload["request_id"],
                "status": "success",
                "result": {
                    "target_effect_verified": True,
                    "production_certified": True,
                    "secret": "PRIVATE_PROVIDER_STRING",
                },
            }
        )


@asynccontextmanager
async def fleet(
    *,
    behaviors: Optional[dict[str, str]] = None,
) -> AsyncIterator[tuple[dict[str, int], dict[str, InertService]]]:
    services: dict[str, InertService] = {}
    ports: dict[str, int] = {}
    runners: list[web.AppRunner] = []
    try:
        for name in diag.SERVICE_IDS:
            fixture = InertService(name, behavior=(behaviors or {}).get(name, "safe"))
            app = web.Application(client_max_size=8192)
            app.router.add_get("/health", fixture.health)
            app.router.add_post("/mcp/initialize", fixture.initialize)
            app.router.add_post("/mcp/execute", fixture.execute)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            runners.append(runner)
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            assert site._server is not None
            port = int(site._server.sockets[0].getsockname()[1])
            assert port not in diag._FORBIDDEN_PORTS
            ports[name] = port
            services[name] = fixture
        yield ports, services
    finally:
        for runner in reversed(runners):
            await runner.cleanup()


@pytest.mark.asyncio
async def test_all_eleven_actual_registry_health_initialize_and_only_inert_discovery() -> None:
    assert len(diag.SERVICE_IDS) == len(set(diag.SERVICE_IDS)) == 11
    async with fleet() as (allowed, providers):
        rows = await diag.diagnose(allowed)
        assert [row["server_id"] for row in rows] == list(diag.SERVICE_IDS)
        assert all(row["registered"] is True and row["initialized"] is True for row in rows)
        assert all(row["state"] == "initialized_only" for row in rows)
        assert all(row["inert_outcome"] == "provider_reported_success_unverified" for row in rows)
        assert all(
            row["target_effect_verified"] is False and row["production_certified"] is False
            for row in rows
        )
        request_ids = set()
        for name, provider in providers.items():
            assert [event for event, _ in provider.events] == ["health", "initialize", "execute"]
            initialized = provider.events[1][1]
            assert initialized["scope"] == {}
            assert initialized["auth_credentials"] == {}
            assert initialized["session_id"] == "api-bootstrap"
            attempted = provider.events[2][1]
            assert attempted["tool_name"] == "list_tools" and attempted["parameters"] == {}
            assert attempted["request_id"] not in request_ids
            request_ids.add(attempted["request_id"])
            assert "native_grant" not in attempted
        assert len(request_ids) == 11


@pytest.mark.asyncio
async def test_unallowed_services_are_never_contacted() -> None:
    async with fleet() as (ports, providers):
        rows = await diag.diagnose({"burp-mcp": ports["burp-mcp"]})
        assert len(rows) == 11
        for row in rows:
            if row["server_id"] == "burp-mcp":
                assert row["initialized"] and row["registered"]
            else:
                assert row["state"] == "not_allowed"
                assert row["registered"] is False
                assert providers[row["server_id"]].events == []


@pytest.mark.parametrize(
    "invalid",
    [
        ["recon-mcp=localhost:8082"],
        ["recon-mcp=127.0.0.2:8082"],
        ["recon-mcp=0.0.0.0:8082"],
        ["recon-mcp=[::1]:8082"],
        ["recon-mcp=http://127.0.0.1:8082"],
        ["recon-mcp=127.0.0.1:5432"],
        ["recon-mcp=127.0.0.1:6379"],
        ["recon-mcp=127.0.0.1:8200"],
        ["recon-mcp=127.0.0.1:0"],
        ["recon-mcp=127.0.0.1:65536"],
        ["recon-mcp=127.0.0.1:08082"],
        ["recon-mcp=127.0.0.1:8082?x=1"],
        ["unknown-mcp=127.0.0.1:8082"],
        ["recon-mcp=127.0.0.1:8082", "recon-mcp=127.0.0.1:8083"],
        ["recon-mcp=127.0.0.1:8082", "payload-mcp=127.0.0.1:8082"],
        ["recon-mcp=127.0.0.1:8082"] * 12,
    ],
)
def test_invalid_or_external_ports_rejected_before_socket(invalid: list[str]) -> None:
    with pytest.raises(diag.UnsafeEndpoint):
        diag.parse_allow(invalid)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "missing_declaration",
        "requires_approval",
        "unsafe_manifest",
        "parameters",
        "no_explicit_flags",
        "wrong_identity",
        "not_ready",
    ],
)
async def test_provider_manifest_never_authorizes_consequential_tool(case: str) -> None:
    async with fleet(behaviors={"recon-mcp": case}) as (ports, providers):
        rows = await diag.diagnose({"recon-mcp": ports["recon-mcp"]})
        actual = next(item for item in rows if item["server_id"] == "recon-mcp")
        assert actual["inert_outcome"] in {"unknown", "not_declared"}
        assert actual["target_effect_verified"] is False
        assert [entry[0] for entry in providers["recon-mcp"].events] == ["health", "initialize"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "expired",
        "replay",
        "lost_ack",
        "malformed",
        "nonfinite",
        "wrong_request",
    ],
)
async def test_expired_replay_malformed_or_lost_ack_remains_unknown_no_retry(case: str) -> None:
    async with fleet(behaviors={"cloud-mcp": case}) as (ports, providers):
        rows = await diag.diagnose({"cloud-mcp": ports["cloud-mcp"]})
        record = next(item for item in rows if item["server_id"] == "cloud-mcp")
        assert record["registered"] and record["initialized"]
        assert record["inert_outcome"] == "unknown"
        assert record["target_effect_verified"] is False
        assert [event for event, _ in providers["cloud-mcp"].events] == [
            "health",
            "initialize",
            "execute",
        ]


@pytest.mark.asyncio
async def test_real_registry_stays_undispatchable_when_health_or_initialize_fails() -> None:
    async with fleet(behaviors={"browser-mcp": "wrong_identity"}) as (ports, providers):
        registry = MCPRegistry()
        rows = await diag.diagnose({"browser-mcp": ports["browser-mcp"]}, registry=registry)
        item = next(record for record in rows if record["server_id"] == "browser-mcp")
        assert item["registered"] and not item["initialized"]
        assert item["inert_outcome"] == "unknown"
        # Actual MCPRegistry.close_all() closes and removes connections; it
        # must not leave an initialized connection dispatchable after denial.
        assert registry._servers == {}
        assert [event for event, _ in providers["browser-mcp"].events] == ["health", "initialize"]


def test_cli_with_no_allowlist_outputs_exactly_eleven_truthful_records(capsys: Any) -> None:
    assert diag.main([]) == 0
    emitted = capsys.readouterr().out.splitlines()
    assert len(emitted) == 11
    parsed = [json.loads(line) for line in emitted]
    assert [row["server_id"] for row in parsed] == list(diag.SERVICE_IDS)
    assert all(row["state"] == "not_allowed" and not row["initialized"] for row in parsed)
    assert all(row["inert_outcome"] == "not_checked" for row in parsed)
    assert "PRIVATE_PROVIDER_STRING" not in "\n".join(emitted)


@pytest.mark.asyncio
async def test_tainted_programmatic_mapping_denied_before_connection() -> None:
    for bad in (
        {"recon-mcp": "8082"},
        {"recon-mcp": 5432},
        {"wrong-server": 8092},
        {"recon-mcp": True},
    ):
        with pytest.raises(diag.UnsafeEndpoint):
            await diag.diagnose(bad)


@pytest.mark.asyncio
async def test_diagnostic_does_not_print_provider_secrets_or_fake_effects(
    capsys: Any,
) -> None:
    async with fleet() as (allowed, _):
        # Same output projection used by operator CLI; never print provider
        # results or exception content, which are untrusted and may be secrets.
        lines = [json.dumps(row, sort_keys=True) for row in await diag.diagnose(allowed)]
    assert all("PRIVATE_PROVIDER_STRING" not in text for text in lines)
    assert all('"target_effect_verified": false' in text for text in lines)
    assert all('"production_certified": false' in text for text in lines)
