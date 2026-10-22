"""Safe 11-slot MCP transport/recovery checks; no scanner, DB or issued approvals.

Only inert bootstrap discovery reaches a disposable 127.0.0.1 HTTP server.
Malformed HTTP is consumed by the REAL aiohttp MCP client and original stream
decoder. Test-provider responses never constitute signed or target-owner proof.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock

import httpx
import pytest
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.core.exceptions import MCPConnectionError, MCPException
from ai_osop.core.models import ScopeDefinition
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp import protocol
from ai_osop.mcp.protocol import MCPRegistry


ROOT = Path(__file__).resolve().parents[2]
SIX_GO = (
    "recon-mcp", "payload-mcp", "nuclei-mcp", "shodan-mcp",
    "threat-intel-mcp", "security-bridge",
)
ALL_ELEVEN = (
    *SIX_GO, "burp-mcp", "browser-mcp", "source-map-mcp",
    "cloud-mcp", "turbo-intruder-mcp",
)
_SAFE_DECL = {
    "name": "list_tools", "description": "INERT LOCAL TEST CATALOGUE",
    "side_effect_class": "READ_ONLY", "requires_approval": False,
    "scope_check": True, "timeout_seconds": 4, "parameters": [],
    "returns": {"type": "object"},
}


class ControlledTransport:
    """A test-owned listener; never binds a configured MCP port."""

    def __init__(self, name: str, behavior: str) -> None:
        self.name = name
        self.behavior = behavior
        self.healthy = True
        self.ready = True
        self.burp_tool_name: str | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def health(self, _: web.Request) -> web.Response:
        self.calls.append(("health", {}))
        return web.json_response(
            {"status": "ready" if self.healthy else "unavailable"},
            status=200 if self.healthy else 503,
        )

    async def initialize(self, request: web.Request) -> web.Response:
        self.calls.append(("initialize", await request.json()))
        is_burp = self.name == "burp-mcp" and self.burp_tool_name is not None
        tools = (
            [{**_SAFE_DECL, "name": self.burp_tool_name, "requires_approval": True}]
            if is_burp else [_SAFE_DECL]
        )
        return web.json_response({
            "server_id": self.name, "version": "controlled-transport-only",
            "status": "ready" if self.ready else "unavailable",
            "capabilities": (["mcp_bound_receipts_v1", "burp_signed_observations_v1"]
                             if is_burp else ["mcp_bound_receipts_v1", "mcp_request_status_v1", "mcp_cancel_request_v1"]),
            "tools": tools,
        })

    async def execute(self, request: web.Request) -> web.StreamResponse:
        body = await request.json()
        self.calls.append(("execute", body))
        # A fixture may *never* run any scanner or any other tool.
        if body.get("tool_name") != "list_tools" or body.get("parameters") != {}:
            return web.json_response({"status": "error", "error": "inert_only"}, status=503)

        request_id = body["request_id"]
        if self.behavior == "duplicate_field":
            raw = (
                '{"request_id":' + json.dumps(request_id)
                + ',"status":"success","result":{"verified":true,"verified":false}}'
            ).encode()
        elif self.behavior == "oversized":
            # Unknown total length (Transfer-Encoding: chunked), no declared
            # Content-Length. More than the production 2MiB decoded limit.
            raw = (
                json.dumps({"request_id": request_id, "status": "success", "result": {"blob": ""}})
                .replace('"blob": ""', '"blob": "' + "X" * (2 * 1024 * 1024) + '"')
            ).encode()
        elif self.behavior == "truncated":
            raw = ('{"request_id":' + json.dumps(request_id) + ',"status":"success","result":').encode()
        elif self.behavior == "contradictory":
            raw = json.dumps({
                "request_id": request_id, "status": "success", "isError": True,
                "result": {"independent_target_effect_verified": True},
                "provider_receipt": {"verified": True, "signature": "fabricated"},
            }).encode()
        elif self.behavior == "untrusted_success":
            raw = json.dumps({
                "request_id": request_id, "status": "success",
                "result": {
                    "available_tools": 1, "target_effect_verified": True,
                    "details": [{"production_certified": True, "name": self.name}],
                },
                "metadata": {"provider_receipt_verified": True, "source": "test-provider"},
            }).encode()
        else:
            raise AssertionError("Unrecognized safe fixture behavior")

        response = web.StreamResponse(
            status=200, headers={"Content-Type": "application/json", "Cache-Control": "no-store"}
        )
        await response.prepare(request)
        # Real HTTP Transfer-Encoding: chunked, not an in-process json() fake.
        for index in range(0, len(raw), 16384):
            await response.write(raw[index:index + 16384])
        await response.write_eof()
        return response

    async def status(self, request: web.Request) -> web.Response:
        self.calls.append(("status", await request.json()))
        return web.json_response({"status": "success", "result": {
            "status": "confirmed_stopped", "verified": True,
            "attestation": {"kid": "forged", "signature": "A" * 86},
        }})

    async def cancel(self, request: web.Request) -> web.Response:
        self.calls.append(("cancel", await request.json()))
        return web.json_response({"status": "success", "result": {
            "status": "confirmed_stopped", "verified": True, "stopped": True,
            "attestation": {"kid": "forged", "signature": "A" * 86},
        }})


@asynccontextmanager
async def owned_fixture(name: str, behavior: str) -> AsyncIterator[tuple[int, ControlledTransport]]:
    fixture = ControlledTransport(name, behavior)
    app = web.Application(client_max_size=65536)
    app.router.add_get("/health", fixture.health)
    app.router.add_post("/mcp/initialize", fixture.initialize)
    app.router.add_post("/mcp/execute", fixture.execute)
    app.router.add_post("/mcp/request/status", fixture.status)
    app.router.add_post("/mcp/cancel", fixture.cancel)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        assert site._server and site._server.sockets
        address = site._server.sockets[0].getsockname()
        assert address[0] == "127.0.0.1"
        yield int(address[1]), fixture
    finally:
        await runner.cleanup()


@pytest.mark.parametrize("server_id", ALL_ELEVEN)
@pytest.mark.parametrize("behavior", ("duplicate_field", "oversized", "truncated", "contradictory"))
def test_real_network_chunked_provider_bad_body_stays_unknown_and_not_reexecuted(
    server_id: str, behavior: str,
) -> None:
    asyncio.run(_exercise_stream_fault(server_id, behavior))


async def _exercise_stream_fault(server_id: str, behavior: str) -> None:
    async with owned_fixture(server_id, behavior) as (port, remote):
        registry = MCPRegistry()
        try:
            connection = await registry.register_server(server_id, "127.0.0.1", port)
            assert connection._initialized is False
            await registry.initialize_server(server_id, {}, {}, "fixture-is-not-authority")
            assert connection._initialized is True and set(connection._tools) == {"list_tools"}
            RequestContext.bind(engagement_id="api-bootstrap", task_id="task-fixture")
            try:
                request_id = "req-" + uuid.uuid4().hex
                result = await registry.execute_tool(
                    server_id, "list_tools", {}, request_id=request_id
                )
                assert result.status == "unknown"
                assert result.metadata.get("signed_provider_receipt") is None
                assert result.result is None
                repeated = await registry.execute_tool(
                    server_id, "list_tools", {}, request_id=request_id
                )
                assert repeated.status == "duplicate_request"
            finally:
                RequestContext.clear()
            actions = [body for kind, body in remote.calls if kind == "execute"]
            assert len(actions) == 1
            assert actions[0]["tool_name"] == "list_tools"
            assert actions[0]["request_id"] == request_id
            assert not any(kind in {"status", "cancel"} for kind, _ in remote.calls)
        finally:
            await registry.close_all()


def test_registry_namespace_collision_same_tool_binds_distinct_server_and_quota() -> None:
    asyncio.run(_namespace_probe())


async def _namespace_probe() -> None:
    async with owned_fixture("recon-mcp", "untrusted_success") as (port_a, a):
        async with owned_fixture("burp-mcp", "untrusted_success") as (port_b, b):
            registry = MCPRegistry()
            charged: list[str] = []

            async def deny_quota(_: str, qualified: str, __: str | None) -> bool:
                charged.append(qualified)
                return False

            registry.set_budget_callback(deny_quota)
            try:
                for name, port in (("recon-mcp", port_a), ("burp-mcp", port_b)):
                    await registry.register_server(name, "127.0.0.1", port)
                    await registry.initialize_server(name, {}, {}, "fixture")
                RequestContext.bind(engagement_id="eng-namespace", task_id="task-namespace")
                try:
                    for name in ("recon-mcp", "burp-mcp"):
                        result = await registry.execute_tool(
                            name, "list_tools", {}, request_id="req-same-id-across-names"
                        )
                        assert result.status == "quota_exceeded"
                finally:
                    RequestContext.clear()
                assert charged == ["recon-mcp.list_tools", "burp-mcp.list_tools"]
                assert registry._servers["recon-mcp"] is not registry._servers["burp-mcp"]
                assert not any(kind == "execute" for kind, _ in (*a.calls, *b.calls))
            finally:
                await registry.close_all()


def test_failed_startup_then_renegotiation_revokes_manifest_before_reconnect() -> None:
    asyncio.run(_reconnect_probe())


async def _reconnect_probe() -> None:
    async with owned_fixture("browser-mcp", "untrusted_success") as (port, fixture):
        registry = MCPRegistry()
        try:
            fixture.healthy = False
            with pytest.raises(MCPConnectionError):
                await registry.register_server("browser-mcp", "127.0.0.1", port)
            assert "browser-mcp" not in registry._servers
            fixture.healthy = True
            connection = await registry.register_server("browser-mcp", "127.0.0.1", port)
            await registry.initialize_server("browser-mcp", {}, {}, "fixture")
            assert connection._initialized and "list_tools" in connection._tools
            fixture.ready = False
            with pytest.raises(MCPConnectionError):
                await registry.initialize_server("browser-mcp", {}, {}, "fixture")
            assert not connection._initialized
            assert connection._tools == {} and connection._capabilities == []
            RequestContext.bind(engagement_id="api-bootstrap", task_id="task-fixture")
            try:
                with pytest.raises(Exception, match="not initialized"):
                    await registry.execute_tool(
                        "browser-mcp", "list_tools", {}, request_id="req-while-revoked"
                    )
                assert not any(kind == "execute" for kind, _ in fixture.calls)
            finally:
                RequestContext.clear()
            fixture.ready = True
            await registry.initialize_server("browser-mcp", {}, {}, "fixture")
            assert connection._initialized
            # A successful RE-handshake does not create a previously missing
            # original Task approval, replay aborted work, or call any tool.
            assert not any(kind in {"execute", "status", "cancel"} for kind, _ in fixture.calls)
        finally:
            await registry.close_all()


def test_failed_durable_event_writer_aborts_inert_dispatch_before_http() -> None:
    asyncio.run(_revoked_writer_probe())


async def _revoked_writer_probe() -> None:
    async with owned_fixture("source-map-mcp", "untrusted_success") as (port, fixture):
        registry = MCPRegistry()
        try:
            await registry.register_server("source-map-mcp", "127.0.0.1", port)
            await registry.initialize_server("source-map-mcp", {}, {}, "fixture")
            events = AsyncMock(return_value=False)
            registry.set_execution_event_callback(events)
            RequestContext.bind(engagement_id="api-bootstrap", task_id="task-fixture")
            try:
                request_id = "req-audit-denied-" + uuid.uuid4().hex
                denied = await registry.execute_tool(
                    "source-map-mcp", "list_tools", {}, request_id=request_id
                )
                assert denied.status == "audit_unavailable"
                second = await registry.execute_tool(
                    "source-map-mcp", "list_tools", {}, request_id=request_id
                )
                assert second.status == "duplicate_request"
            finally:
                RequestContext.clear()
            assert events.await_count >= 1
            assert "dispatch_accepted" in [c.args[2] for c in events.await_args_list]
            assert not any(kind in {"execute", "cancel", "status"} for kind, _ in fixture.calls)
        finally:
            await registry.close_all()


def test_actual_burp_adapter_cannot_reuse_old_manifest_after_renegotiation() -> None:
    asyncio.run(_burp_manifest_rotation_probe())


async def _burp_manifest_rotation_probe() -> None:
    async with owned_fixture("burp-mcp", "untrusted_success") as (port, remote):
        remote.burp_tool_name = "get_proxy_history"
        registry = MCPRegistry()
        try:
            await registry.register_server(
                "burp-mcp", "127.0.0.1", port,
                auth_token="isolated-fixture-only-not-a-real-burp-token",
            )
            adapter = BurpMCPAdapter(registry)
            scope = ScopeDefinition(
                engagement_id="eng-unauthorized", domains=["uncontacted.invalid"],
                authorization_ref="fixture-only-not-an-authority",
            )
            await adapter.initialize(scope, "local-test-session")
            assert adapter._connection()._initialized is True
            # A new signed *tool declaration* from a remote process cannot
            # silently replace the previously pinned Burp adapter capability.
            remote.burp_tool_name = "get_scan_issues"
            await registry.initialize_server("burp-mcp", {}, {}, "local-test-session")
            with pytest.raises(MCPException, match="manifest changed"):
                adapter._connection()
            # A failed subsequent READY also revokes the registry's stale
            # tools, regardless of the earlier adapter scope.
            remote.ready = False
            with pytest.raises(MCPConnectionError):
                await registry.initialize_server("burp-mcp", {}, {}, "local-test-session")
            assert registry._servers["burp-mcp"]._tools == {}
            with pytest.raises(MCPException):
                adapter._connection()
            assert not any(kind in {"execute", "cancel", "status"} for kind, _ in remote.calls)
        finally:
            await registry.close_all()


def test_real_native_python_local_status_untrusted_cannot_issue_signed_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asyncio.run(_native_python_probe(monkeypatch))


def _native_module(file_name: str) -> Any:
    path = ROOT / "mcp-servers" / "python" / file_name
    spec = importlib.util.spec_from_file_location(
        "fleet_transport_recovery_" + file_name.replace(".", "_"), path
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def _native_python_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.delenv("OSOP_BROWSER_MCP_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("OSOP_SOURCEMAP_MCP_BEARER_TOKEN", raising=False)
    binding = {
        "request_id": "req-transport-unknown", "engagement_id": "eng-never-issued",
        "task_id": "task-never-approved",
    }
    for file_name, identity in (
        ("browser_mcp.py", "browser-mcp"),
        ("source_map_mcp.py", "source-map-mcp"),
    ):
        module = _native_module(file_name)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=module.app),
            base_url="http://localhost-fixture.invalid",
        ) as client:
            response = await client.post(
                "/mcp/request/status", json={**binding, "server_id": identity}
            )
            assert response.status_code in {401, 503}
            assert response.json().get("status") != "confirmed_stopped"
            assert not response.json().get("provider_receipt")
    for file_name in ("cloud_mcp.py", "turbo_intruder_mcp.py"):
        module = _native_module(file_name)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=module.app),
            base_url="http://localhost-fixture.invalid",
        ) as client:
            response = await client.post("/mcp/execute", json={
                "request_id": binding["request_id"], "tool_name": "list_tools", "parameters": {},
            })
            assert response.status_code == 503
            assert response.json().get("status") == "error"
            assert response.json().get("error") in {
                "server_unavailable", "local_iac_unavailable", "native_execution_not_authorized",
            }
            assert response.json().get("target_effect_verified") is not True
            assert response.json().get("provider_receipt") is None


def test_actual_six_go_sdk_only_inert_authority_status_without_redeemed_grant() -> None:
    """Source-invariant only: no actual Go PID, target or signer is started."""
    sdk = (ROOT / "mcp-servers/go/sdk/server.go").read_text(encoding="utf-8")
    assert '"native_target_execution_enabled": false' in sdk
    assert '"target_contacted":                false' in sdk
    assert '"provider_contacted":              false' in sdk
    assert '"native_execution_not_authorized"' in sdk
    assert "s.verifyAndRedeemAuthorityStatus(" in sdk
    assert "return []Tool{authorityStatusTool()}" in sdk
    for name in SIX_GO:
        text = (ROOT / "mcp-servers/go/cmd" / name / "main.go").read_text(encoding="utf-8")
        assert f'sdk.NewServer("{name}")' in text


@pytest.mark.parametrize("name", ("burp-mcp", "browser-mcp", "source-map-mcp", "recon-mcp"))
def test_status_and_cancel_test_signature_revoked_before_receipt_consumption(
    name: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Crypto only, never a fabricated signed Task, provider or stop event.

    A properly signed *test provider claim* proves origin to a test root, but
    current trusted-key removal, contradicting HTTP status and forged identity
    must invalidate even that evidence. No physical stop is asserted.
    """
    signer = Ed25519PrivateKey.generate()
    pub = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    issued_at = int(time.time())
    claims = {
        "server_id": name, "request_id": "req-revocable-fixture",
        "engagement_id": "eng-not-a-real-approval", "task_id": "task-not-real",
        "status": "confirmed_stopped", "verified": True,
        "stopped": True, "issued_at": issued_at,
    }
    raw = json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    receipt = {**claims, "attestation": {
        "kid": "throwaway-local-public-key",
        "signature": base64.urlsafe_b64encode(signer.sign(raw)).decode("ascii").rstrip("="),
    }}
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", json.dumps({
        name: {"throwaway-local-public-key": base64.b64encode(pub).decode("ascii")}
    }))
    args = (
        "req-revocable-fixture", "eng-not-a-real-approval", "task-not-real", name
    )
    bound = {"status": "success", "result": receipt}
    assert protocol._verified_remote_status(
        bound, *args, require_bound_identity=True, require_signature=True
    ) == "confirmed_stopped"
    assert protocol._verified_remote_cancel(
        bound, *args, require_bound_identity=True, require_signature=True
    ) == "confirmed_stopped"
    # Transport may report HTTP 200 with a contradictory/failed envelope;
    # nested signatures do not override its top-level error.
    assert protocol._verified_remote_status(
        {**bound, "status": "error"}, *args,
        require_bound_identity=True, require_signature=True,
    ) == "unknown"
    assert protocol._verified_remote_cancel(
        {**bound, "error": "provider_failed"}, *args,
        require_bound_identity=True, require_signature=True,
    ) == "unknown"
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", "{}")
    assert protocol._verified_remote_status(
        bound, *args, require_bound_identity=True, require_signature=True
    ) == "unknown"
    assert protocol._verified_remote_cancel(
        bound, *args, require_bound_identity=True, require_signature=True
    ) == "unknown"
