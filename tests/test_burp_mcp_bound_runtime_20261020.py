"""Burp external MCP contract: real localhost HTTP, no scanner/target/DB.

An isolated aiohttp fixture is NOT a real Burp extension. It tests only
authenticated transport, strict typed MCP init, and fail-closed adapter
execution. The optional external 127.0.0.1:8081 is checked separately.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.adapters.burp_mcp import BurpMCPAdapter, _OBSERVER_DOMAIN
from ai_osop.core.exceptions import MCPException
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import MCPExecuteResponse, MCPRegistry
from ai_osop.orchestrator.flow_mcp_action_executor import FlowMCPActionExecutor

_TOKEN = "test-operator-only-local-burp-auth-token"
_SCOPE = ScopeDefinition(
    engagement_id="eng-owned-local-burp",
    domains=["owned.test"],
    authorization_ref="signed-roe-local-burp",
)
_CONTEXT = {
    "engagement_id": _SCOPE.engagement_id,
    "flow_id": "flow-burp-owned",
    "task_id": "task-burp-owned",
    "user_id": "owner-burp",
}


def _tool(name: str, *, risk: str = "READ_ONLY") -> dict:
    return {
        "name": name,
        "description": "Bound Burp external tool (test-only definition)",
        "parameters": [],
        "returns": {"type": "object"},
        "scope_check": True,
        "requires_approval": True,
        "side_effect_class": risk,
    }


def _declaration() -> dict:
    return {
        "server_id": "burp-mcp",
        "version": "20261020",
        "status": "ready",
        "capabilities": ["mcp_bound_receipts_v1", "burp_signed_observations_v1"],
        "tools": [
            _tool("get_proxy_history"),
            _tool("get_scan_issues"),
            _tool("get_sitemap"),
            _tool("get_request_by_id"),
            _tool("scan_target", risk="RECON_ACTIVE"),
            _tool("send_to_repeater", risk="RECON_ACTIVE"),
            _tool("intruder_attack", risk="INVASIVE_EXPLOIT"),
            _tool("extension_call", risk="INVASIVE_EXPLOIT"),
        ],
    }


@asynccontextmanager
async def _local_burp(*, declaration=None):
    """Real authenticated TCP listener; no Burp extension or external calls."""
    audit = {"health": 0, "initialize": 0, "execute": 0}

    async def health(request: web.Request) -> web.Response:
        audit["health"] += 1
        if request.headers.get("Authorization") != f"Bearer {_TOKEN}":
            return web.json_response({"status": "unauthorized"}, status=401)
        return web.json_response({"server_id": "burp-mcp", "status": "healthy"})

    async def initialize(request: web.Request) -> web.Response:
        audit["initialize"] += 1
        if request.headers.get("Authorization") != f"Bearer {_TOKEN}":
            return web.json_response({"status": "unauthorized"}, status=401)
        payload = await request.json()
        if (
            payload.get("scope", {}).get("engagement_id") != _SCOPE.engagement_id
            or payload.get("scope", {}).get("authorization_ref") != _SCOPE.authorization_ref
            or payload.get("auth_credentials") != {}
            or payload.get("session_id") != "session-owned-local"
        ):
            return web.json_response({"status": "error"}, status=403)
        return web.json_response(declaration if declaration is not None else _declaration())

    async def execute(_: web.Request) -> web.Response:
        audit["execute"] += 1
        # Catch accidental invocation; not even a dummy scanner is available.
        return web.json_response({"status": "unavailable", "execution_enabled": False}, status=503)

    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/mcp/initialize", initialize)
    app.router.add_post("/mcp/execute", execute)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield port, audit
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_genuine_loopback_http_bearer_and_typed_burp_initialization():
    async with _local_burp() as (port, audit):
        registry = MCPRegistry()
        try:
            await registry.register_server("burp-mcp", "127.0.0.1", port, _TOKEN)
            adapter = BurpMCPAdapter(registry)
            await adapter.initialize(_SCOPE, "session-owned-local")
            assert adapter._connection()._initialized is True
            assert set(adapter._connection()._tools) == {
                "scan_target",
                "send_to_repeater",
                "intruder_attack",
                "extension_call",
                "get_proxy_history",
                "get_scan_issues",
                "get_sitemap",
                "get_request_by_id",
            }
            assert audit == {"health": 1, "initialize": 1, "execute": 0}
            for operation in (
                adapter.scan_target("https://owned.test"),
                adapter.send_to_repeater({"url": "https://owned.test"}),
                adapter.intruder_attack({}, [], []),
                adapter.extension_call("ext", "execute", {}),
            ):
                with pytest.raises(MCPException, match="direct execution denied"):
                    await operation
            assert audit["execute"] == 0
            with pytest.raises(MCPException, match="signed Flow/ROE"):
                await adapter.get_proxy_history({"origin": "https://owned.test"})
            assert audit["execute"] == 0
        finally:
            await registry.close_all()


@pytest.mark.asyncio
async def test_wrong_or_absent_burp_bearer_fails_at_health_before_init():
    async with _local_burp() as (port, audit):
        registry = MCPRegistry()
        try:
            with pytest.raises(MCPException):
                await registry.register_server("burp-mcp", "127.0.0.1", port, "bad-credential")
            assert audit["initialize"] == audit["execute"] == 0
        finally:
            await registry.close_all()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["wrong_identity", "simulator", "missing_risk", "read_only_scan", "missing_capability"],
)
async def test_malformed_remote_burp_manifest_is_not_promoted_to_ready(failure):
    declaration = _declaration()
    if failure == "wrong_identity":
        declaration["server_id"] = "foreign-mcp"
    elif failure == "simulator":
        declaration["status"] = "unavailable"
    elif failure == "missing_risk":
        declaration["tools"][0].pop("side_effect_class")
    elif failure == "read_only_scan":
        declaration["tools"][4]["side_effect_class"] = "READ_ONLY"
    else:
        declaration["capabilities"] = ["legacy_browser_tool"]
    async with _local_burp(declaration=declaration) as (port, audit):
        registry = MCPRegistry()
        try:
            await registry.register_server("burp-mcp", "127.0.0.1", port, _TOKEN)
            adapter = BurpMCPAdapter(registry)
            with pytest.raises(MCPException, match="initialization|declaration"):
                await adapter.initialize(_SCOPE, "session-owned-local")
            with pytest.raises(MCPException, match="unavailable"):
                await adapter.get_scan_issues("https://owned.test")
            assert audit["execute"] == 0
        finally:
            await registry.close_all()


def _signed_result(
    result: dict,
    *,
    private: Ed25519PrivateKey,
    context: dict = _CONTEXT,
    tool: str = "get_proxy_history",
    request_id: str = "req-source-bound",
) -> MCPExecuteResponse:
    now = int(time.time())
    digest = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    claims = {
        "version": 1,
        "server_id": "burp-mcp",
        "engagement_id": context["engagement_id"],
        "flow_id": context["flow_id"],
        "task_id": context["task_id"],
        "request_id": request_id,
        "tool_name": tool,
        "result_sha256": digest,
        "issued_at": now,
        "expires_at": now + 12,
    }
    signature = private.sign(
        _OBSERVER_DOMAIN
        + json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
    )
    return MCPExecuteResponse(
        request_id=request_id,
        status="success",
        result=result,
        metadata={
            "burp_observation": {
                "claims": claims,
                "kid": "burp-provider-local-key",
                "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
        },
    )


def test_signed_observation_binds_exact_result_identity_freshness_and_enrolled_key(monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_BURP_MCP_OBSERVATION_TRUST_JSON",
        json.dumps(
            {"burp-provider-local-key": base64.urlsafe_b64encode(public).decode().rstrip("=")}
        ),
    )
    result = {"entries": [{"id": "entry1", "url": "https://owned.test/p", "method": "GET"}]}
    response = _signed_result(result, private=private)
    assert BurpMCPAdapter._signed_observation(response, "get_proxy_history", _CONTEXT) == result
    changed = response.model_copy(deep=True)
    changed.result["entries"][0]["url"] = "https://unowned.test"
    with pytest.raises(MCPException, match="digest"):
        BurpMCPAdapter._signed_observation(changed, "get_proxy_history", _CONTEXT)
    for variant in (
        _signed_result(result, private=Ed25519PrivateKey.generate()),
        _signed_result(result, private=private, tool="get_scan_issues"),
        _signed_result(result, private=private, context={**_CONTEXT, "task_id": "other-task"}),
    ):
        with pytest.raises(MCPException):
            BurpMCPAdapter._signed_observation(variant, "get_proxy_history", _CONTEXT)
    simulated = _signed_result({**result, "status": "simulated"}, private=private)
    with pytest.raises(MCPException, match="UNKNOWN"):
        BurpMCPAdapter._signed_observation(simulated, "get_proxy_history", _CONTEXT)
    assert "secret" not in str(response)


@pytest.mark.asyncio
async def test_real_loopback_fake_signed_observation_sanitizes_proxy_headers_and_cross_origin(
    monkeypatch,
):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_BURP_MCP_OBSERVATION_TRUST_JSON",
        json.dumps(
            {"burp-provider-local-key": base64.urlsafe_b64encode(public).decode().rstrip("=")}
        ),
    )
    async with _local_burp() as (port, audit):
        registry = MCPRegistry()
        try:
            await registry.register_server("burp-mcp", "127.0.0.1", port, _TOKEN)
            adapter = BurpMCPAdapter(registry)
            await adapter.initialize(_SCOPE, "session-owned-local")
            adapter._current_authority = AsyncMock(return_value=dict(_CONTEXT))

            def signed_provider(*args, **kwargs):
                return _signed_result(
                    {
                        "entries": [
                            {
                                "id": "req1",
                                "url": "https://owned.test/resource",
                                "method": "GET",
                                "headers": {"Authorization": "private-secret"},
                                "body": "private patient details",
                            }
                        ]
                    },
                    private=private,
                    request_id=kwargs["request_id"],
                )

            registry.execute_tool = AsyncMock(side_effect=signed_provider)
            entries = await adapter.get_proxy_history({"origin": "https://owned.test"})
            assert entries == [
                {
                    "id": "req1",
                    "url": "https://owned.test/resource",
                    "method": "GET",
                    "status_code": None,
                }
            ]
            assert "private" not in str(entries)
            assert adapter._current_authority.await_count == 2
            assert registry.execute_tool.await_count == 1
            assert audit["execute"] == 0
            registry.execute_tool.reset_mock()
            with pytest.raises(MCPException, match="outside exact signed scope"):
                await adapter.get_proxy_history({"origin": "https://other.test"})
            registry.execute_tool.assert_not_awaited()
        finally:
            await registry.close_all()


@pytest.mark.asyncio
async def test_prepared_flow_dispatch_uses_real_existing_one_shot_executor_boundary(monkeypatch):
    # Inert executor double tests identity routing only; no PG or target.
    registry = MCPRegistry()
    adapter = BurpMCPAdapter(registry)
    adapter._connection = lambda: object()
    executor = object.__new__(FlowMCPActionExecutor)
    executor.registry = registry
    executor._authority = AsyncMock(return_value=None)
    executor.store = SimpleNamespace(
        get=AsyncMock(
            return_value={
                "action_id": "action-" + "a" * 32,
                "server_id": "burp-mcp",
                "status": "prepared",
                "tool_name": "scan_target",
            }
        )
    )
    executor.dispatch = AsyncMock(return_value={"status": "unknown", "secret": "never-return"})
    binding = {"engagement_id": "eng-owned"}
    operator = {"sub": "test-owner"}
    action = "action-" + "a" * 32
    result = await adapter.dispatch_prepared_action(
        executor, binding, operator, action, "scan_target"
    )
    assert result == {
        "status": "unknown",
        "execution_authority": "source_signed_flow_action",
        "independent_target_effect_verified": False,
    }
    executor.dispatch.assert_awaited_once()
    executor.dispatch.reset_mock()
    with pytest.raises(MCPException, match="prepared action identity"):
        await adapter.dispatch_prepared_action(
            executor, binding, operator, action, "intruder_attack"
        )
    executor.dispatch.assert_not_awaited()
    assert registry.call_counts == {}
