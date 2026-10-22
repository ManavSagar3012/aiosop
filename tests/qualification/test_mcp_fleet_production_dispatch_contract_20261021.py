"""Bounded fleet ingress/governance checks; never execute target-side tooling.

READ-ONLY inventory reads use the original dirty workspace. In-process HTTP
is limited to disabled native Python services. A fake aiohttp response tests
initialization trust, not a deployed MCP server or a live registry socket.
No application DB, Docker, external target, Burp, network scanner, or provider.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.mcp.protocol import (
    MCPConnection,
    MCPConnectionError,
    MCPExecuteRequest,
    MCPInitializeRequest,
    MCPToolDefinition,
    SideEffectClass,
)
from ai_osop.core.exceptions import MCPException
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied, _safe_parameters
from ai_osop.orchestrator.flow_mcp_action_executor import (
    FlowMCPActionDenied,
    _bounded_params,
    _tool_definition,
)

ROOT = Path(__file__).resolve().parents[2]
GO = {
    "recon-mcp": 8082,
    "payload-mcp": 8083,
    "nuclei-mcp": 8084,
    "shodan-mcp": 8085,
    "security-bridge": 8087,
    "threat-intel-mcp": 8086,
}
PYTHON = {
    "browser-mcp": ("browser_mcp.py", 8091),
    "source-map-mcp": ("source_map_mcp.py", 8096),
    "cloud-mcp": ("cloud_mcp.py", 8097),
    "turbo-intruder-mcp": ("turbo_intruder_mcp.py", 8098),
}
EXTERNAL = {"burp-mcp": 8081}


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _python_native(name: str) -> Any:
    """Import actual FastAPI code, without lifecycle/background processes."""
    path = ROOT / "mcp-servers" / "python" / (name + ".py")
    spec = importlib.util.spec_from_file_location("qual_dispatch_" + name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # FastAPI/Pydantic forward-ref annotations.
    spec.loader.exec_module(module)
    return module


def _decl(
    name: str,
    parameters: list[dict[str, Any]],
    effect: SideEffectClass,
    *,
    approved: bool = True,
) -> MCPToolDefinition:
    return MCPToolDefinition.model_validate(
        {
            "name": name,
            "description": "Untrusted simulated upstream tool",
            "parameters": [{"description": "test only", **parameter} for parameter in parameters],
            "returns": {},
            "requires_approval": approved,
            "scope_check": True,
            "side_effect_class": effect.value,
        }
    )


def test_exact_eleven_main_registered_services_and_real_entrypoints() -> None:
    """Inventory is exactly the real registry list, not eleven live services."""
    source = _source("src/ai_osop/api/main.py")
    block = source.split("servers = [", 1)[1].split("critical_mcps =", 1)[0]
    discovered = re.findall(r'["\x27]([\w-]+(?:-mcp)?)["\x27]\s*,\s*settings\.', block)
    # Multiline tuples (Browser, SourceMap, Turbo) are included by AST instead.
    mod = ast.parse(source)
    fn = next(
        n
        for n in mod.body
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "register_optional_mcp_servers"
    )
    assigned = next(
        n.value
        for n in ast.walk(fn)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "servers" for t in n.targets)
    )
    names = [entry.elts[0].value for entry in assigned.elts]
    assert set(names) == set(GO) | set(PYTHON) | set(EXTERNAL)
    assert len(names) == len(set(names)) == 11
    assert set(discovered).issubset(set(names))
    settings = _source("src/ai_osop/core/config.py")
    for server_id, port in GO.items():
        program = ROOT / "mcp-servers" / "go" / "cmd" / server_id / "main.go"
        assert program.is_file(), server_id
        text = program.read_text(encoding="utf-8")
        assert f'sdk.NewServer("{server_id}")' in text
        assert "server.Run(" in text
        assert str(port) in settings or str(port) in text
    for server_id, (file, port) in PYTHON.items():
        text = _source("mcp-servers/python/" + file)
        assert '@app.post("/mcp/execute"' in text
        assert '@app.post("/mcp/initialize"' in text
        assert str(port) in settings or str(port) in text
    assert EXTERNAL == {"burp-mcp": 8081}
    assert not (ROOT / "mcp-servers" / "python" / "burp_mcp.py").exists()


def test_go_six_http_handlers_can_report_only_inert_signed_grant() -> None:
    """Static boundary: Cmd registrations cannot bypass shared HTTP SDK mux."""
    sdk = _source("mcp-servers/go/sdk/server.go")
    grant = _source("mcp-servers/go/sdk/native_grant.go")
    assert "func (s *Server) Handler() http.Handler" in sdk
    assert 'mux.HandleFunc("/mcp/execute"' in sdk
    assert "s.verifyAndRedeemAuthorityStatus(" in sdk
    assert '"native_target_execution_enabled": false' in sdk
    assert '"target_contacted":                false' in sdk
    assert '"provider_contacted":              false' in sdk
    assert 'NativeAuthorityStatusTool = "authority_status"' in grant
    assert "s.nativeConfig() != nil" in sdk
    assert "native_execution_not_authorized" in sdk
    for server in GO:
        source = _source(f"mcp-servers/go/cmd/{server}/main.go")
        assert "sdk.NewServer(" in source
        assert ".Run(" in source


@pytest.mark.asyncio
@pytest.mark.parametrize("module", ["cloud_mcp", "turbo_intruder_mcp"])
async def test_disabled_native_facades_never_fabricate_provider_success(module: str) -> None:
    """Use actual FastAPI ASGI handlers; forbid any scan/provider invocation."""
    loaded = _python_native(module)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=loaded.app),
        base_url="http://inert-mcp.test",
    ) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={})
        executed = await client.post(
            "/mcp/execute",
            json={
                "tool_name": "execute_single_packet_attack",
                "parameters": {
                    "target_url": "https://not-contacted.invalid",
                    "headers": {"Authorization": "must-not-echo"},
                },
                "request_id": "req-fabricated-success",
                "approved": True,
            },
        )
    if module == "cloud_mcp":
        # Cloud is now a real OPERATOR-GATED LOCAL Terraform/Checkov static
        # scanner, not a permanently disabled facade. Unconfigured health
        # must be unavailable, and forged unknown execute fields are 422
        # before any provider dispatch. Neither can prove cloud-account work.
        assert health.status_code == 503
        assert init.status_code == 200
        assert init.json()["status"] == "unavailable"
        assert executed.status_code == 422
        assert "provider_receipt" not in executed.text
        assert "Authorization" not in executed.text
        assert "req-fabricated-success" not in executed.text
        return
    assert health.status_code == executed.status_code == 503
    assert health.json()["execution_enabled"] is False
    assert init.status_code == 200
    assert init.json()["status"] == "unavailable"
    assert init.json()["execution_enabled"] is False
    assert init.json()["source_side_signed_authorization_verified"] is False
    assert executed.json()["status"] == "error"
    assert executed.json()["execution_enabled"] is False
    assert "provider_receipt" not in executed.json()
    assert "Authorization" not in executed.text
    assert "req-fabricated-success" not in executed.text


@pytest.mark.asyncio
async def test_browser_requires_native_bearer_before_any_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual Browser ASGI initialization cannot accept absent bearer."""
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.delenv("OSOP_BROWSER_MCP_BEARER_TOKEN", raising=False)
    browser = _python_native("browser_mcp")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=browser.app),
        base_url="http://browser-unstarted.test",
    ) as client:
        denied = await client.post("/mcp/initialize", json={"session_id": "api-bootstrap"})
    assert denied.status_code == 401
    assert "tools" not in denied.json()
    assert browser.manager.browser is None


@pytest.mark.asyncio
async def test_source_map_needs_independent_origin_and_does_not_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Actual SourceMap native ASGI forbids user-minted proof and URL fetching."""
    for name in (
        "OSOP_SOURCEMAP_ALLOWED_HOSTS",
        "OSOP_SOURCEMAP_MCP_BEARER_TOKEN",
        "OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN",
        "OSOP_SOURCEMAP_SOURCE_URL",
        "OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE",
    ):
        monkeypatch.delenv(name, raising=False)
    source = _python_native("source_map_mcp")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=source.app),
        base_url="http://sourcemap-unstarted.test",
    ) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={})
        original = await client.post(
            "/mcp/execute",
            json={
                "tool_name": "inspect_local_original_sourcemap",
                "parameters": {"artifact_sha256": "a" * 64},
                "request_id": "req-unauthorized-original",
                "execution_binding": {
                    "request_id": "req-" + "a" * 48,
                    "engagement_id": "eng-untrusted",
                    "task_id": "task-untrusted",
                    "server_id": "source-map-mcp",
                },
            },
        )
        generic = await client.post(
            "/mcp/execute",
            json={
                "tool_name": "fetch_and_parse_sourcemap",
                "parameters": {"url": "https://not-approved.invalid/app.js.map"},
            },
        )
    assert health.status_code == 503
    assert init.json()["status"] == "unavailable"
    assert original.status_code == 503
    assert original.json()["status"] == "error"
    assert "provider_receipt" not in original.json()
    assert generic.json()["status"] == "error"
    assert "provider_receipt" not in generic.json()


class _Reply:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.payload, self.status = payload, status

    async def __aenter__(self) -> "_Reply":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    async def json(self) -> dict[str, Any]:
        return self.payload


class _FakeSession:
    def __init__(self, payload: dict[str, Any], status: int = 200) -> None:
        self.payload, self.status = payload, status
        self.posts = 0

    def post(self, *_: Any, **__: Any) -> _Reply:
        self.posts += 1
        return _Reply(self.payload, self.status)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        {"status": "unavailable"},
        {"server_id": "other-mcp"},
        {
            "tools": [
                {"name": "scan_target", "description": "forged", "parameters": [], "returns": {}}
            ]
        },
        {
            "tools": [
                {
                    "name": "scan_target",
                    "description": "forged",
                    "parameters": [],
                    "returns": {},
                    "side_effect_class": "RECON_ACTIVE",
                    "scope_check": True,
                    "requires_approval": False,
                }
            ]
        },
        {
            "tools": [
                {
                    "name": "scan_target",
                    "description": "forged",
                    "parameters": [],
                    "returns": {},
                    "side_effect_class": "RECON_ACTIVE",
                    "scope_check": False,
                    "requires_approval": True,
                }
            ]
        },
    ],
)
async def test_remote_initialize_cannot_install_forged_ready_tool(mutation: dict[str, Any]) -> None:
    legitimate = {
        "server_id": "recon-mcp",
        "version": "1",
        "status": "ready",
        "capabilities": ["mcp_bound_receipts_v1"],
        "tools": [
            {
                "name": "scan_target",
                "description": "test",
                "parameters": [],
                "returns": {},
                "side_effect_class": "RECON_ACTIVE",
                "scope_check": True,
                "requires_approval": True,
            }
        ],
    }
    conn = MCPConnection("recon-mcp", "127.0.0.1", 8082)
    conn._session = _FakeSession({**legitimate, **mutation})
    conn._initialized = True
    conn._tools["stale_old_tool"] = _decl("stale_old_tool", [], SideEffectClass.READ_ONLY)
    with pytest.raises(MCPConnectionError):
        await conn.initialize(MCPInitializeRequest(scope={}, session_id="api-bootstrap"))
    assert conn._initialized is False
    assert conn._tools == {}
    assert conn._session.posts == 1


def test_flow_governance_rejects_forged_scanner_tool_and_opaque_input() -> None:
    """Actual central declaration validation before any authorization/dispatch."""
    from types import SimpleNamespace

    scanner = _decl(
        "scan_target",
        [{"name": "target", "type": "string", "required": True}],
        SideEffectClass.RECON_ACTIVE,
    )
    registry = SimpleNamespace(
        _servers={
            "recon-mcp": SimpleNamespace(
                server_id="recon-mcp",
                _initialized=True,
                get_circuit_state=lambda: "closed",
                _tools={"scan_target": scanner},
            )
        }
    )
    with pytest.raises(FlowMCPActionDenied):
        _tool_definition(registry, "recon-mcp", "scan_target")
    # A renamed READ_ONLY tool cannot sneak raw exploit/script instructions in
    # a complex headers/body parameter, even if declared by the provider.
    forged = _decl(
        "health",
        [{"name": "headers", "type": "object", "required": True}],
        SideEffectClass.READ_ONLY,
    )
    with pytest.raises((FlowMCPActionDenied, MCPActionDenied)):
        _bounded_params({"headers": {"Authorization": "forged"}}, forged)
    with pytest.raises(MCPActionDenied):
        _safe_parameters({"headers": "forged"}, forged, server_id="recon-mcp")


@pytest.mark.asyncio
async def test_direct_uninitialized_connection_cannot_send_provider_success() -> None:
    conn = MCPConnection("nuclei-mcp", "127.0.0.1", 8084)
    session = _FakeSession(
        {
            "request_id": "req-direct",
            "status": "success",
            "metadata": {"signed_provider_receipt": True},
        }
    )
    conn._session = session
    with pytest.raises(MCPException, match="not initialized"):
        await conn.execute(
            MCPExecuteRequest(
                tool_name="scan_target",
                parameters={"target": "https://not-contacted.invalid"},
                request_id="req-direct",
            )
        )
    assert session.posts == 0


@pytest.mark.asyncio
async def test_forged_http_success_is_provider_testimony_not_signed_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fake callbacks, NOT PG: HTTP success cannot mint signed reconciliation."""
    import ai_osop.mcp.protocol as protocol
    from ai_osop.core.telemetry import RequestContext

    monkeypatch.setattr(protocol, "check_tool_authorization", AsyncMock(return_value=None))
    monkeypatch.setattr(protocol, "check_tool_budget", AsyncMock(return_value=None))
    response = {
        "request_id": "req-fake-success",
        "status": "success",
        "result": {
            "target_effect_verified": True,  # untrusted assertion
            "independent_target_effect_verified": True,
            "source_count": 1,  # ordinary provider fact preserved
        },
        "metadata": {
            "signed_provider_receipt": {"verified": True},
            "production_certified": True,
            "source": "local",
        },
        "provider_receipt": {
            "request_id": "req-fake-success",
            "status": "succeeded",
            "verified": True,
            "stopped": True,
            "attestation": {"kid": "untrusted", "signature": "A" * 86},
        },
    }
    connection = MCPConnection("recon-mcp", "127.0.0.1", 8082)
    session = _FakeSession(response)
    connection._session = session
    connection._initialized = True
    connection._tools["authority_status"] = _decl("authority_status", [], SideEffectClass.READ_ONLY)
    writer = AsyncMock(return_value=True)
    connection.set_execution_event_callback(writer)
    RequestContext.bind(
        engagement_id="eng-fake",
        task_id="task-fake",
        flow_id="flow-fake",
        subtask_id="subtask-fake",
    )
    try:
        result = await connection.execute(
            MCPExecuteRequest(
                tool_name="authority_status",
                parameters={},
                request_id="req-fake-success",
            )
        )
    finally:
        RequestContext.clear()
    assert result.status == "success"  # provider-reported, NOT independent proof.
    assert result.metadata.get("signed_provider_receipt") is None
    assert session.posts == 1
    kinds = [call.args[2] for call in writer.await_args_list]
    assert "execution_finished" in kinds
    assert "reconciliation_result" not in kinds
    # The provider may report success, but cannot smuggle owner-of-record
    # target-effect authority into the public result as an affirmative flag.
    assert "target_effect_verified" not in (result.result or {})
    assert "independent_target_effect_verified" not in (result.result or {})
    assert result.result["source_count"] == 1
    assert "production_certified" not in result.metadata
    assert result.metadata.get("source") == "local"


def test_provider_success_flag_and_signed_wrong_task_never_settle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cryptographic provider testimony is not independent target evidence."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
        json.dumps({"browser-mcp": {"test-kid": base64.b64encode(pub).decode("ascii")}}),
    )
    claims = {
        "request_id": "req-bound",
        "engagement_id": "eng-owned",
        "task_id": "task-owned",
        "server_id": "browser-mcp",
        "status": "succeeded",
        "verified": True,
        "stopped": True,
        "issued_at": int(time.time()),
    }
    raw = json.dumps(
        claims, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    signed = {
        **claims,
        "attestation": {
            "kid": "test-kid",
            "signature": base64.urlsafe_b64encode(key.sign(raw)).decode("ascii").rstrip("="),
        },
    }
    assert provider_receipt_is_signed(signed, "browser-mcp", "req-bound", "eng-owned", "task-owned")
    assert not provider_receipt_is_signed(
        {**claims, "attestation": None}, "browser-mcp", "req-bound", "eng-owned", "task-owned"
    )
    assert not provider_receipt_is_signed(
        signed, "browser-mcp", "req-bound", "eng-owned", "task-other"
    )
    assert not provider_receipt_is_signed(
        {**signed, "status": "failed"}, "browser-mcp", "req-bound", "eng-owned", "task-owned"
    )
