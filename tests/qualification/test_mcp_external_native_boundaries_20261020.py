"""Native MCP authorization boundaries, isolated ASGI without target transport.

The six Go processes are qualified separately in test_native_go_five_fleet and
test_native_go_fastapi_joined. Here we verify the real configured registration
surface and exercise the actual Python native ASGI routes in memory. In
particular, neither a forged caller binding nor an administrator domain list
constitutes independently signed Flow/Task authority.
"""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ai_osop.mcp.protocol import MCPInitializeResponse, SideEffectClass

_ROOT = Path(__file__).resolve().parents[2]
_GO = (
    "recon-mcp", "payload-mcp", "nuclei-mcp", "shodan-mcp",
    "threat-intel-mcp", "security-bridge",
)
_PYTHON = ("browser-mcp", "source-map-mcp", "cloud-mcp", "turbo-intruder-mcp")
_ALL = {"burp-mcp", *_GO, *_PYTHON}


def _load_native(name: str):
    assert name in _PYTHON
    path = _ROOT / "mcp-servers" / "python" / (name.replace("-", "_") + ".py")
    spec = importlib.util.spec_from_file_location("_native_external_" + name.replace("-", "_"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _client(module: object) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://native-only.invalid",
        follow_redirects=False,
        timeout=3.0,
    )


def test_all_eleven_names_reach_real_registry_registration_source() -> None:
    """Assert configured entrypoints, including the external Burp identity."""
    syntax = ast.parse((_ROOT / "src" / "ai_osop" / "api" / "main.py").read_text(encoding="utf-8"))
    registration = next(
        node for node in syntax.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "register_optional_mcp_servers"
    )
    registered = next(
        node.value for node in registration.body
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "servers"
            for target in node.targets
        )
    )
    from tests.mcp_inventory_source import configured_server_nodes
    registered = configured_server_nodes(syntax)
    assert isinstance(registered, ast.List)
    names = [entry.elts[0].value for entry in registered.elts]
    assert len(names) == 11
    assert set(names) == _ALL
    assert len(names) == len(set(names))

    for server in _GO:
        original = (_ROOT / "mcp-servers" / "go" / "cmd" / server / "main.go").read_text(
            encoding="utf-8"
        )
        assert f'sdk.NewServer("{server}")' in original
        assert "server.Run(" in original
    sdk = (_ROOT / "mcp-servers" / "go" / "sdk" / "server.go").read_text(encoding="utf-8")
    assert 'mux.HandleFunc("/mcp/execute"' in sdk
    assert '"native_execution_not_authorized"' in sdk
    assert "s.verifyAndRedeemAuthorityStatus(" in sdk
    assert "return []Tool{authorityStatusTool()}" in sdk


@pytest.mark.asyncio
@pytest.mark.parametrize("native", ["cloud-mcp", "turbo-intruder-mcp"])
async def test_simulated_handlers_do_not_report_native_success(native: str) -> None:
    module = _load_native(native)
    async with _client(module) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={})
        execute = await client.post("/mcp/execute", json={
            "tool_name": "execute_single_packet_attack" if native.startswith("turbo") else "analyze_iam_trust_policies",
            "parameters": {"target_url": "https://unreachable.invalid", "account_id": "123456789012"},
            "request_id": "req-untrusted", "scope": {"approved": True},
        })
    assert health.status_code == 503
    declaration = MCPInitializeResponse.model_validate(init.json())
    assert declaration.server_id == native and declaration.status == "unavailable"
    assert all(tool.side_effect_class != SideEffectClass.READ_ONLY for tool in declaration.tools)
    assert execute.status_code == (422 if native == "cloud-mcp" else 503)
    assert execute.json()["status"] == "error"
    if native == "cloud-mcp":
        assert execute.json()["error"] == "invalid_request"
    else:
        assert execute.json()["execution_enabled"] is False


@pytest.mark.asyncio
async def test_source_map_allowlist_and_forged_authority_never_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plausible allowed URL must not execute before native Task authority."""
    module = _load_native("source-map-mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    resolver = AsyncMock(side_effect=AssertionError("DNS forbidden"))
    fetch = AsyncMock(side_effect=AssertionError("HTTP forbidden"))
    analyzer = AsyncMock(side_effect=AssertionError("analysis forbidden"))
    monkeypatch.setattr(module, "_resolve_public_ip", resolver)
    monkeypatch.setattr(module, "_fetch_public_https", fetch)
    monkeypatch.setattr(module, "analyze_sourcemap", analyzer)
    async with _client(module) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={
            "scope": {"domains": ["maps.example.org"], "signed": True},
            "auth_credentials": {"operator_claim": "approved"},
        })
        approved_looking = await client.post("/mcp/execute", json={
            "tool_name": "fetch_and_parse_sourcemap", "request_id": "req-allowlisted",
            "parameters": {"url": "https://maps.example.org/assets/app.js.map"},
        })
        forged_task = await client.post("/mcp/execute", json={
            "tool_name": "fetch_and_parse_sourcemap", "request_id": "req-forged",
            "parameters": {"url": "https://maps.example.org/app.js", "signed_task": "approved"},
        })
        malformed = await client.post("/mcp/execute", json={
            "tool_name": "fetch_and_parse_sourcemap", "request_id": "req-ssrf",
            "parameters": {"url": "https://maps.example.org@127.0.0.1/admin"},
        })
    assert health.status_code == 503 and health.json()["execution_enabled"] is False
    declaration = MCPInitializeResponse.model_validate(init.json())
    assert declaration.status == "unavailable"
    assert "UNAVAILABLE" in declaration.tools[0].description
    assert declaration.tools[0].side_effect_class == SideEffectClass.RECON_ACTIVE
    assert approved_looking.status_code == 503
    assert approved_looking.json()["error"] == "signed_source_authority_unavailable"
    assert forged_task.json()["error"] == "source_map_input_denied"
    assert malformed.json()["error"] == "source_map_input_denied"
    resolver.assert_not_awaited()
    fetch.assert_not_awaited()
    analyzer.assert_not_awaited()


@pytest.mark.asyncio
async def test_source_map_redirect_revalidation_never_reaches_second_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain internal redirect protection for future signed-authorized usage."""
    module = _load_native("source-map-mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org,other.example.org")
    seen = []

    async def fake_fetch(url: str, *, initial_host: str | None = None) -> str:
        seen.append((url, initial_host))
        return "//# sourceMappingURL=https://other.example.org/secret.map"

    monkeypatch.setattr(module, "_fetch_public_https", fake_fetch)
    with pytest.raises(module.SourceMapDenied):
        await module.analyze_sourcemap("https://maps.example.org/assets/app.js")
    assert seen == [("https://maps.example.org/assets/app.js", None)]


@pytest.mark.asyncio
async def test_source_map_internal_fetch_pins_public_ip_and_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Metadata-only transport remains hardened if signed authority is added."""
    module = _load_native("source-map-mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    resolved = []
    streams = []

    async def fake_resolution(host: str) -> str:
        resolved.append(host)
        return "8.8.8.8"

    class Response:
        status_code = 200
        headers = {"content-length": "2"}

        async def aiter_bytes(self):
            yield b"{}"

    class Stream:
        async def __aenter__(self):
            return Response()

        async def __aexit__(self, *args):
            return False

    class Client:
        def __init__(self, **options):
            assert options["verify"] is True
            assert options["trust_env"] is False
            assert options["follow_redirects"] is False
            assert options["timeout"].connect == 2.0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, method, uri, **options):
            streams.append((method, uri.host, options))
            return Stream()

    monkeypatch.setattr(module, "_resolve_public_ip", fake_resolution)
    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    assert await module._fetch_public_https("https://maps.example.org/app.js.map") == "{}"
    assert resolved == ["maps.example.org"]
    assert streams == [("GET", "8.8.8.8", {
        "headers": {"Host": "maps.example.org"},
        "extensions": {"sni_hostname": "maps.example.org"},
        "follow_redirects": False,
    })]


@pytest.mark.asyncio
async def test_source_map_internal_redirect_and_length_caps_still_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_native("source-map-mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    monkeypatch.setattr(module, "_resolve_public_ip", AsyncMock(return_value="8.8.8.8"))

    class Response:
        def __init__(self, status: int, headers: dict[str, str], body: bytes):
            self.status_code = status
            self.headers = headers
            self.body = body

        async def aiter_bytes(self):
            yield self.body

    class Stream:
        def __init__(self, item):
            self.item = item

        async def __aenter__(self):
            return self.item

        async def __aexit__(self, *args):
            return False

    cases = [
        Response(302, {"location": "https://other.example.org/secret.map"}, b""),
        Response(200, {"content-length": "999999999"}, b""),
        Response(200, {}, b"A" * (1024 * 1024 + 1)),
    ]

    class Client:
        def __init__(self, **options):
            assert options["verify"] is True
            assert options["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return Stream(cases.pop(0))

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)
    for _ in range(3):
        with pytest.raises(module.SourceMapUnavailable):
            await module._fetch_public_https("https://maps.example.org/app.js.map")
    assert cases == []


@pytest.mark.asyncio
async def test_browser_production_bootstrap_requires_credentials_and_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    module = _load_native("browser-mcp")
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.setenv("OSOP_BROWSER_MCP_BEARER_TOKEN", "test-local-provider-bearer-unique")
    monkeypatch.delenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64", raising=False)
    monkeypatch.setattr(module.manager, "_started", False)
    no_effect = AsyncMock(side_effect=AssertionError("Browser launched without signed Task"))
    monkeypatch.setattr(module.manager, "get_page", no_effect)

    async with _client(module) as client:
        assert (await client.get("/health")).status_code == 503
        anonymous = await client.post("/mcp/initialize", json={"session_id": "api-bootstrap"})
        assert anonymous.status_code == 401
        denied = await client.post(
            "/mcp/initialize", json={"session_id": "api-bootstrap"},
            headers={"Authorization": "Bearer test-local-provider-bearer-unique"},
        )
        assert denied.status_code == 503

        key = Ed25519PrivateKey.generate()
        private = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        monkeypatch.setenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64", base64.b64encode(private).decode())
        monkeypatch.setenv("OSOP_BROWSER_MCP_RECEIPT_KID", "local-signed-browser")
        monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", json.dumps({
            "browser-mcp": {"local-signed-browser": base64.b64encode(public).decode()},
        }))
        monkeypatch.setenv("OSOP_BROWSER_MCP_JOURNAL_ROOT", str(tmp_path))
        bootstrap = await client.post(
            "/mcp/initialize", json={"session_id": "api-bootstrap"},
            headers={"Authorization": "Bearer test-local-provider-bearer-unique"},
        )
        binding = {
            "request_id": "req-forged", "engagement_id": "eng-fake",
            "task_id": "task-fake", "server_id": "browser-mcp",
        }
        payload = {
            "request_id": "req-forged", "session_id": "eng-fake", "tool_name": "execute",
            "parameters": {"action": "navigate", "url": "https://never-contact.invalid/",
                           "engagement_id": "eng-fake", "user_label": "guest"},
            "execution_binding": binding,
        }
        no_bearer = await client.post("/mcp/execute", json=payload)
        unauthenticated_task = await client.post(
            "/mcp/execute", json=payload,
            headers={"Authorization": "Bearer test-local-provider-bearer-unique"},
        )
        legacy_unsigned = await client.post(
            "/mcp/execute", json={**payload, "execution_binding": None},
            headers={"Authorization": "Bearer test-local-provider-bearer-unique"},
        )
    assert bootstrap.status_code == 503
    assert bootstrap.json() == {"detail": "Signed browser provider unavailable"}
    assert no_bearer.status_code == 401
    assert unauthenticated_task.json()["status"] == "error"
    assert "provider_receipt" not in unauthenticated_task.json()
    assert legacy_unsigned.status_code == 403
    no_effect.assert_not_awaited()
