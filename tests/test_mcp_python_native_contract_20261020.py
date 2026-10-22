"""Adversarial in-process ASGI contracts for five native Python MCP services.

No uvicorn start, network socket, app DB, targets, MCP provider, paid service
or credentials. SourceMap HTTP is unavailable without independent signed Task
authority; private fetch/parser defenses are tested only with controlled stubs.
"""

from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
import json
import socket
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_osop.mcp.protocol import MCPInitializeResponse, SideEffectClass

_ROOT = Path(__file__).resolve().parents[1] / "mcp-servers" / "python"
_APPS = (
    "source_map_mcp",
    "threat_intel_mcp",
    "reporting_mcp",
    "session_memory_mcp",
    "attack_graph_mcp",
)
_UNAVAILABLE = {"reporting_mcp", "session_memory_mcp", "attack_graph_mcp"}


def _load(name: str):
    assert name in _APPS
    spec = importlib.util.spec_from_file_location(
        f"_qualification_native_{name}",
        _ROOT / f"{name}.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Pydantic v2 resolves forward annotations via sys.modules for ASGI routes.
    # Register this isolated test module name, never execute __main__.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def _post(module, path: str, data: dict[str, Any]):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://mcp-qualification.invalid",
        follow_redirects=False,
        timeout=3.0,
    ) as client:
        return await client.post(path, json=data)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", _APPS)
async def test_every_native_initialize_is_canonical_complete_and_honest(name, monkeypatch):
    if name == "source_map_mcp":
        monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    module = _load(name)
    response = await _post(
        module,
        "/mcp/initialize",
        {
            "scope": {"domains": []},
            "auth_credentials": {},
            "session_id": "fixture-only",
            "metadata": {},
        },
    )
    assert response.status_code == 200
    data = response.json()
    result = MCPInitializeResponse.model_validate(data)
    assert result.server_id == name.replace("_", "-")
    assert result.capabilities
    assert result.tools
    assert result.status == (
        "unavailable" if name in _UNAVAILABLE or name == "source_map_mcp" else "ready"
    )
    if name == "source_map_mcp":
        assert "execution_unavailable_no_signed_source_authorization" in result.capabilities
    assert len({tool.name for tool in result.tools}) == len(result.tools)
    for tool in result.tools:
        assert tool.description and len(tool.description) >= 10
        assert tool.returns and tool.returns["type"] == "object"
        assert tool.side_effect_class in SideEffectClass
        assert isinstance(tool.requires_approval, bool)
        assert tool.scope_check is True
        assert all(
            parameter.name and parameter.type and parameter.description
            for parameter in tool.parameters
        )
        if name in _UNAVAILABLE:
            assert tool.requires_approval is True
            assert "UNAVAILABLE" in tool.description


@pytest.mark.asyncio
@pytest.mark.parametrize("name", _UNAVAILABLE)
async def test_unimplemented_facade_health_and_execute_never_fabricate_evidence(name):
    module = _load(name)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://mcp-qualification.invalid",
    ) as client:
        status = await client.get("/health")
        assert status.status_code == 503
        assert status.json()["status"] == "unavailable"
        for tool in (
            "compile_findings",
            "get_session_state",
            "store_checkpoint",
            "query_graph",
            "get_neighbors",
            "nonexistent",
        ):
            response = await client.post(
                "/mcp/execute",
                json={
                    "request_id": "req-safe-facade",
                    "tool_name": tool,
                    "timeout_override": None,
                    "parameters": {
                        "engagement_id": "eng-123",
                        "query": "MATCH (n) DETACH DELETE n",
                        "api_key": "sk-live-private-fixture",
                    },
                },
            )
            assert response.status_code == 200
            actual = response.json()
            assert actual == {
                "request_id": "req-safe-facade",
                "status": "error",
                "error": "server_unavailable",
            }
            assert "sk-live-private-fixture" not in response.text
            assert "report_url" not in response.text
            assert "nodes" not in response.text


@pytest.mark.asyncio
async def test_source_map_default_deny_and_unauthorized_urls_never_resolve_or_fetch(monkeypatch):
    module = _load("source_map_mcp")
    monkeypatch.delenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", raising=False)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://mcp-qualification.invalid",
    ) as client:
        health = await client.get("/health")
        initialized = await client.post("/mcp/initialize", json={})
    assert health.status_code == 503
    assert health.json()["status"] == "unavailable"
    assert health.json()["source_side_signed_authorization_verified"] is False
    parsed = MCPInitializeResponse.model_validate(initialized.json())
    assert parsed.status == "unavailable"

    async def forbidden_dns(host):
        raise AssertionError("Unsafe URL reached DNS")

    async def forbidden_fetch(url, *, initial_host=None):
        raise AssertionError("Unsafe URL reached outbound HTTP")

    monkeypatch.setattr(module, "_resolve_public_ip", forbidden_dns)
    monkeypatch.setattr(module, "_fetch_public_https", forbidden_fetch)
    response = await _post(
        module,
        "/mcp/execute",
        {
            "tool_name": "fetch_and_parse_sourcemap",
            "request_id": "req-default-deny",
            "timeout_override": None,
            "parameters": {"url": "https://unapproved.example/app.js.map"},
        },
    )
    assert response.json() == {
        "request_id": "req-default-deny",
        "status": "error",
        "error": "source_map_input_denied",
    }
    assert "verify" not in response.text


@pytest.mark.asyncio
async def test_source_map_allowlisted_http_fails_closed_without_dns_fetch_or_target(monkeypatch):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    calls = []

    async def unexpected_dns(*args, **kwargs):
        calls.append("dns")
        raise AssertionError("Unapproved native HTTP reached DNS")

    async def unexpected_fetch(*args, **kwargs):
        calls.append("fetch")
        raise AssertionError("Unapproved native HTTP fetched a source map")

    monkeypatch.setattr(module, "_resolve_public_ip", unexpected_dns)
    monkeypatch.setattr(module, "_fetch_public_https", unexpected_fetch)
    monkeypatch.setattr(module, "analyze_sourcemap", unexpected_fetch)
    for candidate in (
        "https://maps.example.org/app.js",
        "https://maps.example.org/app.js.map",
    ):
        response = await _post(
            module,
            "/mcp/execute",
            {
                "request_id": "req-unapproved-public-map",
                "tool_name": "fetch_and_parse_sourcemap",
                "parameters": {"url": candidate},
            },
        )
        assert response.status_code == 503
        assert response.json() == {
            "request_id": "req-unapproved-public-map",
            "status": "error",
            "error": "signed_source_authority_unavailable",
            "execution_enabled": False,
        }
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "allowlist",
    [
        "*",
        "*.example.org",
        "127.0.0.1",
        "xn--homograph.example.org",
        "maps.example.org," + "invalid host",
        "maps.example.org," * 34,
    ],
)
async def test_source_map_malformed_administrator_allowlist_is_not_ready(
    monkeypatch,
    allowlist,
):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", allowlist)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://mcp-qualification.invalid",
    ) as client:
        health = await client.get("/health")
        init = await client.post("/mcp/initialize", json={})
    assert health.status_code == 503
    assert health.json()["status"] == "unavailable"
    assert MCPInitializeResponse.model_validate(init.json()).status == "unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://maps.example.org/example.map",
        "ftp://maps.example.org/example.map",
        "file:///etc/passwd",
        "gopher://maps.example.org",
        "https://127.0.0.1/example.map",
        "https://10.0.0.1/example.map",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/metadata",
        "https://2130706433/example.map",
        "https://maps.example.org@evil.example/secret.map",
        "https://user:pass@maps.example.org/example.map",
        "https://maps.example.org:8443/example.map",
        "https://maps.example.org.evil.test/example.map",
        "https://xn--maps-vta.example.org/example.map",
        "https://mаps.example.org/example.map",  # Cyrillic lookalike 'а'
        "https://maps.example.org/example.map#fragment",
        "https://maps.example.org/example.map?api_key=private",
        "https://maps.example.org\\@evil.test/example.map",
        "https://maps.example.org/example.map\nHost:evil.test",
        "https://maps.example.org/" + "a" * 2049,
        "https://maps.example.org.",
        "data:application/json,{}",
        "//maps.example.org/example.map",
        "https://maps.example.org%2Fevil.test/example.map",
    ],
)
async def test_source_map_blocks_scheme_ip_userinfo_homograph_and_url_ambiguity_before_dns(
    monkeypatch,
    url,
):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")

    async def forbidden_dns(host):
        raise AssertionError("Rejected URL reached DNS")

    monkeypatch.setattr(module, "_resolve_public_ip", forbidden_dns)
    result = await _post(
        module,
        "/mcp/execute",
        {
            "request_id": "req-invalid-source",
            "tool_name": "fetch_and_parse_sourcemap",
            "parameters": {"url": url},
        },
    )
    assert result.status_code == 200
    assert result.json()["status"] == "error"
    assert result.json()["error"] == "source_map_input_denied"
    assert url not in result.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answers",
    [
        ("127.0.0.1",),
        ("10.1.2.3",),
        ("192.168.5.5",),
        ("172.16.0.4",),
        ("169.254.169.254",),
        ("0.0.0.0",),
        ("::1",),
        ("fe80::a",),
        ("::ffff:127.0.0.1",),
        ("8.8.8.8", "10.0.0.1"),
    ],
)
async def test_source_map_rejects_untrusted_or_mixed_dns_addresses_before_http(
    monkeypatch,
    answers,
):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    loop = asyncio.get_running_loop()

    async def fake_getaddrinfo(host, port, **options):
        assert host == "maps.example.org" and port == 443
        assert options["type"] == socket.SOCK_STREAM
        return [
            (
                socket.AF_INET6 if ":" in host_ip else socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (host_ip, 443),
            )
            for host_ip in answers
        ]

    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(module.SourceMapDenied):
        await module._resolve_public_ip("maps.example.org")


@pytest.mark.asyncio
async def test_source_map_public_dns_ip_is_pinned_and_tls_checked(monkeypatch):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    dns_seen = []
    stream_calls = []
    response_data = [
        "//# sourceMappingURL=app.js.map\nconst harmless = 1;",
        json.dumps(
            {
                "sources": ["../../private/alice/secrets.js"],
                "sourcesContent": [
                    'const API_KEY="sk-live-private-fixture";' 'const k="AKIAABCDEFGHIJKLMNOP";'
                ],
            }
        ),
    ]

    async def safe_resolve(host):
        dns_seen.append(host)
        return "8.8.8.8"

    class FakeResponse:
        status_code = 200
        headers = {}

        def __init__(self, content):
            self.content = content.encode()

        async def aiter_bytes(self):
            yield self.content[:10]
            yield self.content[10:]

    class FakeStream:
        def __init__(self, payload):
            self.payload = FakeResponse(payload)

        async def __aenter__(self):
            return self.payload

        async def __aexit__(self, *args):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["verify"] is True
            assert kwargs["trust_env"] is False
            assert kwargs["follow_redirects"] is False
            assert kwargs["timeout"].connect == 2.0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, method, url, **kwargs):
            assert method == "GET"
            assert url.host == "8.8.8.8"
            assert kwargs["follow_redirects"] is False
            assert kwargs["headers"] == {"Host": "maps.example.org"}
            assert kwargs["extensions"] == {"sni_hostname": "maps.example.org"}
            stream_calls.append(str(url))
            return FakeStream(response_data[len(stream_calls) - 1])

    # Public HTTP deliberately refuses even a host allowlisted by an admin.
    denied = await _post(
        module,
        "/mcp/execute",
        {
            "request_id": "req-local-metadata",
            "tool_name": "fetch_and_parse_sourcemap",
            "parameters": {"url": "https://maps.example.org/app.js"},
        },
    )
    assert denied.status_code == 503
    assert denied.json()["error"] == "signed_source_authority_unavailable"
    assert dns_seen == stream_calls == []

    # Internal helper tests verify pinned DNS, TLS SNI and redacted metadata
    # without making the forbidden HTTP route usable or sending network traffic.
    monkeypatch.setattr(module, "_resolve_public_ip", safe_resolve)
    monkeypatch.setattr(module.httpx, "AsyncClient", FakeClient)
    data = await module.analyze_sourcemap("https://maps.example.org/app.js")
    assert data["credentials_disclosed"] is False
    assert data["sources"] == ["source_0.js"]
    assert data["source_side_signed_authorization_verified"] is False
    assert data["findings"][0]["secret_type_counts"]["aws_access_key"] == 1
    assert dns_seen == ["maps.example.org", "maps.example.org"]
    assert all("8.8.8.8" in url for url in stream_calls)
    assert "sk-live-private-fixture" not in json.dumps(data)
    assert "AKIAABCDEFGHIJKLMNOP" not in json.dumps(data)
    assert "private/alice" not in json.dumps(data)


@pytest.mark.asyncio
async def test_source_map_redirect_and_cross_host_map_fail_without_second_fetch(monkeypatch):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    calls = []

    async def redirect(url, *, initial_host=None):
        calls.append(url)
        if len(calls) == 1:
            return "//# sourceMappingURL=https://other.example.org/private.map"
        raise AssertionError("Cross-host sourceMappingURL triggered forbidden fetch")

    response = await _post(
        module,
        "/mcp/execute",
        {
            "request_id": "req-cross-host",
            "tool_name": "fetch_and_parse_sourcemap",
            "parameters": {"url": "https://maps.example.org/bundle.js"},
        },
    )
    assert response.status_code == 503
    assert response.json()["error"] == "signed_source_authority_unavailable"
    assert calls == []
    monkeypatch.setattr(module, "_fetch_public_https", redirect)
    with pytest.raises(module.SourceMapDenied):
        await module.analyze_sourcemap("https://maps.example.org/bundle.js")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_source_map_rejects_non200_redirect_and_oversize_before_disclosure(monkeypatch):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    monkeypatch.setattr(module, "_resolve_public_ip", lambda host: _await_public())

    class FakeResponse:
        def __init__(self, status, content, headers=None):
            self.status_code = status
            self.headers = headers or {}
            self.content = content

        async def aiter_bytes(self):
            yield self.content

    class FakeStream:
        def __init__(self, response):
            self.response = response

        async def __aenter__(self):
            return self.response

        async def __aexit__(self, *args):
            return False

    choices = [
        FakeResponse(302, b"", {"location": "http://127.0.0.1/private"}),
        FakeResponse(200, b"{}", {"content-length": "99999999"}),
        FakeResponse(200, b"A" * (1024 * 1024 + 1)),
    ]

    class FakeClient:
        def __init__(self, **options):
            assert options["verify"] is True
            assert options["follow_redirects"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return FakeStream(choices.pop(0))

    denied = await _post(
        module,
        "/mcp/execute",
        {
            "request_id": "req-reject-public",
            "tool_name": "fetch_and_parse_sourcemap",
            "parameters": {"url": "https://maps.example.org/app.js.map"},
        },
    )
    assert denied.status_code == 503
    assert denied.json()["error"] == "signed_source_authority_unavailable"
    assert len(choices) == 3

    monkeypatch.setattr(module.httpx, "AsyncClient", FakeClient)
    for _ in range(3):
        with pytest.raises(module.SourceMapUnavailable):
            await module._fetch_public_https("https://maps.example.org/app.js.map")
    assert not choices


async def _await_public():
    return "8.8.8.8"


@pytest.mark.asyncio
async def test_source_map_rejects_malformed_parameters_and_huge_source_document(monkeypatch):
    module = _load("source_map_mcp")
    monkeypatch.setenv("OSOP_SOURCEMAP_ALLOWED_HOSTS", "maps.example.org")
    for parameters in (
        None,
        {},
        {"url": ["https://maps.example.org/app.map"]},
        {"url": "https://maps.example.org/app.map", "api_key": "secret"},
    ):
        response = await _post(
            module,
            "/mcp/execute",
            {
                "request_id": "req-denied-parameters",
                "tool_name": "fetch_and_parse_sourcemap",
                "parameters": parameters,
            },
        )
        assert response.json()["status"] == "error"
        assert "secret" not in response.text

    async def oversized(url, *, initial_host=None):
        return json.dumps({"sources": [f"file-{i}" for i in range(129)], "sourcesContent": []})

    response = await _post(
        module,
        "/mcp/execute",
        {
            "request_id": "req-oversized-map",
            "tool_name": "fetch_and_parse_sourcemap",
            "parameters": {"url": "https://maps.example.org/app.js.map"},
        },
    )
    assert response.status_code == 503
    assert response.json()["error"] == "signed_source_authority_unavailable"
    monkeypatch.setattr(module, "_fetch_public_https", oversized)
    with pytest.raises(module.SourceMapUnavailable):
        await module.analyze_sourcemap("https://maps.example.org/app.js.map")


@pytest.mark.asyncio
async def test_threat_intel_valid_public_cve_local_fixture_and_never_exploit_effect(monkeypatch):
    module = _load("threat_intel_mcp")
    network_calls = []

    async def local_fixture(url, *, cve_id=None):
        network_calls.append((url, cve_id))
        if url == module._NVD:
            return json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2025-12345",
                                "descriptions": [{"lang": "en", "value": "Inert description"}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 4.2}}]},
                            }
                        }
                    ],
                }
            ).encode()
        return (
            "id,description,codes\n" "12345,An inert public exploit listing,CVE-2025-12345\n"
        ).encode()

    monkeypatch.setattr(module.manager, "_fetch", local_fixture)
    for tool in ("cve_lookup", "search_exploits"):
        response = await _post(
            module,
            "/mcp/execute",
            {
                "request_id": f"req-{tool}",
                "tool_name": tool,
                "timeout_override": None,
                "parameters": {"cve_id": "CVE-2025-12345"},
            },
        )
        assert response.json()["status"] == "success"
        assert response.json()["result"]["target_effect_verified"] is False
        assert "PUBLIC_UNVERIFIED" in response.json()["result"]["source"]
    assert len(network_calls) == 2
    assert set(url for url, _ in network_calls) == {module._NVD, module._EXPLOITDB_CSV}


@pytest.mark.asyncio
async def test_threat_intel_kev_membership_and_unavailable_catalog(monkeypatch):
    module = _load("threat_intel_mcp")

    async def catalog(url, *, cve_id=None):
        assert url == module._CISA_KEV
        assert cve_id is None
        return json.dumps({"vulnerabilities": [{"cveID": "CVE-2025-12345"}]}).encode()

    monkeypatch.setattr(module.manager, "_fetch", catalog)
    for cve, expected in (("CVE-2025-12345", True), ("CVE-2025-67890", False)):
        response = await _post(
            module,
            "/mcp/execute",
            {"tool_name": "kev_check", "parameters": {"cve_id": cve}},
        )
        assert response.json()["status"] == "success"
        assert response.json()["result"]["in_kev"] is expected
        assert response.json()["result"]["target_effect_verified"] is False

    async def malformed(url, *, cve_id=None):
        return json.dumps({"vulnerabilities": "invalid"}).encode()

    monkeypatch.setattr(module.manager, "_fetch", malformed)
    response = await _post(
        module,
        "/mcp/execute",
        {"tool_name": "kev_check", "parameters": {"cve_id": "CVE-2025-67890"}},
    )
    assert response.json()["status"] == "error"


@pytest.mark.asyncio
async def test_threat_intel_malformed_cve_and_upstream_error_are_never_success(monkeypatch):
    module = _load("threat_intel_mcp")
    hits = []

    async def unavailable(*args, **kwargs):
        hits.append(args)
        raise module.ThreatIntelUnavailable("private upstream details")

    monkeypatch.setattr(module.manager, "_fetch", unavailable)
    for candidate in (
        "",
        "invalid",
        "CVE-2025-0001?api_key=private",
        "CVE-2025-1",
        "CVE-2025-" + "0" * 100,
        ["CVE-2025-12345"],
    ):
        response = await _post(
            module,
            "/mcp/execute",
            {
                "request_id": "req-bad-cve",
                "tool_name": "cve_lookup",
                "parameters": {"cve_id": candidate},
            },
        )
        assert response.json()["status"] == "error"
        assert "private upstream" not in response.text
    assert hits == []
    response = await _post(
        module,
        "/mcp/execute",
        {
            "request_id": "req-upstream-failed",
            "tool_name": "cve_lookup",
            "parameters": {"cve_id": "CVE-2025-12345"},
        },
    )
    assert response.json() == {
        "request_id": "req-upstream-failed",
        "status": "error",
        "error": "public_intel_unavailable",
    }
    assert len(hits) == 1


@pytest.mark.asyncio
async def test_threat_intel_public_client_only_fixed_https_and_no_proxy_redirects(monkeypatch):
    module = _load("threat_intel_mcp")
    for bad in (
        "http://169.254.169.254/metadata",
        "https://user:pass@services.nvd.nist.gov/",
        "https://services.nvd.nist.gov.evil.test/",
    ):
        with pytest.raises(module.ThreatIntelUnavailable):
            await module.manager._fetch(bad)

    class FakeResponse:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/"}

        async def aiter_bytes(self):
            yield b""

    class FakeStream:
        async def __aenter__(self):
            return FakeResponse()

        async def __aexit__(self, *args):
            return False

    class FakeClient:
        def __init__(self, **opts):
            assert opts["verify"] is True
            assert opts["trust_env"] is False
            assert opts["follow_redirects"] is False
            assert opts["timeout"].connect == 3.0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, method, url, **kwargs):
            assert method == "GET"
            assert url == module._NVD
            assert kwargs["follow_redirects"] is False
            return FakeStream()

    monkeypatch.setattr(module.httpx, "AsyncClient", FakeClient)
    with pytest.raises(module.ThreatIntelUnavailable):
        await module.manager._fetch(module._NVD, cve_id="CVE-2025-12345")
