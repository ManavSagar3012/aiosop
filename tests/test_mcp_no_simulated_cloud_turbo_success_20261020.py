"""Adversarial in-process ASGI qualification of unconfigured Cloud/Turbo MCP.

These applications previously returned fabricated IAM, privilege and race
evidence as success. Cloud now has an optional independent local Terraform
Checkov path; it must be explicitly UNCONFIGURED for these old negative tests.
No sockets, cloud accounts, app DBs, scanner subprocesses, upstream providers,
credentials or test targets are opened by this suite.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_osop.mcp.protocol import MCPInitializeResponse, SideEffectClass

_ROOT = Path(__file__).resolve().parents[1] / "mcp-servers" / "python"
_CASES = {
    "cloud_mcp": (
        "cloud-mcp",
        SideEffectClass.RECON_ACTIVE,
        ("analyze_iam_trust_policies", "discover_privilege_escalation"),
    ),
    "turbo_intruder_mcp": (
        "turbo-intruder-mcp",
        SideEffectClass.INVASIVE_EXPLOIT,
        ("execute_single_packet_attack",),
    ),
}


def _app(name: str) -> Any:
    assert name in _CASES
    spec = importlib.util.spec_from_file_location(
        "_unavailable_native_qualification_" + name, _ROOT / (name + ".py")
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _client(module: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app),
        base_url="http://cloud-turbo-no-socket.invalid",
        follow_redirects=False,
        timeout=3.0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(_CASES))
async def test_both_native_servers_report_unavailable_and_typed_safe_manifest(
    name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if name == "cloud_mcp":
        monkeypatch.delenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", raising=False)
    module = _app(name)
    server_id, risk, expected_tools = _CASES[name]
    async with _client(module) as client:
        health = await client.get("/health")
        assert health.status_code == 503
        expected_health = {
            "server_id": server_id,
            "status": "unavailable",
        }
        if name != "cloud_mcp":
            expected_health.update(
                {
                    "execution_enabled": False,
                    "source_side_signed_authorization_verified": False,
                }
            )
        assert health.json() == expected_health
        assert health.headers["cache-control"] == "no-store"
        init = await client.post(
            "/mcp/initialize",
            json={
                "scope": {"domains": ["example.invalid"]},
                "auth_credentials": {"operator_claim": "signed-but-untrusted"},
                "session_id": "eng-adversarial",
                "metadata": {"simulate": True, "allow_cloud": True},
            },
        )
        assert init.status_code == 200
        data = init.json()
        parsed = MCPInitializeResponse.model_validate(data)
        assert parsed.server_id == server_id
        assert parsed.status == "unavailable"
        if name == "cloud_mcp":
            # The *configured* module exposes static-IaC only; unconfigured
            # Cloud is 503 and advertises no runnable tool, not a fake IAM API.
            assert parsed.capabilities == []
            assert parsed.tools == []
            assert "execution_enabled" not in data
            return
        assert data["execution_enabled"] is False
        assert data["source_side_signed_authorization_verified"] is False
        assert parsed.capabilities == ["execution_unavailable"]
        assert tuple(tool.name for tool in parsed.tools) == expected_tools
        for tool in parsed.tools:
            # Actual production MCPConnection.initialize rejects status!=ready.
            # Explicit risk schema also prevents READ_ONLY default laundering.
            original = next(item for item in data["tools"] if item["name"] == tool.name)
            assert original["side_effect_class"] == risk.value
            assert original["requires_approval"] is True
            assert original["scope_check"] is True
            assert tool.side_effect_class == risk
            assert tool.requires_approval is True
            assert tool.scope_check is True
            assert tool.description.startswith("UNAVAILABLE:")
            assert tool.returns["type"] == "object"
            assert tool.parameters
            assert all(
                parameter.name and parameter.type and parameter.description
                for parameter in tool.parameters
            )
            assert not set(["status", "fake_success"]) & set(tool.returns)


_CLAIMS = [
    {},
    {"account_id": "123456789012"},
    {"principal_arn": "arn:aws:iam::123456789012:role/Admin"},
    {
        "target_url": "https://no-contact.invalid/withdraw",
        "method": "POST",
        "headers": {"Authorization": "Bearer test-do-not-disclose"},
        "body": "private-test-body",
        "concurrent_requests": 99,
    },
    {"operator_approved": True, "side_effect_class": "READ_ONLY", "scope_check": True},
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(_CASES))
async def test_direct_http_execute_denies_all_tools_and_injected_credentials(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if name == "cloud_mcp":
        monkeypatch.delenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", raising=False)
    module = _app(name)
    _, _, names = _CASES[name]
    async with _client(module) as client:
        for tool in (*names, "authority_status", "unsafe-not-registered"):
            for params in _CLAIMS:
                response = await client.post(
                    "/mcp/execute",
                    json={
                        "request_id": "req-adversarial-signature-forged",
                        "tool_name": tool,
                        "parameters": params,
                        "side_effect_class": "READ_ONLY",
                        "scope_check": True,
                        "approval_id": "apr-fake",
                        "source_side_signed_authorization_verified": True,
                    },
                    headers={
                        "Authorization": "Bearer test-credential-do-not-leak",
                        "X-OSOP-Native-Grant": "forged-inert-token",
                    },
                )
                assert response.status_code == 503
                expected_body = {
                    "status": "error",
                    "error": (
                        "local_iac_unavailable" if name == "cloud_mcp" else "server_unavailable"
                    ),
                }
                if name != "cloud_mcp":
                    expected_body["execution_enabled"] = False
                assert response.json() == expected_body
                assert response.headers["cache-control"] == "no-store"
                for forbidden in (
                    "123456789012",
                    "private-test-body",
                    "Bearer test-",
                    "race_condition_detected",
                    "findings",
                    "paths",
                    "verified",
                    "req-adversarial",
                    "example.invalid",
                    "no-contact.invalid",
                ):
                    assert forbidden not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("name", sorted(_CASES))
async def test_malformed_direct_requests_are_not_a_fake_execution_escape(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if name == "cloud_mcp":
        monkeypatch.delenv("OSOP_CLOUD_MCP_LOCAL_IAC_ENABLED", raising=False)
    module = _app(name)
    async with _client(module) as client:
        for raw, content_type in (
            (b"{not-json", "application/json"),
            (b"null", "application/json"),
            (b"[]", "application/json"),
            (b"account_id=123456789012", "application/x-www-form-urlencoded"),
            (b"x" * 8192, "application/octet-stream"),
        ):
            response = await client.post(
                "/mcp/execute",
                content=raw,
                headers={"Content-Type": content_type},
            )
            if name == "cloud_mcp":
                # FastAPI schema parsing may 422 malformed data before Cloud
                # checks the disabled static-IaC host configuration.
                assert response.status_code in (415, 422, 503)
                assert response.status_code != 200
                assert "success" not in response.text
            else:
                assert response.status_code == 503
                assert response.json()["error"] == "server_unavailable"
                assert response.json()["execution_enabled"] is False
