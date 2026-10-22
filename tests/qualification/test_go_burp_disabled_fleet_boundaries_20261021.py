"""Qualify the Go/Burp/disabled fleet without executing a target-side handler.

Default tests inspect production paths and exercise Python ASGI in-process.
The optional Go SDK regression runs local httptest HTTPS *only* with explicit
OSOP_GO_FLEET_NEGATIVE_20261021=1. There is no app DB, Docker, provider or scan.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
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

from ai_osop.adapters.burp_mcp import BurpMCPAdapter
from ai_osop.core.exceptions import MCPConnectionError, MCPException
from ai_osop.core.models import ScopeDefinition
from ai_osop.core.native_mcp_grant_signing import NativeGrantDenied, sign_grant, verify_grant
from ai_osop.mcp.protocol import MCPConnection, MCPRegistry

ROOT = Path(__file__).resolve().parents[2]
GO = {
    "recon-mcp": (8082, "subfinder_enum"),
    "payload-mcp": (8083, "generate_payload"),
    "nuclei-mcp": (8084, "scan"),
    "shodan-mcp": (8085, "shodan_lookup"),
    "threat-intel-mcp": (8086, "cve_lookup"),
    "security-bridge": (8087, "sqlmap"),
}
DISABLED = {
    "cloud-mcp": ("cloud_mcp.py", "analyze_iam_trust_policies"),
    "turbo-intruder-mcp": ("turbo_intruder_mcp.py", "execute_single_packet_attack"),
}
GO_NEGATIVE = (
    "TestForgedSignatureUnknownKidWrongDomainAndMutatedClaimsNeverRedeem",
    "TestValidSignatureButStaleCrossIdentityAndMissingScopeIsRejectedBeforeRedeem",
    "TestNativeGrantSignatureCannotBeRedeemedWithAnotherServerKey",
    "TestIndependentlyOperatedValidatorDeniesSignedButWrongTenantAndStaleLease",
    "TestDurableValidatorRejectsRevokedOrCancelledActionGrant",
    "TestAllRegisteredToolsBlockedEvenWithValidAuthorityStatusGrant",
)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _native(name: str) -> Any:
    path = ROOT / "mcp-servers" / "python" / DISABLED[name][0]
    spec = importlib.util.spec_from_file_location("qual_disabled_" + name.replace("-", "_"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_six_production_go_entrypoints_and_sdk_dispatch_are_one_inert_contract() -> None:
    source = ast.parse(_read("src/ai_osop/api/main.py"))
    register = next(
        node
        for node in source.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "register_optional_mcp_servers"
    )
    assignments = [
        node.value
        for node in ast.walk(register)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "servers" for target in node.targets)
    ]
    assert len(assignments) == 1
    from tests.mcp_inventory_source import configured_server_nodes

    registered = [value.elts[0].value for value in configured_server_nodes(source).elts]
    assert len(registered) == len(set(registered)) == 11
    assert set(GO) | set(DISABLED) | {"burp-mcp", "browser-mcp", "source-map-mcp"} == set(
        registered
    )

    sdk = _read("mcp-servers/go/sdk/server.go")
    grant = _read("mcp-servers/go/sdk/native_grant.go")
    assert 'mux.HandleFunc("/mcp/execute"' in sdk
    assert "s.verifyAndRedeemAuthorityStatus(" in sdk
    assert "item.Handler = nil" in sdk
    assert "return []Tool{authorityStatusTool()}" in sdk
    assert 'NativeAuthorityStatusTool = "authority_status"' in grant
    assert "c.ServerID != serverID" in grant
    assert "c.ExpiresAt <= epoch" in grant
    assert "ed25519.Verify(pub" in grant
    assert 'uri.Path != "/native-grants/redeem"' in grant
    assert "result.StatusCode != http.StatusOK" in grant
    assert "redeemed.DurablyRedeemed" in grant
    assert "s.consumeSupervisorProof(" in grant
    for name, (port, legacy_tool) in GO.items():
        cmd = _read(f"mcp-servers/go/cmd/{name}/main.go")
        assert f'sdk.NewServer("{name}")' in cmd
        assert re.search(r'Name:\s*"' + re.escape(legacy_tool) + '"', cmd)
        assert "Handler: func(" in cmd
        assert "server.Run(" in cmd
        if name != "recon-mcp":
            assert f"sdk.LocalPortAddress({port})" in cmd
        else:
            assert "reconListenAddress()" in cmd
        # Legacy handler is a declaration; the actual shared SDK HTTP mux
        # routes no registered handler, even when marked scope_check=true.
        assert "/mcp/execute" not in cmd

    # The only host-side 0033 provisioning path with a fixed Docker-exec
    # observation is Recon. Grant identities for the remaining five must not
    # be interpreted as qualifying 0033 resource/worker stages for them.
    supervised = _read("src/ai_osop/orchestrator/native_mcp_docker_supervisor.py")
    assert 'if original["server_id"] != "recon-mcp":' in supervised
    assert "observe_isolated_native_container(" in supervised
    assert "verify_grant(grant, public_keys=self._issuers" in supervised
    issuer = _read("src/ai_osop/core/native_mcp_grant_signing.py")
    assert 'DOMAIN = b"ai-osop/native-grant/v1\\x00"' in issuer


def _test_grant(now: int) -> tuple[dict[str, Any], str, dict[str, str]]:
    key = Ed25519PrivateKey.generate()
    secret = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    issuer = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    public = (
        base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode("ascii")
        .rstrip("=")
    )
    claims = {
        "version": 1,
        "grant_id": "ngr-" + "1" * 32,
        "request_id": "req-" + "2" * 32,
        "engagement_id": "eng-owner",
        "flow_id": "flow-owner",
        "task_id": "task-owner",
        "subtask_id": "subtask-owner",
        "action_id": "action-owner",
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "parameters_sha256": hashlib.sha256(b"{}").hexdigest(),
        "manifest_sha256": "a" * 64,
        "authorization_version": 3,
        "authorization_sha256": "b" * 64,
        "lease_id": "lease-owner",
        "resource_sha256": None,
        "issued_at": now - 2,
        "expires_at": now + 20,
        "side_effect_class": "READ_ONLY",
    }
    return claims, issuer, {"qualification-key": public}


def test_fake_signed_grants_do_not_inherit_issuer_authority_or_freshness() -> None:
    """Real Python issuance/verification rejects forged, expired, foreign issuer.

    A valid signature alone still needs the Go server-id fence and independently
    maintained 0029/0033 source. Those Go checks are exercised by opt-in tests.
    """
    now = int(time.time())
    claims, issuer, keys = _test_grant(now)
    signed = sign_grant(claims, kid="qualification-key", private_seed_b64url=issuer, now=now)
    assert verify_grant(signed, public_keys=keys, now=now) == claims

    altered = json.loads(json.dumps(signed))
    altered["claims"]["engagement_id"] = "eng-foreign"
    with pytest.raises(NativeGrantDenied):
        verify_grant(altered, public_keys=keys, now=now)

    other_key = (
        Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    foreign = base64.urlsafe_b64encode(other_key).decode("ascii").rstrip("=")
    with pytest.raises(NativeGrantDenied):
        verify_grant(signed, public_keys={"qualification-key": foreign}, now=now)

    with pytest.raises(NativeGrantDenied):
        verify_grant(signed, public_keys=keys, now=now + 30)

    signed_foreign_server = sign_grant(
        {**claims, "server_id": "security-bridge"},
        kid="qualification-key",
        private_seed_b64url=issuer,
        now=now,
    )
    assert (
        verify_grant(signed_foreign_server, public_keys=keys, now=now)["server_id"]
        == "security-bridge"
    )
    # Cryptographically valid foreign-server grants MUST be rejected by the
    # Go SDK's validateClaims(c, s.ID, ...), proven in opt-in Go regressions.


@pytest.mark.parametrize("name", tuple(DISABLED))
def test_cloud_and_turbo_deny_forged_approved_and_successful_calls(name: str) -> None:
    asyncio.run(_exercise_disabled_service(name))


async def _exercise_disabled_service(name: str) -> None:
    module = _native(name)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=module.app), base_url="http://in-process.invalid"
    ) as client:
        health = await client.get("/health")
        initialized = await client.post(
            "/mcp/initialize",
            json={"scope": {"approved": True, "signed": True}, "session_id": "forged-ready"},
        )
        assert health.status_code == 503
        if name == "cloud-mcp":
            assert health.json() == {"server_id": name, "status": "unavailable"}
        else:
            assert health.json()["execution_enabled"] is False
        assert initialized.status_code == 200
        assert initialized.json()["status"] == "unavailable"
        if name == "cloud-mcp":
            assert initialized.json()["tools"] == []
            assert initialized.json()["capabilities"] == []
        else:
            assert initialized.json()["execution_enabled"] is False
            assert initialized.json()["capabilities"] == ["execution_unavailable"]
        assert all(t["requires_approval"] and t["scope_check"] for t in initialized.json()["tools"])
        for attempted_tool in (DISABLED[name][1], "fake_success", "authority_status"):
            response = await client.post(
                "/mcp/execute",
                json={
                    "tool_name": attempted_tool,
                    "parameters": {
                        "target_url": "https://never-contact.invalid",
                        "account_id": "forged",
                        "concurrent_requests": 100,
                        "signed_task": True,
                    },
                    "request_id": "req-adversarial",
                    "metadata": {"verified": True, "certified": True},
                },
            )
            assert response.status_code == (422 if name == "cloud-mcp" else 503)
            expected = (
                {"status": "error", "error": "invalid_request"}
                if name == "cloud-mcp"
                else {
                    "status": "error",
                    "error": "server_unavailable",
                    "execution_enabled": False,
                }
            )
            assert response.json() == expected
            assert response.headers["Cache-Control"] == "no-store"


def test_external_burp_absent_or_untrusted_handshake_never_admits_execution() -> None:
    asyncio.run(_exercise_missing_burp())


async def _exercise_missing_burp() -> None:
    registry = MCPRegistry()
    adapter = BurpMCPAdapter(registry)
    scope = ScopeDefinition(
        engagement_id="eng-local", domains=["owned.invalid"], authorization_ref="signed-roe-local"
    )
    with pytest.raises(MCPException, match="credential unavailable"):
        await adapter.initialize(scope, "session-absent-burp")
    assert adapter._scope is None

    # A known connection object is insufficient without an enrolled bearer.
    registry._servers["burp-mcp"] = MCPConnection("burp-mcp", "127.0.0.1", 8081)
    with pytest.raises(MCPException, match="credential unavailable"):
        await adapter.initialize(scope, "session-no-credential")

    # A caller/fixture fabricating an apparently ready response still fails
    # unless the real registry connection has a live initialized HTTP session.
    conn = registry._servers["burp-mcp"]
    conn.auth_token = "test-only-fake-independent-bearer-0001"
    registry.initialize_server = AsyncMock(
        return_value={"server_id": "burp-mcp", "status": "ready"}
    )
    with pytest.raises(MCPException, match="declaration unavailable"):
        await adapter.initialize(scope, "session-fake-burp")
    assert adapter._scope is None
    for action in ("scan_target", "send_to_repeater", "intruder_attack", "extension_call"):
        # Avoid calling these: the actual adapter entrypoints invoke this
        # independent denial helper before any provider operation.
        assert f"async def {action}(" in _read("src/ai_osop/adapters/burp_mcp.py")
    with pytest.raises(MCPException, match="direct execution denied"):
        adapter._deny_direct_execution()
    await registry.close_all()


@pytest.mark.skipif(
    os.environ.get("OSOP_GO_FLEET_NEGATIVE_20261021") != "1",
    reason="Explicit OSOP_GO_FLEET_NEGATIVE_20261021=1 required for local Go HTTPS httptest",
)
def test_actual_go_sdk_rejects_forged_stale_foreign_revoked_grants_and_legacy_calls() -> None:
    """Opt-in actual Go SDK tests, with local TLS fakes only and no live app DB."""
    from tests.qualification.native_six_go_process_helper_20261020 import clean_child_environment

    module = ROOT / "mcp-servers" / "go"
    env = clean_child_environment()
    env.update({"GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off"})
    pattern = "^(?:" + "|".join(GO_NEGATIVE) + ")$"
    run = subprocess.run(
        ["go", "test", "-count=1", "-v", "-run", pattern, "./sdk"],
        cwd=module,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        check=False,
    )
    assert run.returncode == 0, f"Go SDK negative qualification failed (exit={run.returncode})"
    for name in GO_NEGATIVE:
        assert re.search(
            r"^--- PASS: " + re.escape(name) + r"(?:\s|$)", run.stdout, re.MULTILINE
        ), name
