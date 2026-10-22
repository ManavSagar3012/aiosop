"""Mounted native redemption never accepts browser claims or unsigned promises."""

import copy
import base64
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.api.routers import native_mcp_redemption as api
from ai_osop.core.native_mcp_grant_signing import claim_sha256, sign_grant

EID = "eng-native-redemption"


def fake_grant():
    now = int(time.time())
    return {
        "claims": {
            "version": 1,
            "grant_id": "ngr-" + "1" * 32,
            "request_id": "req-" + "2" * 32,
            "engagement_id": EID,
            "flow_id": "flow-native-redemption",
            "task_id": "task-native-redemption",
            "subtask_id": "subtask-native-redemption",
            "action_id": "action-" + "3" * 32,
            "server_id": "recon-mcp",
            "tool_name": "authority_status",
            "parameters_sha256": "4" * 64,
            "manifest_sha256": "5" * 64,
            "authorization_version": 3,
            "authorization_sha256": "6" * 64,
            "lease_id": "lease-native-redemption",
            "resource_sha256": None,
            "issued_at": now - 1,
            "expires_at": now + 30,
            "side_effect_class": "READ_ONLY",
        },
        "kid": "independent-native-issuer",
        "signature": "S" * 86,
    }


@pytest.mark.asyncio
async def test_real_mounted_fastapi_native_route_requires_separate_service_principal(monkeypatch):
    from ai_osop.api.main import app

    routes = [r for r in app.routes if r.path == "/native-mcp/grants/redeem"]
    assert len(routes) == 1 and routes[0].methods == {"POST"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        anonymous = await client.post("/native-mcp/grants/redeem", json=fake_grant())
        assert anonymous.status_code == 401
        wrong = await client.post(
            "/native-mcp/grants/redeem",
            json=fake_grant(),
            headers={"Authorization": "Bearer " + "x" * 48},
        )
        assert wrong.status_code == 401
    assert "S" * 30 not in anonymous.text + wrong.text


@pytest.mark.asyncio
async def test_real_http_strict_duplicates_and_ambiguous_grants_precede_store(monkeypatch):
    from ai_osop.api.main import app

    forbidden = json.dumps(fake_grant()).replace('"kid":', '"kid":"duplicate", "kid":', 1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/native-mcp/grants/redeem",
            content=forbidden,
            headers={
                "Authorization": "Bearer " + "t" * 48,
                "X-OSOP-Native-Server-ID": "recon-mcp",
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 422
    assert "native" in response.text.lower()


@pytest.mark.asyncio
async def test_actual_ed25519_mounted_http_and_atomic_redeemer_without_application_database(
    monkeypatch,
):
    """Real HTTP + crypto; isolated in-memory redemption stub is NOT real PG."""
    import ai_osop.memory.flow_mcp_action_dispatch as action_mod
    import ai_osop.memory.native_mcp_execution_grants as store_mod
    from ai_osop.api.main import app

    signer = Ed25519PrivateKey.generate()
    private_seed = signer.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_key = signer.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    claims = fake_grant()["claims"]
    kid = "independent-native-issuer"
    grant = sign_grant(claims, kid=kid, private_seed_b64url=b64(private_seed))
    service_secret = "signed-independent-native-service-only-48chars"
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON", json.dumps({kid: b64(public_key)})
    )
    monkeypatch.setenv(
        "OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON",
        json.dumps({"recon-mcp": service_secret}),
    )
    monkeypatch.setitem(
        api.state, "orchestrator", SimpleNamespace(session_memory=object(), mcp_registry=object())
    )
    monkeypatch.setattr(action_mod, "FlowMCPActionStore", lambda memory, registry: object())
    redeemed = set()

    class StubRedeemer:
        def __init__(self, action_store):
            pass

        async def redeem(self, signed, *, server_id, server_secret):
            assert server_id == "recon-mcp"
            assert server_secret == service_secret
            identity = signed["claims"]["grant_id"]
            if identity in redeemed:
                raise ValueError("grant consumed")
            redeemed.add(identity)
            return {
                "grant_id": identity,
                "request_id": signed["claims"]["request_id"],
                "claim_sha256": claim_sha256(signed["claims"]),
                "durably_redeemed": True,
            }

    monkeypatch.setattr(store_mod, "NativeMCPExecutionGrantStore", StubRedeemer)
    headers = {
        "Authorization": "Bearer " + service_secret,
        "X-OSOP-Native-Server-ID": "recon-mcp",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.post("/native-grants/redeem", json=grant, headers=headers)
        assert first.status_code == 200
        assert first.json() == {
            "grant_id": claims["grant_id"],
            "request_id": claims["request_id"],
            "claim_sha256": claim_sha256(claims),
            "durably_redeemed": True,
        }
        assert first.headers["cache-control"] == "private, no-store"
        second = await client.post("/native-grants/redeem", json=grant, headers=headers)
        assert second.status_code == 409
        forged = copy.deepcopy(grant)
        forged["claims"]["engagement_id"] = "eng-foreign-owner"
        bad = await client.post("/native-grants/redeem", json=forged, headers=headers)
        assert bad.status_code == 409
        assert len(redeemed) == 1
    assert "signed-independent-native-service-only" not in first.text + second.text + bad.text


@pytest.mark.asyncio
async def test_authorized_service_must_also_verify_signed_claims_and_committed_pg(monkeypatch):
    import ai_osop.memory.native_mcp_execution_grants as store_mod
    import ai_osop.memory.flow_mcp_action_dispatch as action_mod

    signed = fake_grant()
    seen = []
    original = copy.deepcopy(signed)

    class FakeStore:
        def __init__(self, actions):
            assert isinstance(actions, FakeActionStore)

        async def redeem(self, token, *, server_id, server_secret):
            assert server_id == "recon-mcp" and server_secret == "test-native-service-key"
            seen.append(token)
            return {
                "grant_id": token["claims"]["grant_id"],
                "request_id": token["claims"]["request_id"],
                "claim_sha256": claim_sha256(token["claims"]),
                "durably_redeemed": True,
            }

    class FakeActionStore:
        def __init__(self, memory, registry):
            assert memory is backend.session_memory
            assert registry is backend.mcp_registry

    backend = SimpleNamespace(session_memory=object(), mcp_registry=object())
    monkeypatch.setitem(api.state, "orchestrator", backend)
    monkeypatch.setattr(action_mod, "FlowMCPActionStore", FakeActionStore)
    monkeypatch.setattr(store_mod, "NativeMCPExecutionGrantStore", FakeStore)
    monkeypatch.setattr(api, "_trust_roots", lambda: {signed["kid"]: "public_key_stub"})
    monkeypatch.setattr(api, "verify_grant", lambda document, public_keys: document["claims"])
    accepted = await api._redeem_trusted(
        signed, server_id="recon-mcp", server_secret="test-native-service-key"
    )
    assert accepted == {
        "grant_id": original["claims"]["grant_id"],
        "request_id": original["claims"]["request_id"],
        "claim_sha256": claim_sha256(original["claims"]),
        "durably_redeemed": True,
    }
    assert len(seen) == 1 and seen[0] == signed
    assert "authorization_sha256" in seen[0]["claims"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["reject", "unknown", "wrong_action", "wrong_digest", "crash"])
async def test_store_rejection_or_ambiguous_db_ack_never_reports_admission(monkeypatch, mode):
    import ai_osop.memory.native_mcp_execution_grants as store_mod
    import ai_osop.memory.flow_mcp_action_dispatch as action_mod

    signed = fake_grant()
    monkeypatch.setattr(api, "_trust_roots", lambda: {signed["kid"]: "irrelevant"})
    monkeypatch.setattr(api, "verify_grant", lambda document, public_keys: document["claims"])
    monkeypatch.setitem(
        api.state, "orchestrator", SimpleNamespace(session_memory=object(), mcp_registry=object())
    )

    monkeypatch.setattr(action_mod, "FlowMCPActionStore", lambda memory, registry: object())

    class Store:
        def __init__(self, actions):
            pass

        async def redeem(self, token, *, server_id, server_secret):
            claims = token["claims"]
            if mode == "crash":
                raise ConnectionError("private-redemption-connection")
            if mode == "reject":
                return {"status": "denied"}
            if mode == "wrong_action":
                return {
                    "grant_id": "ngr-" + "f" * 32,
                    "request_id": claims["request_id"],
                    "claim_sha256": claim_sha256(claims),
                    "durably_redeemed": True,
                }
            if mode == "wrong_digest":
                return {
                    "grant_id": claims["grant_id"],
                    "request_id": claims["request_id"],
                    "claim_sha256": "0" * 64,
                    "durably_redeemed": True,
                }
            return None

    monkeypatch.setattr(store_mod, "NativeMCPExecutionGrantStore", Store)
    with pytest.raises(Exception) as raised:
        await api._redeem_trusted(
            signed, server_id="recon-mcp", server_secret="test-native-service-key"
        )
    assert getattr(raised.value, "status_code", 0) == 409
    assert "private" not in str(raised.value)
