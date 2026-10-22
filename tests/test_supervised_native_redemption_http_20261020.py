"""Mounted transport contract for separate 0033 supervisor proof forwarding.

Source trust is independently exercised by test_supervisor_bound_native_grants;
this isolated ASGI test checks HTTP boundaries and forwarding only, not PG.
"""

import base64
import json
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.api.routers import native_mcp_redemption as api
from ai_osop.core.native_mcp_grant_signing import claim_sha256, sign_grant
from tests.test_native_mcp_redemption_api_20261020 import fake_grant


@pytest.mark.asyncio
async def test_mounted_supervised_envelope_forwarding_without_weakening_legacy(monkeypatch):
    from ai_osop.api.main import app
    import ai_osop.memory.flow_mcp_action_dispatch as action_mod
    import ai_osop.memory.native_mcp_execution_grants as store_mod

    signer = Ed25519PrivateKey.generate()
    secret = "test-only-independent-native-service-secret"
    seed = signer.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub = signer.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    b64 = lambda value: base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    kid = "independent-native-issuer"
    token = sign_grant(fake_grant()["claims"], kid=kid, private_seed_b64url=b64(seed))
    monkeypatch.setenv("OSOP_NATIVE_MCP_ISSUER_PUBLIC_KEYS_JSON", json.dumps({kid: b64(pub)}))
    monkeypatch.setenv("OSOP_NATIVE_MCP_REDEMPTION_SECRETS_JSON", json.dumps({"recon-mcp": secret}))
    monkeypatch.setitem(
        api.state, "orchestrator", SimpleNamespace(session_memory=object(), mcp_registry=object())
    )
    monkeypatch.setattr(action_mod, "FlowMCPActionStore", lambda *_: object())
    seen = []

    class Stub:
        def __init__(self, _store):
            pass

        async def redeem(self, grant, *, server_id, server_secret, worker_proof=None):
            assert server_id == "recon-mcp" and server_secret == secret
            seen.append(worker_proof)
            return {
                "grant_id": grant["claims"]["grant_id"],
                "request_id": grant["claims"]["request_id"],
                "claim_sha256": claim_sha256(grant["claims"]),
                "durably_redeemed": True,
            }

    monkeypatch.setattr(store_mod, "NativeMCPExecutionGrantStore", Stub)
    headers = {"X-OSOP-Native-Server-ID": "recon-mcp", "Authorization": "Bearer " + secret}
    proof = {
        "claims": {"nonce": "test-forwarding-only"},
        "kid": "supervisor-test",
        "signature": "invalid-test",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://localhost"
    ) as client:
        old = await client.post("/native-grants/redeem", json=token, headers=headers)
        assert old.status_code == 200
        new = await client.post(
            "/native-grants/redeem", json={"grant": token, "worker_proof": proof}, headers=headers
        )
        assert new.status_code == 200
        assert seen == [None, proof]
        assert new.headers["cache-control"] == "private, no-store"
        for malformed in (
            {"grant": token, "worker_proof": "forged"},
            {"grant": token, "worker_proof": {}},
            {"grant": token, "worker_proof": proof, "extra": "yes"},
        ):
            denied = await client.post("/native-grants/redeem", json=malformed, headers=headers)
            assert denied.status_code == 422
        unsigned = await client.post(
            "/native-grants/redeem", json={"grant": token, "worker_proof": proof}
        )
        assert unsigned.status_code == 401
    assert seen == [None, proof]
