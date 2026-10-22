"""Central private issuer must accept only IDs the public redeemer accepts."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.native_mcp_grant_signing import _KID as PUBLIC_KID
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    _signers,
)


@pytest.mark.parametrize(
    "kid,valid",
    [
        ("native-issuer", True),
        ("I_1", True),
        ("x", False),
        ("ab", False),
        ("1issuer", False),
        ("issuer.bad", False),
        ("I" * 49, False),
    ],
)
def test_0029_private_issuer_matches_public_grant_key_contract(
    monkeypatch: pytest.MonkeyPatch, kid: str, valid: bool
) -> None:
    signer = Ed25519PrivateKey.generate()
    seed = signer.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    encoded = base64.b64encode(seed).decode("ascii")
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_ACTIVE_KID", kid)
    monkeypatch.setenv("OSOP_NATIVE_MCP_GRANT_SIGNING_KEYS_JSON", json.dumps({kid: encoded}))
    assert (PUBLIC_KID.fullmatch(kid) is not None) is valid
    if valid:
        active, keys = _signers()
        assert active == kid
        assert set(keys) == {kid}
    else:
        # This must fail BEFORE durable grant issuance, rather than creating
        # an unusable 0029 row which the public redemption route rejects.
        with pytest.raises(NativeMCPGrantDenied):
            _signers()
