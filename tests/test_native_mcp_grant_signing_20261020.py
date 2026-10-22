"""Independent signature validity is necessary, but never sufficient for execution."""

import base64
import copy
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.native_mcp_grant_signing import (
    NativeGrantDenied,
    canonical_claims,
    claim_sha256,
    header_value,
    sign_grant,
    verify_grant,
)


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@pytest.fixture
def authority():
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return b64(private_bytes), {"separately-operated-test-key": b64(public_bytes)}


def claims(now=None):
    now = int(time.time()) if now is None else now
    return {
        "version": 1,
        "grant_id": "ngr-" + "1" * 32,
        "request_id": "req-" + "2" * 32,
        "engagement_id": "eng-native-lab",
        "flow_id": "flow-native-lab",
        "task_id": "task-native-lab",
        "subtask_id": "subtask-native-lab",
        "action_id": "action-" + "3" * 32,
        "server_id": "recon-mcp",
        "tool_name": "authority_status",
        "parameters_sha256": "4" * 64,
        "manifest_sha256": "5" * 64,
        "authorization_version": 4,
        "authorization_sha256": "6" * 64,
        "lease_id": "lease-native-lab",
        "resource_sha256": None,
        "issued_at": now - 1,
        "expires_at": now + 30,
        "side_effect_class": "READ_ONLY",
    }


def test_real_ed25519_signer_and_go_compatible_ascii_canonicalization(authority):
    private, public = authority
    value = claims()
    encoded = canonical_claims(value)
    assert encoded == json.dumps(
        value, separators=(",", ":"), sort_keys=True, ensure_ascii=True
    ).encode("ascii")
    signed = sign_grant(value, kid="separately-operated-test-key", private_seed_b64url=private)
    assert verify_grant(signed, public_keys=public) == value
    digest = hashlib.sha256(encoded).hexdigest()
    assert claim_sha256(value) == digest
    header = header_value(signed)
    assert "=" not in header
    assert json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))) == signed
    assert "private" not in repr(signed)


@pytest.mark.parametrize(
    "tamper",
    [
        "foreign_tenant",
        "foreign_server",
        "wrong_tool",
        "different_request",
        "changed_digest",
        "different_flow",
        "new_field",
        "removed_field",
        "bool_version",
        "expired",
        "future",
        "overlong",
        "active_side_effect",
        "unbound_resource",
        "invalid_signature",
    ],
)
def test_forged_stale_or_cross_scope_grants_are_rejected(authority, tamper):
    private, public = authority
    original = claims()
    signed = sign_grant(original, kid="separately-operated-test-key", private_seed_b64url=private)
    forged = copy.deepcopy(signed)
    c = forged["claims"]
    if tamper == "foreign_tenant":
        c["engagement_id"] = "eng-another-owner"
    elif tamper == "foreign_server":
        c["server_id"] = "security-bridge"
    elif tamper == "wrong_tool":
        c["tool_name"] = "scan"
    elif tamper == "different_request":
        c["request_id"] = "req-" + "b" * 32
    elif tamper == "changed_digest":
        c["parameters_sha256"] = "b" * 64
    elif tamper == "different_flow":
        c["flow_id"] = "flow-another-owner"
    elif tamper == "new_field":
        c["is_admin"] = True
    elif tamper == "removed_field":
        c.pop("lease_id")
    elif tamper == "bool_version":
        c["version"] = True
    elif tamper == "expired":
        c["expires_at"] = c["issued_at"]
    elif tamper == "future":
        c["issued_at"] += 999
        c["expires_at"] += 999
    elif tamper == "overlong":
        c["lease_id"] = "lease-" + "x" * 10000
    elif tamper == "active_side_effect":
        c["side_effect_class"] = "INVASIVE_EXPLOIT"
    elif tamper == "unbound_resource":
        c["resource_sha256"] = "not-a-sha"
    else:
        forged["signature"] = b64(b"B" * 64)
    with pytest.raises(NativeGrantDenied):
        verify_grant(forged, public_keys=public)


def test_unknown_signer_and_overlong_lifetime_rejected(authority):
    private, public = authority
    c = claims()
    signed = sign_grant(c, kid="separately-operated-test-key", private_seed_b64url=private)
    with pytest.raises(NativeGrantDenied):
        verify_grant(signed, public_keys={"other-trusted-key": next(iter(public.values()))})
    c["expires_at"] = c["issued_at"] + 70
    with pytest.raises(NativeGrantDenied):
        sign_grant(c, kid="separately-operated-test-key", private_seed_b64url=private)


def test_public_signature_cannot_become_untrusted_self_issued_approval(authority):
    private, public = authority
    signed = sign_grant(claims(), kid="separately-operated-test-key", private_seed_b64url=private)
    rogue = Ed25519PrivateKey.generate()
    rogue_pub = rogue.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert public["separately-operated-test-key"] != b64(rogue_pub)
    forged = copy.deepcopy(signed)
    forged["signature"] = b64(
        rogue.sign(b"ai-osop/native-grant/v1\x00" + canonical_claims(forged["claims"]))
    )
    with pytest.raises(NativeGrantDenied):
        verify_grant(forged, public_keys=public)
