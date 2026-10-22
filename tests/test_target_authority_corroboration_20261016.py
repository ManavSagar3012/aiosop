"""Independent ownership and access audit records never directly promote findings."""

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core import target_authority_corroboration as audit


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _public(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _signature(key, data):
    return base64.urlsafe_b64encode(key.sign(audit._DOMAIN + data)).decode().rstrip("=")


def _case(monkeypatch):
    ownership_key, access_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    monkeypatch.setattr(audit, "_keys", lambda: {})
    config = {
        "version": 1,
        "engagement_id": "eng-example",
        "flow_id": "flow-example",
        "origin": "https://app.example.test",
        "keys": {"ownership": _public(ownership_key), "access": _public(access_key)},
    }
    monkeypatch.setenv("OSOP_TARGET_AUDIT_KEYS_JSON", _encode(config).decode())
    now = int(time.time())
    common = {
        "schema": "ai-osop.target-owned-authority.v1",
        "engagement_id": "eng-example",
        "flow_id": "flow-example",
        "authorization_id": "auth-1",
        "authorization_version": 1,
        "authorization_sha256": "1" * 64,
        "flow_revision": 2,
        "original_source_task_id": "task-original",
        "source_task_id": "task-source",
        "target_task_id": "task-target",
        "source_identity": "alice",
        "target_identity": "bob",
        "endpoint_url": "https://app.example.test/owned/item-1",
        "method": "GET",
        "source_request_sha256": "2" * 64,
        "target_request_sha256": "3" * 64,
        "source_session_sha256": "4" * 64,
        "target_session_sha256": "5" * 64,
        "source_response_sha256": "6" * 64,
        "target_response_sha256": "6" * 64,
        "resource_visibility": "private",
        "resource_owner_identity": "alice",
        "source_http_status": 200,
        "target_http_status": 200,
        "anonymous_http_status": 403,
        "target_access_forbidden": True,
    }

    def record(role, nonce):
        return {
            **common,
            "schema": "ai-osop.target-independent-audit.v1",
            "role": role,
            "resource_id": "item-1",
            "source_access_allowed": True,
            "target_proof_sha256": "a" * 64,
            "nonce": nonce,
            "issued_at": now,
            "expires_at": now + 60,
        }

    own, access = record("ownership", "o" * 32), record("access", "a" * 32)
    return common, own, access, ownership_key, access_key


def _verify(common, own, access, owner_key, access_key):
    own_blob, access_blob = _encode(own), _encode(access)
    return audit.corroborate_target_audits(
        target_claims_json=_encode(common),
        target_proof_sha256="a" * 64,
        ownership_json=own_blob,
        ownership_signature=_signature(owner_key, own_blob),
        access_json=access_blob,
        access_signature=_signature(access_key, access_blob),
    )


def test_independently_signed_matching_records_remain_candidate(monkeypatch):
    common, own, access, k1, k2 = _case(monkeypatch)
    result = _verify(common, own, access, k1, k2)
    assert result.source_records_correlated is True
    assert result.target_audit_signatures_verified is True
    assert result.finding_verified is False
    assert result.report_release_approved is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource_id", "other-object"),
        ("source_identity", "mallory"),
        ("target_identity", "alice"),
        ("resource_visibility", "public"),
        ("anonymous_http_status", 200),
        ("target_access_forbidden", False),
        ("source_session_sha256", "9" * 64),
        ("flow_revision", 3),
        ("source_http_status", 401),
        ("target_http_status", 302),
        ("source_access_allowed", False),
        ("expires_at", 0),
    ],
)
def test_changed_or_denied_target_audit_fails_closed(monkeypatch, field, value):
    common, own, access, k1, k2 = _case(monkeypatch)
    access[field] = value
    with pytest.raises(audit.TargetAuditUnverified):
        _verify(common, own, access, k1, k2)


def test_missing_independent_audit_signature_fails_closed(monkeypatch):
    common, own, access, k1, k2 = _case(monkeypatch)
    blob = _encode(access)
    with pytest.raises(audit.TargetAuditUnverified):
        audit.corroborate_target_audits(
            target_claims_json=_encode(common),
            target_proof_sha256="a" * 64,
            ownership_json=_encode(own),
            ownership_signature=_signature(k1, _encode(own)),
            access_json=blob,
            access_signature=_signature(k1, blob),
        )


def test_identical_signing_keys_not_independent(monkeypatch):
    common, own, access, k1, k2 = _case(monkeypatch)
    config = json.loads(__import__("os").environ["OSOP_TARGET_AUDIT_KEYS_JSON"])
    config["keys"]["access"] = config["keys"]["ownership"]
    monkeypatch.setenv("OSOP_TARGET_AUDIT_KEYS_JSON", _encode(config).decode())
    with pytest.raises(audit.TargetAuditUnverified):
        _verify(common, own, access, k1, k2)


def test_two_trusted_signers_cannot_correlate_unrelated_resource(monkeypatch):
    common, own, access, k1, k2 = _case(monkeypatch)
    own["resource_id"] = "other-object"
    access["resource_id"] = "other-object"
    with pytest.raises(audit.TargetAuditUnverified, match="not correlated"):
        _verify(common, own, access, k1, k2)
