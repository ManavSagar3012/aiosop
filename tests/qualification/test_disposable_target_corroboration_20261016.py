"""Controlled real ASGI requests plus three independently keyed target receipts.

This is a disposable in-process target, NOT a certification for any deployed
external target. No application DB, paid provider, external network or exploit.
"""

import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core import target_authority_corroboration as audit
from ai_osop.core.target_authority_proof import (
    TargetAuthorityDenied,
    verify_target_authority_proof,
)
from tests.qualification.test_disposable_target_owner_oracle_20261016 import (
    _controlled_target,
    _response_digest,
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _public(key):
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bug,public,expected",
    [(True, False, True), (False, False, False), (True, True, False)],
)
async def test_actual_lab_target_request_correlated_with_separate_audit_keys(
    proof_case, monkeypatch, bug, public, expected
):
    app = _controlled_target(bug=bug, publicly_readable=public)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://local-fixture.invalid"
    ) as client:
        source = await client.get(
            "/api/record/123", headers={"Authorization": "Bearer source-test-session"}
        )
        target = await client.get(
            "/api/record/123", headers={"Authorization": "Bearer target-test-session"}
        )
        anonymous = await client.get("/api/record/123")

    assert source.status_code == 200
    case = proof_case
    source_sha = _response_digest(engagement=case.source.engagement_id, response_body=source.json())
    target_sha = (
        _response_digest(engagement=case.target.engagement_id, response_body=target.json())
        if target.status_code == 200
        else "0" * 64
    )
    case.source.result["response_body_sha256"] = source_sha
    case.target.result["response_body_sha256"] = target_sha
    case.target.result["http_status_code"] = target.status_code
    claims = dict(case.claims)
    claims.update(
        {
            "source_response_sha256": source_sha,
            "target_response_sha256": target_sha,
            "target_http_status": target.status_code,
            "anonymous_http_status": anonymous.status_code,
            "resource_visibility": "public" if public else "private",
            "public_access": public,
            "cross_identity_disclosure_confirmed": expected,
            "resource_owner_identity": source.json()["owner"],
        }
    )
    proof_blob, target_signature = case.signed_bytes(claims)
    if not expected:
        with pytest.raises(TargetAuthorityDenied):
            await verify_target_authority_proof(
                claims_json=proof_blob, signature_b64url=target_signature, **case.context
            )
        return

    result = await verify_target_authority_proof(
        claims_json=proof_blob, signature_b64url=target_signature, **case.context
    )
    ownership_key = Ed25519PrivateKey.generate()
    access_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "OSOP_TARGET_AUDIT_KEYS_JSON",
        _canonical(
            {
                "version": 1,
                "engagement_id": case.flow.engagement_id,
                "flow_id": case.flow.id,
                "origin": case.key_row["origin"],
                "keys": {"ownership": _public(ownership_key), "access": _public(access_key)},
            }
        ).decode(),
    )
    now = int(time.time())

    def signed_audit(role, key, nonce):
        signed = {field: claims[field] for field in audit._MATCHED_FIELDS}
        signed.update(
            {
                "schema": "ai-osop.target-independent-audit.v1",
                "role": role,
                "resource_id": "123",
                "source_access_allowed": source.status_code == 200,
                "target_proof_sha256": result.proof_sha256,
                "nonce": nonce,
                "issued_at": now,
                "expires_at": now + 50,
            }
        )
        blob = _canonical(signed)
        signature = base64.urlsafe_b64encode(key.sign(audit._DOMAIN + blob)).decode().rstrip("=")
        return blob, signature

    owner_blob, owner_sig = signed_audit("ownership", ownership_key, "o" * 32)
    access_blob, access_sig = signed_audit("access", access_key, "a" * 32)
    corroborated = audit.corroborate_target_audits(
        target_claims_json=proof_blob,
        target_proof_sha256=result.proof_sha256,
        ownership_json=owner_blob,
        ownership_signature=owner_sig,
        access_json=access_blob,
        access_signature=access_sig,
    )
    assert corroborated.target_audit_signatures_verified is True
    assert corroborated.source_records_correlated is True
    assert corroborated.finding_verified is False
    assert corroborated.report_release_approved is False

    # Genuine independently signed but wrong resource cannot be correlated.
    altered = json.loads(access_blob)
    altered["resource_id"] = "other-object"
    corrupted_blob = _canonical(altered)
    corrupted_signature = (
        base64.urlsafe_b64encode(access_key.sign(audit._DOMAIN + corrupted_blob))
        .decode()
        .rstrip("=")
    )
    with pytest.raises(audit.TargetAuditUnverified):
        audit.corroborate_target_audits(
            target_claims_json=proof_blob,
            target_proof_sha256=result.proof_sha256,
            ownership_json=owner_blob,
            ownership_signature=owner_sig,
            access_json=corrupted_blob,
            access_signature=corrupted_signature,
        )
