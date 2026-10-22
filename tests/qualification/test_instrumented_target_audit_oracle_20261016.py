"""Real in-process target HTTP qualification for the cooperating audit oracle.

No application database, external network, provider, report release or targets
outside the target-owned disposable ASGI app. Both signer keys are independent
from the separate target authority key. Production PG authorization and durable
nonce admission are not simulated as production evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from typing import Any, Dict, Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Request
from fastapi.responses import RedirectResponse

from ai_osop.core import target_authority_corroboration as audit
from ai_osop.core import target_authority_proof as authority
from ai_osop.core.controlled_target_audit_oracle import (
    ControlledOracleDenied,
    ControlledTargetAuditOracle,
    OwnerRecord,
    TargetAuditBinding,
    TargetSession,
)
from tests.qualification.test_disposable_target_owner_oracle_20261016 import (
    _controlled_target,
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401

_TOKENS = {
    b"Bearer source-test-session": "a",
    b"Bearer target-test-session": "b",
}


def _configure(case: Any, monkeypatch: Any, *, bug: bool = True, public: bool = False):
    app = _controlled_target(bug=bug, publicly_readable=public)
    ownership = {"123": OwnerRecord("123", "account_a", "private", 1)}
    store: Dict[str, TargetSession] = {
        "a": TargetSession("account_a", "a", b"validated-generation-source"),
        "b": TargetSession("account_b", "b", b"validated-generation-target"),
    }

    def from_scope(scope: Dict[str, Any]) -> Optional[TargetSession]:
        raw = [value for key, value in scope.get("headers", []) if key.lower() == b"authorization"]
        return store.get(_TOKENS.get(raw[0], "")) if len(raw) == 1 else None

    def current(handle: str) -> Optional[TargetSession]:
        return store.get(handle)

    def owner(resource_id: str) -> Optional[OwnerRecord]:
        return ownership.get(resource_id)

    keys = {
        "ownership": Ed25519PrivateKey.from_private_bytes(bytes(range(65, 97))),
        "access": Ed25519PrivateKey.from_private_bytes(bytes(range(97, 129))),
    }
    binding = TargetAuditBinding(
        engagement_id=case.flow.engagement_id,
        flow_id=case.flow.id,
        flow_revision=case.flow.revision,
        authorization_id=case.signed.authorization_id,
        authorization_version=case.signed.version,
        authorization_sha256=case.signed.policy_sha256,
        original_source_task_id=case.original.id,
        source_task_id=case.source.id,
        target_task_id=case.target.id,
        source_identity=case.source.payload["user_label"],
        target_identity=case.target.payload["user_label"],
        endpoint_url=case.key_row["origin"] + "/api/record/123",
        resource_id="123",
        workflow_id="wf-tenant",
        step_id="step-resource",
    )
    wrapped = ControlledTargetAuditOracle(
        app,
        binding=binding,
        session_for_scope=from_scope,
        current_session=current,
        owner_of_record=owner,
        target_proof_public_key=case.signer.public_key(),
        ownership_signer=keys["ownership"],
        access_signer=keys["access"],
    )
    public_keys = {
        role: base64.b64encode(
            key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).decode()
        for role, key in keys.items()
    }
    monkeypatch.setenv(
        "OSOP_TARGET_AUDIT_KEYS_JSON",
        json.dumps(
            {
                "version": 1,
                "engagement_id": case.flow.engagement_id,
                "flow_id": case.flow.id,
                "origin": case.key_row["origin"],
                "keys": public_keys,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    return wrapped, app, store, ownership, keys, binding


async def _http(oracle: ControlledTargetAuditOracle, origin: str) -> Dict[str, httpx.Response]:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oracle),
        base_url=origin,
        follow_redirects=False,
    ) as client:
        return {
            "source": await client.get(
                "/api/record/123", headers={"Authorization": "Bearer source-test-session"}
            ),
            "target": await client.get(
                "/api/record/123", headers={"Authorization": "Bearer target-test-session"}
            ),
            "anonymous": await client.get("/api/record/123"),
        }


def _signed_proof(case: Any, oracle: ControlledTargetAuditOracle) -> tuple[bytes, str, str]:
    source, target, anon = (oracle.observations[role] for role in ("source", "target", "anonymous"))
    for task, row in ((case.source, source), (case.target, target)):
        task.payload["_authority_request_sha256"] = row.request_sha256
        task.payload["_authority_session_sha256"] = row.session_sha256
        task.result["http_status_code"] = row.status
        task.result["response_body_sha256"] = row.response_sha256 or "0" * 64
    claims = dict(case.claims)
    if source.status == target.status == 200 and source.response_sha256 == target.response_sha256:
        claims.update(
            authority._task_lineage(
                source=case.source,
                target=case.target,
                original=case.original,
                flow=case.flow,
                signed=case.signed,
                engagement_id=case.flow.engagement_id,
            )
        )
    claims.update(
        {
            "source_request_sha256": source.request_sha256,
            "target_request_sha256": target.request_sha256,
            "source_session_sha256": source.session_sha256,
            "target_session_sha256": target.session_sha256,
            "source_response_sha256": source.response_sha256,
            "target_response_sha256": target.response_sha256,
            "source_http_status": source.status,
            "target_http_status": target.status,
            "anonymous_http_status": anon.status,
            "resource_owner_identity": source.owner_snapshot.owner_identity,
            "resource_visibility": source.owner_snapshot.visibility,
            "target_access_forbidden": True,
            "cross_identity_disclosure_confirmed": (
                source.status == target.status == 200 and anon.status in (401, 403, 404)
            ),
            "public_access": anon.status == 200,
        }
    )
    blob, signature = case.signed_bytes(claims)
    sig_bytes = base64.urlsafe_b64decode(signature + "==")
    digest = hashlib.sha256(authority._DOMAIN + blob + sig_bytes).hexdigest()
    return blob, signature, digest


@pytest.mark.asyncio
async def test_actual_target_observations_issue_canonical_three_key_candidate_receipts(
    proof_case: Any, monkeypatch: Any
) -> None:
    oracle, _app, store, ownership, keys, binding = _configure(proof_case, monkeypatch)
    replies = await _http(oracle, proof_case.key_row["origin"])
    assert [replies[role].status_code for role in ("source", "target", "anonymous")] == [
        200,
        200,
        403,
    ]
    assert ownership["123"].owner_identity == "account_a"
    assert oracle.observations["source"].identity == "account_a"
    assert oracle.observations["target"].identity == "account_b"
    assert oracle.observations["anonymous"].session_sha256 is None
    assert (
        oracle.observations["source"].session_sha256 != oracle.observations["target"].session_sha256
    )
    assert (
        oracle.observations["source"].request_sha256 != oracle.observations["target"].request_sha256
    )
    assert (
        oracle.observations["source"].response_sha256
        == oracle.observations["target"].response_sha256
    )

    blob, signature, digest = _signed_proof(proof_case, oracle)
    verified = await authority.verify_target_authority_proof(
        claims_json=blob, signature_b64url=signature, **proof_case.context
    )
    assert verified.proof_sha256 == digest
    assert verified.finding_verified is False
    assert verified.report_release_approved is False
    receipts = await oracle.attest(
        target_claims_json=blob,
        target_signature_b64url=signature,
        verified_target_proof_sha256=verified.proof_sha256,
    )
    assert receipts.validation_state == "candidate_only"
    assert receipts.finding_verified is False
    assert receipts.report_release_approved is False
    assert receipts.target_proof_sha256 == verified.proof_sha256
    for role, raw in (("ownership", receipts.ownership_json), ("access", receipts.access_json)):
        record = json.loads(raw)
        assert set(record) == audit._FIELDS
        assert record["role"] == role
        assert record["resource_id"] == "123"
        assert record["resource_owner_identity"] == "account_a"
        assert record["source_request_sha256"] == oracle.observations["source"].request_sha256
        assert record["target_request_sha256"] == oracle.observations["target"].request_sha256
        assert record["target_proof_sha256"] == digest
        assert raw == audit._canonical(record)
        assert b"source-test-session" not in raw
        assert b"controlled-object-123" not in raw
    assertion = audit.corroborate_target_audits(
        target_claims_json=blob,
        target_proof_sha256=verified.proof_sha256,
        ownership_json=receipts.ownership_json,
        ownership_signature=receipts.ownership_signature,
        access_json=receipts.access_json,
        access_signature=receipts.access_signature,
    )
    assert assertion.source_records_correlated is True
    assert assertion.target_audit_signatures_verified is True
    assert assertion.finding_verified is False
    assert assertion.report_release_approved is False
    assert len(assertion.audit_sha256) == 64
    assert all("secret_version" not in repr(row) for row in oracle.observations.values())
    assert len(store) == 2
    with pytest.raises(ControlledOracleDenied, match="Complete uncontaminated"):
        await oracle.attest(
            target_claims_json=blob,
            target_signature_b64url=signature,
            verified_target_proof_sha256=verified.proof_sha256,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["public", "denied", "redirect"])
async def test_observed_public_denied_or_redirected_target_cannot_sign(
    proof_case: Any, monkeypatch: Any, scenario: str
) -> None:
    oracle, app, _store, _ownership, _keys, _binding = _configure(
        proof_case, monkeypatch, bug=scenario != "denied", public=scenario == "public"
    )
    if scenario == "redirect":

        @app.middleware("http")
        async def redirect_target(request: Request, call_next: Any) -> Any:
            if request.headers.get("authorization") == "Bearer target-test-session":
                return RedirectResponse("/redirected", status_code=302)
            return await call_next(request)

    replies = await _http(oracle, proof_case.key_row["origin"])
    assert replies["target"].status_code == (
        403 if scenario == "denied" else 302 if scenario == "redirect" else 200
    )
    if scenario == "public":
        assert replies["anonymous"].status_code == 200
    with pytest.raises(ControlledOracleDenied):
        await oracle.attest(
            target_claims_json=b"{}",
            target_signature_b64url="invalid",
            verified_target_proof_sha256="0" * 64,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "rotated_source_session",
        "revoked_target_session",
        "owner_changed",
        "owner_became_public",
        "removed_owner",
        "tampered_proof_bytes",
        "tampered_proof_digest",
        "tampered_request_provenance",
        "untrusted_claim_owner",
        "replaced_target_public_key",
    ],
)
async def test_attestation_refuses_live_rotation_tamper_or_model_claims(
    proof_case: Any, monkeypatch: Any, scenario: str
) -> None:
    oracle, _app, store, ownership, _keys, binding = _configure(proof_case, monkeypatch)
    await _http(oracle, proof_case.key_row["origin"])
    blob, signature, digest = _signed_proof(proof_case, oracle)
    if scenario == "rotated_source_session":
        store["a"] = replace(store["a"], secret_version=b"generation-two")
    elif scenario == "revoked_target_session":
        del store["b"]
    elif scenario == "owner_changed":
        ownership["123"] = OwnerRecord("123", "account_b", "private", 2)
    elif scenario == "owner_became_public":
        ownership["123"] = OwnerRecord("123", "account_a", "public", 2)
    elif scenario == "removed_owner":
        del ownership["123"]
    elif scenario == "tampered_proof_bytes":
        blob = blob.replace(b'"method":"GET"', b'"method":"PUT"')
    elif scenario == "tampered_proof_digest":
        digest = "0" * 64
    elif scenario == "tampered_request_provenance":
        data = json.loads(blob)
        data["source_request_sha256"] = "b" * 64
        blob, signature = proof_case.signed_bytes(data)
        digest = hashlib.sha256(
            authority._DOMAIN + blob + base64.urlsafe_b64decode(signature + "==")
        ).hexdigest()
    elif scenario == "untrusted_claim_owner":
        data = json.loads(blob)
        data["resource_owner_identity"] = "account_b"
        blob, signature = proof_case.signed_bytes(data)
        digest = hashlib.sha256(
            authority._DOMAIN + blob + base64.urlsafe_b64decode(signature + "==")
        ).hexdigest()
    elif scenario == "replaced_target_public_key":
        oracle._target_proof_public_key = Ed25519PrivateKey.from_private_bytes(
            bytes(range(33, 65))
        ).public_key()
    with pytest.raises(ControlledOracleDenied):
        await oracle.attest(
            target_claims_json=blob,
            target_signature_b64url=signature,
            verified_target_proof_sha256=digest,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario", ["missing_target_session", "duplicate_source", "unrecognized_session"]
)
async def test_untrusted_or_duplicate_requests_poison_target_oracle(
    proof_case: Any, monkeypatch: Any, scenario: str
) -> None:
    oracle, _app, store, _ownership, _keys, _binding = _configure(proof_case, monkeypatch)
    if scenario == "missing_target_session":
        del store["b"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oracle), base_url=proof_case.key_row["origin"]
    ) as client:
        await client.get("/api/record/123", headers={"Authorization": "Bearer source-test-session"})
        if scenario == "duplicate_source":
            await client.get(
                "/api/record/123", headers={"Authorization": "Bearer source-test-session"}
            )
        elif scenario == "unrecognized_session":
            await client.get("/api/record/123", headers={"Authorization": "Bearer unknown"})
        else:
            await client.get(
                "/api/record/123", headers={"Authorization": "Bearer target-test-session"}
            )
        await client.get("/api/record/123")
    with pytest.raises(ControlledOracleDenied, match="Complete uncontaminated"):
        await oracle.attest(
            target_claims_json=b"{}",
            target_signature_b64url="invalid",
            verified_target_proof_sha256="0" * 64,
        )


@pytest.mark.parametrize("same_role", ["ownership", "access"])
def test_signers_cannot_reuse_target_authority_key(
    proof_case: Any, monkeypatch: Any, same_role: str
) -> None:
    oracle, app, store, ownership, keys, binding = _configure(proof_case, monkeypatch)
    with pytest.raises(ControlledOracleDenied, match="independent signing keys"):
        ControlledTargetAuditOracle(
            app,
            binding=binding,
            session_for_scope=lambda scope: None,
            current_session=lambda handle: None,
            owner_of_record=lambda resource_id: ownership.get(resource_id),
            target_proof_public_key=proof_case.signer.public_key(),
            ownership_signer=(proof_case.signer if same_role == "ownership" else keys["ownership"]),
            access_signer=(proof_case.signer if same_role == "access" else keys["access"]),
        )


@pytest.mark.asyncio
async def test_get_with_hidden_body_poisoned_even_when_target_ignores_receive(
    proof_case: Any, monkeypatch: Any
) -> None:
    oracle, _app, _store, _owner, _keys, _binding = _configure(proof_case, monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=oracle), base_url=proof_case.key_row["origin"]
    ) as client:
        request = client.build_request(
            "GET",
            "/api/record/123",
            headers={"Authorization": "Bearer source-test-session"},
            content=b"unsolicited-hidden-body",
        )
        del request.headers["Content-Length"]
        assert (await client.send(request)).status_code == 200
        assert (
            await client.get(
                "/api/record/123", headers={"Authorization": "Bearer target-test-session"}
            )
        ).status_code == 200
        assert (await client.get("/api/record/123")).status_code == 403
    with pytest.raises(ControlledOracleDenied, match="Complete uncontaminated"):
        await oracle.attest(
            target_claims_json=b"{}",
            target_signature_b64url="invalid",
            verified_target_proof_sha256="0" * 64,
        )
