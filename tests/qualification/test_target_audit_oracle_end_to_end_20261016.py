"""Offline qualification of a controlled owner oracle and three trust-separated signers.

Real HTTP requests use httpx.ASGITransport against the existing disposable
FastAPI target. The independently configured target, object-ledger, and access
keys attest only to this controlled test. The in-memory replay stub is *not* a
durable PostgreSQL admission, so neither verdict can release a finding/report.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Request
from fastapi.responses import RedirectResponse

from ai_osop.core import target_authority_corroboration as audit
from ai_osop.core.target_authority_proof import (
    TargetAuthorityDenied,
    _task_lineage,
    verify_target_authority_proof,
)
from ai_osop.orchestrator.context_compaction import task_assignment_sha256
from tests.qualification.test_disposable_target_owner_oracle_20261016 import (
    _controlled_target,
    _response_digest,
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401

_OWNER_OF_RECORD = {"123": "account_a"}
_AUTH = {
    "source": "Bearer source-test-session",
    "target": "Bearer target-test-session",
}
_ACTOR = {
    _AUTH["source"]: "account_a",
    _AUTH["target"]: "account_b",
}
_PATH = "/api/record/123"
_AUDIT_SIGNERS = {
    "ownership": Ed25519PrivateKey.from_private_bytes(bytes(range(65, 97))),
    "access": Ed25519PrivateKey.from_private_bytes(bytes(range(97, 129))),
}


def _canonical(value: Dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(namespace: bytes, value: Dict[str, Any]) -> str:
    return hashlib.sha256(namespace + _canonical(value)).hexdigest()


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


def _sign_audit(role: str, claim: Dict[str, Any]) -> tuple[bytes, str]:
    payload = _canonical(claim)
    signature = _AUDIT_SIGNERS[role].sign(audit._DOMAIN + payload)
    return payload, base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


@dataclass
class ControlledOracle:
    case: Any
    observed: Dict[str, Dict[str, Any]]
    claims: Dict[str, Any]
    proof: bytes
    signature: str


async def _exercise_controlled_http(
    case: Any, *, vulnerable: bool, publicly_readable: bool, redirect_target: bool = False
) -> ControlledOracle:
    app = _controlled_target(bug=vulnerable, publicly_readable=publicly_readable)
    audit_log: list[Dict[str, Any]] = []

    @app.middleware("http")
    async def capture_actual_http(request: Request, call_next: Any) -> Any:
        # Capture request bytes/identity at the target boundary, before any
        # signing; never construct provenance from provider-reported strings.
        authorization = request.headers.get("authorization", "")
        if redirect_target and authorization == _AUTH["target"]:
            response = RedirectResponse(url=case.key_row["origin"] + "/redirected", status_code=302)
        else:
            response = await call_next(request)
        audit_log.append(
            {
                "method": request.method,
                "url": str(request.url),
                "authorization": authorization,
                "actor": _ACTOR.get(authorization),
                "http_status": response.status_code,
            }
        )
        return response

    # HTTPS is the exact logical signed origin, but ASGITransport never opens a
    # network socket. Redirects must remain observable, never auto-followed.
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=case.key_row["origin"],
        follow_redirects=False,
        timeout=3,
    ) as client:
        replies = {
            "source": await client.get(_PATH, headers={"Authorization": _AUTH["source"]}),
            "target": await client.get(_PATH, headers={"Authorization": _AUTH["target"]}),
            "anonymous": await client.get(_PATH),
        }

    assert len(audit_log) == 3
    observed = dict(zip(("source", "target", "anonymous"), audit_log))
    for role in ("source", "target", "anonymous"):
        record = observed[role]
        assert record["url"] == case.key_row["origin"] + _PATH
        assert record["method"] == "GET"
        assert record["http_status"] == replies[role].status_code
    assert observed["source"]["actor"] == _OWNER_OF_RECORD["123"]
    assert observed["target"]["actor"] != _OWNER_OF_RECORD["123"]
    assert observed["target"]["actor"] is not None
    assert observed["anonymous"]["actor"] is None
    assert replies["source"].json()["owner"] == _OWNER_OF_RECORD["123"]

    for role in ("source", "target"):
        observed_request = observed[role]
        task = case.source if role == "source" else case.target
        session_sha = _digest(
            b"controlled-oracle-session-v1\x00",
            {
                "actor": observed_request["actor"],
                "authorization": observed_request["authorization"],
                "engagement_id": case.flow.engagement_id,
            },
        )
        request_sha = _digest(
            b"controlled-oracle-request-v1\x00",
            {
                "task_id": task.id,
                "flow_id": case.flow.id,
                "method": observed_request["method"],
                "url": observed_request["url"],
                "session_sha256": session_sha,
            },
        )
        task.payload["_authority_request_sha256"] = request_sha
        task.payload["_authority_session_sha256"] = session_sha
        observed_request["request_sha256"] = request_sha
        observed_request["session_sha256"] = session_sha
        reply = replies[role]
        task.result["http_status_code"] = reply.status_code
        task.result["redirected"] = reply.is_redirect
        task.result["response_body_sha256"] = (
            _response_digest(engagement=case.flow.engagement_id, response_body=reply.json())
            if reply.content
            and reply.headers.get("content-type", "").startswith("application/json")
            else hashlib.sha256(reply.content).hexdigest()
        )
        observed_request["response_sha256"] = task.result["response_body_sha256"]

    # All three proofs bind the same exact observed HTTP request/session/status
    # records and the immutable approved Task assignment fingerprints.
    claims = dict(case.claims)
    claims.update(
        source_task_sha256=task_assignment_sha256(case.source),
        target_task_sha256=task_assignment_sha256(case.target),
        source_request_sha256=observed["source"]["request_sha256"],
        target_request_sha256=observed["target"]["request_sha256"],
        source_session_sha256=observed["source"]["session_sha256"],
        target_session_sha256=observed["target"]["session_sha256"],
        source_response_sha256=observed["source"]["response_sha256"],
        target_response_sha256=observed["target"]["response_sha256"],
        source_http_status=observed["source"]["http_status"],
        target_http_status=observed["target"]["http_status"],
        anonymous_http_status=observed["anonymous"]["http_status"],
        resource_owner_identity=_OWNER_OF_RECORD["123"],
        resource_visibility="public" if publicly_readable else "private",
        target_access_forbidden=True,
        public_access=publicly_readable,
        redirected=replies["target"].is_redirect,
        denied=replies["target"].status_code in (401, 403, 404),
        cross_identity_disclosure_confirmed=(
            replies["source"].status_code == 200
            and replies["target"].status_code == 200
            and replies["anonymous"].status_code in (401, 403, 404)
            and not publicly_readable
        ),
    )
    if not publicly_readable and vulnerable and not redirect_target:
        expected = _task_lineage(
            source=case.source,
            target=case.target,
            original=case.original,
            flow=case.flow,
            signed=case.signed,
            engagement_id=case.flow.engagement_id,
        )
        assert all(claims[key] == value for key, value in expected.items())
        assert claims["source_response_sha256"] == claims["target_response_sha256"]
        assert claims["source_session_sha256"] != claims["target_session_sha256"]

    proof, signature = case.signed_bytes(claims)
    return ControlledOracle(
        case=case, observed=observed, claims=claims, proof=proof, signature=signature
    )


def _independent_audits(
    oracle: ControlledOracle, proof_sha256: str, monkeypatch: Any
) -> Dict[str, tuple[bytes, str]]:
    case, claims = oracle.case, oracle.claims
    trusted_target_key = case.key_row["ed25519_public_key_b64"]
    public_keys = {role: _public(key) for role, key in _AUDIT_SIGNERS.items()}
    assert len(set((*public_keys.values(), trusted_target_key))) == 3
    monkeypatch.setenv(
        "OSOP_TARGET_AUDIT_KEYS_JSON",
        _canonical(
            {
                "version": 1,
                "engagement_id": case.flow.engagement_id,
                "flow_id": case.flow.id,
                "origin": case.key_row["origin"],
                "keys": public_keys,
            }
        ).decode(),
    )
    issued = int(time.time())
    receipts = {}
    for role, nonce in (("ownership", "o" * 32), ("access", "a" * 32)):
        # Owner ledger and access gateway independently sign matching details,
        # including exact request/session/body digests from genuine ASGI calls.
        record = {field: claims[field] for field in audit._MATCHED_FIELDS}
        record.update(
            schema="ai-osop.target-independent-audit.v1",
            role=role,
            resource_id="123",
            resource_owner_identity=_OWNER_OF_RECORD["123"],
            source_access_allowed=(
                oracle.observed["source"]["http_status"] == 200
                and oracle.observed["source"]["actor"] == _OWNER_OF_RECORD["123"]
            ),
            target_access_forbidden=(oracle.observed["target"]["actor"] != _OWNER_OF_RECORD["123"]),
            target_proof_sha256=proof_sha256,
            nonce=nonce,
            issued_at=issued,
            expires_at=issued + 60,
        )
        receipts[role] = _sign_audit(role, record)
    return receipts


def _corroborate(
    oracle: ControlledOracle, proof_sha256: str, receipts: Dict[str, tuple[bytes, str]]
) -> audit.CorroboratedTargetAudit:
    return audit.corroborate_target_audits(
        target_claims_json=oracle.proof,
        target_proof_sha256=proof_sha256,
        ownership_json=receipts["ownership"][0],
        ownership_signature=receipts["ownership"][1],
        access_json=receipts["access"][0],
        access_signature=receipts["access"][1],
    )


@pytest.mark.asyncio
async def test_three_independent_signers_correlate_real_owned_http_but_only_candidate(
    proof_case: Any, monkeypatch: Any
) -> None:
    oracle = await _exercise_controlled_http(proof_case, vulnerable=True, publicly_readable=False)
    assert {key: row["http_status"] for key, row in oracle.observed.items()} == {
        "source": 200,
        "target": 200,
        "anonymous": 403,
    }
    verdict = await verify_target_authority_proof(
        claims_json=oracle.proof,
        signature_b64url=oracle.signature,
        **proof_case.context,
    )
    assert verdict.target_controlled_signature_verified is True
    assert verdict.independent_target_authority_verified is True
    assert verdict.authorization_violation_verified is False
    assert verdict.finding_verified is False
    assert verdict.report_release_approved is False
    assert proof_case.check.await_count == 2
    assert proof_case.replay.calls == [
        {
            "engagement_id": proof_case.flow.engagement_id,
            "flow_id": proof_case.flow.id,
            "key_id": proof_case.key_row["key_id"],
            "nonce": oracle.claims["nonce"],
            "proof_sha256": verdict.proof_sha256,
        }
    ]
    receipts = _independent_audits(oracle, verdict.proof_sha256, monkeypatch)
    independently_signed = _corroborate(oracle, verdict.proof_sha256, receipts)
    assert independently_signed.proof_sha256 == verdict.proof_sha256
    assert independently_signed.source_records_correlated is True
    assert independently_signed.target_audit_signatures_verified is True
    assert len(independently_signed.audit_sha256) == 64
    assert independently_signed.finding_verified is False
    assert independently_signed.report_release_approved is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "public",
        "denied",
        "redirect",
        "rotated_session",
        "rotated_trusted_target_key",
        "tampered_target_assertion",
    ],
)
async def test_real_http_and_signed_target_oracle_fail_closed(
    proof_case: Any, monkeypatch: Any, scenario: str
) -> None:
    oracle = await _exercise_controlled_http(
        proof_case,
        vulnerable=scenario != "denied",
        publicly_readable=scenario == "public",
        redirect_target=scenario == "redirect",
    )
    if scenario == "public":
        assert oracle.observed["anonymous"]["http_status"] == 200
    elif scenario == "denied":
        assert oracle.observed["target"]["http_status"] == 403
    elif scenario == "redirect":
        assert oracle.observed["target"]["http_status"] == 302
        assert oracle.claims["redirected"] is True
    elif scenario == "rotated_session":
        # Signing a historical session cannot authenticate a newly rotated one.
        proof_case.target.payload["_authority_session_sha256"] = "9" * 64
    elif scenario == "rotated_trusted_target_key":
        replacement = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
        config = {
            "version": 1,
            "keys": [
                dict(
                    proof_case.key_row,
                    ed25519_public_key_b64=_public(replacement),
                )
            ],
        }
        monkeypatch.setenv("OSOP_TARGET_AUTHORITY_KEYS_JSON", _canonical(config).decode())
    elif scenario == "tampered_target_assertion":
        oracle.proof = oracle.proof.replace(b'"method":"GET"', b'"method":"PUT"')
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=oracle.proof,
            signature_b64url=oracle.signature,
            **proof_case.context,
        )
    assert proof_case.replay.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "owner_of_other_object",
        "access_request_digest",
        "access_session_digest",
        "access_response_digest",
        "access_identity",
        "access_public",
        "access_denied",
        "access_redirect",
        "alter_signed_bytes",
        "wrong_access_signing_key",
        "reuse_target_signing_key",
        "rotated_access_signing_key",
    ],
)
async def test_independent_owner_access_oracle_must_correlate_exact_provenance(
    proof_case: Any, monkeypatch: Any, tamper: str
) -> None:
    oracle = await _exercise_controlled_http(proof_case, vulnerable=True, publicly_readable=False)
    verdict = await verify_target_authority_proof(
        claims_json=oracle.proof,
        signature_b64url=oracle.signature,
        **proof_case.context,
    )
    receipts = _independent_audits(oracle, verdict.proof_sha256, monkeypatch)
    owner_claim = json.loads(receipts["ownership"][0])
    access_claim = json.loads(receipts["access"][0])
    if tamper == "owner_of_other_object":
        owner_claim["resource_id"] = access_claim["resource_id"] = "other-object"
    elif tamper == "access_request_digest":
        access_claim["target_request_sha256"] = "8" * 64
    elif tamper == "access_session_digest":
        access_claim["source_session_sha256"] = "8" * 64
    elif tamper == "access_response_digest":
        access_claim["target_response_sha256"] = "8" * 64
    elif tamper == "access_identity":
        access_claim["resource_owner_identity"] = "account_b"
    elif tamper == "access_public":
        access_claim["resource_visibility"] = "public"
    elif tamper == "access_denied":
        access_claim["target_http_status"] = 403
    elif tamper == "access_redirect":
        access_claim["anonymous_http_status"] = 302
    if tamper in {"owner_of_other_object"}:
        receipts["ownership"] = _sign_audit("ownership", owner_claim)
    if tamper in {
        "owner_of_other_object",
        "access_request_digest",
        "access_session_digest",
        "access_response_digest",
        "access_identity",
        "access_public",
        "access_denied",
        "access_redirect",
    }:
        # Even an otherwise cryptographically VALID access signer cannot
        # contradict the separate target authority and observed HTTP oracle.
        receipts["access"] = _sign_audit("access", access_claim)
    elif tamper == "alter_signed_bytes":
        original_blob, original_sig = receipts["access"]
        receipts["access"] = (
            original_blob.replace(b'"method":"GET"', b'"method":"PUT"'),
            original_sig,
        )
    elif tamper == "wrong_access_signing_key":
        access_payload, _ = receipts["access"]
        wrong = _AUDIT_SIGNERS["ownership"].sign(audit._DOMAIN + access_payload)
        receipts["access"] = (
            access_payload,
            base64.urlsafe_b64encode(wrong).decode("ascii").rstrip("="),
        )
    elif tamper == "reuse_target_signing_key":
        config = json.loads(__import__("os").environ["OSOP_TARGET_AUDIT_KEYS_JSON"])
        config["keys"]["access"] = proof_case.key_row["ed25519_public_key_b64"]
        monkeypatch.setenv("OSOP_TARGET_AUDIT_KEYS_JSON", _canonical(config).decode())
    elif tamper == "rotated_access_signing_key":
        config = json.loads(__import__("os").environ["OSOP_TARGET_AUDIT_KEYS_JSON"])
        rotated = Ed25519PrivateKey.from_private_bytes(bytes(range(129, 161)))
        config["keys"]["access"] = _public(rotated)
        monkeypatch.setenv("OSOP_TARGET_AUDIT_KEYS_JSON", _canonical(config).decode())
    with pytest.raises(audit.TargetAuditUnverified):
        _corroborate(oracle, verdict.proof_sha256, receipts)
    assert len(proof_case.replay.calls) == 1
