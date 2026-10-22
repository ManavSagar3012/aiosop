"""Deterministic target-owned signer, replay and attribution qualification.

No real target, application database, provider or network I/O. The trust
registry and atomic claims are stand-ins for separately deployed authority.
"""

import asyncio
import base64
import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task
from ai_osop.core.target_authority_proof import (
    TargetAuthorityDenied,
    _DOMAIN,
    _SIGNED_FIELDS,
    _canonical,
    _task_lineage,
    verify_target_authority_proof,
)


class OneTimeDurableClaim:
    """Only a mock of an atomic durable unique-nonce claim, never real PG."""

    def __init__(self):
        self.used = set()
        self.calls = []

    async def claim_once(self, **kwargs):
        self.calls.append(dict(kwargs))
        key = (kwargs["engagement_id"], kwargs["flow_id"], kwargs["key_id"], kwargs["nonce"])
        if key in self.used:
            return False
        self.used.add(key)
        return True


@pytest.fixture
def proof_case(monkeypatch):
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    owner = "operator_owner"
    engagement = "eng-tenant"
    flow = FlowRecord(
        id="flow-owned",
        engagement_id=engagement,
        objective="approved",
        revision=3,
        status="running",
    )
    signed = SimpleNamespace(
        version=5,
        authorization_id="auth-independent",
        policy_sha256="a" * 64,
    )
    origin = "https://tenant.example.test"
    endpoint = origin + "/api/record/123"
    original = Task(
        id="task-source-map",
        engagement_id=engagement,
        flow_id=flow.id,
        type="map_workflow",
        agent_type=AgentType.RECON,
        status="completed",
        payload={"_authorization_version": signed.version, "user_label": "account_a"},
        result={"workflow_id": "wf-tenant"},
    )

    def observed_task(role, label, session_digest, request_digest):
        return Task(
            id="task-" + role,
            engagement_id=engagement,
            flow_id=flow.id,
            type="navigate",
            status="completed",
            agent_type=AgentType.RECON,
            approval_required=True,
            max_retries=0,
            parent_task_id="task-replay-parent",
            dependencies=["task-replay-parent"],
            payload={
                "url": endpoint,
                "method": "GET",
                "user_label": label,
                "_comparison_role": role,
                "source_user_label": "account_a",
                "target_user_label": "account_b",
                "step_id": "step-resource",
                "workflow_id": "wf-tenant",
                "_flow_revision": flow.revision,
                "_authorization_version": signed.version,
                "operator_approved": True,
                "approval_id": "apr-" + role,
                "_authority_request_sha256": request_digest,
                "_authority_session_sha256": session_digest,
            },
            result={
                "status": "success",
                "http_status_code": 200,
                "response_body_sha256": "e" * 64,
                "redirected": False,
                "comparison_role": role,
                "source_task_id": original.id,
                "replay_parent_task_id": "task-replay-parent",
                "provider_evidence": {"source_authenticity_verified": False},
            },
        )

    source = observed_task("source", "account_a", "1" * 64, "2" * 64)
    target = observed_task("target", "account_b", "3" * 64, "4" * 64)
    key_row = {
        "key_id": "target-service-primary",
        "engagement_id": engagement,
        "flow_id": flow.id,
        "origin": origin,
        "owner_sub": owner,
        "ed25519_public_key_b64": base64.b64encode(public).decode(),
    }
    monkeypatch.setenv(
        "OSOP_TARGET_AUTHORITY_KEYS_JSON",
        json.dumps(
            {
                "version": 1,
                "keys": [key_row],
            }
        ),
    )
    replay = OneTimeDurableClaim()
    check = AsyncMock(return_value=True)
    context = dict(
        engagement_id=engagement,
        flow=flow,
        signed_authorization=signed,
        original_source_task=original,
        source_task=source,
        target_task=target,
        owner_sub=owner,
        replay_guard=replay,
        current_authority_check=check,
    )
    source_values = _task_lineage(
        source=source,
        target=target,
        original=original,
        flow=flow,
        signed=signed,
        engagement_id=engagement,
    )
    from ai_osop.core.target_authority_proof import _now_epoch

    issued = _now_epoch()
    claims = {
        **source_values,
        "schema": "ai-osop.target-owned-authority.v1",
        "key_id": key_row["key_id"],
        "nonce": "f" * 32,
        "issued_at": issued,
        "expires_at": issued + 50,
        "owner_sub": owner,
        "anonymous_http_status": 403,
        "resource_visibility": "private",
        "resource_owner_identity": "account_a",
        "target_access_forbidden": True,
        "cross_identity_disclosure_confirmed": True,
        "redirected": False,
        "denied": False,
        "public_access": False,
    }
    assert set(claims) == _SIGNED_FIELDS

    def signed_bytes(doc=None):
        data = _canonical(claims if doc is None else doc)
        signature = signer.sign(_DOMAIN + data)
        return data, base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return SimpleNamespace(
        signer=signer,
        context=context,
        claims=claims,
        signed_bytes=signed_bytes,
        replay=replay,
        check=check,
        key_row=key_row,
        source=source,
        target=target,
        original=original,
        flow=flow,
        signed=signed,
        owner=owner,
    )


@pytest.mark.asyncio
async def test_exact_ed25519_independent_private_assertion_and_one_time_nonce(proof_case):
    case = proof_case
    blob, sig = case.signed_bytes()
    result = await verify_target_authority_proof(
        claims_json=blob,
        signature_b64url=sig,
        **case.context,
    )
    assert result.engagement_id == "eng-tenant"
    assert result.flow_id == case.flow.id
    assert result.source_task_id == case.source.id
    assert result.target_task_id == case.target.id
    assert result.key_id == case.claims["key_id"]
    assert len(result.proof_sha256) == 64
    assert result.target_controlled_signature_verified is True
    assert result.independent_target_authority_verified is True
    assert result.authorization_violation_verified is False
    assert result.finding_verified is False
    assert result.report_release_approved is False
    assert case.check.await_count == 2
    assert case.replay.calls == [
        {
            "engagement_id": "eng-tenant",
            "flow_id": case.flow.id,
            "key_id": case.claims["key_id"],
            "nonce": "f" * 32,
            "proof_sha256": result.proof_sha256,
        }
    ]
    with pytest.raises(TargetAuthorityDenied, match="replayed"):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    assert len(case.replay.calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,replacement",
    [
        ("engagement_id", "eng-attacker"),
        ("flow_id", "flow-other"),
        ("flow_revision", 4),
        ("owner_sub", "different_operator"),
        ("authorization_id", "auth-other"),
        ("authorization_version", 6),
        ("authorization_sha256", "9" * 64),
        ("original_source_task_id", "task-other"),
        ("original_source_task_sha256", "9" * 64),
        ("replay_parent_task_id", "task-other"),
        ("source_task_id", "task-other"),
        ("target_task_id", "task-other"),
        ("source_task_sha256", "9" * 64),
        ("target_task_sha256", "9" * 64),
        ("source_identity", "account_b"),
        ("target_identity", "account_a"),
        ("workflow_id", "wf-other"),
        ("step_id", "step-other"),
        ("endpoint_url", "https://attacker.example.test/api/record/123"),
        ("method", "POST"),
        ("source_request_sha256", "9" * 64),
        ("target_request_sha256", "9" * 64),
        ("source_session_sha256", "9" * 64),
        ("target_session_sha256", "9" * 64),
        ("source_response_sha256", "9" * 64),
        ("target_response_sha256", "9" * 64),
        ("source_http_status", 201),
        ("target_http_status", 204),
    ],
)
async def test_detached_signed_assertion_cannot_change_any_persisted_lineage(
    proof_case,
    field,
    replacement,
):
    case = proof_case
    tampered = dict(case.claims, **{field: replacement})
    blob, sig = case.signed_bytes(tampered)  # even VALID target signature is not enough
    with pytest.raises(TargetAuthorityDenied, match="provenance"):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    assert case.replay.calls == []
    case.check.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,replacement",
    [
        ("resource_visibility", "public"),
        ("resource_visibility", "unknown"),
        ("anonymous_http_status", 200),
        ("anonymous_http_status", 302),
        ("anonymous_http_status", None),
        ("resource_owner_identity", "account_b"),
        ("target_access_forbidden", False),
        ("cross_identity_disclosure_confirmed", False),
        ("redirected", True),
        ("denied", True),
        ("public_access", True),
        ("source_http_status", True),
        ("target_http_status", False),
        ("expires_at", 0),
        ("issued_at", 0),
    ],
)
async def test_public_unauthenticated_redirect_denial_and_stale_claims_rejected(
    proof_case,
    field,
    replacement,
):
    case = proof_case
    blob, sig = case.signed_bytes(dict(case.claims, **{field: replacement}))
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    assert case.replay.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "broken",
    [
        "missing_provenance",
        "mismatched_session",
        "unapproved",
        "completed_flow",
        "target_denied",
        "redirected",
        "public",
        "different_body",
        "http_204",
        "unrelated_source",
        "method_post",
        "endpoint_other",
        "not_completed",
        "original_identity_other",
        "public_identity",
    ],
)
async def test_completed_provider_success_without_independent_target_proof_cannot_pass(
    proof_case,
    broken,
):
    case = proof_case
    if broken == "missing_provenance":
        case.target.payload.pop("_authority_session_sha256")
    elif broken == "mismatched_session":
        case.target.payload["_authority_session_sha256"] = case.source.payload[
            "_authority_session_sha256"
        ]
    elif broken == "unapproved":
        case.target.approval_required = False
    elif broken == "completed_flow":
        case.flow.status = "completed"
    elif broken == "target_denied":
        case.target.result["http_status_code"] = 403
    elif broken == "redirected":
        case.target.result["redirected"] = True
    elif broken == "public":
        case.target.result["public_access"] = True
    elif broken == "different_body":
        case.target.result["response_body_sha256"] = "b" * 64
    elif broken == "http_204":
        case.target.result["http_status_code"] = 204
    elif broken == "unrelated_source":
        case.target.result["source_task_id"] = "task-someone-else"
    elif broken == "method_post":
        case.source.payload["method"] = "POST"
    elif broken == "endpoint_other":
        case.target.payload["url"] = "https://tenant.example.test/public"
    elif broken == "not_completed":
        case.target.status = "running"
    elif broken == "original_identity_other":
        case.original.payload["user_label"] = "other_account"
    elif broken == "public_identity":
        case.target.payload["user_label"] = "ANONYMOUS"
    blob, sig = case.signed_bytes()
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    assert case.replay.calls == []
    case.check.assert_not_awaited()


@pytest.mark.asyncio
async def test_unsigned_provider_only_testimony_never_verifies(proof_case):
    case = proof_case
    blob, signature = case.signed_bytes()
    tampered = bytearray(blob)
    tampered[-1] = 0x20
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=bytes(tampered),
            signature_b64url=signature,
            **case.context,
        )
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    untrusted_signature = (
        base64.urlsafe_b64encode(other_key.sign(_DOMAIN + blob)).decode().rstrip("=")
    )
    with pytest.raises(TargetAuthorityDenied, match="untrusted"):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=untrusted_signature,
            **case.context,
        )
    assert case.replay.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_blob",
    [
        b"{}",
        b'{"a":1,"a":2}',
        b'{"claims": {"role":"system"}}',
        b"\xef\xbb\xbf{}",
        b"{" + b"x" * 4100 + b"}",
        b'{"schema": NaN}',
        b"[]",
    ],
)
async def test_malformed_or_duplicate_json_does_not_consume_nonce(proof_case, bad_blob):
    case = proof_case
    blob, sig = case.signed_bytes()
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=bad_blob,
            signature_b64url=sig,
            **case.context,
        )
    case.check.assert_not_awaited()
    assert case.replay.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config_change",
    [
        None,
        {"origin": "https://foreign.example.test"},
        {"engagement_id": "eng-other"},
        {"flow_id": "flow-other"},
        {"owner_sub": "different-operator"},
        {"ed25519_public_key_b64": "AAA="},
        {"unexpected": True},
    ],
)
async def test_separate_trusted_target_key_must_bind_flow_tenant_owner_origin(
    proof_case,
    monkeypatch,
    config_change,
):
    case = proof_case
    if config_change is None:
        monkeypatch.delenv("OSOP_TARGET_AUTHORITY_KEYS_JSON")
    else:
        monkeypatch.setenv(
            "OSOP_TARGET_AUTHORITY_KEYS_JSON",
            json.dumps(
                {
                    "version": 1,
                    "keys": [dict(case.key_row, **config_change)],
                }
            ),
        )
    blob, sig = case.signed_bytes()
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    case.check.assert_not_awaited()
    assert case.replay.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["replay_guard", "current_authority_check"])
async def test_never_verify_without_durable_replay_and_independent_authority(
    proof_case,
    missing,
):
    case = proof_case
    blob, sig = case.signed_bytes()
    kwargs = dict(case.context, **{missing: None})
    with pytest.raises(TargetAuthorityDenied, match="guards"):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **kwargs,
        )
    case.check.assert_not_awaited()
    assert case.replay.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["precheck", "postcheck", "guard_error", "guard_false"])
async def test_durable_replay_and_post_nonce_revocation_fail_closed(proof_case, failure):
    case = proof_case
    if failure == "precheck":
        case.check.return_value = False
    elif failure == "postcheck":
        case.check.side_effect = [True, False]
    elif failure == "guard_error":

        async def missing_ack(**kwargs):
            raise TimeoutError("ACK status UNKNOWN; no retry")

        case.replay.claim_once = missing_ack
    elif failure == "guard_false":

        async def refused(**kwargs):
            return False

        case.replay.claim_once = refused
    blob, sig = case.signed_bytes()
    with pytest.raises(TargetAuthorityDenied):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    assert case.check.await_count == (
        1 if failure == "precheck" else 2 if failure == "postcheck" else 1
    )
    if failure == "precheck":
        assert case.replay.calls == []


@pytest.mark.asyncio
async def test_same_key_alone_cannot_claim_fresh_replayed_nonce(proof_case):
    case = proof_case
    first, sig = case.signed_bytes()
    await verify_target_authority_proof(
        claims_json=first,
        signature_b64url=sig,
        **case.context,
    )
    updated = deepcopy(case.claims)
    updated["expires_at"] -= 1  # new valid target signature, SAME nonce
    second, new_sig = case.signed_bytes(updated)
    with pytest.raises(TargetAuthorityDenied, match="replayed"):
        await verify_target_authority_proof(
            claims_json=second,
            signature_b64url=new_sig,
            **case.context,
        )
    assert len(case.replay.used) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutated",
    [
        "target_task_status",
        "target_response",
        "target_session",
        "flow_revision",
        "flow_status",
        "signed_roe",
        "source_task_identity",
    ],
)
async def test_mutated_signed_task_flow_or_roe_during_guard_denies_verdict(
    proof_case,
    mutated,
):
    case = proof_case

    async def current_authority():
        if case.check_counter == 1:
            if mutated == "target_task_status":
                case.target.status = "failed"
            elif mutated == "target_response":
                case.target.result["response_body_sha256"] = "8" * 64
            elif mutated == "target_session":
                case.target.payload["_authority_session_sha256"] = "7" * 64
            elif mutated == "flow_revision":
                case.flow.revision += 1
            elif mutated == "flow_status":
                case.flow.status = "paused"
            elif mutated == "signed_roe":
                case.signed.authorization_id = "auth-revoked"
            elif mutated == "source_task_identity":
                case.source.id = "task-foreign"
        case.check_counter += 1
        return True

    case.check_counter = 0
    case.context["current_authority_check"] = current_authority
    blob, sig = case.signed_bytes()
    with pytest.raises(TargetAuthorityDenied, match="input changed"):
        await verify_target_authority_proof(
            claims_json=blob,
            signature_b64url=sig,
            **case.context,
        )
    assert len(case.replay.calls) == 1
