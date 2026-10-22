"""Live witness protocol qualifications; mock all networks and durable guards."""

import asyncio
import base64
import copy
import hashlib
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.core import independent_target_effect_observer as observer
from ai_osop.core.target_authority_proof import _canonical, _task_lineage
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401

NONCE = "d" * 32
FINDING = "vuln-123"
REVIEW_ID = "vfdec-" + "a" * 32
QUAL_ID = "teqa-" + "b" * 32
R_SHA = "7" * 64
Q_SHA = "8" * 64
PROOF_SHA = "9" * 64
AUDIT_SHA = "e" * 64
RESOURCE = "123"


def _b64(value):
    return base64.b64encode(value).decode("ascii")


def _url64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _pub(key):
    return _b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


@pytest.fixture
def witness(proof_case, monkeypatch):
    owner_signer = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    observer_signer = Ed25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    now = int(time.time())
    config = {
        "engagement_id": proof_case.flow.engagement_id,
        "flow_id": proof_case.flow.id,
        "version": 1,
        "enabled": True,
        "deployment": "production",
        "generation": 1,
        "not_before": now - 100,
        "not_after": now + 3600,
        "origin": "https://witness.example.test",
        "pinned_public_ipv4": "8.8.8.8",
        "allowed_hosts": ["witness.example.test", "owner.example.test"],
        "observer_key_id": "real-gateway-a1",
        "observer_operator_id": "production-access-owner",
        "observer_public_key_b64": _pub(observer_signer),
        "owner_key_id": "real-owner-b1",
        "owner_operator_id": "production-record-owner",
        "owner_public_key_b64": _pub(owner_signer),
    }

    def set_config():
        monkeypatch.setenv(
            "OSOP_INDEPENDENT_EFFECT_OBSERVER_JSON",
            _canonical(config).decode(),
        )

    set_config()
    expected = _task_lineage(
        source=proof_case.source,
        target=proof_case.target,
        original=proof_case.original,
        flow=proof_case.flow,
        signed=proof_case.signed,
        engagement_id=proof_case.flow.engagement_id,
    )
    owner_claim = {
        "schema": "ai-osop.live-target-owner-of-record.v1",
        "key_id": config["owner_key_id"],
        "operator_id": config["owner_operator_id"],
        "nonce": NONCE,
        "observed_at": now,
        "engagement_id": proof_case.flow.engagement_id,
        "flow_id": proof_case.flow.id,
        "finding_id": FINDING,
        "endpoint_url": expected["endpoint_url"],
        "resource_id": RESOURCE,
        "owner_identity": expected["source_identity"],
        "visibility": "private",
        "revision": 3,
        "record_sha256": "f" * 64,
        "private_content_sha256": expected["source_response_sha256"],
        "production_owner_ledger": True,
    }
    events = {}
    for role in ("source", "target", "anonymous"):
        authenticated = role != "anonymous"
        events[role] = {
            "identity": (
                expected["source_identity"]
                if role == "source"
                else expected["target_identity"] if role == "target" else None
            ),
            "task_id": (
                expected["source_task_id"]
                if role == "source"
                else expected["target_task_id"] if role == "target" else "task-anonymous-approved"
            ),
            "event_id": "evt-" + role,
            "method": "GET",
            "endpoint_url": expected["endpoint_url"],
            "resource_id": RESOURCE,
            "request_sha256": (
                expected["source_request_sha256"]
                if role == "source"
                else expected["target_request_sha256"] if role == "target" else "2" * 64
            ),
            "response_sha256": (expected["source_response_sha256"] if authenticated else "5" * 64),
            "session_sha256": (
                expected["source_session_sha256"]
                if role == "source"
                else expected["target_session_sha256"] if role == "target" else None
            ),
            "session_current": authenticated,
            "session_generation": 5 if authenticated else None,
            "http_status": 200 if authenticated else 403,
            "redirected": False,
            "access_allowed": role == "source",
            "private_record_disclosed": authenticated,
        }
    outer_claim = {
        "schema": "ai-osop.independent-target-effect.v1",
        "key_id": config["observer_key_id"],
        "operator_id": config["observer_operator_id"],
        "nonce": NONCE,
        "issued_at": now,
        "expires_at": now + 60,
        "binding": expected,
        "finding_id": FINDING,
        "review_decision_id": REVIEW_ID,
        "review_decision_sha256": R_SHA,
        "qualification_id": QUAL_ID,
        "qualification_sha256": Q_SHA,
        "qualification_revision": 1,
        "proof_sha256": PROOF_SHA,
        "audit_sha256": AUDIT_SHA,
        "resource_id": RESOURCE,
        "owner_claims_b64url": "",
        "owner_signature_b64url": "",
        "owner_record_sha256": "",
        "observations": events,
        "live_session_store": True,
        "durable_approved_task_events": True,
        "target_private_effect_observed": True,
        "synthetic": False,
    }

    def seal():
        owner_bytes = _canonical(owner_claim)
        outer_claim["owner_claims_b64url"] = _url64(owner_bytes)
        outer_claim["owner_signature_b64url"] = _url64(
            owner_signer.sign(observer._OWNER_DOMAIN + owner_bytes)
        )
        outer_claim["owner_record_sha256"] = hashlib.sha256(
            observer._OWNER_DOMAIN + owner_bytes
        ).hexdigest()
        outer_bytes = _canonical(outer_claim)
        outer_signature = _url64(observer_signer.sign(observer._EFFECT_DOMAIN + outer_bytes))
        return outer_bytes, outer_signature

    seen = set()

    async def admitted(finding, task, nonce):
        assert finding == FINDING
        assert task == "task-anonymous-approved"
        if nonce in seen:
            return False
        seen.add(nonce)
        return True

    ctx = {
        "engagement_id": proof_case.flow.engagement_id,
        "flow": proof_case.flow,
        "signed_authorization": proof_case.signed,
        "original_source_task": proof_case.original,
        "source_task": proof_case.source,
        "target_task": proof_case.target,
        "finding_id": FINDING,
        "review_decision_id": REVIEW_ID,
        "review_decision_sha256": R_SHA,
        "qualification_id": QUAL_ID,
        "qualification_sha256": Q_SHA,
        "qualification_revision": 1,
        "proof_sha256": PROOF_SHA,
        "audit_sha256": AUDIT_SHA,
        "trusted_current_authority_check": AsyncMock(return_value=True),
        "trusted_current_review_check": AsyncMock(return_value=True),
        "trusted_current_qualification_check": AsyncMock(return_value=True),
        "trusted_one_shot_admission_check": admitted,
    }
    return SimpleNamespace(
        proof=proof_case,
        config=config,
        set_config=set_config,
        owner=owner_claim,
        outer=outer_claim,
        expected=expected,
        ctx=ctx,
        seal=seal,
        seen=seen,
        owner_signer=owner_signer,
        observer_signer=observer_signer,
        now=now,
    )


async def _verify(case, *, nonce=NONCE):
    raw, sig = case.seal()
    return await observer.verify_independent_target_effect_claims(
        observer_claims_json=raw,
        observer_signature_b64url=sig,
        expected_nonce=nonce,
        **case.ctx,
    )


@pytest.mark.asyncio
async def test_two_independent_real_signatures_current_private_effect_and_full_handoff(witness):
    case = witness
    result = await _verify(case)
    raw, sig = case.seal()
    assert type(result) is observer.LiveIndependentEffectEvidence
    assert result.observer_claims_json == raw
    assert result.observer_signature_b64url == sig
    assert result.evidence_origin == "separately_operated_live_target_receipts"
    assert result.validation_state == "independent_observation_pending_durable_admission"
    assert result.finding_verified is False
    assert result.report_release_approved is False
    assert result.authorization_violation_verified is False
    assert result.review_decision_id == REVIEW_ID
    assert result.review_decision_sha256 == R_SHA
    assert result.qualification_id == QUAL_ID
    assert result.qualification_sha256 == Q_SHA
    assert result.qualification_revision == 1
    assert result.private_content_sha256 == case.expected["source_response_sha256"]
    assert result.original_source_task_id == case.proof.original.id
    assert result.source_task_id == case.proof.source.id
    assert result.target_task_id == case.proof.target.id
    assert result.flow_revision == case.proof.flow.revision
    assert result.authorization_version == case.proof.signed.version
    assert result.authorization_sha256 == case.proof.signed.policy_sha256
    assert result.endpoint_url == case.proof.claims["endpoint_url"]
    assert result.source_event_id == "evt-source"
    assert result.target_event_id == "evt-target"
    assert result.anonymous_event_id == "evt-anonymous"
    assert result.source_session_sha256 == case.expected["source_session_sha256"]
    assert result.target_session_sha256 == case.expected["target_session_sha256"]
    assert result.source_request_sha256 == case.expected["source_request_sha256"]
    assert result.target_request_sha256 == case.expected["target_request_sha256"]
    assert result.anonymous_request_sha256 == "2" * 64
    assert result.source_http_status == result.target_http_status == 200
    assert result.anonymous_http_status == 403
    assert result.anonymous_task_id == "task-anonymous-approved"
    assert result.owner_identity == "account_a"
    assert len(result.observation_sha256) == 64
    assert result.nonce == NONCE
    assert case.ctx["trusted_current_authority_check"].await_count == 2
    assert case.ctx["trusted_current_review_check"].await_count == 2
    assert case.ctx["trusted_current_qualification_check"].await_count == 2
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)  # persisted one-shot guard refuses nonce replay


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,invalid",
    [
        ("schema", "ai-osop.independent-lab-access.v1"),
        ("synthetic", True),
        ("live_session_store", False),
        ("durable_approved_task_events", False),
        ("target_private_effect_observed", False),
        ("nonce", "c" * 32),
        ("key_id", "other-key"),
        ("operator_id", "other-operator"),
        ("finding_id", "vuln-foreign"),
        ("review_decision_id", "vfdec-" + "3" * 32),
        ("review_decision_sha256", "a" * 64),
        ("qualification_id", "teqa-" + "4" * 32),
        ("qualification_sha256", "b" * 64),
        ("qualification_revision", 2),
        ("proof_sha256", "a" * 64),
        ("audit_sha256", "a" * 64),
        ("resource_id", "owned-but-different"),
        ("expires_at", 1),
    ],
)
async def test_signed_outer_claim_cannot_rebind_any_scope_or_fake_production(
    witness,
    field,
    invalid,
):
    case = witness
    case.outer[field] = invalid
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,invalid",
    [
        ("visibility", "public"),
        ("owner_identity", "account_b"),
        ("resource_id", "unrelated"),
        ("record_sha256", "not-sha"),
        ("private_content_sha256", "a" * 64),
        ("production_owner_ledger", False),
        ("revision", 0),
        ("observed_at", 1),
        ("nonce", "c" * 32),
        ("operator_id", "attacker"),
        ("key_id", "attacker"),
    ],
)
async def test_separately_signed_owner_record_must_be_real_current_private(
    witness,
    field,
    invalid,
):
    case = witness
    case.owner[field] = invalid
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "role,field,invalid",
    [
        ("source", "identity", "account_b"),
        ("target", "identity", "account_a"),
        ("target", "session_current", False),
        ("source", "session_generation", 0),
        ("target", "session_sha256", "f" * 64),
        ("source", "request_sha256", "e" * 64),
        ("target", "response_sha256", "c" * 64),
        ("source", "method", "POST"),
        ("target", "endpoint_url", "https://other.example.test/123"),
        ("target", "resource_id", "other"),
        ("target", "http_status", 403),
        ("anonymous", "http_status", 200),
        ("anonymous", "http_status", 302),
        ("anonymous", "session_sha256", "d" * 64),
        ("anonymous", "session_current", True),
        ("anonymous", "private_record_disclosed", True),
        ("target", "access_allowed", True),
        ("target", "private_record_disclosed", False),
        ("target", "redirected", True),
        ("anonymous", "redirected", True),
        ("target", "task_id", "task-foreign"),
        ("anonymous", "task_id", "task-target"),
        ("anonymous", "event_id", "evt-source"),
    ],
)
async def test_witness_cannot_substitute_client_response_200_or_session_provenance(
    witness,
    role,
    field,
    invalid,
):
    case = witness
    case.outer["observations"][role][field] = invalid
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("enabled", False),
        ("deployment", "synthetic"),
        ("origin", "http://witness.example.test"),
        ("origin", "https://127.0.0.1"),
        ("origin", "https://witness.example.test:444"),
        ("origin", "https://witness.example.test@other.test"),
        ("origin", "https://witness.example.test/extra"),
        ("origin", "https://witness.example.test.evil.test"),
        ("pinned_public_ipv4", "127.0.0.1"),
        ("pinned_public_ipv4", "10.0.0.1"),
        ("pinned_public_ipv4", "169.254.169.254"),
        ("pinned_public_ipv4", "::1"),
        ("allowed_hosts", ["other.example.test", "owner.example.test"]),
        ("observer_operator_id", "production-record-owner"),
        ("observer_key_id", "real-owner-b1"),
        ("generation", 0),
    ],
)
async def test_explicit_prod_trust_registry_no_ssrf_or_synthetic(
    witness,
    field,
    value,
):
    case = witness
    case.config[field] = value
    case.set_config()
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "callback",
    [
        "trusted_current_authority_check",
        "trusted_current_review_check",
        "trusted_current_qualification_check",
        "trusted_one_shot_admission_check",
    ],
)
async def test_no_current_signed_roe_review_qualification_or_one_shot_admission(
    witness,
    callback,
):
    case = witness
    case.ctx[callback] = AsyncMock(return_value=False)
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
async def test_rotated_trust_epoch_after_network_await_fails_closed(witness):
    case = witness

    async def rotation(*args):
        case.config["generation"] += 1
        case.set_config()
        return True

    case.ctx["trusted_one_shot_admission_check"] = rotation
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
async def test_revocation_after_first_live_check_fails_closed(witness):
    case = witness
    case.ctx["trusted_current_authority_check"] = AsyncMock(side_effect=[True, False])
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)
    assert case.ctx["trusted_current_authority_check"].await_count == 2


@pytest.mark.asyncio
async def test_rejected_unapproved_anonymous_task_or_replayed_nonce(witness):
    case = witness
    case.outer["observations"]["anonymous"]["task_id"] = "task-not-admitted"
    with pytest.raises(observer.IndependentEffectUnavailable):
        await _verify(case)


@pytest.mark.asyncio
async def test_wrong_detached_outer_signature_and_duplicate_json_denied(witness):
    case = witness
    raw, sig = case.seal()
    kwargs = dict(
        case.ctx,
        observer_claims_json=raw,
        observer_signature_b64url="A" * 86,
        expected_nonce=NONCE,
    )
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(**kwargs)


@pytest.mark.asyncio
async def test_nested_owner_signature_or_owner_digest_cannot_be_forged_by_gateway(witness):
    case = witness
    raw, sig = case.seal()
    payload = json.loads(raw)
    payload["owner_signature_b64url"] = "A" * 86
    outer = _canonical(payload)
    kwargs = dict(
        case.ctx,
        observer_claims_json=outer,
        observer_signature_b64url=_url64(
            case.observer_signer.sign(observer._EFFECT_DOMAIN + outer)
        ),
        expected_nonce=NONCE,
    )
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(**kwargs)
    payload["owner_signature_b64url"] = json.loads(raw)["owner_signature_b64url"]
    payload["owner_record_sha256"] = "c" * 64
    outer = _canonical(payload)
    kwargs["observer_claims_json"] = outer
    kwargs["observer_signature_b64url"] = _url64(
        case.observer_signer.sign(observer._EFFECT_DOMAIN + outer)
    )
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(**kwargs)
    raw = raw[:-1] + b',"nonce":"d"}'
    kwargs["observer_claims_json"] = raw
    kwargs["observer_signature_b64url"] = sig
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.verify_independent_target_effect_claims(**kwargs)


@pytest.mark.asyncio
async def test_no_unapproved_target_replay_audit_only_fixed_tls_path(witness, monkeypatch):
    case = witness

    async def fake_fetch(*, origin, pinned_ip, nonce):
        assert origin == case.config["origin"]
        assert pinned_ip == case.config["pinned_public_ipv4"]
        assert nonce == NONCE
        return case.seal()

    monkeypatch.setattr(observer, "_fetch_pinned_audit", fake_fetch)
    result = await observer.fetch_independent_target_effect_observation(
        **case.ctx,
        expected_nonce=NONCE,
    )
    assert result.anonymous_task_id == "task-anonymous-approved"
    assert result.finding_verified is False
    assert result.report_release_approved is False


@pytest.mark.asyncio
async def test_raw_signed_receipt_for_0022_is_transport_only_not_preverified(
    witness,
    monkeypatch,
):
    case = witness
    called = []

    async def fake_fetch(*, origin, pinned_ip, nonce):
        called.append((origin, pinned_ip, nonce))
        # This accessor intentionally does NOT cryptographically verify here;
        # the PG admission must perform the full independent verifier.
        return b"untrusted-unchecked-outer", "signature-unchecked"

    monkeypatch.setattr(observer, "_fetch_pinned_audit", fake_fetch)
    result = await observer.fetch_independent_target_effect_signed_receipt(
        engagement_id=case.proof.flow.engagement_id,
        flow=case.proof.flow,
        expected_nonce=NONCE,
    )
    assert result == (b"untrusted-unchecked-outer", "signature-unchecked")
    assert called == [(case.config["origin"], "8.8.8.8", NONCE)]


@pytest.mark.asyncio
async def test_raw_receipt_denied_when_trust_revoked_mid_fetch(witness, monkeypatch):
    case = witness

    async def fake_fetch(**kwargs):
        case.config["enabled"] = False
        case.set_config()
        return case.seal()

    monkeypatch.setattr(observer, "_fetch_pinned_audit", fake_fetch)
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.fetch_independent_target_effect_signed_receipt(
            engagement_id=case.proof.flow.engagement_id,
            flow=case.proof.flow,
            expected_nonce=NONCE,
        )


@pytest.mark.asyncio
async def test_non_persisted_or_client_supplied_nonce_rejected_before_raw_fetch(
    witness,
    monkeypatch,
):
    fetch = AsyncMock(return_value=(b"fake", "fake"))
    monkeypatch.setattr(observer, "_fetch_pinned_audit", fetch)
    with pytest.raises(observer.IndependentEffectUnavailable):
        await observer.fetch_independent_target_effect_signed_receipt(
            engagement_id=witness.proof.flow.engagement_id,
            flow=witness.proof.flow,
            expected_nonce="../../attacker",
        )
    fetch.assert_not_awaited()


class _MemoryWriter:
    def __init__(self):
        self.requests = []

    def write(self, chunk):
        self.requests.append(chunk)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


@pytest.mark.asyncio
async def test_pinned_tls_ca_sni_get_is_read_only_and_rejects_redirect_headers(
    monkeypatch,
):
    response = _canonical(
        {
            "observer_claims_b64url": _url64(b'{"schema":"test"}'),
            "observer_signature_b64url": "a" * 86,
        }
    )
    wire = (
        b"HTTP/1.1 200\r\nContent-Type: application/json\r\n"
        + b"Content-Length: "
        + str(len(response)).encode()
        + b"\r\nConnection: close\r\n\r\n"
        + response
    )
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    reader.feed_eof()
    writer = _MemoryWriter()
    seen = []

    async def fake_connect(**kwargs):
        seen.append(kwargs)
        return reader, writer

    monkeypatch.setattr(observer.asyncio, "open_connection", fake_connect)
    raw, signature = await observer._fetch_pinned_audit(
        origin="https://witness.example.test",
        pinned_ip="8.8.8.8",
        nonce=NONCE,
    )
    assert raw == b'{"schema":"test"}'
    assert signature == "a" * 86
    assert len(seen) == 1
    assert seen[0]["host"] == "8.8.8.8"
    assert seen[0]["port"] == 443
    assert seen[0]["server_hostname"] == "witness.example.test"
    assert seen[0]["ssl"].verify_mode.name == "CERT_REQUIRED"
    assert writer.requests == [
        (
            f"GET /v1/approved-task-effects/{NONCE} HTTP/1.1\r\n"
            "Host: witness.example.test\r\n"
            "Accept: application/json\r\n"
            "Accept-Encoding: identity\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
    ]

    for extra in (
        b"Location: https://evil.example.test\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"Content-Encoding: gzip\r\n",
    ):
        reader = asyncio.StreamReader()
        reader.feed_data(
            b"HTTP/1.1 200\r\nContent-Type: application/json\r\n"
            + extra
            + b"Content-Length: "
            + str(len(response)).encode()
            + b"\r\n\r\n"
            + response
        )
        reader.feed_eof()
        with pytest.raises(observer.IndependentEffectUnavailable):
            await observer._fetch_pinned_audit(
                origin="https://witness.example.test",
                pinned_ip="8.8.8.8",
                nonce=NONCE,
            )
