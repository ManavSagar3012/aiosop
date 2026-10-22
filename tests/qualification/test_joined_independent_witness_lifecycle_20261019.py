"""Joined, three-process LIVE SOCKET qualification of CONTROLLED witness denial.

Contract: a fresh local target independently signs current source/target and
anonymous session observations; a separate local owner signs its private
owner-of-record, and an access process verifies all signed inputs before it
serves a strictly bounded HTTPS witness envelope. Exercise the production
TLS HTTP/1.1 parser with a TEST-ONLY ephemeral-port redirect and trusted
temporary CA. No production public-IP policy is changed.

This controlled local evidence is SYNTHETIC. It cannot satisfy real separately
administered production signers, signed ROE, approved Task/Subtask/Action
lineage, genuine external private effect, current senior review, 0022 LIVE
promotion or final finding/report release. The production registry must reject
loopback even if these independent local signatures verify. No existing app
PostgreSQL, third-party target, external provider, deployed operator or
unrelated container is contacted. No existing 0022 PG-only CAS test is repeated.
"""

from __future__ import annotations

import asyncio
import base64
import json
import secrets
import ssl
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ai_osop.core import independent_target_effect_observer as production
from ai_osop.core.models import FlowRecord
from tests.qualification.joined_witness_processes_20261019 import (
    HOSTNAME,
    _EFFECT_DOMAIN,
    _OWNER_DOMAIN,
    _SESSION_DOMAIN,
    _decoded,
    disposable_joined_witness,
)


async def _actual_pinned_tls_parser(monkeypatch, lab, nonce: str, *,
                                    hostname: str = HOSTNAME, lab_ca: bool = True):
    """Run UNMODIFIED production parser/TLS/SNI with ONLY local socket reroute.

    The true adapter hardcodes port 443 and requires public IPv4 in its
    separately configured production registry. Our transient fake only maps
    the adapter's port to this test's fresh local TLS port; all TLS certificate
    verification and HTTP parsing remain executed by the production code.
    """
    original_context = ssl.create_default_context
    original_open = asyncio.open_connection

    def local_trust_context():
        return original_context(cafile=str(lab.cert)) if lab_ca else original_context()

    async def owned_socket(*, host, port, ssl, server_hostname, limit):
        assert host == "127.0.0.1" and port == 443
        assert server_hostname == hostname and limit == 4096
        return await original_open(
            host="127.0.0.1",
            port=lab.access["port"],
            ssl=ssl,
            server_hostname=server_hostname,
            limit=limit,
        )

    with monkeypatch.context() as local:
        local.setattr(production.ssl, "create_default_context", local_trust_context)
        local.setattr(production.asyncio, "open_connection", owned_socket)
        return await production._fetch_pinned_audit(
            origin="https://" + hostname,
            pinned_ip="127.0.0.1",
            nonce=nonce,
        )


def _verify_lab_receipt(lab, claims_raw: bytes, access_sig: str, nonce: str) -> dict:
    Ed25519PublicKey.from_public_bytes(base64.b64decode(lab.access["public"])).verify(
        _decoded(access_sig), production._EFFECT_DOMAIN + claims_raw
    )
    claims = json.loads(claims_raw)
    assert claims["schema"] == "ai-osop.joined-controlled-fixture.v1"
    assert claims["authority_level"] == "synthetic_local_only"
    assert claims["finding_verified"] is False
    assert claims["report_release_approved"] is False
    assert claims["nonce"] == nonce
    assert claims["resource_id"] == "123"
    owner = claims["owner_signed"]
    owner_raw = _decoded(owner["claims_b64url"])
    Ed25519PublicKey.from_public_bytes(base64.b64decode(lab.owner["public"])).verify(
        _decoded(owner["signature_b64url"]), production._OWNER_DOMAIN + owner_raw
    )
    owner_claims = json.loads(owner_raw)
    assert owner_claims == {
        "schema": "ai-osop.joined-local-owner-only.v1",
        "nonce": nonce,
        "resource_id": "123",
        "owner_identity": "account_a",
        "visibility": "private",
        "private_content_sha256": owner_claims["private_content_sha256"],
        "local_only": True,
    }
    receipts = claims["observations"]
    events = {}
    for role in ("source", "target", "anonymous"):
        message = _decoded(receipts[role]["claims_b64url"])
        Ed25519PublicKey.from_public_bytes(
            base64.b64decode(lab.target["session_public"])
        ).verify(_decoded(receipts[role]["signature_b64url"]), _SESSION_DOMAIN + message)
        events[role] = json.loads(message)
        assert events[role]["nonce"] == nonce
        assert events[role]["role"] == role
        assert events[role]["session_current"] is True
        assert events[role]["method"] == "GET"
        assert events[role]["redirected"] is False
    assert {role: events[role]["status"] for role in events} == {
        "source": 200, "target": 200, "anonymous": 403
    }
    assert events["source"]["identity"] == owner_claims["owner_identity"]
    assert events["target"]["identity"] == "account_b"
    assert events["anonymous"]["identity"] is None
    assert events["anonymous"]["session_sha256"] is None
    assert events["source"]["session_sha256"] != events["target"]["session_sha256"]
    assert events["source"]["response_sha256"] == events["target"]["response_sha256"]
    assert events["source"]["response_sha256"] == owner_claims["private_content_sha256"]
    # The witness exposes signed metadata/digests, never the private object.
    assert b"joined-fixture-confidential-20261019" not in claims_raw
    assert b"joined-fixture-confidential-20261019" not in owner_raw
    return claims


@pytest.mark.asyncio
async def test_three_distinct_processes_real_tls_signed_current_sessions_and_one_shot(
    monkeypatch,
):
    assert _EFFECT_DOMAIN == production._EFFECT_DOMAIN
    assert _OWNER_DOMAIN == production._OWNER_DOMAIN
    async with disposable_joined_witness() as lab:
        nonce = secrets.token_hex(16)
        responses = await lab.roles(nonce)
        assert [responses[role][0] for role in ("source", "target", "anonymous")] == [
            200, 200, 403
        ]
        assert responses["source"][1] == responses["target"][1]
        assert b"joined-fixture-confidential-20261019" in responses["source"][1]
        assert b"joined-fixture-confidential-20261019" not in responses["anonymous"][1]

        raw, signature = await _actual_pinned_tls_parser(monkeypatch, lab, nonce)
        observed = _verify_lab_receipt(lab, raw, signature, nonce)
        assert observed["finding_verified"] is False
        assert observed["report_release_approved"] is False

        with pytest.raises(production.IndependentEffectUnavailable):
            await _actual_pinned_tls_parser(monkeypatch, lab, nonce)
        assert lab.owner["public"] != lab.access["public"]
        assert len({lab.owner["pid"], lab.access["pid"], lab.target["pid"]}) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["public", "rotated"])
async def test_disposable_access_signer_denies_anonymous_public_or_rotated_signed_session(
    monkeypatch, scenario
):
    async with disposable_joined_witness(scenario) as lab:
        nonce = secrets.token_hex(16)
        results = await lab.roles(nonce)
        assert results["source"][0] == 200
        if scenario == "public":
            assert results["anonymous"][0] == 200
        else:
            assert results["target"][0] == 403
        with pytest.raises(production.IndependentEffectUnavailable):
            await _actual_pinned_tls_parser(monkeypatch, lab, nonce)


@pytest.mark.asyncio
@pytest.mark.parametrize("tls_attack", ["untrusted_ca", "wrong_hostname"])
async def test_production_transport_checks_real_tls_ca_and_sni(
    monkeypatch, tls_attack
):
    async with disposable_joined_witness() as lab:
        nonce = secrets.token_hex(16)
        await lab.roles(nonce)
        with pytest.raises(production.IndependentEffectUnavailable):
            await _actual_pinned_tls_parser(
                monkeypatch, lab, nonce,
                hostname="wrong.lab.invalid" if tls_attack == "wrong_hostname" else HOSTNAME,
                lab_ca=tls_attack != "untrusted_ca",
            )


@pytest.mark.asyncio
async def test_production_registry_rejects_even_cryptographically_valid_local_owner_access(
    monkeypatch,
):
    async with disposable_joined_witness() as lab:
        nonce = secrets.token_hex(16)
        await lab.roles(nonce)
        raw, sig = await _actual_pinned_tls_parser(monkeypatch, lab, nonce)
        _verify_lab_receipt(lab, raw, sig, nonce)

        engagement_id = "eng-joined-" + secrets.token_hex(8)
        flow = FlowRecord(
            id="flow-joined-" + secrets.token_hex(8),
            engagement_id=engagement_id,
            objective="Controlled synthetic fixture only",
            status="running",
        )
        now = int(time.time())
        # A correctly shaped *claim* of production trust cannot white-list
        # a private address. This exercises the real registry and top-level
        # production ingress without allowing a privileged lab bypass.
        alleged = {
            "version": 1,
            "enabled": True,
            "deployment": "production",
            "generation": 1,
            "not_before": now - 30,
            "not_after": now + 120,
            "engagement_id": engagement_id,
            "flow_id": flow.id,
            "origin": "https://" + HOSTNAME,
            "pinned_public_ipv4": "127.0.0.1",
            "allowed_hosts": [HOSTNAME, "witness-backup.lab.invalid"],
            "observer_key_id": "joined-access-only",
            "observer_operator_id": "lab-access-operator",
            "observer_public_key_b64": lab.access["public"],
            "owner_key_id": "joined-owner-only",
            "owner_operator_id": "lab-owner-operator",
            "owner_public_key_b64": lab.owner["public"],
        }
        monkeypatch.setenv("OSOP_INDEPENDENT_EFFECT_OBSERVER_JSON", json.dumps(alleged))

        async def forbidden_socket(**_kwargs):
            raise AssertionError("Production must reject loopback before any network access")

        monkeypatch.setattr(production, "_fetch_pinned_audit", forbidden_socket)
        with pytest.raises(production.IndependentEffectUnavailable):
            await production.fetch_independent_target_effect_signed_receipt(
                engagement_id=engagement_id, flow=flow, expected_nonce=nonce
            )
        with pytest.raises(production.IndependentEffectUnavailable):
            await production.verify_independent_target_effect_claims(
                observer_claims_json=raw,
                observer_signature_b64url=sig,
                expected_nonce=nonce,
                engagement_id=engagement_id,
                flow=flow,
                signed_authorization=None,
                original_source_task=None,
                source_task=None,
                target_task=None,
                finding_id="lab-candidate-only",
                review_decision_id="vfdec-" + "1" * 32,
                review_decision_sha256="1" * 64,
                qualification_id="teqa-" + "2" * 32,
                qualification_sha256="2" * 64,
                qualification_revision=1,
                proof_sha256="3" * 64,
                audit_sha256="4" * 64,
                trusted_current_authority_check=_never_current,
                trusted_current_review_check=_never_current,
                trusted_current_qualification_check=_never_current,
                trusted_one_shot_admission_check=_never_current,
            )


async def _never_current(*_args):
    """No synthetic fixture supplies real current signed ROE/review/Task authority."""
    return False
