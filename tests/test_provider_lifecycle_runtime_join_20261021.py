"""Synthetic, non-network host HTTPS material/revocation proof join.

Never opens a vault, application database, Docker, provider or paid API. The
inline self-signed *test CA* and Ed25519 keys cannot certify a deployment.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from ai_osop.core.provider_credential_lifecycle import (
    _DOMAIN,
    _canonical,
    _policy_digest,
    _reference_digest,
    CredentialLifecycleDenied,
    CredentialReadinessRequest,
    HostVaultReadbackChannel,
    HostVaultRuntimeReadinessAdapter,
)


NOW = 1792584000
KINDS = ("profile", "flow", "principal", "policy", "vault", "budget", "vault_revocation")
MATERIAL_URL = "https://vault-readback.example.test/v1/provider-credentials/material-readback"
REVOCATION_URL = "https://vault-revocation.example.test/v1/provider-credentials/revocation-readback"
TOKEN_MATERIAL = "host-only-material-service-proof-12345"
TOKEN_REVOCATION = "host-only-revoke-service-proof-12345"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


@pytest.fixture(scope="module")
def ca_pem() -> bytes:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Readback Root CA")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def _request() -> tuple[CredentialReadinessRequest, Dict[str, Dict[str, Any]]]:
    reviewed = {
        "provider": "openai", "model": "openai/test-model",
        "operations": ["completion"], "allowed_roles": ["vuln_analysis"],
        "capabilities": ["text_completion"], "max_output_tokens": 512,
        "budget_source": "signed_postgres_roe",
    }
    r = CredentialReadinessRequest(
        engagement_id="eng-tenant-a",
        flow_id="flow-tenant-a",
        flow_revision=7, authorization_version=9,
        authorization_id="auth-pinned", authorization_sha256=_hash("signed-roe"),
        owner_sub="owner-a", actor_sub="owner-a",
        task_id="task-provider-1", agent_role="vuln_analysis",
        ref_id="pcref-" + "b" * 32, reference_sha256="0" * 64,
        reference_revision=6, generation=3,
        provider="openai", slot="primary",
        policy_review_id="provider-review-" + "c" * 32,
        policy_sha256=_policy_digest(reviewed),
        model="openai/test-model", operation="completion",
        cost_request_micro_usd=300, purpose="rotate",
    )
    r = replace(r, reference_sha256=_reference_digest(r))
    proofs: Dict[str, Dict[str, Any]] = {
        "profile": {
            "ref_id": r.ref_id,
            "reference_sha256": r.reference_sha256,
            "reference_revision": r.reference_revision,
            "generation": r.generation, "provider": r.provider, "slot": r.slot,
            "owner_sub": r.owner_sub, "policy_review_id": r.policy_review_id,
            "policy_sha256": r.policy_sha256, "flow_revision": r.flow_revision,
            "authorization_version": r.authorization_version,
            "authorization_id": r.authorization_id,
            "authorization_sha256": r.authorization_sha256,
            "status": "approved", "revoked": False, "senior_active": True,
            "senior_sub": "independent-senior", "profile_valid_until": NOW + 1000,
        },
        "flow": {
            "owner_sub": r.owner_sub, "flow_revision": r.flow_revision,
            "authorization_version": r.authorization_version,
            "authorization_id": r.authorization_id,
            "authorization_sha256": r.authorization_sha256,
            "status": "running", "revoked": False,
        },
        "principal": {
            "actor_sub": r.actor_sub, "role": "operator", "disabled": False,
            "bearer_expires_at": NOW + 1000,
        },
        "policy": {
            "review_id": r.policy_review_id, "policy_sha256": r.policy_sha256,
            "creator_sub": r.owner_sub, "provider": r.provider,
            "status": "approved", "revoked": False, "senior_active": True,
            "senior_sub": "other-independent-senior", "policy": reviewed,
        },
        "vault": {
            "ref_id": r.ref_id, "reference_sha256": r.reference_sha256,
            "reference_revision": r.reference_revision,
            "generation": r.generation, "provider": r.provider, "slot": r.slot,
            "policy_sha256": r.policy_sha256, "flow_revision": r.flow_revision,
            "authorization_version": r.authorization_version,
            "authorization_sha256": r.authorization_sha256,
            "material_source": "vault_material_store_current",
            "credential_material": "present", "vault_state": "active",
            "credential_version_sha256": _hash("current-secret-v3"),
            "credential_valid_until": NOW + 500,
            "previous_generation": r.generation - 1,
            "previous_vault_state": "revoked",
            "previous_credential_version_sha256": _hash("previous-secret-v2"),
            "vault_revision": 101,
            "observed_revocation_revision": 72,
        },
        "budget": {
            "task_id": r.task_id, "agent_role": r.agent_role,
            "model": r.model, "operation": r.operation,
            "budget_source": "signed_postgres_roe",
            "budget_state": "within_current_limit",
            "authorization_version": r.authorization_version,
            "authorization_sha256": r.authorization_sha256,
            "flow_revision": r.flow_revision, "available_micro_usd": 1000,
        },
    }
    proofs["vault_revocation"] = {
        **{
            name: proofs["vault"][name] for name in (
                "ref_id", "reference_sha256", "reference_revision",
                "generation", "provider", "slot", "policy_sha256",
                "flow_revision", "authorization_version", "authorization_sha256",
                "credential_version_sha256", "vault_revision",
                "previous_generation", "previous_credential_version_sha256",
            )
        },
        "revocation_source": "independent_current_revocation_ledger",
        "credential_revoked": False, "previous_credential_revoked": True,
        "revocation_revision": 73,
    }
    return r, proofs


def _bundle(
    ca_pem: bytes,
    *,
    minimum_vault_revision: int = 100,
    minimum_revocation_revision: int = 70,
) -> tuple[
    HostVaultRuntimeReadinessAdapter, CredentialReadinessRequest,
    Dict[str, Dict[str, Any]], Dict[str, Any]
]:
    r, proofs = _request()
    signer = {kind: ed25519.Ed25519PrivateKey.generate() for kind in KINDS}
    control: Dict[str, Any] = {
        "calls": [], "status": 200, "bad_response": None, "bad_signer_kind": None,
    }

    def signed(kind: str, nonce: str) -> bytes:
        claims = {
            "engagement_id": r.engagement_id, "flow_id": r.flow_id,
            "nonce": nonce, "issued_at": NOW, "expires_at": NOW + 10,
            **proofs[kind],
        }
        private = signer["profile"] if control["bad_signer_kind"] == kind else signer[kind]
        signature = private.sign(_DOMAIN + kind.encode("ascii") + b"\x00" + _canonical(claims))
        return json.dumps({
            "claims": claims,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
        }, separators=(",", ":")).encode("ascii")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.scheme == "https"
        assert request.headers.get("content-type") == "application/json"
        assert request.headers.get("cache-control") == "no-store"
        incoming = json.loads(request.content)
        assert set(incoming) == {
            "nonce", "engagement_id", "flow_id", "flow_revision",
            "authorization_version", "authorization_sha256", "ref_id",
            "reference_sha256", "reference_revision", "generation",
            "provider", "slot", "policy_sha256",
        }
        assert incoming["ref_id"] == r.ref_id
        kind = "vault" if request.url.path.endswith("/material-readback") else "vault_revocation"
        expected_host = "vault-readback.example.test" if kind == "vault" else "vault-revocation.example.test"
        assert request.url.host == expected_host
        assert request.headers["Authorization"] == (
            "Bearer " + (TOKEN_MATERIAL if kind == "vault" else TOKEN_REVOCATION)
        )
        control["calls"].append(kind)
        if control["bad_response"] is not None:
            content = control["bad_response"]
        else:
            content = signed(kind, incoming["nonce"])
        return httpx.Response(
            status_code=control["status"],
            headers={"Content-Type": "application/json"},
            content=content,
        )

    def reader(kind: str):
        async def from_host(context: CredentialReadinessRequest, nonce: str) -> bytes:
            assert context == r
            return signed(kind, nonce)
        return from_host

    adapter = HostVaultRuntimeReadinessAdapter(
        other_public_keys={
            kind: signer[kind].public_key() for kind in KINDS
            if kind not in ("vault", "vault_revocation")
        },
        other_readers={
            kind: reader(kind) for kind in KINDS
            if kind not in ("vault", "vault_revocation")
        },
        vault_public_key=signer["vault"].public_key(),
        revocation_public_key=signer["vault_revocation"].public_key(),
        material_channel=HostVaultReadbackChannel(
            url=MATERIAL_URL, ca_pem=ca_pem, service_bearer=TOKEN_MATERIAL,
        ),
        revocation_channel=HostVaultReadbackChannel(
            url=REVOCATION_URL, ca_pem=ca_pem, service_bearer=TOKEN_REVOCATION,
        ),
        minimum_vault_revision=minimum_vault_revision,
        minimum_revocation_revision=minimum_revocation_revision,
        transport=httpx.MockTransport(handler),
        clock=lambda: NOW,
    )
    control["signer"] = signer
    return adapter, r, proofs, control


def test_pinned_https_two_independent_host_readbacks_join_every_current_authority(
    ca_pem: bytes,
) -> None:
    adapter, r, _, control = _bundle(ca_pem)
    outcome = asyncio.run(adapter.assess(r))
    assert control["calls"] == ["vault", "vault_revocation"]
    assert outcome.proof_expires_at == NOW + 10
    assert outcome.rotation_readiness_verified is True
    assert not outcome.budget_reserved
    assert not outcome.provider_contacted
    assert not outcome.provider_accepts_credential_verified
    assert not outcome.dispatch_authorized
    assert TOKEN_MATERIAL not in repr(adapter._material)
    assert TOKEN_REVOCATION not in repr(adapter._revocation)
    assert "current-secret-v3" not in repr(outcome)


@pytest.mark.parametrize("kind,member,value", [
    ("vault", "vault_revision", 99),
    ("vault", "observed_revocation_revision", 80),
    ("vault", "reference_revision", 7),
    ("vault", "generation", 2),
    ("vault", "credential_material", "absent"),
    ("vault", "material_source", "caller_boolean"),
    ("vault", "policy_sha256", _hash("wrong-policy")),
    ("vault_revocation", "vault_revision", 102),
    ("vault_revocation", "revocation_revision", 69),
    ("vault_revocation", "credential_revoked", True),
    ("vault_revocation", "previous_credential_revoked", False),
    ("vault_revocation", "previous_credential_version_sha256", _hash("mismatch")),
    ("vault_revocation", "credential_version_sha256", _hash("different-version")),
    ("vault_revocation", "revocation_source", "provider_assertion"),
    ("vault_revocation", "reference_sha256", "0" * 64),
    ("vault_revocation", "generation", 9),
    ("vault", "api_key", "sk-not-for-output"),
    ("vault", "credential_handle", "hidden-provider-key-handle"),
    ("vault_revocation", "secret_value", "hidden-provider-key-material"),
])
def test_signed_host_readback_revision_revocation_cross_join_deny(
    ca_pem: bytes, kind: str, member: str, value: Any,
) -> None:
    adapter, r, proofs, _ = _bundle(ca_pem)
    proofs[kind][member] = value
    with pytest.raises(CredentialLifecycleDenied):
        asyncio.run(adapter.assess(r))


def test_material_revision_rollback_and_revocation_rollback_after_positive(
    ca_pem: bytes,
) -> None:
    adapter, r, proofs, _ = _bundle(ca_pem)
    async def scenario() -> None:
        await adapter.assess(r)
        proofs["vault"]["vault_revision"] = 102
        proofs["vault_revocation"]["vault_revision"] = 102
        proofs["vault"]["observed_revocation_revision"] = 74
        proofs["vault_revocation"]["revocation_revision"] = 74
        await adapter.assess(r)
        proofs["vault"]["vault_revision"] = 101
        proofs["vault_revocation"]["vault_revision"] = 101
        with pytest.raises(CredentialLifecycleDenied):
            await adapter.assess(r)
        proofs["vault"]["vault_revision"] = 103
        proofs["vault_revocation"]["vault_revision"] = 103
        proofs["vault"]["observed_revocation_revision"] = 72
        proofs["vault_revocation"]["revocation_revision"] = 73
        with pytest.raises(CredentialLifecycleDenied):
            await adapter.assess(r)
    asyncio.run(scenario())


def test_host_revocation_forgery_or_malformed_response_fails_closed(
    ca_pem: bytes,
) -> None:
    adapter, r, _, control = _bundle(ca_pem)
    async def scenario() -> None:
        for forged_kind in ("vault", "vault_revocation"):
            control["bad_signer_kind"] = forged_kind
            with pytest.raises(CredentialLifecycleDenied):
                await adapter.assess(r)
        control["bad_signer_kind"] = None
        control["status"] = 307
        with pytest.raises(CredentialLifecycleDenied):
            await adapter.assess(r)
        control["status"] = 200
        for response in (
            b"x" * 9000,
            b'{"claims":{},"claims":{},"signature_b64":""}',
            b'{"secret":"should-never-pass"}',
        ):
            control["bad_response"] = response
            with pytest.raises(CredentialLifecycleDenied):
                await adapter.assess(r)
    asyncio.run(scenario())


@pytest.mark.parametrize("url", [
    "http://vault-readback.example.test/v1/provider-credentials/material-readback",
    "https://localhost/v1/provider-credentials/material-readback",
    "https://127.0.0.1/v1/provider-credentials/material-readback",
    "https://vault-readback.example.test:8443/v1/provider-credentials/material-readback",
    "https://vault-readback.example.test/v1/provider-credentials/material-readback?token=bad",
    "https://bad@vault-readback.example.test/v1/provider-credentials/material-readback",
    "https://vault-readback.example.test/other-path",
    "https://vault-readback.example.test/v1/provider-credentials/%6daterial-readback",
])
def test_disallowed_host_urls_denied_before_any_request(
    ca_pem: bytes, url: str,
) -> None:
    with pytest.raises(CredentialLifecycleDenied):
        HostVaultReadbackChannel(url=url, ca_pem=ca_pem, service_bearer=TOKEN_MATERIAL)


def test_missing_vault_cert_or_enrolled_root_fails_before_network(ca_pem: bytes) -> None:
    for missing_pem in (b"", b"not a CA certificate"):
        with pytest.raises(CredentialLifecycleDenied):
            HostVaultReadbackChannel(
                url=MATERIAL_URL, ca_pem=missing_pem,
                service_bearer=TOKEN_MATERIAL,
            )
    adapter, _, _, c = _bundle(ca_pem)
    other = {k: v for k, v in adapter._verifier._keys.items() if k != "vault"}
    readers = {k: v for k, v in adapter._verifier._readers.items() if k != "vault"}
    for no_revocation_root in (None, c["signer"]["vault"].public_key()):
        with pytest.raises(CredentialLifecycleDenied):
            HostVaultRuntimeReadinessAdapter(
                other_public_keys=other,
                other_readers=readers,
                vault_public_key=c["signer"]["vault"].public_key(),
                revocation_public_key=no_revocation_root,
                material_channel=adapter._material,
                revocation_channel=adapter._revocation,
                minimum_vault_revision=1, minimum_revocation_revision=1,
            )


def test_no_response_after_material_readback_does_not_claim_vault_current(
    ca_pem: bytes,
) -> None:
    adapter, r, _, control = _bundle(ca_pem)
    original_transport = adapter._transport
    async def offline(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("revocation-readback"):
            raise httpx.ConnectError("mock independent revocation host offline")
        assert original_transport is not None
        return await original_transport.handle_async_request(request)
    # Valid signed material readback followed by a missing independent
    # revocation witness MUST still deny.
    adapter._transport = httpx.MockTransport(offline)
    with pytest.raises(CredentialLifecycleDenied):
        asyncio.run(adapter.assess(r))
    assert control["calls"] == ["vault"]
