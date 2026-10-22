"""Isolated synthetic crypto checks. No real senior release is enrolled here.

These tests do not issue a certificate, make a target request, reach a DB, or
activate a host endpoint. Positive checks prove only the verifier's encoding,
pinning and challenge semantics against deliberately ephemeral fixture keys.
"""

import base64
import copy
import hashlib
import json
from typing import Any

import pytest
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.safety import independent_release_authority as mod

NOW = 1_800_000_000


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _pub(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _encode(payload: dict[str, Any], signer: Ed25519PrivateKey, domain: bytes) -> bytes:
    signature = signer.sign(domain + mod._canonical(payload))
    return mod._canonical(
        {
            "claim": payload,
            "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
        }
    )


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def case(monkeypatch, tmp_path):
    senior, host, report, provider, target = [Ed25519PrivateKey.generate() for _ in range(5)]
    trust = mod.PinnedReleaseTrust(
        senior_key_id="separate-senior-release-root",
        senior_public_key=_pub(senior),
        host_public_key=_pub(host),
        report_signer_keys=(_pub(report),),
        provider_signer_keys=(_pub(provider),),
        target_owner_keys=(_pub(target),),
    )
    attestation, manifest, report_json = b"original signed attestation", b"manifest", b"json report"
    claim = {
        "schema": "ai-osop-independent-senior-release-v1",
        "senior_key_id": "separate-senior-release-root",
        "senior_sub": "senior-owner",
        "report": {
            "engagement_id": "eng-audit-20261021",
            "report_id": "report-eng-audit-20261021-v3",
            "attestation_sha256": _hash(attestation),
            "manifest_sha256": _hash(manifest),
            "report_json_sha256": _hash(report_json),
            "generation_task_id": "task-report-source",
        },
        "scope": {
            "tenant_id": "tenant-A",
            "owner_sub": "senior-owner",
            "flow_id": "flow-release-20261021",
            "flow_revision": 7,
            "authorization_id": "auth-release",
            "authorization_version": 4,
            "authorization_sha256": "a" * 64,
        },
        "target_owner_receipts": [
            {
                "finding_id": "finding-one",
                "verification_id": "itefv-" + "1" * 32,
                "verdict_sha256": "b" * 64,
                "qualification_id": "teqa-" + "2" * 32,
                "qualification_sha256": "c" * 64,
                "challenge_id": "itefc-" + "3" * 32,
                "target_owner_assertion_id": "tauth-" + "4" * 32,
                "target_owner_assertion_sha256": "d" * 64,
                "nonce_receipt_id": "tauth-" + "5" * 32,
                "nonce_receipt_sha256": "e" * 64,
            },
        ],
        "replica_qualifications": [
            {
                "replica_id": "host-a",
                "qualification_id": "qualification-A",
                "qualification_sha256": "f" * 64,
                "run_receipt_id": "runreceipt-A",
                "run_receipt_sha256": "1" * 64,
            },
            {
                "replica_id": "host-b",
                "qualification_id": "qualification-B",
                "qualification_sha256": "2" * 64,
                "run_receipt_id": "runreceipt-B",
                "run_receipt_sha256": "3" * 64,
            },
        ],
        "release_receipt_id": "srelease-" + "0" * 32,
        "release_receipt_sha256": "9" * 64,
        "issued_at": NOW - 10,
        "expires_at": NOW + 120,
    }
    # Deliberately do not enroll any CA, create a production-like host service,
    # or mint a certificate. Stand-in is used only for signed-host parsing tests.
    pinned = object.__new__(mod.PinnedHostCurrentAuthority)
    monkeypatch.setattr(mod.time, "time", lambda: NOW)
    return {
        "senior": senior,
        "host": host,
        "report": report,
        "provider": provider,
        "target": target,
        "trust": trust,
        "pinned": pinned,
        "claim": claim,
        "artifacts": (attestation, manifest, report_json),
    }


def _inputs(case):
    attestation, manifest, report_json = case["artifacts"]
    return {
        "trust": case["trust"],
        "expected_engagement_id": "eng-audit-20261021",
        "expected_report_id": "report-eng-audit-20261021-v3",
        "original_attestation_bytes": attestation,
        "original_manifest_bytes": manifest,
        "original_report_json_bytes": report_json,
    }


def _live_response(case, challenge, claim_sha, *, change=None, signer=None):
    claim = case["claim"]
    body = {
        "schema": "ai-osop-current-release-authority-v1",
        "claim_sha256": claim_sha,
        "challenge_sha256": _hash(challenge),
        "report": claim["report"],
        "scope": claim["scope"],
        "target_owner_receipts": claim["target_owner_receipts"],
        "replica_qualifications": claim["replica_qualifications"],
        "release_receipt_id": claim["release_receipt_id"],
        "release_receipt_sha256": claim["release_receipt_sha256"],
        "checked_at": NOW,
        "expires_at": NOW + 5,
        "decision": "current_independently_verified",
    }
    body = copy.deepcopy(body)
    if change:
        change(body)
    return _encode(body, signer or case["host"], mod.HOST_DOMAIN)


def _attach_host(case, monkeypatch, *, change=None, signer=None, echo=None):
    async def fake_host(self, challenge, claim_sha):
        if echo is not None:
            return echo
        return _live_response(case, challenge, claim_sha, change=change, signer=signer)

    monkeypatch.setattr(mod.PinnedHostCurrentAuthority, "__call__", fake_host)


async def _check(case, *, claim=None, authority=None, signer=None, inputs=None):
    return await mod.verify_independent_release_approval(
        _encode(
            claim if claim is not None else case["claim"],
            signer or case["senior"],
            mod.RELEASE_DOMAIN,
        ),
        current_authority=case["pinned"] if authority is None else authority,
        **(inputs or _inputs(case)),
    )


@pytest.mark.anyio
async def test_synthetic_dual_signature_exact_binding_only(case, monkeypatch):
    _attach_host(case, monkeypatch)
    checked = await _check(case)
    assert checked["production_certificate_issued"] is False
    assert checked["release_receipt_id"] == case["claim"]["release_receipt_id"]
    assert checked["status"] == "independent_senior_release_signature_and_host_snapshot_verified"


@pytest.mark.anyio
async def test_without_host_service_denies_even_with_valid_ephemeral_senior_signature(case):
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case, authority=False)
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case, authority=lambda *_: True)


@pytest.mark.anyio
async def test_wrong_original_report_bytes_and_request_denied_before_host(case, monkeypatch):
    _attach_host(case, monkeypatch)
    for name, changed in (
        ("original_attestation_bytes", b"substituted attestation"),
        ("original_manifest_bytes", b"substituted manifest"),
        ("original_report_json_bytes", b"substituted JSON"),
        ("expected_engagement_id", "eng-another-tenant"),
        ("expected_report_id", "report-other-v3"),
    ):
        inputs = _inputs(case)
        inputs[name] = changed
        with pytest.raises(mod.IndependentReleaseDenied):
            await _check(case, inputs=inputs)


@pytest.mark.anyio
async def test_senior_signature_must_be_from_independently_pinned_key(case, monkeypatch):
    _attach_host(case, monkeypatch)
    for wrong_key in (case["provider"], case["report"], case["target"], case["host"]):
        with pytest.raises(mod.IndependentReleaseDenied):
            await _check(case, signer=wrong_key)


def test_reject_key_role_reuse_and_missing_independent_registries(case):
    trust = case["trust"]
    for changes in (
        {"target_owner_keys": (trust.senior_public_key,)},
        {"provider_signer_keys": (trust.senior_public_key,)},
        {"report_signer_keys": (trust.senior_public_key,)},
        {"host_public_key": trust.senior_public_key},
        {"target_owner_keys": ()},
        {"provider_signer_keys": ()},
        {"report_signer_keys": ()},
    ):
        args = vars(trust).copy()
        args.update(changes)
        with pytest.raises(mod.IndependentReleaseDenied):
            mod.PinnedReleaseTrust(**args)


@pytest.mark.anyio
async def test_tampered_envelope_and_json_parser_fail_closed(case, monkeypatch):
    _attach_host(case, monkeypatch)
    valid = _encode(case["claim"], case["senior"], mod.RELEASE_DOMAIN)
    invalid = [
        valid.replace(b"eng-audit-20261021", b"eng-altered-20261021"),
        valid.replace(b'"claim":{', b'"claim":{"schema":"duplicated",'),
        valid.replace(b'"flow_revision":7', b'"flow_revision":NaN'),
        b"{" + b"x" * 65536 + b"}",
    ]
    for raw in invalid:
        with pytest.raises(mod.IndependentReleaseDenied):
            await mod.verify_independent_release_approval(
                raw, current_authority=case["pinned"], **_inputs(case)
            )


@pytest.mark.anyio
@pytest.mark.parametrize(
    "change",
    [
        lambda c: c["scope"].update(tenant_id="tenant-B"),
        lambda c: c["scope"].update(owner_sub="other-owner"),
        lambda c: c["scope"].update(flow_revision=999),
        lambda c: c["scope"].update(authorization_version=10),
        lambda c: c["report"].update(generation_task_id="task-other"),
        lambda c: c.update(issued_at=NOW - 400),
        lambda c: c.update(expires_at=NOW + 400),
        lambda c: c.update(release_receipt_sha256="not-a-digest"),
        lambda c: c.update(replica_qualifications=c["replica_qualifications"][:1]),
        lambda c: c["replica_qualifications"][1].update(replica_id="host-a"),
        lambda c: c.update(target_owner_receipts=[]),
        lambda c: c["target_owner_receipts"][0].pop("nonce_receipt_sha256"),
    ],
)
async def test_invalid_signed_claim_shapes_and_freshness_deny(case, monkeypatch, change):
    _attach_host(case, monkeypatch)
    claim = copy.deepcopy(case["claim"])
    change(claim)
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case, claim=claim)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(decision=True),
        lambda r: r.update(decision="VERIFIED"),
        lambda r: r.update(challenge_sha256="0" * 64),
        lambda r: r.update(claim_sha256="0" * 64),
        lambda r: r["scope"].update(owner_sub="foreign-owner"),
        lambda r: r["scope"].update(authorization_version=5),
        lambda r: r["report"].update(report_json_sha256="0" * 64),
        lambda r: r["target_owner_receipts"][0].update(verdict_sha256="f" * 64),
        lambda r: r["replica_qualifications"][0].update(replica_id="different"),
        lambda r: r.update(release_receipt_id="srelease-other"),
        lambda r: r.update(checked_at=NOW - 6),
        lambda r: r.update(expires_at=NOW + 60),
    ],
)
async def test_host_signed_but_stale_or_mismatched_current_authority_denies(
    case, monkeypatch, change
):
    _attach_host(case, monkeypatch, change=change)
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case)


@pytest.mark.anyio
async def test_wrong_host_signer_and_caller_boolean_payload_denied(case, monkeypatch):
    _attach_host(case, monkeypatch, signer=case["provider"])
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case)
    _attach_host(case, monkeypatch, echo=b'{"verified":true,"approved":true}')
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case)


@pytest.mark.anyio
async def test_cached_host_response_fails_fresh_challenge(case, monkeypatch):
    _attach_host(case, monkeypatch)
    saved_challenge = b"z" * 32
    old_sha = _hash(mod.RELEASE_DOMAIN + mod._canonical(case["claim"]))
    stale = _live_response(case, saved_challenge, old_sha)
    _attach_host(case, monkeypatch, echo=stale)
    monkeypatch.setattr(mod.secrets, "token_bytes", lambda count: b"y" * count)
    with pytest.raises(mod.IndependentReleaseDenied):
        await _check(case)


def test_pinned_host_endpoint_checks_tls_identity_and_credential(case, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("fixture")
    for url in (
        "http://authority.example/release/current-authority",
        "https://attacker@authority.example/release/current-authority",
        "https://authority.example/release/current-authority?allow=true",
        "https://authority.example/",
        "https://authority.example:444/release/current-authority",
        "https://127.0.0.1/release/current-authority",
        "https://localhost/release/current-authority",
        "https://intranet.local/release/current-authority",
        "https://authority.example/host/current",
    ):
        with pytest.raises(mod.IndependentReleaseDenied):
            mod.PinnedHostCurrentAuthority(url=url, ca_file=str(ca), service_token="A" * 40)
    with pytest.raises(mod.IndependentReleaseDenied):
        mod.PinnedHostCurrentAuthority(
            url="https://authority.example/release/current-authority",
            ca_file=str(ca),
            service_token="none",
        )


def test_host_rejects_mutable_or_untrusted_ca_even_with_correct_url(tmp_path):
    cert = tmp_path / "untrusted-ca.pem"
    cert.write_text("not a CA PEM")
    params = {
        "url": "https://authority.example.internal/release/current-authority",
        "ca_file": str(cert.resolve()),
        "service_token": "synthetic-host-token-only-0123456789",
    }
    with pytest.raises(mod.IndependentReleaseDenied):
        mod.PinnedHostCurrentAuthority(**params)
    link = tmp_path / "linked.pem"
    try:
        link.symlink_to(cert)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this host")
    with pytest.raises(mod.IndependentReleaseDenied):
        mod.PinnedHostCurrentAuthority(**{**params, "ca_file": str(link)})


@pytest.mark.anyio
@pytest.mark.parametrize("status,oversized", [(200, False), (302, False), (200, True)])
async def test_real_host_client_protocol_enforces_bounds_and_no_redirects(
    case, monkeypatch, status, oversized
):
    """Fake only HTTP transport, using the production __call__ implementation."""
    pinned = object.__new__(mod.PinnedHostCurrentAuthority)
    pinned._url = "https://authority.example.internal/release/current-authority"
    pinned._ssl_context = object()  # transport captures this without opening a socket
    pinned._token = "separate-opaque-host-service-token-0123456789"
    calls = []

    class FakeResponse:
        status_code = status

        def __init__(self, body):
            self.body = body

        async def aiter_bytes(self):
            if oversized:
                yield b"x" * (mod._MAX + 1)
            else:
                yield self.body

    class FakeStream:
        def __init__(self, response):
            self.response = response

        async def __aenter__(self):
            return self.response

        async def __aexit__(self, *_):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            calls.append(("client", kwargs))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        def stream(self, method, url, *, headers, content):
            calls.append(("request", (method, url, headers)))
            request = json.loads(content)
            raw = base64.urlsafe_b64decode(request["challenge"] + "==")
            body = _live_response(case, raw, request["claim_sha256"])
            return FakeStream(FakeResponse(body))

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    if status != 200 or oversized:
        with pytest.raises(mod.IndependentReleaseDenied):
            await _check(case, authority=pinned)
    else:
        checked = await _check(case, authority=pinned)
        assert checked["production_certificate_issued"] is False
    assert calls[0][1]["follow_redirects"] is False
    assert calls[0][1]["trust_env"] is False
    assert calls[0][1]["verify"] is pinned._ssl_context
    assert calls[1][1][0] == "POST"
    assert calls[1][1][1] == pinned._url
    assert calls[1][1][2]["Authorization"] == "Bearer " + pinned._token
