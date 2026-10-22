"""Host-side strict original Browser READ-ONLY bridge against actual ASGI routes.

Synthetic test-owned original bytes and FakePG central fixture only; *no*
browser navigation, application DB, Docker, live target or provider network.
Custody signer and raw-byte reader here are explicitly TEST fixture producers
and cannot establish a production host/process owner or target-side effect.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping, Optional

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.adapters.native_browser_current_original_bridge import (
    BrowserOriginalBridgeDenied,
    NativeBrowserCurrentOriginalBridge,
    _CUSTODY_DOMAIN,
)
from tests.qualification.test_browser_central_current_api_20261021 import (
    HOST_TOKEN,
    api_case,
)
from tests.qualification.test_browser_current_central_state_join_20261021 import (
    _proof,
    current_case as signed_current_case,
)
from tests.qualification.test_browser_current_original_custody_join_20261021 import (
    _complete_local_original,
    _expected,
    custody_case,
)


class FreshCentralReadOnlyTransport(httpx.AsyncBaseTransport):
    """FakePG fixture resets its *in-memory statement trace* per request."""

    def __init__(self, case: Mapping[str, Any]) -> None:
        self.case = case
        self.inner = httpx.ASGITransport(app=case["app"], client=("127.0.0.1", 14567))
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.case["pg"].statements.clear()
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


class CaptureNativeCalls(httpx.AsyncBaseTransport):
    def __init__(self, case: Mapping[str, Any]) -> None:
        self.calls = 0
        self.inner = httpx.ASGITransport(app=case["native"].app, client=("127.0.0.1", 14568))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        assert request.url.path == "/mcp/request/evidence/readback"
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self.inner.aclose()


@pytest.fixture
def bridge_case(
    custody_case: dict[str, Any],
) -> dict[str, Any]:
    case = custody_case
    _complete_local_original(case)
    independent_key = Ed25519PrivateKey.generate()
    read_events: list[str] = []
    sign_events: list[dict[str, Any]] = []
    transport = FreshCentralReadOnlyTransport(case)
    native_transport = CaptureNativeCalls(case)
    central_client = httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1/",
        follow_redirects=False,
    )
    provider_client = httpx.AsyncClient(
        transport=native_transport,
        base_url="http://127.0.0.1/",
        follow_redirects=False,
    )

    async def original_reader(
        binding: Mapping[str, str], artifacts: Mapping[str, Mapping[str, Any]]
    ) -> Mapping[str, bytes]:
        assert binding == case["binding"]
        read_events.append("owned-originals")
        # Fixture trust boundary: only path names from independently verified
        # signed manifest, confined to a test-owned private tenant directory.
        result = {}
        for name, row in artifacts.items():
            candidate = case["tenant"] / row["path"]
            assert candidate.is_relative_to(case["tenant"] / "captures")
            assert not candidate.is_symlink()
            result[name] = candidate.read_bytes()
        return result

    async def signed_observation(claims: Mapping[str, Any]) -> Mapping[str, Any]:
        sign_events.append(copy.deepcopy(dict(claims)))
        return _proof(independent_key, "hostCustody", _CUSTODY_DOMAIN, dict(claims))

    case.update(
        {
            "central_client": central_client,
            "provider_client": provider_client,
            "central_transport": transport,
            "native_transport": native_transport,
            "reader": original_reader,
            "signer": signed_observation,
            "read_events": read_events,
            "sign_events": sign_events,
            "custody_key": independent_key,
            "custody_roots": {"hostCustody": independent_key.public_key().public_bytes_raw()},
            "expected": {
                **_expected(case),
                "authorization_sha256": case["source"]["claims"]["authorization_sha256"],
                "original_intent_sha256": case["rows"]["action"]["intent_sha256"],
                "url_sha256": case["source"]["claims"]["url_sha256"],
            },
        }
    )
    return case


def _bridge(case: dict[str, Any], **overrides: Any) -> NativeBrowserCurrentOriginalBridge:
    values = {
        "enabled": True,
        "central_client": case["central_client"],
        "provider_client": case["provider_client"],
        "central_bearer": HOST_TOKEN,
        "provider_bearer": "local-readback-only-provider-token-20261021",
        "original_reader": case["reader"],
        "independent_signer": case["signer"],
        "independent_roots": case["custody_roots"],
    }
    values.update(overrides)
    return NativeBrowserCurrentOriginalBridge(**values)


async def _join(case: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    return await _bridge(case, **overrides).join(
        case["source"],
        case["attestation"],
        case["expected"],
    )


@pytest.mark.asyncio
async def test_actual_mounted_two_routes_original_byte_host_witness_and_independent_signature(
    bridge_case: dict[str, Any],
) -> None:
    case = bridge_case
    result = await _join(case)
    assert result["status"] == "host_original_bytes_current_read_only"
    assert result["independent_target_effect_verified"] is False
    assert result["automatic_retry_authorized"] is False
    assert result["production_release_certified"] is False
    assert "original_bytes" not in result
    assert "raw" not in json.dumps(result)
    assert set(result["artifacts"]) == {"screenshot", "dom", "har"}
    assert result["custody_claims"]["original_bytes_read"] is True
    assert result["custody_claims"]["target_effect_verified"] is False
    assert result["custody_claims"]["automatic_retry_authorized"] is False
    assert (
        result["custody_claims"]["original_intent_sha256"]
        == case["expected"]["original_intent_sha256"]
    )
    assert len(case["read_events"]) == 1
    assert len(case["sign_events"]) == 1
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
    assert case["pg"].statements[0].endswith("READ ONLY")
    assert all(stmt.startswith("SELECT ") for stmt in case["pg"].statements[1:])
    assert case["journal"].reserve() is False
    assert case["rows"]["action"]["status"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "missing",
    ["disabled", "original_reader", "independent_signer", "independent_roots"],
)
async def test_default_deny_absent_external_original_reader_or_enrolled_signer(
    bridge_case: dict[str, Any],
    missing: str,
) -> None:
    case = bridge_case
    options = {"enabled": False} if missing == "disabled" else {missing: None}
    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case, **options)
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
    assert case["read_events"] == []
    assert case["sign_events"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["screenshot", "dom", "har"])
async def test_actual_byte_mutation_denies_before_host_custody_signing(
    bridge_case: dict[str, Any],
    kind: str,
) -> None:
    case = bridge_case
    path = case["paths"][kind]
    path.write_bytes(path.read_bytes() + b"BAD_CHANGED_ORIGINAL")
    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case)
    assert case["central_transport"].calls == 1
    assert case["native_transport"].calls == 1
    assert not case["read_events"]
    assert not case["sign_events"]
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_host_reader_missing_raw_or_wrong_sha_denies_before_lifecycle_signer(
    bridge_case: dict[str, Any],
) -> None:
    case = bridge_case

    async def forged_reader(
        binding: Mapping[str, str],
        artifacts: Mapping[str, Mapping[str, Any]],
    ) -> Mapping[str, bytes]:
        return {name: b"fake-provider-wants-owner-cert" for name in artifacts}

    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case, original_reader=forged_reader)
    assert case["sign_events"] == []
    assert case["native_transport"].calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forgery",
    ["native_signer", "source_signer", "forged_effect", "untrusted_custody_kid"],
)
async def test_custody_signer_must_be_independent_and_never_assert_target_effect(
    bridge_case: dict[str, Any],
    forgery: str,
) -> None:
    case = bridge_case
    if forgery == "native_signer":
        key = case["native_key"]
        roots = {"hostCustody": key.public_key().public_bytes_raw()}
    elif forgery == "source_signer":
        key = case["source_key"]
        roots = {"hostCustody": key.public_key().public_bytes_raw()}
    else:
        key = case["custody_key"]
        roots = case["custody_roots"]

    async def bad_signer(claims: Mapping[str, Any]) -> Mapping[str, Any]:
        claim = dict(claims)
        if forgery == "forged_effect":
            claim["target_effect_verified"] = True
        kid = "untrustedHost" if forgery == "untrusted_custody_kid" else "hostCustody"
        return _proof(key, kid, _CUSTODY_DOMAIN, claim)

    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case, independent_signer=bad_signer, independent_roots=roots)
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_revoke_current_roe_or_change_trusted_owner_denies_before_byte_read(
    bridge_case: dict[str, Any],
) -> None:
    case = bridge_case
    case["rows"]["authorization"]["status"] = "revoked"
    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case)
    assert not case["read_events"]
    assert not case["sign_events"]
    assert case["native_transport"].calls == 0
    case["rows"]["authorization"]["status"] = "active"
    wrong = copy.deepcopy(case["expected"])
    wrong["owner_id"] = "operator-untrusted-foreign"
    with pytest.raises(BrowserOriginalBridgeDenied):
        await _bridge(case).join(case["source"], case["attestation"], wrong)
    assert case["native_transport"].calls == 0


@pytest.mark.asyncio
async def test_current_authority_revoked_between_before_and_after_byte_checks_fails_closed(
    bridge_case: dict[str, Any],
) -> None:
    case = bridge_case
    original_reader = case["reader"]

    async def revoking_reader(
        binding: Mapping[str, str],
        artifacts: Mapping[str, Mapping[str, Any]],
    ) -> Mapping[str, bytes]:
        data = await original_reader(binding, artifacts)
        case["rows"]["authorization"]["status"] = "revoked"
        return data

    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case, original_reader=revoking_reader)
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 2
    assert not case["sign_events"]
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_lost_central_ack_or_missing_provider_readback_keeps_unknown_no_retry(
    bridge_case: dict[str, Any],
) -> None:
    case = bridge_case
    case["central_bearer_secret"] = HOST_TOKEN
    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case, central_bearer="not-current-authority-token-20261021")
    assert case["central_transport"].calls == 1
    assert case["native_transport"].calls == 0
    assert not case["read_events"]
    with pytest.raises(BrowserOriginalBridgeDenied):
        await _join(case, provider_bearer="provider-refuses-unknown-authority-20261021")
    assert case["central_transport"].calls == 2
    assert case["native_transport"].calls == 1
    assert not case["sign_events"]
    assert case["journal"].reserve() is False


@pytest.mark.asyncio
async def test_reject_untrusted_remote_endpoint_before_credentials_leave_host(
    bridge_case: dict[str, Any],
) -> None:
    case = bridge_case
    async with httpx.AsyncClient(base_url="http://attacker.example/") as unsafe:
        with pytest.raises(BrowserOriginalBridgeDenied):
            await _join(case, central_client=unsafe)
    assert case["central_transport"].calls == 0
    assert case["native_transport"].calls == 0
