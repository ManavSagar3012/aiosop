"""SourceMap host readback API and original immutable admission constraints.

Actual local HMAC JWT parsing is used. All host evidence is inert synthetic
metadata: route-positive tests stub the final witness solely to test API
plumbing, never to assert production 0033/0035/0037 qualification. No app DB,
container, mount, external provider, grant or scanner is accessed.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any, Optional

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import deps
from ai_osop.api import source_map_host_witness_operator as host
from ai_osop.core.config import settings
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    _require_operational_pair,
)

SECRET = "source-map-operator-offline-jwt-test-20261022"
URI = "/system/source-map/host-witness/readback"
REQUEST = "req-" + "a" * 48
ENGAGEMENT = "eng-source-map-qualification"
IDENTITY = {
    "request_id": REQUEST,
    "engagement_id": ENGAGEMENT,
    "flow_id": "flow-original",
    "task_id": "task-original",
    "subtask_id": "subtask-original",
    "action_id": "action-" + "b" * 32,
    "owner_id": "owner-original",
    "approval_id": "approval-original",
    "lease_id": "lease-original",
    "artifact_sha256": "c" * 64,
    "manifest_sha256": "d" * 64,
    "authorization_sha256": "e" * 64,
}
PRIVATE = "test-only-secret-pid-private-path-or-signed-token-must-not-leak"


def _bearer(role: str = "senior_operator", *, secret: str = SECRET, expired: bool = False) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": "independently-signed-operator",
            "role": role,
            "iat": now - 5,
            "exp": now - 4 if expired else now + 120,
        },
        secret,
        algorithm="HS256",
    )


def _proofs() -> dict[str, Any]:
    original = {"claims": dict(IDENTITY), "kid": "SourceKid", "signature": PRIVATE}
    return {
        "supervisor_observation": {"claims": {}, "kid": "LedgerKid", "signature": PRIVATE},
        "source_status": original,
        "source_preflight_proof": {
            "claims": dict(IDENTITY),
            "kid": "SourceKid",
            "signature": PRIVATE,
        },
        "native_grant_token": {"claims": {}, "kid": "GrantKid", "signature": PRIVATE},
        "live_process_witness": {"claims": {}, "kid": "ProcessKid", "signature": PRIVATE},
        "signed_supervisor_source": {"claims": {}, "kid": "SupervisorKid", "signature": PRIVATE},
        "native_mount_witness": {"claims": {}, "kid": "MountKid", "signature": PRIVATE},
    }


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "api_token", "shared-development-api-key")
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    for index, key in enumerate(host._ROOT_ENVS, start=1):
        public = (
            Ed25519PrivateKey.from_private_bytes(bytes((index,)) * 32)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        monkeypatch.setenv(
            key, json.dumps({f"Signer{index:02}": base64.b64encode(public).decode("ascii")})
        )
    return {"app": FastAPI(), "monkeypatch": monkeypatch}


def _mount(
    api: dict[str, Any], service: Optional[host.SourceMapHostWitnessOperator] = None
) -> None:
    api["app"].include_router(host.create_source_map_host_witness_router(service))


async def _call(
    api: dict[str, Any],
    *,
    token: Optional[str] = None,
    body: Optional[bytes] = None,
    headers: Optional[list[tuple[str, str]]] = None,
    method: str = "POST",
    suffix: str = "",
    scheme: str = "http",
    peer: str = "127.0.0.1",
) -> httpx.Response:
    supplied = list(headers or [])
    if token is not None:
        supplied.append(("Authorization", "Bearer " + token))
    if body is None:
        body = json.dumps({"engagement_id": ENGAGEMENT, "request_id": REQUEST}).encode()
    if not any(key.lower() == "content-type" for key, _ in supplied):
        supplied.append(("Content-Type", "application/json"))
    transport = httpx.ASGITransport(app=api["app"], client=(peer, 40400))
    async with httpx.AsyncClient(
        transport=transport, base_url=f"{scheme}://original-source-map.test"
    ) as client:
        return await client.request(method, URI + suffix, headers=supplied, content=body)


def _unverified(response: httpx.Response, expected: int) -> None:
    assert response.status_code == expected, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert PRIVATE not in response.text
    if response.status_code in (503, 422, 415, 413):
        assert response.json()["detail"]["status"] == "UNVERIFIED"
        assert response.json()["detail"]["original_action_replayed"] is False
        assert response.json()["detail"]["automatic_retry_authorized"] is False


@pytest.mark.asyncio
async def test_signed_senior_unconfigured_fails_closed_and_native_grant_pair_is_inert(
    api: dict[str, Any]
) -> None:
    _mount(api)
    result = await _call(api, token=_bearer())
    _unverified(result, 503)
    assert result.json()["detail"]["reason"] == "INDEPENDENT_HOST_VERIFIER_UNAVAILABLE"
    with pytest.raises(NativeMCPGrantDenied):
        _require_operational_pair("source-map-mcp", "inspect_local_original_sourcemap", "READ_ONLY")


@pytest.mark.asyncio
async def test_signed_ordinary_operator_and_bad_tokens_denied_before_host_reader(
    api: dict[str, Any]
) -> None:
    calls: list[tuple[str, str, str]] = []

    async def source(
        engagement: str, request: str, operator: str
    ) -> host.HostPinnedSourceMapReadback:
        calls.append((engagement, request, operator))
        return host.HostPinnedSourceMapReadback(dict(IDENTITY), _proofs())

    _mount(
        api,
        host.SourceMapHostWitnessOperator(
            independently_enrolled=True,
            host_pinned_reader=source,
            actions=object.__new__(FlowMCPActionStore),
        ),
    )
    for token, expected in (
        (_bearer("operator"), 403),
        (_bearer(expired=True), 401),
        (_bearer(secret="wrong-signer"), 401),
        ("shared-development-api-key", 401),
    ):
        response = await _call(api, token=token)
        assert response.status_code == expected, response.text
    response = await _call(api)
    assert response.status_code in (401, 403)
    assert calls == []


@pytest.mark.asyncio
async def test_host_channel_denies_query_browser_and_remote_plaintext(api: dict[str, Any]) -> None:
    _mount(api)
    for arguments in (
        {"suffix": "?token=invalid"},
        {"peer": "192.0.2.10"},
        {"headers": [("Origin", "https://external.invalid")]},
        {"headers": [("Authorization", "Bearer " + _bearer())]},
        {"headers": [("Content-Encoding", "gzip")]},
    ):
        result = await _call(api, token=_bearer(), **arguments)
        assert result.status_code in (401, 403, 415), result.text
        assert PRIVATE not in result.text


@pytest.mark.asyncio
async def test_only_exact_original_identity_is_accepted(api: dict[str, Any]) -> None:
    _mount(api)
    payloads = (
        b"{}",
        b'{"engagement_id":"eng-valid","request_id":"req-bad"}',
        b'{"engagement_id":"eng-valid","request_id":"' + REQUEST.encode() + b'","path":"/proc/1"}',
        b'{"engagement_id":"'
        + ENGAGEMENT.encode()
        + b'","request_id":"'
        + REQUEST.encode()
        + b'","roots":{}}',
        b'{"engagement_id":"'
        + ENGAGEMENT.encode()
        + b'","request_id":"'
        + REQUEST.encode()
        + b'","request_id":"'
        + REQUEST.encode()
        + b'"}',
        b'{"engagement_id":true,"request_id":"' + REQUEST.encode() + b'"}',
        b'{"engagement_id":"'
        + ENGAGEMENT.encode()
        + b'","request_id":"'
        + REQUEST.encode()
        + b'","pid":1}',
        b"{" + b"x" * 600 + b"}",
    )
    for body in payloads:
        response = await _call(api, token=_bearer(), body=body)
        _unverified(response, 413 if len(body) > host._MAX_BODY else 422)


@pytest.mark.asyncio
async def test_pinned_reader_identity_scope_and_root_rotation_block_positive(
    api: dict[str, Any]
) -> None:
    calls: list[str] = []

    async def mismatched(
        engagement: str, request: str, actor: str
    ) -> host.HostPinnedSourceMapReadback:
        calls.append(actor)
        forged = dict(IDENTITY, engagement_id="eng-other-tenant")
        return host.HostPinnedSourceMapReadback(forged, _proofs())

    active = host.SourceMapHostWitnessOperator(
        independently_enrolled=True,
        host_pinned_reader=mismatched,
        actions=object.__new__(FlowMCPActionStore),
    )
    _mount(api, active)
    response = await _call(api, token=_bearer())
    _unverified(response, 503)
    assert response.json()["detail"]["reason"] == "HOST_ORIGINAL_IDENTITY_UNVERIFIED"
    assert calls == ["independently-signed-operator"]
    # Even a pre-enrolled reader cannot continue after the root set changes.
    api["monkeypatch"].setenv(host._ROOT_ENVS[0], "{}")
    response = await _call(api, token=_bearer())
    _unverified(response, 503)
    assert response.json()["detail"]["reason"] == "INDEPENDENT_CURRENT_WITNESS_UNAVAILABLE"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_unsigned_or_mismatched_external_proofs_cannot_verify(api: dict[str, Any]) -> None:
    async def source(engagement: str, request: str, actor: str) -> host.HostPinnedSourceMapReadback:
        return host.HostPinnedSourceMapReadback(dict(IDENTITY), _proofs())

    _mount(
        api,
        host.SourceMapHostWitnessOperator(
            independently_enrolled=True,
            host_pinned_reader=source,
            actions=object.__new__(FlowMCPActionStore),
        ),
    )
    # Original production verifier rejects test-only unsigned evidence before
    # accessing a live database or attempting to issue a new credential.
    response = await _call(api, token=_bearer())
    _unverified(response, 503)
    assert response.json()["detail"]["reason"] == "INDEPENDENT_CURRENT_WITNESS_UNAVAILABLE"


@pytest.mark.asyncio
async def test_readback_reports_only_verified_metadata_with_bounded_stub(
    api: dict[str, Any]
) -> None:
    """Adapter-only positive; monkeypatched corroborator is NOT production witness."""
    calls: list[dict[str, Any]] = []

    class SyntheticFinalJoin:
        def __init__(self, actions: FlowMCPActionStore) -> None:
            assert isinstance(actions, FlowMCPActionStore)

        async def corroborate(self, **proofs: Any) -> dict[str, Any]:
            calls.append(proofs)
            return {
                "status": "corroborated_read_only",
                "0033_epoch": 3,
                "0033_revision": 5,
                "observed_mount_read_only": True,
                "authorizes_execution": False,
                "authorizes_mount_or_replay": False,
                "pid": PRIVATE,
            }

    api["monkeypatch"].setattr(host, "SourceMap0033CurrentWitness", SyntheticFinalJoin)

    async def source(engagement: str, request: str, actor: str) -> host.HostPinnedSourceMapReadback:
        assert (engagement, request, actor) == (
            ENGAGEMENT,
            REQUEST,
            "independently-signed-operator",
        )
        return host.HostPinnedSourceMapReadback(dict(IDENTITY), _proofs())

    _mount(
        api,
        host.SourceMapHostWitnessOperator(
            independently_enrolled=True,
            host_pinned_reader=source,
            actions=object.__new__(FlowMCPActionStore),
        ),
    )
    result = await _call(api, token=_bearer())
    assert result.status_code == 200, result.text
    document = result.json()
    assert document["status"] == "CURRENT_ORIGINAL_HOST_WITNESS_VERIFIED"
    assert document["signed_0033_current_witness_verified"] is True
    assert document["read_only_host_mount_verified"] is True
    assert document["one_use_grant_and_binding_verified"] is True
    assert document["original_action_replayed"] is False
    assert document["authorizes_execution"] is False
    assert document["target_effect_verified"] is False
    assert document["production_certified"] is False
    assert len(calls) == 1
    assert PRIVATE not in result.text
    assert "signature" not in result.text
    assert "pid" not in document


@pytest.mark.asyncio
async def test_positive_shape_cannot_be_raised_by_unsupported_status(api: dict[str, Any]) -> None:
    class LyingFinalJoin:
        def __init__(self, actions: FlowMCPActionStore) -> None:
            pass

        async def corroborate(self, **proofs: Any) -> dict[str, Any]:
            return {"status": "running", "observed_mount_read_only": True}

    api["monkeypatch"].setattr(host, "SourceMap0033CurrentWitness", LyingFinalJoin)

    async def source(engagement: str, request: str, actor: str) -> host.HostPinnedSourceMapReadback:
        return host.HostPinnedSourceMapReadback(dict(IDENTITY), _proofs())

    _mount(
        api,
        host.SourceMapHostWitnessOperator(
            independently_enrolled=True,
            host_pinned_reader=source,
            actions=object.__new__(FlowMCPActionStore),
        ),
    )
    response = await _call(api, token=_bearer())
    _unverified(response, 503)
    assert response.json()["detail"]["reason"] == "CURRENT_SOURCE_MAP_WITNESS_UNVERIFIED"


@pytest.mark.asyncio
async def test_trust_change_while_corroborating_cannot_admit_readback(
    api: dict[str, Any],
) -> None:
    class RotatingFinalJoin:
        def __init__(self, actions: FlowMCPActionStore) -> None:
            pass

        async def corroborate(self, **proofs: Any) -> dict[str, Any]:
            # An enrolled producer rotation AFTER the join still blocks READY.
            api["monkeypatch"].setenv(host._ROOT_ENVS[0], "{}")
            return {
                "status": "corroborated_read_only",
                "0033_epoch": 3,
                "0033_revision": 5,
                "observed_mount_read_only": True,
                "authorizes_execution": False,
                "authorizes_mount_or_replay": False,
            }

    async def source(engagement: str, request: str, actor: str) -> host.HostPinnedSourceMapReadback:
        return host.HostPinnedSourceMapReadback(dict(IDENTITY), _proofs())

    api["monkeypatch"].setattr(host, "SourceMap0033CurrentWitness", RotatingFinalJoin)
    _mount(
        api,
        host.SourceMapHostWitnessOperator(
            independently_enrolled=True,
            host_pinned_reader=source,
            actions=object.__new__(FlowMCPActionStore),
        ),
    )
    response = await _call(api, token=_bearer())
    _unverified(response, 503)
    assert response.json()["detail"]["reason"] == "INDEPENDENT_CURRENT_WITNESS_UNAVAILABLE"


@pytest.mark.asyncio
async def test_duplicate_public_root_prevents_reader_call(api: dict[str, Any]) -> None:
    calls: list[str] = []

    async def source(engagement: str, request: str, actor: str) -> host.HostPinnedSourceMapReadback:
        calls.append(actor)
        raise RuntimeError(PRIVATE)

    # Reusing a signer key across independent producer domains is invalid.
    api["monkeypatch"].setenv(host._ROOT_ENVS[1], os.environ[host._ROOT_ENVS[0]])
    _mount(
        api,
        host.SourceMapHostWitnessOperator(
            independently_enrolled=True,
            host_pinned_reader=source,
            actions=object.__new__(FlowMCPActionStore),
        ),
    )
    response = await _call(api, token=_bearer())
    _unverified(response, 503)
    assert PRIVATE not in response.text
    assert calls == []
