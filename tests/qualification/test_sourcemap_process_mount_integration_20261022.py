"""Actual mounted SourceMap ASGI boundary + signed host-process join qualification.

No app lifespan/DB, Docker, native scan, source issuer, original mount, external
target or grant is touched. A genuine Linux original process/mount witness
requires an independently enrolled host, which this Windows runner lacks.
Test-only Ed25519 proof positives qualify the *pure host prerequisite* only;
the ACTUAL mounted original 0029/0033/0037 readback must still return 503.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
import time
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jose import jwt

from ai_osop.api import deps
from ai_osop.api import source_map_host_witness_operator as mounted_witness
from ai_osop.api.main import app as actual_mounted_app
from ai_osop.core.config import settings
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    _require_operational_pair,
)
from ai_osop.orchestrator import sourcemap_host_process_join_20261022 as host_join
from test_sourcemap_host_process_join_20261022 import proof_fixture

SECRET = "qualification-isolated-local-sourcemap-senior-jwt-20261022"
SOURCE = "/native-sourcemap/source-preflight"
STATUS = "/native-sourcemap/status-preflight"
READBACK = "/system/source-map/host-witness/readback"
PRIVATE = "test-only-private-original-process-key-DO-NOT-RETURN"
ORIGINAL_REQUEST = "req-" + "1" * 48
ORIGINAL_ENGAGEMENT = "eng-original"


def _jwt(role: str = "senior_operator", *, wrong_key: bool = False, expired: bool = False) -> str:
    now = int(time.time())
    return cast(
        str,
        jwt.encode(
            {
                "sub": "signed-sourcemap-qualification-senior",
                "role": role,
                "iat": now - 10,
                "exp": now - 3 if expired else now + 120,
            },
            ("independent-wrong-key" if wrong_key else SECRET),
            algorithm="HS256",
        ),
    )


@pytest.fixture
def mounted(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Production route set, no application startup or production DB."""
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "api_token", "unattributed-dev-shared-key")
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    monkeypatch.setattr(deps, "_oidc_config", lambda: None)
    monkeypatch.setitem(deps.state, "orchestrator", None)
    # Test the as-mounted default: it may only become enrolled by the
    # independent host installer, not by HTTP or a test bearer claim.
    if hasattr(actual_mounted_app.state, mounted_witness._HOST_SLOT):
        pytest.skip("An existing independent host enrollment must remain untouched")
    for key in host_join._ROOT_ENVS.values():
        monkeypatch.delenv(key, raising=False)
    return actual_mounted_app


async def _request(
    app: Any,
    path: str,
    *,
    auth: str | None = None,
    body: Any = None,
    extra: list[tuple[str, str]] | None = None,
    peer: str = "127.0.0.1",
    scheme: str = "http",
) -> httpx.Response:
    headers = list(extra or [])
    if auth is not None:
        headers.append(("Authorization", "Bearer " + auth))
    if not any(k.lower() == "content-type" for k, _ in headers):
        headers.append(("Content-Type", "application/json"))
    if body is None:
        body = {"engagement_id": ORIGINAL_ENGAGEMENT, "request_id": ORIGINAL_REQUEST}
    content = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body
    transport = httpx.ASGITransport(app=app, client=(peer, 40119))
    async with httpx.AsyncClient(
        transport=transport,
        base_url=f"{scheme}://source-map-local.invalid",
        timeout=10,
    ) as client:
        return await client.post(path, content=content, headers=headers)


def _assert_not_certified(response: httpx.Response, *, expected_status: int = 503) -> None:
    assert response.status_code == expected_status, response.text
    assert PRIVATE not in response.text
    assert "CURRENT_ORIGINAL_HOST_WITNESS_VERIFIED" not in response.text
    assert "corroborated_read_only" not in response.text
    if response.status_code == 503 and "detail" in response.json():
        detail = response.json()["detail"]
        if isinstance(detail, dict):
            assert detail["status"] == "UNVERIFIED"
            assert detail["original_action_replayed"] is False
            assert detail["automatic_retry_authorized"] is False
            assert detail["production_certified"] is False
            assert detail["current_pid_and_nonroot_mount_verified"] is False
            assert detail["one_use_grant_and_binding_verified"] is False


def test_actual_main_registers_exact_source_status_and_host_readback_routes_once(
    mounted: Any,
) -> None:
    for path in (SOURCE, STATUS, READBACK):
        matches = [route for route in mounted.routes if route.path == path]
        assert len(matches) == 1
        assert getattr(matches[0], "methods", set()) == {"POST"}
    assert not hasattr(mounted.state, mounted_witness._HOST_SLOT)


@pytest.mark.asyncio
async def test_actual_mounted_readback_signed_senior_with_no_host_enrollment_denies(
    mounted: Any,
) -> None:
    result = await _request(mounted, READBACK, auth=_jwt())
    _assert_not_certified(result)
    assert result.headers["cache-control"] == "no-store"
    assert result.headers["x-content-type-options"] == "nosniff"
    assert result.json()["detail"]["reason"] == "INDEPENDENT_HOST_VERIFIER_UNAVAILABLE"
    assert not hasattr(mounted.state, mounted_witness._HOST_SLOT)


@pytest.mark.asyncio
async def test_actual_mounted_reader_auth_and_request_scope_denied_before_enrollment(
    mounted: Any,
) -> None:
    cases = (
        (None, None, 403),
        (_jwt("operator"), None, 403),
        (_jwt(expired=True), None, 401),
        (_jwt(wrong_key=True), None, 401),
        (
            _jwt(),
            {"engagement_id": ORIGINAL_ENGAGEMENT, "request_id": ORIGINAL_REQUEST, "pid": 1234},
            422,
        ),
        (
            _jwt(),
            {
                "engagement_id": ORIGINAL_ENGAGEMENT,
                "request_id": ORIGINAL_REQUEST,
                "private_key": PRIVATE,
            },
            422,
        ),
        (
            _jwt(),
            {
                "engagement_id": ORIGINAL_ENGAGEMENT,
                "request_id": ORIGINAL_REQUEST,
                "native_stage_root": "/proc/self/mountinfo",
            },
            422,
        ),
    )
    for auth, body, expected in cases:
        result = await _request(mounted, READBACK, auth=auth, body=body)
        assert result.status_code == expected, result.text
        assert PRIVATE not in result.text
    response = await _request(
        mounted,
        READBACK + "?action=retry",
        auth=_jwt(),
    )
    assert response.status_code == 403
    response = await _request(
        mounted,
        READBACK,
        auth=_jwt(),
        extra=[("Origin", "https://attacker.invalid")],
    )
    assert response.status_code == 403
    response = await _request(
        mounted,
        READBACK,
        auth=_jwt(),
        peer="192.0.2.7",
    )
    assert response.status_code == 403
    assert not hasattr(mounted.state, mounted_witness._HOST_SLOT)


@pytest.mark.asyncio
async def test_actual_mounted_source_and_status_do_not_reissue_or_replay_without_service_auth(
    mounted: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even an operator-signed JWT is not a separately enrolled issuer identity.
    # Correct-looking originals cannot reach issuer/DB in this qualification.
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", raising=False)
    scoped = {
        "request_id": ORIGINAL_REQUEST,
        "engagement_id": ORIGINAL_ENGAGEMENT,
        "task_id": "task-original",
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "artifact_sha256": "a" * 64,
    }
    for endpoint in (SOURCE, STATUS):
        for bearer in (None, _jwt(), "unattributed-dev-shared-key"):
            result = await _request(mounted, endpoint, auth=bearer, body=scoped)
            assert result.status_code in (401, 403), result.text
            assert PRIVATE not in result.text
    with pytest.raises(NativeMCPGrantDenied):
        _require_operational_pair("source-map-mcp", "inspect_local_original_sourcemap", "READ_ONLY")


@pytest.fixture
def local_signed_sources(mounted: Any, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Six independently controlled Ed25519 *test-only* issuer domains."""
    private = {
        group: Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
        for index, group in enumerate(host_join._ROOT_ENVS, 1)
    }
    for group, variable in host_join._ROOT_ENVS.items():
        pub = (
            private[group]
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        signer = "Signer" + group.replace("_", "").title()
        monkeypatch.setenv(variable, json.dumps({signer: base64.b64encode(pub).decode()}))
    proofs = proof_fixture(int(time.time()), private)
    # No real process was observed or original bytes ever read by this fixture.
    original = proofs["original"]
    host_only = host_join.SourceMapHostProcessJoin(
        pinned_mount_root=host_join.HostPinnedSourceMapMountRoot(
            root_dev=201,
            root_ino=902,
        )
    )
    return {"proofs": proofs, "original": original, "host_only": host_only}


def test_signed_test_only_host_join_positive_stays_read_only_and_nontransferable(
    local_signed_sources: dict[str, Any],
) -> None:
    result = local_signed_sources["host_only"].verify(**local_signed_sources["proofs"])
    assert result.status == "host_process_readonly_mount_correlated_only"
    assert result.native_fsuid > 0
    assert result.root_dev == 201 and result.root_ino == 902
    assert result.pid > 0 and result.pid_start_ticks > 0
    assert result.expires_at > result.observed_at
    assert result.authorizes_execution is False
    assert result.authorizes_mount_or_replay is False
    assert result.native_grant_redemption_verified_here is False
    assert result.durable_0037_binding_verified_here is False
    assert result.target_effect_verified is False


@pytest.mark.parametrize(
    ("envelope", "field", "value"),
    [
        ("native_mount_witness", "read_only", False),
        ("native_mount_witness", "root_ino", 12345),
        ("native_mount_witness", "native_fsuid", 0),
        ("live_process_witness", "pid_start_ticks", 987654),
        ("current_db_witness", "lease_active", False),
    ],
)
def test_host_mount_and_pid_mismatches_fail_even_with_independent_signature_claims(
    local_signed_sources: dict[str, Any],
    envelope: str,
    field: str,
    value: Any,
) -> None:
    forged = copy.deepcopy(local_signed_sources["proofs"])
    forged[envelope]["claims"][field] = value
    # Editing a test-only signed envelope invalidates its signature: the real
    # verifier must reject rather than upgrading a mere PID or RO flag.
    with pytest.raises(host_join.SourceMapHostProcessJoinDenied):
        local_signed_sources["host_only"].verify(**forged)


@pytest.mark.asyncio
async def test_actual_mounted_readback_never_promotes_signed_host_test_proofs_to_0033(
    local_signed_sources: dict[str, Any],
    mounted: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = local_signed_sources["proofs"]
    original = local_signed_sources["original"]
    host_layer = local_signed_sources["host_only"].verify(**source)
    assert host_layer.authorizes_execution is False
    calls: list[tuple[str, str, str]] = []

    async def trusted_test_only_reader(
        engagement: str,
        request: str,
        operator: str,
    ) -> mounted_witness.HostPinnedSourceMapReadback:
        calls.append((engagement, request, operator))
        # The native 0029 signature is deliberately absent. No test mints it.
        signed = {key: source[key] for key in mounted_witness._PROOFS if key in source}
        signed["native_grant_token"] = {
            "claims": {},
            "kid": "NotANativeIssuer",
            "signature": PRIVATE,
        }
        identity = {key: getattr(original, key) for key in mounted_witness._IDENTITY}
        return mounted_witness.HostPinnedSourceMapReadback(identity, signed)

    # Prohibit DB access even if a bug moves _verify_native past the DB read.
    def no_database(_: Any) -> Any:
        pytest.fail("SourceMap verifier attempted production DB before 0029 native denial")

    monkeypatch.setattr(FlowMCPActionStore, "_sessions", no_database)
    service = mounted_witness.SourceMapHostWitnessOperator(
        independently_enrolled=True,
        host_pinned_reader=trusted_test_only_reader,
        actions=object.__new__(FlowMCPActionStore),
    )
    assert service._pins is not None
    mounted_witness.install_host_source_map_witness_operator(mounted, service)
    try:
        response = await _request(mounted, READBACK, auth=_jwt())
        _assert_not_certified(response)
        assert response.json()["detail"]["reason"] == "INDEPENDENT_CURRENT_WITNESS_UNAVAILABLE"
        assert calls == [
            (ORIGINAL_ENGAGEMENT, ORIGINAL_REQUEST, "signed-sourcemap-qualification-senior")
        ]
    finally:
        # Do not use monkeypatch.delattr: its automatic undo would restore the
        # synthetic enrollment after this case and contaminate later tests.
        delattr(mounted.state, mounted_witness._HOST_SLOT)


def test_absent_host_root_is_not_enrollment_and_no_0033_issuer_is_exposed(
    mounted: Any,
) -> None:
    with pytest.raises(host_join.SourceMapHostProcessJoinDenied):
        host_join.SourceMapHostProcessJoin(
            pinned_mount_root=host_join.HostPinnedSourceMapMountRoot(201, 902)
        )
    assert not hasattr(mounted.state, mounted_witness._HOST_SLOT)
    assert not hasattr(host_join.SourceMapHostProcessJoin, "issue")
    assert not hasattr(host_join.SourceMapHostProcessJoin, "redeem")
    assert not hasattr(host_join.SourceMapHostProcessJoin, "dispatch")


@pytest.mark.skipif(
    sys.platform != "linux" or os.name != "posix",
    reason="Real Linux pidfd + nonroot read-only SourceMap mount unavailable on Windows host",
)
def test_real_linux_host_original_mount_requires_external_enrollment() -> None:
    """Linux only: an absent protected host enrollment must reject the observer.

    An authorized positive E2E needs an existing real original 0027 Action,
    independent 0033 current signed supervisor PID and nonroot readonly mount.
    This test deliberately never forges those, starts a scanner or mounts data.
    """
    from ai_osop.orchestrator.sourcemap_supervisor_process_witness import (
        IndependentSourceMapSupervisorProcessWitness,
        SourceMapProcessWitnessDenied,
    )

    with pytest.raises(SourceMapProcessWitnessDenied):
        IndependentSourceMapSupervisorProcessWitness()
