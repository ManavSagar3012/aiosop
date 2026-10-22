"""Host-stage native SourceMap must not possess the central 0035 issuer bearer.

FAKE PG/TLS: a signed preissued 0035 proof and independent host-stage receipt
come from offline fixtures; current STATUS uses httpx.MockTransport, never a
live PostgreSQL/HTTPS service. Native signed source/host verification, strict
configuration, journal one-shot, and ASGI tool/status calls are exercised.

Windows does not implement the privileged POSIX host-root check. Only that
specific gate is substituted on Windows, using independently enrolled fixture
host public keys; production Linux retains the genuine root check.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_source_map_signed_original_intake_20261020 import (
    ENGAGEMENT,
    NATIVE,
    REQUEST_ID,
    TASK,
    _REAL_HTTPX_CLIENT,
    call,
    configure,
    request,
)
from tests.test_sourcemap_preissued_proof_handoff_20261021 import (
    _HOST_KID,
    _STATUS_SERVICE,
    _public,
    _setup,
)


def _no_issuer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_URL", raising=False)


def _fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, enable_windows_host_gate: bool = False
) -> dict[str, Any]:
    world = _setup(monkeypatch, tmp_path)
    _no_issuer(monkeypatch)
    native = world["module"]
    if enable_windows_host_gate and os.name == "nt":
        host_roots = {_HOST_KID: base64.b64decode(_public(world["host_key"]))}

        def windows_offline_host_root(_config: Any) -> dict[str, bytes]:
            # Emulates ONLY root ownership/mount, not either cryptographic proof.
            return host_roots

        monkeypatch.setattr(native, "_preissued_handoff_roots", windows_offline_host_root)
    return world


async def _status(native: Any) -> httpx.Response:
    async with _REAL_HTTPX_CLIENT(
        transport=httpx.ASGITransport(app=native.app),
        base_url="http://native.invalid",
    ) as client:
        return await client.post(
            "/mcp/request/status",
            json={
                "request_id": REQUEST_ID,
                "engagement_id": ENGAGEMENT,
                "task_id": TASK,
                "server_id": "source-map-mcp",
            },
            headers={"Authorization": "Bearer " + NATIVE},
        )


@pytest.mark.asyncio
async def test_no_issuer_bearer_or_endpoint_preissued_native_proof_executes_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = _fixture(monkeypatch, tmp_path, enable_windows_host_gate=True)
    native = world["module"]
    config = native._local_original_config()
    assert config[0] == "" and config[2] == ""
    assert config[3] and config[4].name == "sourcemap-originals"
    assert "OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN" not in os.environ
    assert "OSOP_SOURCEMAP_SOURCE_URL" not in os.environ
    assert native._approved_original_transport_configured()
    initialize = await native.mcp_initialize()
    assert initialize["status"] == "ready"
    assert initialize["capabilities"] == [
        "mcp_bound_receipts_v1",
        "original_sourcemap_signed_preflight_v1",
        "mcp_request_status_v1",
    ]

    # Explicitly forbid the issuer code path even for an accidental fallback.
    async def never_issue(*_args: Any) -> None:
        raise AssertionError("Native must not request a second 0035 source preflight")

    monkeypatch.setattr(native, "_central_original_source", never_issue)
    processed = await call(native, request())
    assert processed.status_code == 200, processed.text
    assert processed.json()["status"] == "success"
    assert len(world["traffic"]) == 1
    assert not world["legacy_issuer_traffic"]
    assert len(list(world["journal"].glob("*.used"))) == 2
    assert len(list(world["journal"].glob("completed-*.json"))) == 1
    assert len(list(world["journal"].glob("request-index-*.json"))) == 1
    receipt = processed.json()["provider_receipt"]
    assert provider_receipt_is_signed(receipt, "source-map-mcp", REQUEST_ID, ENGAGEMENT, TASK)
    queried = await _status(native)
    assert queried.status_code == 200, queried.text
    assert provider_receipt_is_signed(
        queried.json(), "source-map-mcp", REQUEST_ID, ENGAGEMENT, TASK
    )
    assert len(world["traffic"]) == 2
    assert (await call(native, request())).status_code == 503
    assert len(world["traffic"]) == 3  # status allowed; one-shot still denies
    assert len(list(world["journal"].glob("completed-*.json"))) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "issuer-bearer-must-not-exist-in-host-stage"),
        ("OSOP_SOURCEMAP_SOURCE_SERVICE_TOKEN", "x"),
        (
            "OSOP_SOURCEMAP_SOURCE_URL",
            "https://authority.example.org/native-sourcemap/source-preflight",
        ),
        (
            "OSOP_SOURCEMAP_SOURCE_URL",
            "https://authority.example.org/native-sourcemap/status-preflight",
        ),
        ("OSOP_SOURCEMAP_SOURCE_URL", "%%%"),
        ("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", ""),
        ("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", NATIVE),
        ("OSOP_SOURCEMAP_STATUS_URL", "https://evil.example.org/native-sourcemap/source-preflight"),
        (
            "OSOP_SOURCEMAP_STATUS_URL",
            "https://authority.example.org:444/native-sourcemap/status-preflight",
        ),
        (
            "OSOP_SOURCEMAP_STATUS_URL",
            "https://authority.example.org/native-sourcemap/status-preflight?issue=1",
        ),
        ("OSOP_SOURCEMAP_SOURCE_CA_BUNDLE", ""),
        ("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON", "{}"),
        ("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", "host-stage-v2"),
    ],
)
async def test_host_mode_refuses_issuer_capability_or_insecure_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    variable: str,
    value: str,
) -> None:
    world = _fixture(monkeypatch, tmp_path, enable_windows_host_gate=True)
    native = world["module"]
    monkeypatch.setenv(variable, value)
    assert not native._approved_original_transport_configured()
    initializer = await native.mcp_initialize()
    assert initializer["status"] == "unavailable"
    execution = await call(native, request())
    assert execution.status_code == 503
    assert "provider_receipt" not in execution.text
    assert not world["traffic"]
    assert not world["legacy_issuer_traffic"]
    assert not list(world["journal"].iterdir())


@pytest.mark.asyncio
async def test_host_mode_status_only_transport_pinned_no_proxy_or_redirect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    world = _fixture(monkeypatch, tmp_path, enable_windows_host_gate=True)
    native = world["module"]
    seen: list[tuple[str, str]] = []
    original = native.httpx.AsyncClient

    def inspecting_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["verify"] == os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"]
        client = original(*args, **kwargs)
        return client

    monkeypatch.setattr(native.httpx, "AsyncClient", inspecting_client)
    config = native._local_original_config()
    endpoint, status_token = native._status_transport_config(config)
    seen.append((endpoint, status_token))
    assert seen == [
        ("https://authority.example.org/native-sourcemap/status-preflight", _STATUS_SERVICE)
    ]
    assert await native._central_original_status(
        request()["execution_binding"], world["source"], config
    )
    assert len(world["traffic"]) == 1
    assert not world["legacy_issuer_traffic"]


@pytest.mark.asyncio
async def test_legacy_nonstage_issuer_contract_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, _, journal, central_calls = configure(monkeypatch, tmp_path)
    monkeypatch.delenv("OSOP_SOURCEMAP_PREISSUED_HANDOFF_MODE", raising=False)
    config = native._local_original_config()
    assert config[0].endswith("/native-sourcemap/source-preflight")
    assert len(config[2]) >= 32
    assert native._approved_original_transport_configured()
    initialized = await native.mcp_initialize()
    assert initialized["capabilities"] == [
        "mcp_bound_receipts_v1",
        "original_sourcemap_signed_preflight_v1",
    ]
    result = await call(native, request())
    assert result.status_code == 200, result.text
    assert len(central_calls) == 1
    assert central_calls[0]["path"] == "/native-sourcemap/source-preflight"
    assert len(list(journal.glob("completed-*.json"))) == 1


@pytest.mark.asyncio
async def test_no_legacy_issuer_without_host_stage_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, _, journal, central_calls = configure(monkeypatch, tmp_path)
    _no_issuer(monkeypatch)
    assert not native._approved_original_transport_configured()
    assert (await call(native, request())).status_code == 503
    assert not central_calls
    assert not list(journal.iterdir())
