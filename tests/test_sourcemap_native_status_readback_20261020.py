"""Native SourceMap status journal readback (ASGI + fake central signed issuer).

FAKE PG: central preflight responses come from httpx.MockTransport. No live
PostgreSQL signed reviewer/ROE/0035 state or actual HTTPS TLS transport is tested.
The native app, original artifact double-SHA, journal, and Ed25519 are real.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.mcp.protocol import _verified_remote_status
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.test_source_map_signed_original_intake_20261020 import (
    ACTION,
    APPROVAL,
    DIGEST,
    DOCUMENT,
    ENGAGEMENT,
    KID,
    NATIVE,
    REQUEST_ID,
    SECRET,
    SERVICE,
    TASK,
    _REAL_HTTPX_CLIENT,
    configure,
    request,
)

STATUS_SERVICE = "separate-authoritative-status-service-bearer-20261020"
STATUS_URL = "https://authority.example.org/native-sourcemap/status-preflight"


def _bytes(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")


def _sign(key: Ed25519PrivateKey, domain: bytes, claims: dict[str, Any]) -> dict[str, Any]:
    canonical = json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    signature = key.sign(domain + canonical)
    return {
        "claims": claims,
        "kid": KID,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


def _fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Any, Path, list, dict]:
    native, original, journal, _ = configure(monkeypatch, tmp_path)
    central = Ed25519PrivateKey.generate()
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON", json.dumps({KID: _bytes(central)})
    )
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_URL", STATUS_URL)
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", STATUS_SERVICE)
    received: list[tuple[str, dict[str, Any]]] = []
    state = {"approved": True, "corrupt_status": False, "source_claims": None}

    def central_reply(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        received.append((req.url.path, body))
        assert req.url.host == "authority.example.org"
        assert req.headers["Cache-Control"] == "no-store"
        assert set(body) == {
            "request_id",
            "engagement_id",
            "task_id",
            "server_id",
            "tool_name",
            "artifact_sha256",
        }
        if req.url.path == "/native-sourcemap/source-preflight":
            assert req.headers["Authorization"] == "Bearer " + SERVICE
            now = int(time.time())
            source = {
                **body,
                "version": 1,
                "preflight_id": "nsp-" + "f" * 32,
                "flow_id": "flow-approved",
                "subtask_id": "subtask-approved",
                "action_id": ACTION,
                "owner_id": "owner-approved",
                "manifest_sha256": "d" * 64,
                "approval_id": APPROVAL,
                "lease_id": "lease-current",
                "authorization_version": 3,
                "authorization_sha256": "c" * 64,
                "issued_at": now,
                "expires_at": now + 10,
            }
            state["source_claims"] = source
            return httpx.Response(200, json=_sign(central, native._SOURCE_DOMAIN, source))
        assert req.url.path == "/native-sourcemap/status-preflight"
        assert req.headers["Authorization"] == "Bearer " + STATUS_SERVICE
        if not state["approved"]:
            return httpx.Response(409, json={"status": "revoked"})
        source = state["source_claims"]
        assert source is not None
        now = int(time.time())
        signed_claims = {
            **source,
            "status_id": "nss-" + "e" * 32,
            "issued_at": now,
            "expires_at": now + 5,
        }
        if state["corrupt_status"]:
            signed = _sign(central, native._SOURCE_DOMAIN, signed_claims)
        else:
            signed = _sign(central, native._STATUS_DOMAIN, signed_claims)
        return httpx.Response(200, json=signed)

    def mocked_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        assert kwargs["verify"] == os.environ["OSOP_SOURCEMAP_SOURCE_CA_BUNDLE"]
        return _REAL_HTTPX_CLIENT(*args, transport=httpx.MockTransport(central_reply), **kwargs)

    monkeypatch.setattr(native.httpx, "AsyncClient", mocked_client)
    assert original.read_bytes() == DOCUMENT
    return native, journal, received, state


async def _native_call(
    native: Any, path: str, body: dict[str, Any], bearer: str = NATIVE
) -> httpx.Response:
    async with _REAL_HTTPX_CLIENT(
        transport=httpx.ASGITransport(app=native.app), base_url="http://native.invalid"
    ) as client:
        return await client.post(
            path,
            json=body,
            headers={"Authorization": "Bearer " + bearer} if bearer else {},
        )


def _identity(request_id: str = REQUEST_ID, task_id: str = TASK) -> dict[str, str]:
    return {
        "request_id": request_id,
        "engagement_id": ENGAGEMENT,
        "task_id": task_id,
        "server_id": "source-map-mcp",
    }


@pytest.mark.asyncio
async def test_completed_action_recovered_twice_with_fresh_status_and_no_original_replay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, journal, received, state = _fixture(monkeypatch, tmp_path)
    initialize = (await _native_call(native, "/mcp/initialize", {})).json()
    assert initialize["capabilities"] == [
        "mcp_bound_receipts_v1",
        "original_sourcemap_signed_preflight_v1",
        "mcp_request_status_v1",
    ]
    completed = await _native_call(native, "/mcp/execute", request())
    assert completed.status_code == 200, completed.text
    assert len(list(journal.glob("completed-*.json"))) == 1
    assert len(list(journal.glob("request-index-*.json"))) == 1
    assert len(list(journal.glob("*.used"))) == 2
    invoked = []

    def reject_original(*args: Any) -> bytes:
        invoked.append(True)
        raise AssertionError("Status attempted original artifact read")

    monkeypatch.setattr(native, "_read_original_bytes", reject_original)
    monkeypatch.setattr(native, "_inspect_original_map", reject_original)
    monkeypatch.setattr(native, "_reserve_original_once", reject_original)
    for attempt in range(2):
        status_response = await _native_call(native, "/mcp/request/status", _identity())
        assert status_response.status_code == 200, status_response.text
        receipt = status_response.json()
        assert set(receipt) == {
            "request_id",
            "engagement_id",
            "task_id",
            "server_id",
            "status",
            "verified",
            "stopped",
            "issued_at",
            "attestation",
        }
        assert receipt["status"] == "succeeded"
        assert receipt["verified"] is True
        assert receipt["stopped"] is False
        assert provider_receipt_is_signed(receipt, "source-map-mcp", REQUEST_ID, ENGAGEMENT, TASK)
        assert (
            _verified_remote_status(
                receipt,
                REQUEST_ID,
                ENGAGEMENT,
                TASK,
                "source-map-mcp",
                require_bound_identity=True,
                require_signature=True,
            )
            == "confirmed_finished"
        )
        assert len(received) == 2 + attempt
        assert received[-1] == (
            "/native-sourcemap/status-preflight",
            {
                **_identity(),
                "tool_name": "inspect_local_original_sourcemap",
                "artifact_sha256": DIGEST,
            },
        )
        assert SECRET not in status_response.text
        assert "sources" not in status_response.text
        assert "manifest_sha256" not in status_response.text
    assert not invoked
    assert len(list(journal.glob("completed-*.json"))) == 1
    assert len(list(journal.glob("*.used"))) == 2
    assert state["source_claims"]["action_id"] == ACTION


@pytest.mark.asyncio
async def test_status_revocation_wrong_task_and_wrong_signature_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, journal, received, state = _fixture(monkeypatch, tmp_path)
    assert (await _native_call(native, "/mcp/execute", request())).status_code == 200
    wrong_task = await _native_call(native, "/mcp/request/status", _identity(task_id="task-forged"))
    assert wrong_task.status_code == 503
    assert len(received) == 1
    state["approved"] = False
    revoked = await _native_call(native, "/mcp/request/status", _identity())
    assert revoked.status_code == 503
    assert len(received) == 2
    state["approved"] = True
    state["corrupt_status"] = True
    wrong_domain = await _native_call(native, "/mcp/request/status", _identity())
    assert wrong_domain.status_code == 503
    assert len(received) == 3
    assert all("attestation" not in reply.json() for reply in (wrong_task, revoked, wrong_domain))
    assert len(list(journal.glob("completed-*.json"))) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption", ["missing_index", "tampered_index", "tampered_receipt", "linked_index"]
)
async def test_status_fences_missing_modified_and_unsafe_local_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, corruption: str
) -> None:
    native, journal, received, _ = _fixture(monkeypatch, tmp_path)
    assert (await _native_call(native, "/mcp/execute", request())).status_code == 200
    index = next(journal.glob("request-index-*.json"))
    completed = next(journal.glob("completed-*.json"))
    if corruption == "missing_index":
        index.unlink()
    elif corruption == "tampered_index":
        content = json.loads(index.read_text())
        content["original_claims"]["artifact_sha256"] = "0" * 64
        index.write_text(json.dumps(content))
    elif corruption == "tampered_receipt":
        content = json.loads(completed.read_text())
        content["provider_receipt"]["attestation"]["signature"] = "A" * 86
        completed.write_text(json.dumps(content))
    else:
        try:
            os.link(index, journal / "alternate-index-link")
        except OSError:
            pytest.skip("Hardlinks unavailable in this filesystem")
    reply = await _native_call(native, "/mcp/request/status", _identity())
    assert reply.status_code == 503
    assert "attestation" not in reply.json()
    assert len(received) == 1


@pytest.mark.asyncio
async def test_status_configuration_is_optional_but_identity_and_url_strict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, journal, received, _ = _fixture(monkeypatch, tmp_path)
    monkeypatch.delenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN")
    baseline = (await _native_call(native, "/mcp/initialize", {})).json()
    assert baseline["capabilities"] == [
        "mcp_bound_receipts_v1",
        "original_sourcemap_signed_preflight_v1",
    ]
    denied = await _native_call(native, "/mcp/request/status", _identity())
    assert denied.status_code == 503
    assert not received and not list(journal.iterdir())
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_SERVICE_TOKEN", STATUS_SERVICE)
    for url in (
        "http://authority.example.org/native-sourcemap/status-preflight",
        "https://foreign.example.org/native-sourcemap/status-preflight",
        STATUS_URL + "?access=1",
        "https://authority.example.org:444/native-sourcemap/status-preflight",
    ):
        monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_URL", url)
        assert (await _native_call(native, "/mcp/initialize", {})).json()[
            "capabilities"
        ] == baseline["capabilities"]
    monkeypatch.setenv("OSOP_SOURCEMAP_STATUS_URL", STATUS_URL)
    assert (
        await _native_call(native, "/mcp/request/status", _identity(), bearer=SERVICE)
    ).status_code == 503
    assert (
        await _native_call(native, "/mcp/request/status", _identity(), bearer=STATUS_SERVICE)
    ).status_code == 503
    assert not received


@pytest.mark.asyncio
async def test_corrupt_index_write_after_completed_leaves_execution_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native, journal, received, _ = _fixture(monkeypatch, tmp_path)

    def unable_to_index(*args: Any) -> None:
        raise OSError("simulated request index fsync failure")

    monkeypatch.setattr(native, "_persist_request_index", unable_to_index)
    execution = await _native_call(native, "/mcp/execute", request())
    assert execution.status_code == 503
    assert "provider_receipt" not in execution.json()
    assert len(list(journal.glob("completed-*.json"))) == 1
    assert len(list(journal.glob("*.used"))) == 2
    assert not list(journal.glob("request-index-*.json"))
    again = await _native_call(native, "/mcp/execute", request())
    assert again.status_code == 503
    status = await _native_call(native, "/mcp/request/status", _identity())
    assert status.status_code == 503
    assert len(received) == 2  # source preflight attempts only
