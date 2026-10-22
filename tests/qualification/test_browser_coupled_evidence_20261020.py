"""Coupled original Browser evidence bytes, offline Chrome, HTTPS source trust.

Chromium can only reach one owned 127.0.0.1 page. A 403-only loopback proxy
denies Chrome background or redirected traffic. The central issuer is an
independently pinned LOCAL test signer, NOT a real PostgreSQL Action reviewer.
All observed proof is confined to the provider and original captured bytes.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import ssl
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock

import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from tests.qualification.native_browser_local_helper_20261020 import (
    ENGAGEMENT,
    FOREIGN,
    LABEL,
    TASK,
    native_browser_local,
)


CENTRAL_KID = "independent-local-evidence-source"
CENTRAL_BEARER = "central-browser-original-action-service-secret"
REQUEST_NAV = "req-" + "a" * 48
REQUEST_NONE = "req-" + "b" * 48
REQUEST_BAD = "req-" + "c" * 48


def _action(request_id: str, url: str, mode: str | None) -> dict[str, Any]:
    parameters = {"action": "navigate", "url": url, "user_label": LABEL}
    if mode is not None:
        parameters["evidence_mode"] = mode
    return {
        "tool_name": "execute",
        "request_id": request_id,
        "session_id": ENGAGEMENT,
        "execution_binding": {
            "request_id": request_id,
            "engagement_id": ENGAGEMENT,
            "task_id": TASK,
            "server_id": "browser-mcp",
        },
        "parameters": parameters,
    }


def _binding(request_id: str) -> dict[str, str]:
    return {
        "request_id": request_id,
        "engagement_id": ENGAGEMENT,
        "task_id": TASK,
        "server_id": "browser-mcp",
    }


def _source_token(signer: Ed25519PrivateKey, request: dict[str, Any]) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "version": 1,
        "preflight_id": "nbp-" + "a" * 32,
        **request,
        "flow_id": "flow-browser-local-reviewed",
        "subtask_id": "subtask-browser-reviewed",
        "action_id": "action-" + "a" * 32,
        "owner_id": "operator-reviewer-fixture",
        "authorization_version": 2,
        "authorization_sha256": "b" * 64,
        "approval_id": "approval-source-fixture",
        "lease_id": "lease-source-fixture",
        "issued_at": now,
        "expires_at": now + 10,
    }
    source_bytes = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    signature = signer.sign(b"ai-osop/browser-source-preflight/v1\x00" + source_bytes)
    return {
        "claims": claims,
        "kid": CENTRAL_KID,
        "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


@asynccontextmanager
async def owned_signed_source(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> AsyncIterator[SimpleNamespace]:
    """One local HTTPS server, independent service credential and signer."""
    key = Ed25519PrivateKey.generate()
    cert_key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(cert_key, algorithm=None)
    )
    pem = tmp_path / "independent-browser-local-ca.pem"
    private = tmp_path / "independent-browser-local-key.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        cert_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(pem), str(private))
    calls: list[dict[str, Any]] = []
    control = SimpleNamespace(status=200, calls=calls, signer=key)

    async def preflight(request: web.Request) -> web.Response:
        if request.headers.get("Authorization") != f"Bearer {CENTRAL_BEARER}":
            return web.json_response({"detail": "untrusted service"}, status=401)
        submitted = await request.json()
        calls.append(dict(submitted))
        if control.status != 200:
            return web.json_response(
                {"detail": "central source unavailable"}, status=control.status
            )
        return web.json_response(_source_token(key, submitted))

    app = web.Application()
    app.router.add_post("/native-browser/source-preflight", preflight)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    listener = web.TCPSite(runner, host="127.0.0.1", port=0, ssl_context=tls)
    await listener.start()
    assert listener._server is not None
    ip, port = listener._server.sockets[0].getsockname()[:2]
    assert ip == "127.0.0.1"
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_URL",
        f"https://127.0.0.1:{port}/native-browser/source-preflight",
    )
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(pem))
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", CENTRAL_BEARER)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps(
            {
                CENTRAL_KID: base64.b64encode(
                    key.public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    )
                ).decode("ascii"),
            }
        ),
    )
    try:
        yield control
    finally:
        await runner.cleanup()


async def _invoke(native: Any, request: dict[str, Any]) -> dict[str, Any]:
    async with native.client() as client:
        response = await client.post(
            "/mcp/execute",
            json=request,
            headers=native.headers(),
        )
        assert response.status_code == 200
        return response.json()


def _assert_unknown(native: Any, request_id: str, outcome: dict[str, Any]) -> None:
    assert outcome["status"] == "error"
    assert "provider_receipt" not in outcome
    assert native.native.RequestJournal(_binding(request_id)).read() == "unknown"


@pytest.mark.asyncio
async def test_coupled_original_bytes_single_action_with_real_offline_chromium(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path) as central:
            result = await _invoke(
                native,
                _action(REQUEST_NAV, native.base_url + "/", "screenshot_dom_har"),
            )
            assert result["status"] == "success"
            assert provider_receipt_is_signed(
                result["provider_receipt"],
                "browser-mcp",
                REQUEST_NAV,
                ENGAGEMENT,
                TASK,
            )
            assert result["result"]["evidence_mode"] == "screenshot_dom_har"
            assert native.native.RequestJournal(_binding(REQUEST_NAV)).read() == "succeeded"
            assert len(central.calls) == 1
            assert central.calls[0]["evidence_mode"] == "screenshot_dom_har"
            assert central.calls[0]["user_label"] == LABEL
            assert native.page_hits.count("/") == 1
            assert not native.blocked
            artifacts = result["result"]["evidence"]
            assert set(artifacts) == {"screenshot", "dom", "har"}
            witness = result["result"]["evidence_attestation"]
            assert set(witness) == {"claims", "kid", "signature"}
            assert witness["claims"]["request_id"] == REQUEST_NAV
            assert witness["claims"]["task_id"] == TASK
            assert witness["claims"]["action_id"] == "action-" + "a" * 32
            assert witness["claims"]["evidence_mode"] == "screenshot_dom_har"
            signer, enrolled_kid = native.native._signer()
            assert witness["kid"] == enrolled_kid
            signed_claims = json.dumps(
                witness["claims"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            signature = base64.urlsafe_b64decode(witness["signature"] + "==")
            signer.public_key().verify(
                signature,
                b"ai-osop/browser-reviewed-evidence/v1\x00" + signed_claims,
            )
            forged = json.loads(signed_claims)
            forged["artifacts"]["dom"]["sha256"] = "f" * 64
            from cryptography.exceptions import InvalidSignature

            with pytest.raises(InvalidSignature):
                signer.public_key().verify(
                    signature,
                    b"ai-osop/browser-reviewed-evidence/v1\x00"
                    + json.dumps(
                        forged,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    ).encode("ascii"),
                )
            for kind, extension in (("screenshot", "png"), ("dom", "html"), ("har", "har")):
                metadata = artifacts[kind]
                assert metadata["path"].startswith("captures/")
                assert metadata["path"].endswith("." + extension)
                assert metadata["capture_task_id"] == TASK
                original = (native.tenant / metadata["path"]).read_bytes()
                assert len(original) == metadata["size_bytes"]
                assert hashlib.sha256(original).hexdigest() == metadata["resource_sha256"]
                assert witness["claims"]["artifacts"][kind] == {
                    "sha256": metadata["resource_sha256"],
                    "size_bytes": metadata["size_bytes"],
                    "path": metadata["path"],
                }
                assert (
                    metadata["mount_sha256"]
                    == json.loads(os.environ["OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS"])[ENGAGEMENT]
                )
                assert metadata["container_image_sha256"] == "a" * 64
                if kind == "screenshot":
                    assert original.startswith(b"\x89PNG\r\n\x1a\n")
                if kind == "dom":
                    assert b"LOCAL_ONLY_BROWSER_PROOF" in original
                if kind == "har":
                    parsed = json.loads(original)
                    assert any(
                        entry["request"]["url"].startswith(native.base_url)
                        for entry in parsed["log"]["entries"]
                    )
            assert not list((native.tenant / "captures").glob("trace_*.zip"))
            assert "LOCAL_ONLY_BROWSER_PROOF" not in json.dumps(result)
            assert b"LOCAL_ONLY_BROWSER_PROOF" not in json.dumps(result).encode("utf-8")
            assert not native.native.manager.contexts and not native.native.manager.pages
            again = await _invoke(
                native,
                _action(REQUEST_NAV, native.base_url + "/", "screenshot_dom_har"),
            )
            assert again["status"] == "duplicate_request"
            assert len(central.calls) == 1
            assert native.page_hits.count("/") == 1
            denied = await _invoke(
                native,
                {
                    **_action("req-" + "d" * 48, native.base_url + "/", "screenshot_dom_har"),
                    "parameters": {"action": "screenshot", "user_label": LABEL},
                },
            )
            assert denied["status"] == "error"
            assert len(central.calls) == 1
            assert native.proxy_attempts == [
                event for event in native.proxy_attempts if "google.com" in event
            ] or all(
                "browser-external-must-not-resolve.invalid" not in x for x in native.proxy_attempts
            )


@pytest.mark.asyncio
async def test_none_mode_never_writes_undeclared_capture_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path) as central:
            result = await _invoke(native, _action(REQUEST_NONE, native.base_url + "/", None))
            assert result["status"] == "success"
            assert "evidence" not in result["result"]
            assert central.calls[0]["evidence_mode"] == "none"
            assert not (native.tenant / "captures").exists()


@pytest.mark.asyncio
async def test_rejected_source_redirect_or_lost_ack_never_captures_or_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path) as central:
            central.status = 409
            denied = await _invoke(
                native, _action(REQUEST_BAD, native.base_url + "/", "screenshot_dom_har")
            )
            _assert_unknown(native, REQUEST_BAD, denied)
            assert native.page_hits == []
            assert not (native.tenant / "captures").exists()
            again = await _invoke(
                native, _action(REQUEST_BAD, native.base_url + "/", "screenshot_dom_har")
            )
            assert again["status"] == "duplicate_request"
            assert len(central.calls) == 1


@pytest.mark.asyncio
async def test_capture_failure_stays_unknown_and_never_signs_partial_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path) as central:
            native.native.manager.dom_snapshot = AsyncMock(
                side_effect=ValueError("malicious dom exceeds bounded budget")
            )
            denied = await _invoke(
                native, _action(REQUEST_NAV, native.base_url + "/", "screenshot_dom_har")
            )
            _assert_unknown(native, REQUEST_NAV, denied)
            assert len(central.calls) == 1
            assert native.page_hits == ["/"]
            assert "malicious dom" not in json.dumps(denied)
            assert all(p.suffix != ".html" for p in (native.tenant / "captures").iterdir())


@pytest.mark.asyncio
async def test_real_chromium_blocked_redirect_cannot_issue_coupled_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path) as central:
            requested = native.base_url + "/redirect"
            denied = await _invoke(native, _action(REQUEST_BAD, requested, "screenshot_dom_har"))
            _assert_unknown(native, REQUEST_BAD, denied)
            assert central.calls[0]["evidence_mode"] == "screenshot_dom_har"
            assert native.page_hits == ["/redirect"]
            assert any(
                "browser-external-must-not-resolve.invalid" in item
                for item in (*native.blocked, *native.proxy_attempts)
            )
            assert "evidence" not in denied and "provider_receipt" not in denied
            replay = await _invoke(native, _action(REQUEST_BAD, requested, "screenshot_dom_har"))
            assert replay["status"] == "duplicate_request"
            assert len(central.calls) == 1


@pytest.mark.asyncio
async def test_revoked_mount_during_coupled_capture_never_signs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path) as central:
            captured = native.native.manager.screenshot

            async def revoke_before_screen(*args, **kwargs):
                monkeypatch.setenv(
                    "OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS",
                    json.dumps({ENGAGEMENT: "0" * 64}),
                )
                return await captured(*args, **kwargs)

            monkeypatch.setattr(native.native.manager, "screenshot", revoke_before_screen)
            denied = await _invoke(
                native, _action(REQUEST_NAV, native.base_url + "/", "screenshot_dom_har")
            )
            _assert_unknown(native, REQUEST_NAV, denied)
            assert len(central.calls) == 1
            assert native.page_hits == ["/"]
            assert not list((native.tenant / "captures").glob("*.png"))


@pytest.mark.asyncio
async def test_malicious_html_original_bytes_stay_inside_tenant_and_never_escape_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path):
            payload = (
                b"<html><script>DO_NOT_EXECUTE</script>"
                b"<img src='https://exfil-do-not-contact.invalid/token'>"
                b"<div data-secret='SECRET_DO_NOT_LEAK'>proof</div></html>"
            )

            async def malicious_dom(*args, **kwargs):
                # Feed inert hostile-looking bytes at the capture persistence
                # seam. Do NOT navigate to or execute any injected URLs/JS.
                return native.native.manager._persist_signed_capture(
                    LABEL,
                    ENGAGEMENT,
                    TASK,
                    payload,
                    "html",
                    1024 * 1024,
                )

            monkeypatch.setattr(native.native.manager, "dom_snapshot", malicious_dom)
            result = await _invoke(
                native, _action(REQUEST_NAV, native.base_url + "/", "screenshot_dom_har")
            )
            assert result["status"] == "success"
            html = (native.tenant / result["result"]["evidence"]["dom"]["path"]).read_bytes()
            assert html == payload
            serialized = json.dumps(result)
            assert "DO_NOT_EXECUTE" not in serialized
            assert "SECRET_DO_NOT_LEAK" not in serialized
            assert "exfil-do-not-contact.invalid" not in serialized
            assert not any("exfil-do-not-contact.invalid" in item for item in native.proxy_attempts)


@pytest.mark.asyncio
async def test_mutated_har_original_bytes_keep_entire_action_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with native_browser_local(tmp_path, monkeypatch) as native:
        async with owned_signed_source(native, monkeypatch, tmp_path):
            flush = native.native.manager.flush_har

            async def mutate_original(*args, **kwargs):
                result = await flush(*args, **kwargs)
                original = native.tenant / result["path"]
                original.write_bytes(original.read_bytes() + b"changed")
                return result

            monkeypatch.setattr(native.native.manager, "flush_har", mutate_original)
            denied = await _invoke(
                native, _action(REQUEST_NAV, native.base_url + "/", "screenshot_dom_har")
            )
            _assert_unknown(native, REQUEST_NAV, denied)
            assert native.page_hits == ["/"]
            assert not native.native.manager.contexts


def test_reviewed_capture_readback_denies_symlink_and_changed_original_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.qualification.native_browser_local_helper_20261020 import _load_browser_module

    module = _load_browser_module()
    root = tmp_path / "tenant"
    root.mkdir()
    capture = root / "captures"
    capture.mkdir()
    original = b"\x89PNG\r\n\x1a\nsmall"
    leaf = capture / ("f" * 32 + ".png")
    leaf.write_bytes(original)
    monkeypatch.setattr(module, "_signed_mount", lambda engagement: (root, "a" * 64, "b" * 64))
    meta = {
        "path": f"captures/{leaf.name}",
        "exists": True,
        "engagement_id": ENGAGEMENT,
        "user_label": LABEL,
        "capture_task_id": TASK,
        "size_bytes": len(original),
        "resource_sha256": hashlib.sha256(original).hexdigest(),
        "mount_sha256": "a" * 64,
        "container_image_sha256": "b" * 64,
    }
    passed = module._reviewed_capture_metadata(
        meta,
        engagement_id=ENGAGEMENT,
        user_label=LABEL,
        task_id=TASK,
        suffix="png",
        limit=100,
    )
    assert passed["resource_sha256"] == meta["resource_sha256"]
    leaf.write_bytes(original + b"altered")
    with pytest.raises(ValueError):
        module._reviewed_capture_metadata(
            meta,
            engagement_id=ENGAGEMENT,
            user_label=LABEL,
            task_id=TASK,
            suffix="png",
            limit=100,
        )
    with pytest.raises(ValueError):
        module._reviewed_capture_metadata(
            {**meta, "path": "../outside/escape.png"},
            engagement_id=ENGAGEMENT,
            user_label=LABEL,
            task_id=TASK,
            suffix="png",
            limit=100,
        )
    leaf.unlink()
    foreign = tmp_path / "foreign"
    foreign.write_bytes(original)
    try:
        leaf.symlink_to(foreign)
    except (OSError, NotImplementedError):
        # Preserve the other original-byte and traversal assertions on Windows
        # where an unprivileged account may not create filesystem symlinks.
        return
    with pytest.raises((ValueError, OSError)):
        module._reviewed_capture_metadata(
            meta,
            engagement_id=ENGAGEMENT,
            user_label=LABEL,
            task_id=TASK,
            suffix="png",
            limit=100,
        )
