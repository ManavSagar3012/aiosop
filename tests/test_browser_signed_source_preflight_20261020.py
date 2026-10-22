"""Independent central signed Browser preflight, no sockets/target/DB/provider.

Tests the ACTUAL FastAPI native producer, first durable request reservation,
separate central trust configuration and Playwright call ordering with a
strictly in-memory HTTPX stand-in. Does not simulate successful Flow authority
at the central source; that requires its independently owned joined tests.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import ssl
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from ai_osop.memory import browser_source_authority as central_source
from tests.test_browser_mcp_signed_provider import (
    SID,
    TASK,
    USER,
    TOKEN,
    _binding,
    _post,
    provider,
)


URL = "https://example.test/"
SOURCE_URL = "https://127.0.0.1:18443/native-browser/source-preflight"
SOURCE_TOKEN = "separately-provisioned-native-service-credential"
SOURCE_KID = "central-preflight-root-1"


def _original(req_id: str, *, url: str = URL) -> dict:
    return {
        "tool_name": "execute",
        "request_id": req_id,
        "session_id": SID,
        "execution_binding": _binding(req_id),
        "parameters": {"action": "navigate", "url": url, "user_label": USER},
    }


def _source_request(req_id: str, *, url: str = URL) -> dict:
    return {
        "request_id": req_id,
        "engagement_id": SID,
        "task_id": TASK,
        "server_id": "browser-mcp",
        "tool_name": "execute",
        "action": "navigate",
        "user_label": USER,
        "evidence_mode": "none",
        "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
        "origin": "https://example.test:443",
    }


def _signed_reply(
    signer: Ed25519PrivateKey,
    req: dict,
    *,
    overrides: dict | None = None,
) -> dict:
    now = int(time.time())
    claims = {
        "version": 1,
        "preflight_id": "nbp-" + "a" * 32,
        **req,
        "flow_id": "flow-signed-1",
        "subtask_id": "subtask-reviewed-1",
        "action_id": "action-" + "b" * 32,
        "owner_id": "owner-original-1",
        "authorization_version": 2,
        "authorization_sha256": "c" * 64,
        "approval_id": "approval-human-1",
        "lease_id": "lease-current-1",
        "issued_at": now,
        "expires_at": now + 8,
    }
    if overrides:
        claims.update(overrides)
    canonical = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    signed = signer.sign(b"ai-osop/browser-source-preflight/v1\x00" + canonical)
    return {
        "claims": claims,
        "kid": SOURCE_KID,
        "signature": base64.urlsafe_b64encode(signed).decode("ascii").rstrip("="),
    }


@pytest.fixture
def source(provider, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Independent signer, trust root and local stub HTTPX, never real network."""
    module = provider.module
    signer = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    public = signer.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    cert_key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "browser-local-source-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(cert_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(cert_key, algorithm=None)
    )
    ca = tmp_path / "independently-enrolled-ca.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.setenv("OSOP_BROWSER_MCP_SIGNED_ORIGINS_JSON", json.dumps({SID: [URL[:-1]]}))
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_URL", SOURCE_URL)
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(ca))
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_SERVICE_TOKEN", SOURCE_TOKEN)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps(
            {
                SOURCE_KID: base64.b64encode(public).decode("ascii"),
            }
        ),
    )
    calls: list[dict] = []
    client_options: list[dict] = []
    responses: list[object] = []

    class LocalCentral:
        def __init__(self, **kwargs):
            client_options.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, endpoint, *, json, headers):
            calls.append({"endpoint": endpoint, "json": dict(json), "headers": dict(headers)})
            # Represent the central original Action's reviewed user_label.
            # This does NOT implement PG verification in the native fixture;
            # the genuine central worker handles its own durable authority.
            if json.get("user_label") != USER:
                return httpx.Response(
                    409, json={"detail": "current Action user binding unavailable"}
                )
            if responses:
                planned = responses.pop(0)
                if isinstance(planned, BaseException):
                    raise planned
                if callable(planned):
                    return planned(json)
                return planned
            return httpx.Response(200, json=_signed_reply(signer, json))

    # Replace ONLY the native module's outbound source transport. Patching
    # httpx.AsyncClient globally would also replace our ASGI inbound driver
    # and silently skip the actual Browser MCP FastAPI handler.
    monkeypatch.setattr(
        module,
        "httpx",
        SimpleNamespace(
            AsyncClient=LocalCentral,
            Timeout=httpx.Timeout,
        ),
    )
    real_new_context = provider.browser.new_context

    async def fake_context(**kwargs):
        created = await real_new_context(**kwargs)
        created.route = AsyncMock()
        real_goto = created.page.goto

        async def real_page_response(url, **kw):
            await real_goto(url, **kw)
            return SimpleNamespace(
                status=200,
                request=SimpleNamespace(url=url, redirected_from=None),
            )

        created.page.goto = AsyncMock(side_effect=real_page_response)
        return created

    monkeypatch.setattr(provider.browser, "new_context", fake_context)
    return SimpleNamespace(
        provider=provider,
        signer=signer,
        ca=ca,
        calls=calls,
        opts=client_options,
        responses=responses,
        module=module,
    )


@pytest.mark.asyncio
async def test_source_preflight_exact_one_use_precedes_any_browser_effect(source):
    request_id = "req-original-source-1"
    result = (await _post(source.provider, _original(request_id))).json()
    assert result["status"] == "success"
    assert result["provider_receipt"]["status"] == "succeeded"
    assert source.module.RequestJournal(_binding(request_id)).read() == "succeeded"
    assert len(source.calls) == 1
    assert source.calls[0]["json"] == _source_request(request_id)
    assert source.calls[0]["endpoint"] == SOURCE_URL
    assert source.calls[0]["headers"]["Authorization"] == f"Bearer {SOURCE_TOKEN}"
    assert TOKEN not in repr(source.calls)
    assert len(source.provider.browser.created) == 1
    assert source.opts[0]["verify"] == str(source.ca)
    assert source.opts[0]["trust_env"] is False
    assert source.opts[0]["follow_redirects"] is False
    ctx = source.provider.browser.created[0]
    assert ctx.route.await_count == 1
    assert ctx.page.goto.await_count == 1
    replay = (await _post(source.provider, _original(request_id))).json()
    assert replay["status"] == "duplicate_request"
    assert len(source.calls) == 1
    assert ctx.page.goto.await_count == 1


def test_central_and_native_strict_wire_shapes_and_domain_match(source):
    """Exact cross-component 9/21 contract without touching application PG."""
    native = source.module
    assert central_source.DOMAIN == native._SOURCE_DOMAIN
    assert central_source._FIELDS == native._SOURCE_REQUEST
    assert central_source._CLAIM_FIELDS == native._SOURCE_CLAIMS
    assert central_source.exact_origin(URL) == native._exact_browser_origin(URL)
    request = _source_request("req-" + "a" * 48)
    assert central_source.validate_request(request) == request
    signed = _signed_reply(source.signer, request)
    canonical = central_source._canonical(signed["claims"])
    assert canonical == json.dumps(
        signed["claims"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    _, _, _, trust = native._source_configuration()
    assert native._verify_source_preflight(signed, request, trust) == signed["claims"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [302, 401, 403, 409, 503])
async def test_http_denial_or_redirect_cannot_navigate(source, status: int):
    source.responses.append(httpx.Response(status, json={"status": "approved"}))
    request_id = f"req-http-denied-{status}"
    denied = (await _post(source.provider, _original(request_id))).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert source.module.RequestJournal(_binding(request_id)).read() == "unknown"
    assert not source.provider.browser.created
    replay = (await _post(source.provider, _original(request_id))).json()
    assert replay["status"] == "duplicate_request"
    assert len(source.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "problem",
    [
        "wrong-url",
        "wrong-tenant",
        "wrong-action",
        "wrong-user-label",
        "wrong-lease-shape",
        "expired",
        "far-future",
        "unsigned",
        "wrong-signer",
        "extra-field",
        "wrong-content-type",
        "oversized",
        "ambiguous-json",
    ],
)
async def test_forged_or_stale_signed_source_reply_is_unknown(source, problem: str):
    req = f"req-preflight-forged-{problem}"

    def forged(envelope: dict) -> httpx.Response:
        override = {}
        if problem == "wrong-url":
            override["url_sha256"] = "f" * 64
        if problem == "wrong-tenant":
            override["engagement_id"] = "eng-another-tenant"
        if problem == "wrong-action":
            override["action"] = "click"
        if problem == "wrong-user-label":
            override["user_label"] = "user-swapped-identity"
        if problem == "wrong-lease-shape":
            override["lease_id"] = ""
        if problem == "expired":
            override.update(
                {"issued_at": int(time.time()) - 20, "expires_at": int(time.time()) - 12}
            )
        if problem == "far-future":
            override.update(
                {"issued_at": int(time.time()) + 50, "expires_at": int(time.time()) + 58}
            )
        payload = _signed_reply(source.signer, envelope, overrides=override)
        if problem == "unsigned":
            payload["signature"] = "a" * 86
        if problem == "wrong-signer":
            payload["kid"] = "foreign-central-key"
        if problem == "extra-field":
            payload["claims"]["caller_override"] = True
        if problem == "wrong-content-type":
            return httpx.Response(200, json=payload, headers={"Content-Type": "text/html"})
        if problem == "oversized":
            return httpx.Response(
                200, content=b"X" * 4097, headers={"Content-Type": "application/json"}
            )
        if problem == "ambiguous-json":
            return httpx.Response(
                200,
                content=b'{"kid":"a","kid":"b","claims":{},"signature":"x"}',
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(200, json=payload)

    source.responses.append(forged)
    denied = (await _post(source.provider, _original(req))).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert source.module.RequestJournal(_binding(req)).read() == "unknown"
    assert not source.provider.browser.created
    assert len(source.calls) == 1


@pytest.mark.asyncio
async def test_source_ack_lost_does_not_repeat_redemption_or_browser_navigation(source):
    req = "req-source-ack-lost"
    source.responses.append(httpx.ReadTimeout("lost central ACK after commit"))
    denied = (await _post(source.provider, _original(req))).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert source.module.RequestJournal(_binding(req)).read() == "unknown"
    assert not source.provider.browser.created
    replay = (await _post(source.provider, _original(req))).json()
    assert replay["status"] == "duplicate_request"
    assert len(source.calls) == 1


@pytest.mark.asyncio
async def test_bearer_cannot_swap_original_approved_browser_identity(source):
    request_id = "req-swapped-caller-identity"
    payload = _original(request_id)
    payload["parameters"]["user_label"] = "user-more-privileged"
    result = (await _post(source.provider, payload)).json()
    assert result["status"] == "error" and "provider_receipt" not in result
    assert source.calls[0]["json"]["user_label"] == "user-more-privileged"
    assert source.module.RequestJournal(_binding(request_id)).read() == "unknown"
    assert source.provider.browser.created == []


@pytest.mark.asyncio
async def test_signed_source_does_not_authorize_same_origin_redirect_to_changed_path(
    source, monkeypatch
):
    """A central grant binds exact URL bytes, even on an approved origin."""
    original_new_context = source.provider.browser.new_context

    async def redirected_context(**kwargs):
        context = await original_new_context(**kwargs)

        async def changed_path_goto(url, **_):
            context.page.url = url
            return SimpleNamespace(
                status=200,
                request=SimpleNamespace(
                    url=url,
                    redirected_from=SimpleNamespace(url=url + "unapproved", redirected_from=None),
                ),
            )

        context.page.goto = AsyncMock(side_effect=changed_path_goto)
        return context

    monkeypatch.setattr(source.provider.browser, "new_context", redirected_context)
    req = "req-reviewed-url-only"
    rejected = (await _post(source.provider, _original(req))).json()
    assert rejected["status"] == "error" and "provider_receipt" not in rejected
    assert source.module.RequestJournal(_binding(req)).read() == "unknown"
    assert len(source.calls) == 1
    assert source.provider.browser.created[0].page.goto.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "parameter_override",
    [
        {"action": "click"},
        {"engagement_id": SID},
        {"engagement_id": "eng-foreign"},
        {"storage_state": {"cookies": [], "origins": []}},
    ],
)
async def test_signed_production_non_original_action_never_reaches_central(
    source, parameter_override
):
    req = "req-bad-original-" + str(len(source.calls))
    payload = _original(req)
    payload["parameters"].update(parameter_override)
    denied = (await _post(source.provider, payload)).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert source.calls == []
    assert not source.provider.browser.created


@pytest.mark.asyncio
async def test_missing_root_configuration_fails_before_network_or_page(source, monkeypatch):
    monkeypatch.delenv("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
    req = "req-no-independent-source-root"
    denied = (await _post(source.provider, _original(req))).json()
    assert denied["status"] == "error" and "provider_receipt" not in denied
    assert source.calls == []
    assert source.module.RequestJournal(_binding(req)).read() == "unknown"
    assert not source.provider.browser.created


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["", "staging", "development"])
async def test_signed_source_cannot_be_bypassed_by_nonproduction_environment(
    source, monkeypatch, mode
):
    monkeypatch.setenv("OSOP_ENVIRONMENT", mode)
    monkeypatch.delenv("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
    req = "req-staging-cannot-bypass-central"
    refused = (await _post(source.provider, _original(req))).json()
    assert refused["status"] == "error" and "provider_receipt" not in refused
    assert not source.calls and not source.provider.browser.created
    assert source.module.RequestJournal(_binding(req)).read() == "unknown"


@pytest.mark.asyncio
async def test_legacy_unsigned_inert_local_fixture_requires_no_central_source(source, monkeypatch):
    monkeypatch.setenv("OSOP_ENVIRONMENT", "development")
    monkeypatch.delenv("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON")
    payload = _original("req-legacy-unsigned-local-only")
    payload.pop("execution_binding")
    payload["parameters"]["engagement_id"] = SID
    result = (await _post(source.provider, payload, bearer=False)).json()
    assert result["status"] == "success"
    assert "provider_receipt" not in result
    assert not source.calls
    assert len(source.provider.browser.created) == 1


@pytest.mark.asyncio
async def test_real_owned_loopback_https_ca_pin_and_independent_signed_response(
    source,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """Actual OpenSSL-backed HTTPS; separately trusted local source, no DB/egress."""
    tls_key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(tls_key, algorithm=None)
    )
    certfile = tmp_path / "loopback-central-cert.pem"
    keyfile = tmp_path / "loopback-central-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        tls_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(str(certfile), str(keyfile))
    accepts = []

    async def source_handler(request: web.Request) -> web.Response:
        assert request.headers.get("Authorization") == f"Bearer {SOURCE_TOKEN}"
        body = await request.json()
        accepts.append(body)
        return web.json_response(_signed_reply(source.signer, body))

    app = web.Application()
    app.router.add_post("/native-browser/source-preflight", source_handler)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
    await site.start()
    assert site._server is not None
    address = site._server.sockets[0].getsockname()
    assert address[0] == "127.0.0.1"
    monkeypatch.setattr(source.module, "httpx", httpx)
    monkeypatch.setenv(
        "OSOP_BROWSER_SOURCE_URL",
        f"https://127.0.0.1:{address[1]}/native-browser/source-preflight",
    )
    try:
        # A configured-but-unrelated cert must not be accepted from system
        # root/proxies or from any response-provided signer identity.
        rejected_id = "req-source-untrusted-ca"
        untrusted = (await _post(source.provider, _original(rejected_id))).json()
        assert untrusted["status"] == "error"
        assert source.module.RequestJournal(_binding(rejected_id)).read() == "unknown"
        assert not accepts and not source.provider.browser.created

        monkeypatch.setenv("OSOP_BROWSER_SOURCE_CA_BUNDLE", str(certfile))
        approved_id = "req-source-valid-owned-https"
        accepted = (await _post(source.provider, _original(approved_id))).json()
        assert accepted["status"] == "success"
        assert source.module.RequestJournal(_binding(approved_id)).read() == "succeeded"
        assert accepts == [_source_request(approved_id)]
        assert len(source.provider.browser.created) == 1
    finally:
        await runner.cleanup()
