"""Actual loopback TCP IdP + ASGI operator login qualification.

No production IdP, app DB, target, browser profile or external network.
The production OIDC configuration intentionally requires HTTPS/port 443. Only
this isolated TEST overrides its already-validated HTTPS URLs with ephemeral
127.0.0.1 HTTP endpoints, never modifying the production verifier or settings.

Run: poetry run pytest -q --no-cov tests/qualification/test_live_oidc_provider_browser.py
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, HTTPException
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.routers.auth import router as auth_router
from ai_osop.core.config import settings

_REAL_OIDC_CONFIG = deps._oidc_config

_ISSUER = "https://issuer.qualification.invalid/realm"
_AUDIENCE = "ai-osop-operator-api"
_BASIC_ID = "osop-qualification"
_BASIC_SECRET = "loopback-only-secret"
_ROLE_MAP = {
    "qualified-operators": "operator",
    "qualified-seniors": "senior_operator",
}


def _base64_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _keypair(kid: str) -> tuple[bytes, dict]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _base64_int(numbers.n),
        "e": _base64_int(numbers.e),
    }
    return private_pem, public


class LoopbackIdentity:
    """In-process state, isolated real HTTP socket, zero external requests."""

    def __init__(self) -> None:
        self.mutex = threading.RLock()
        self.keys = {}
        self.public_keys = {}
        self.active_tokens = {}
        self.jwks_calls = 0
        self.introspection_calls = 0
        self.auth_failures = 0
        self.jwks_status = 200
        self.introspection_status = 200
        self.introspection_override = None
        self.last_hint = None
        self.server = None
        self.thread = None
        self.add_key("signing-one")

    def add_key(self, kid: str) -> None:
        private, public = _keypair(kid)
        with self.mutex:
            self.keys[kid] = private
            self.public_keys[kid] = public

    def retain_keys(self, *kids: str) -> None:
        with self.mutex:
            self.public_keys = {kid: self.public_keys[kid] for kid in kids}

    def sign(self, *, kid="signing-one", subject="operator-alice", groups=None, **claims) -> str:
        now = int(time.time())
        body = {
            "iss": _ISSUER,
            "aud": _AUDIENCE,
            "sub": subject,
            "iat": now - 20,
            "nbf": now - 20,
            "exp": now + 300,
            "groups": groups if groups is not None else ["qualified-operators"],
            "jti": "jti-" + str(len(self.active_tokens) + 1),
        }
        body.update(claims)
        with self.mutex:
            token = jwt.encode(
                body,
                self.keys[kid],
                algorithm="RS256",
                headers={"typ": "at+jwt", "kid": kid},
            )
            self.active_tokens[token] = dict(body)
            return token

    def revoke(self, token: str) -> None:
        with self.mutex:
            self.active_tokens.pop(token, None)

    def start(self) -> "LoopbackIdentity":
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args) -> None:
                return

            def _json(self, value: dict, status=200) -> None:
                content = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(content)

            def do_GET(self) -> None:
                if self.path != "/jwks":
                    self._json({"error": "not found"}, status=404)
                    return
                with owner.mutex:
                    owner.jwks_calls += 1
                    status = owner.jwks_status
                    data = list(owner.public_keys.values())
                self._json({"keys": data}, status=status)

            def do_POST(self) -> None:
                if self.path != "/introspect":
                    self._json({"error": "not found"}, status=404)
                    return
                expected = (
                    "Basic " + base64.b64encode(f"{_BASIC_ID}:{_BASIC_SECRET}".encode()).decode()
                )
                if self.headers.get("Authorization") != expected:
                    with owner.mutex:
                        owner.auth_failures += 1
                    self._json({"error": "invalid_client"}, status=401)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 1 <= length <= 20000:
                        raise ValueError("bad input length")
                    params = parse_qs(
                        self.rfile.read(length).decode("ascii"),
                        strict_parsing=True,
                    )
                    token = params["token"][0]
                    hint = params["token_type_hint"][0]
                except (ValueError, KeyError, UnicodeError, IndexError):
                    self._json({"error": "invalid_request"}, status=400)
                    return
                with owner.mutex:
                    owner.introspection_calls += 1
                    owner.last_hint = hint
                    current = owner.active_tokens.get(token)
                    status = owner.introspection_status
                    override = owner.introspection_override
                if status != 200:
                    self._json({"error": "temporarily_unavailable"}, status=status)
                elif current is None:
                    self._json({"active": False})
                else:
                    info = {
                        "active": True,
                        "sub": current["sub"],
                        "iss": current["iss"],
                        "aud": current["aud"],
                        "jti": current["jti"],
                        "exp": current["exp"],
                    }
                    if override is not None:
                        info.update(override)
                    self._json(info)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        server.timeout = 1
        self.server = server
        self.thread = threading.Thread(
            target=server.serve_forever,
            name="test-oidc-loopback",
            daemon=True,
        )
        self.thread.start()
        return self

    @property
    def url(self) -> str:
        assert self.server is not None
        return "http://127.0.0.1:" + str(self.server.server_port)

    def close(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None


@pytest.fixture
def provider(monkeypatch):
    with _provider(monkeypatch) as runtime:
        yield runtime


@contextmanager
def _provider(monkeypatch):
    service = LoopbackIdentity().start()
    deps._JWKS_CACHE.clear()
    try:
        monkeypatch.setattr(settings, "environment", "production")
        monkeypatch.setattr(settings, "api_token", "legacy-not-an-identity")
        monkeypatch.setattr(settings, "jwt_secret", None)
        monkeypatch.setattr(settings, "oidc_issuer", _ISSUER)
        monkeypatch.setattr(settings, "oidc_audience", _AUDIENCE)
        monkeypatch.setattr(
            settings,
            "oidc_jwks_url",
            _ISSUER + "/jwks",
        )
        monkeypatch.setattr(settings, "oidc_algorithms", "RS256")
        monkeypatch.setattr(settings, "oidc_token_typ", "at+jwt")
        monkeypatch.setattr(settings, "oidc_role_claim", "groups")
        monkeypatch.setattr(settings, "oidc_role_map_json", json.dumps(_ROLE_MAP))
        monkeypatch.setattr(settings, "oidc_jwks_cache_seconds", 300)
        monkeypatch.setattr(settings, "oidc_max_token_seconds", 3600)
        monkeypatch.setattr(
            settings,
            "oidc_introspection_url",
            _ISSUER + "/introspect",
        )
        monkeypatch.setattr(settings, "oidc_introspection_client_id", _BASIC_ID)
        monkeypatch.setattr(
            settings,
            "oidc_introspection_client_secret",
            _BASIC_SECRET,
        )
        production = deps._oidc_config()
        assert production["jwks_url"].startswith("https://")
        assert production["introspection"][0].startswith("https://")

        # Only this qualification's transport points to real loopback HTTP.
        # Keep production's network-origin restrictions completely unchanged.
        test_config = {
            **production,
            "jwks_url": service.url + "/jwks",
            "introspection": (service.url + "/introspect", _BASIC_ID, _BASIC_SECRET),
        }
        monkeypatch.setattr(deps, "_oidc_config", lambda: test_config)
        app = FastAPI()
        app.include_router(auth_router)

        @app.get("/operator/action")
        async def operator_action(
            identity=Depends(
                deps.require_role(
                    "operator",
                    "senior_operator",
                )
            )
        ):
            return {"subject": identity["sub"], "role": identity["role"], "authorized": True}

        @app.get("/operator/senior")
        async def senior_action(identity=Depends(deps.require_role("senior_operator"))):
            return {"subject": identity["sub"], "role": identity["role"], "authorized": True}

        yield {"service": service, "app": app, "config": test_config}
    finally:
        deps._JWKS_CACHE.clear()
        service.close()


async def _request(runtime, token=None, *, path="/auth/me", bearer=True):
    headers = {"Authorization": "Bearer " + token} if token and bearer else {}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=runtime["app"]),
        base_url="http://testserver",
        trust_env=False,
    ) as browser:
        return await browser.get(path, headers=headers)


@pytest.mark.asyncio
async def test_real_loopback_operator_browser_journey_and_revocation(provider):
    idp = provider["service"]
    token = idp.sign()
    first = await _request(provider, token)
    assert first.status_code == 200, first.text
    assert first.headers["cache-control"] == "no-store"
    expected = (
        "oidc-"
        + hashlib.sha256(
            (_ISSUER + "\0operator-alice").encode("utf-8"),
        ).hexdigest()[:48]
    )
    assert first.json()["sub"] == expected
    assert first.json()["role"] == "operator"
    assert (await _request(provider, token, path="/operator/action")).status_code == 200
    assert (await _request(provider, token, path="/operator/senior")).status_code == 403
    assert idp.last_hint == "access_token"
    assert idp.jwks_calls == 1  # Verified signing key is cached.
    assert idp.introspection_calls == 3  # Live RFC7662 for EVERY admission.
    idp.revoke(token)
    denied = await _request(provider, token)
    assert denied.status_code == 401
    assert idp.introspection_calls == 4
    assert _BASIC_SECRET not in denied.text and token not in denied.text
    assert (await _request(provider, token, path="/operator/action")).status_code == 401


@pytest.mark.asyncio
async def test_real_loopback_senior_journey_requires_mapped_group(provider):
    idp = provider["service"]
    viewer = idp.sign(groups=["untrusted-group"])
    assert (await _request(provider, viewer, path="/operator/action")).status_code == 401
    senior = idp.sign(groups=["qualified-seniors", "other-untrusted-group"])
    result = await _request(provider, senior, path="/operator/senior")
    assert result.status_code == 200, result.text
    assert result.json()["role"] == "senior_operator"
    assert result.json()["subject"].startswith("oidc-")
    assert (await _request(provider, senior, path="/auth/me?token=leak")).status_code == 403
    assert (await _request(provider, "legacy-not-an-identity")).status_code == 401
    assert (await _request(provider, senior, bearer=False)).status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wrong",
    [
        {"iss": "https://attacker.qualification.invalid"},
        {"aud": "other-api"},
        {"azp": "evil-client"},
        {"exp": int(time.time()) - 60},
    ],
)
async def test_loopback_rejects_invalid_issuer_audience_party_and_expiry(provider, wrong):
    token = provider["service"].sign(**wrong)
    result = await _request(provider, token)
    assert result.status_code == 401, result.text
    assert result.json()["detail"] != token


@pytest.mark.asyncio
async def test_real_jwks_rotation_invalidates_removed_key_on_refresh(provider):
    idp = provider["service"]
    original = idp.sign()
    assert (await _request(provider, original)).status_code == 200
    first_count = idp.jwks_calls
    idp.add_key("signing-two")
    idp.retain_keys("signing-two")
    rotated = idp.sign(kid="signing-two", subject="other-human")
    next_identity = await _request(provider, rotated)
    assert next_identity.status_code == 200
    assert idp.jwks_calls == first_count + 1  # Unknown KID causes refetch.
    assert (await _request(provider, original)).status_code == 401
    assert idp.introspection_calls == 2  # Old token refused before introspection.


@pytest.mark.asyncio
async def test_real_idp_unavailable_denies_fresh_keys_and_introspection(provider):
    idp = provider["service"]
    token = idp.sign()
    assert (await _request(provider, token)).status_code == 200
    idp.introspection_status = 503
    rejected = await _request(provider, token)
    assert rejected.status_code == 503
    assert "unavailable" in rejected.text.lower()
    assert _BASIC_SECRET not in rejected.text
    idp.introspection_status = 200
    deps._JWKS_CACHE["expires"] = 0
    idp.jwks_status = 503
    assert (await _request(provider, token)).status_code == 503
    assert idp.introspection_calls == 2  # Deny at JWKS before introspection.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forgery",
    [
        {"sub": "different-operator"},
        {"iss": "https://foreign-issuer.invalid"},
        {"aud": "wrong-api"},
        {"jti": "replayed-other-token"},
        {"exp": 1},
        {"active": "true"},
    ],
)
async def test_live_rfc7662_active_is_bound_to_signed_token(provider, forgery):
    idp = provider["service"]
    token = idp.sign()
    idp.introspection_override = forgery
    response = await _request(provider, token, path="/operator/action")
    assert response.status_code in {401, 503}
    assert response.status_code == (503 if forgery == {"active": "true"} else 401)
    assert idp.introspection_calls == 1
    assert not response.is_success


@pytest.mark.asyncio
async def test_real_idp_socket_disconnection_is_never_offline_allow(provider):
    idp = provider["service"]
    token = idp.sign()
    assert (await _request(provider, token)).status_code == 200
    idp.close()
    # Token still has a valid cached public key, but live RFC7662 fails.
    rejected = await _request(provider, token)
    assert rejected.status_code == 503
    assert "unavailable" in rejected.text.lower()


def test_production_configuration_rejects_plaintext_loopback_idp(provider, monkeypatch):
    # A test-only HTTP transport override must not become a production bypass.
    monkeypatch.setattr(settings, "oidc_jwks_url", provider["service"].url + "/jwks")
    with pytest.raises(HTTPException) as denied:
        _REAL_OIDC_CONFIG()
    assert denied.value.status_code == 503


_CHILD_ASGI_JOURNEY = """
import asyncio, json, os, sys
import httpx
from fastapi import FastAPI
from ai_osop.api import deps
from ai_osop.api.routers.auth import router as auth_router
from ai_osop.core.config import settings

item = json.loads(sys.stdin.read())
settings.environment = "production"
settings.api_token = "legacy-not-an-identity"
settings.jwt_secret = None
settings.oidc_issuer = "https://issuer.qualification.invalid/realm"
settings.oidc_audience = "ai-osop-operator-api"
settings.oidc_jwks_url = settings.oidc_issuer + "/jwks"
settings.oidc_algorithms = "RS256"
settings.oidc_token_typ = "at+jwt"
settings.oidc_role_claim = "groups"
settings.oidc_role_map_json = '{"qualified-operators":"operator","qualified-seniors":"senior_operator"}'
settings.oidc_jwks_cache_seconds = 300
settings.oidc_max_token_seconds = 3600
settings.oidc_introspection_url = settings.oidc_issuer + "/introspect"
settings.oidc_introspection_client_id = "osop-qualification"
settings.oidc_introspection_client_secret = "loopback-only-secret"
production_config = deps._oidc_config()
assert production_config["jwks_url"].startswith("https://")
config = {
    **production_config,
    "jwks_url": item["idp"] + "/jwks",
    "introspection": (
        item["idp"] + "/introspect",
        "osop-qualification",
        "loopback-only-secret",
    ),
}
deps._oidc_config = lambda: config  # TEST-ONLY ephemeral transport
app = FastAPI()
app.include_router(auth_router)

async def main():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        trust_env=False,
    ) as client:
        response = await client.get(
            "/auth/me", headers={"Authorization": "Bearer " + item["jwt"]},
        )
    print(json.dumps({
        "status": response.status_code,
        "role": response.json().get("role"),
        "pid": os.getpid(),
    }))

asyncio.run(main())
"""


def _child_operator_request(service: LoopbackIdentity, token: str) -> dict:
    # Pass even test-only bearer over stdin, not argv or environment. The
    # subprocess has a fresh process-level JWKS cache and uses real TCP.
    child = subprocess.run(
        [sys.executable, "-c", _CHILD_ASGI_JOURNEY],
        input=json.dumps({"idp": service.url, "jwt": token}),
        capture_output=True,
        text=True,
        # A fresh Windows Python process cold-imports the complete auth/API
        # dependency graph. Under the full 4k-test regression workload that
        # startup exceeded 25s once, although isolated revocation passed.
        # Keep a strict finite subprocess bound without confusing slow local
        # startup with a successful/failed JWT revocation decision.
        timeout=60,
        check=False,
    )
    assert child.returncode == 0, child.stderr[-800:]
    return json.loads(child.stdout.strip().splitlines()[-1])


def test_fresh_processes_also_enforce_live_oidc_token_revocation(provider):
    idp = provider["service"]
    token = idp.sign(groups=["qualified-seniors"])
    first = _child_operator_request(idp, token)
    assert first["status"] == 200
    assert first["role"] == "senior_operator"
    assert first["pid"] != os.getpid()
    assert idp.jwks_calls == 1 and idp.introspection_calls == 1
    idp.revoke(token)
    second = _child_operator_request(idp, token)
    assert second["status"] == 401
    assert second["pid"] != os.getpid()
    assert idp.jwks_calls == 2 and idp.introspection_calls == 2
