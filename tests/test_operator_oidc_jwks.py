"""Operator OIDC uses configured public JWKS only; no external IdP or app DB."""

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import Depends, FastAPI, HTTPException
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.routers.auth import router as auth_router
from ai_osop.core.config import settings


@dataclass(frozen=True)
class _SecondsFromRequestTime:
    """Test-only JWT clock offset; no epoch is captured during collection."""

    offset: int


def _runtime_claim_mutation(mutate: dict, *, now: int | None = None) -> dict:
    """Resolve exp/nbf/iat fixtures immediately before signing a request."""

    request_time = int(time.time()) if now is None else now
    return {
        name: request_time + value.offset
        if isinstance(value, _SecondsFromRequestTime) else value
        for name, value in mutate.items()
    }


def _urlsafe_int(integer: int) -> str:
    data = integer.to_bytes((integer.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rsa_pair(kid: str):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwk = {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
        "n": _urlsafe_int(numbers.n), "e": _urlsafe_int(numbers.e),
    }
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, jwk


def _ec_pair(kid: str):
    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    jwk = {
        "kty": "EC", "kid": kid, "crv": "P-256", "use": "sig",
        # JWK EC coordinates are fixed-width octet strings, not minimally
        # encoded integers. Random P-256 keys occasionally have a leading
        # zero byte; dropping it made the isolated JWKS fixture intermittently
        # invalid (503 key unavailable) during unrelated invalid-claim tests.
        "alg": "ES256",
        "x": base64.urlsafe_b64encode(numbers.x.to_bytes(32, "big")).rstrip(b"=").decode(),
        "y": base64.urlsafe_b64encode(numbers.y.to_bytes(32, "big")).rstrip(b"=").decode(),
    }
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, jwk


@pytest.fixture
def oidc(monkeypatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "jwt_secret", None)
    monkeypatch.setattr(settings, "api_token", "shared-does-not-grant-senior")
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example.test/realm")
    monkeypatch.setattr(settings, "oidc_audience", "ai-osop-operator-api")
    monkeypatch.setattr(settings, "oidc_jwks_url", "https://idp.example.test/realm/jwks")
    monkeypatch.setattr(settings, "oidc_algorithms", "RS256,ES256")
    monkeypatch.setattr(settings, "oidc_token_typ", "at+jwt")
    monkeypatch.setattr(settings, "oidc_role_claim", "groups")
    monkeypatch.setattr(settings, "oidc_role_map_json", json.dumps({
        "trusted-security": "operator", "trusted-leads": "senior_operator",
    }))
    monkeypatch.setattr(settings, "oidc_jwks_cache_seconds", 300)
    monkeypatch.setattr(settings, "oidc_max_token_seconds", 3600)
    deps._JWKS_CACHE.clear()
    rsa_private, rsa_public = _rsa_pair("key-one")
    ec_private, ec_public = _ec_pair("ec-one")
    state = {"keys": [rsa_public, ec_public], "requests": 0, "status": 200, "invalid": None}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"] += 1
        assert request.method == "GET"
        assert str(request.url) == settings.oidc_jwks_url
        if state["invalid"] is not None:
            return httpx.Response(200, content=state["invalid"])
        return httpx.Response(state["status"], json={"keys": state["keys"]})

    monkeypatch.setattr(deps, "_jwks_http_client", lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        timeout=httpx.Timeout(3.0), trust_env=False, follow_redirects=False,
    ))
    app = FastAPI()
    app.include_router(auth_router)

    @app.get("/senior")
    async def _senior(user=Depends(deps.require_role("senior_operator"))):
        return {"role": user["role"]}

    def sign(*, key=rsa_private, kid="key-one", algorithm="RS256", **changes):
        now = int(time.time())
        claims = {
            "iss": settings.oidc_issuer, "aud": settings.oidc_audience,
            "sub": "alice", "exp": now + 300, "nbf": now - 30,
            "iat": now - 60, "groups": ["trusted-security"],
        }
        claims.update(changes)
        return jwt.encode(claims, key, algorithm=algorithm, headers={
            "kid": kid, "typ": "at+jwt",
        })

    async def request(token: str, path="/auth/me"):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
        ) as client:
            return await client.get(path, headers={"Authorization": "Bearer " + token})

    yield {
        "state": state, "sign": sign, "request": request,
        "rsa_private": rsa_private, "rsa_public": rsa_public,
        "ec_private": ec_private, "ec_public": ec_public,
    }
    deps._JWKS_CACHE.clear()


@pytest.mark.asyncio
async def test_oidc_rsa_signature_and_explicit_role_mapping(oidc):
    token = oidc["sign"](groups=["trusted-security", "untrusted-injected-admin"])
    response = await oidc["request"](token)
    assert response.status_code == 200, response.text
    expected_actor = "oidc-" + hashlib.sha256(
        (settings.oidc_issuer + "\0alice").encode(),
    ).hexdigest()[:48]
    assert response.json()["sub"] == expected_actor
    assert response.json()["role"] == "operator"
    assert response.json()["exp"] is not None
    assert oidc["state"]["requests"] == 1
    assert (await oidc["request"](token)).status_code == 200
    assert oidc["state"]["requests"] == 1
    assert (await oidc["request"](token, "/senior")).status_code == 403


@pytest.mark.asyncio
async def test_trusted_senior_group_with_es256(oidc):
    token = oidc["sign"](
        key=oidc["ec_private"], kid="ec-one", algorithm="ES256",
        groups=["trusted-leads"],
    )
    response = await oidc["request"](token, "/senior")
    assert response.status_code == 200, response.text
    assert response.json() == {"role": "senior_operator"}


@pytest.mark.asyncio
async def test_unknown_kid_fetches_rotated_jwks_and_old_key_denied(oidc):
    first = oidc["sign"]()
    assert (await oidc["request"](first)).status_code == 200
    second_private, second_public = _rsa_pair("rotated-key")
    oidc["state"]["keys"] = [second_public]
    rotated = oidc["sign"](key=second_private, kid="rotated-key")
    assert (await oidc["request"](rotated)).status_code == 200
    assert oidc["state"]["requests"] == 2
    assert (await oidc["request"](first)).status_code == 401


@pytest.mark.asyncio
async def test_cache_expiry_failure_never_reuses_stale_keys(oidc):
    token = oidc["sign"]()
    assert (await oidc["request"](token)).status_code == 200
    deps._JWKS_CACHE["expires"] = 0
    oidc["state"]["status"] = 500
    response = await oidc["request"](token)
    assert response.status_code == 503
    assert "key" in response.text.lower()


@pytest.mark.parametrize("fault", [
    "invalid_json", "duplicate", "symmetric", "private", "wrong_alg", "weak_rsa",
])
@pytest.mark.asyncio
async def test_malformed_unsafe_or_ambiguous_jwks_fails_closed(oidc, fault):
    if fault == "invalid_json":
        oidc["state"]["invalid"] = b'{not-json'
    elif fault == "duplicate":
        oidc["state"]["keys"].append(dict(oidc["rsa_public"]))
    elif fault == "symmetric":
        oidc["state"]["keys"] = [{"kid": "key-one", "kty": "oct", "k": "secret"}]
    elif fault == "private":
        oidc["state"]["keys"][0]["d"] = "private-unsafe"
    elif fault == "wrong_alg":
        oidc["state"]["keys"][0]["alg"] = "HS256"
    elif fault == "weak_rsa":
        oidc["state"]["keys"][0]["n"] = _urlsafe_int(65537)
    response = await oidc["request"](oidc["sign"]())
    assert response.status_code in {401, 503}
    assert "secret" not in response.text


@pytest.mark.parametrize("mutate", [
    {"iss": "https://fake-idp.test"},
    {"aud": "foreign-service"},
    {"exp": None},
    {"nbf": None},
    {"iat": None},
    {"sub": None},
    {"sub": ""},
    {"sub": "alice\nadmin"},
    {"exp": True},
    {"iat": True},
    {"nbf": True},
    {"groups": ["senior_operator"]},
    {"groups": "senior_operator"},
    {"groups": []},
    {"groups": ["random-admin"]},
    {"iat": _SecondsFromRequestTime(100)},
    {"nbf": _SecondsFromRequestTime(100)},
    {"exp": _SecondsFromRequestTime(-1)},
    {"aud": ["ai-osop-operator-api", "another-api"]},
    {"aud": ["ai-osop-operator-api", "another-api"], "azp": "another-api"},
    {"iat": _SecondsFromRequestTime(-7200)},
])
@pytest.mark.asyncio
async def test_oidc_invalid_claims_and_untrusted_roles_are_denied(oidc, mutate):
    response = await oidc["request"](oidc["sign"](**_runtime_claim_mutation(mutate)))
    assert response.status_code == 401, (mutate, response.text)


@pytest.mark.parametrize("claim", ["iat", "nbf"])
@pytest.mark.asyncio
async def test_future_claims_still_denied_after_simulated_long_collection_delay(oidc, claim):
    # Simulate collection 10 minutes before execution without slowing the
    # suite. A fixed "collection_time + 100" would now be in the past, making
    # these otherwise-valid tokens pass. Production JWT verification is real.
    request_time = int(time.time())
    collection_time = request_time - 600
    assert collection_time + 100 < request_time
    mutation = _runtime_claim_mutation(
        {claim: _SecondsFromRequestTime(100)}, now=request_time,
    )
    assert mutation[claim] == request_time + 100
    response = await oidc["request"](oidc["sign"](**mutation))
    assert response.status_code == 401, (claim, response.text)


@pytest.mark.asyncio
async def test_oidc_multi_audience_requires_azp(oidc):
    multi = oidc["sign"](
        aud=["ai-osop-operator-api", "another-api"], azp="ai-osop-operator-api",
    )
    assert (await oidc["request"](multi)).status_code == 200


@pytest.mark.asyncio
async def test_id_token_profile_cannot_be_used_as_api_access_token_by_default(oidc):
    now = int(time.time())
    id_token = jwt.encode({
        "iss": settings.oidc_issuer, "aud": settings.oidc_audience,
        "sub": "alice", "exp": now + 300, "iat": now - 30,
        "nbf": now - 30, "groups": ["trusted-leads"],
    }, oidc["rsa_private"], algorithm="RS256", headers={"kid": "key-one", "typ": "JWT"})
    assert (await oidc["request"](id_token, "/senior")).status_code == 401
    assert oidc["state"]["requests"] == 0


@pytest.mark.asyncio
async def test_oidc_identity_cannot_impersonate_local_jwt_subject(oidc, monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", "isolated-local-secret")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    oidc_id = (await oidc["request"](oidc["sign"]())).json()["sub"]
    token = jwt.encode({"sub": "alice", "role": "operator", "exp": int(time.time()) + 300},
                       settings.jwt_secret, algorithm="HS256")
    local_id = (await oidc["request"](token)).json()["sub"]
    assert local_id == "alice"
    assert oidc_id != local_id
    assert len(oidc_id) <= 64


@pytest.mark.asyncio
async def test_repeated_unknown_kid_limits_key_fetches(oidc):
    attacker_key, _ = _rsa_pair("foreign-kid")
    foreign = oidc["sign"](key=attacker_key, kid="foreign-kid")
    assert (await oidc["request"](foreign)).status_code == 401
    requests = oidc["state"]["requests"]
    assert (await oidc["request"](foreign)).status_code == 401
    assert oidc["state"]["requests"] == requests


@pytest.mark.asyncio
async def test_duplicate_jwt_claims_and_header_fields_rejected_before_network(oidc):
    key = oidc["rsa_private"]
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    def wrap(header: bytes, claims: bytes) -> str:
        raw_header = base64.urlsafe_b64encode(header).decode().rstrip("=")
        raw_claims = base64.urlsafe_b64encode(claims).decode().rstrip("=")
        content = (raw_header + "." + raw_claims).encode()
        private = serialization.load_pem_private_key(key, password=None)
        signature = private.sign(content, padding.PKCS1v15(), hashes.SHA256())
        return content.decode() + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")

    now = int(time.time())
    good_claims = json.dumps({
        "iss": settings.oidc_issuer, "aud": settings.oidc_audience,
        "sub": "alice", "exp": now + 300, "nbf": now, "iat": now - 30,
        "groups": ["trusted-security"],
    }).encode()
    duplicate_header = b'{"alg":"RS256","alg":"HS256","kid":"key-one"}'
    assert (await oidc["request"](wrap(duplicate_header, good_claims))).status_code == 401
    normal_header = b'{"alg":"RS256","kid":"key-one"}'
    duplicate_claims = good_claims[:-1] + b',"groups":["trusted-leads"]}'
    assert (await oidc["request"](wrap(normal_header, duplicate_claims))).status_code == 401
    assert oidc["state"]["requests"] == 0


@pytest.mark.asyncio
async def test_unsigned_and_wrong_key_never_pass(oidc):
    attacker_private, _ = _rsa_pair("attacker")
    forged = oidc["sign"](key=attacker_private, kid="key-one")
    assert (await oidc["request"](forged)).status_code == 401
    now = int(time.time())
    hs = jwt.encode({
        "sub": "mallory", "role": "senior_operator", "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience, "exp": now + 300, "nbf": now,
        "iat": now, "groups": ["trusted-leads"],
    }, "attacker-secret", algorithm="HS256", headers={"kid": "key-one"})
    assert (await oidc["request"](hs)).status_code == 401


@pytest.mark.parametrize("broken", ["issuer", "audience", "url", "role_map", "algorithm"])
@pytest.mark.asyncio
async def test_partial_or_unsafe_oidc_configuration_never_falls_back_to_shared_secret(
    oidc, monkeypatch, broken,
):
    if broken == "issuer":
        monkeypatch.setattr(settings, "oidc_issuer", None)
    elif broken == "audience":
        monkeypatch.setattr(settings, "oidc_audience", "")
    elif broken == "url":
        monkeypatch.setattr(settings, "oidc_jwks_url", "http://127.0.0.1/jwks")
    elif broken == "role_map":
        monkeypatch.setattr(settings, "oidc_role_map_json", '{"bad":"root"}')
    elif broken == "algorithm":
        monkeypatch.setattr(settings, "oidc_algorithms", "HS256")
    assert (await oidc["request"]("shared-does-not-grant-senior")).status_code == 503
    assert oidc["state"]["requests"] == 0


@pytest.mark.asyncio
async def test_local_hmac_jwt_remains_supported_in_parallel(oidc, monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", "local-token-signing-secret")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setattr(settings, "jwt_audience", None)
    token = jwt.encode({
        "sub": "local-owner", "role": "senior_operator",
        "exp": int(time.time()) + 300,
    }, settings.jwt_secret, algorithm="HS256")
    result = await oidc["request"](token, "/senior")
    assert result.status_code == 200
    assert oidc["state"]["requests"] == 0
    no_exp = jwt.encode({"sub": "local-owner", "role": "senior_operator"},
                        settings.jwt_secret, algorithm="HS256")
    assert (await oidc["request"](no_exp)).status_code == 401


@pytest.mark.asyncio
async def test_shared_development_token_never_gets_senior_role(oidc, monkeypatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "oidc_issuer", None)
    monkeypatch.setattr(settings, "oidc_audience", None)
    monkeypatch.setattr(settings, "oidc_jwks_url", None)
    from fastapi.security import HTTPAuthorizationCredentials
    bearer = HTTPAuthorizationCredentials(scheme="Bearer", credentials=settings.api_token)
    principal = await deps.verify_token(credentials=bearer, token=None)
    assert principal["role"] == "dev_api_token"
    assert principal["role"] not in ("operator", "senior_operator")
    assert (await oidc["request"](settings.api_token, "/senior")).status_code == 403
