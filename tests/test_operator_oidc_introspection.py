"""Optional RFC7662 IdP status checks invalidate revoked operator access tokens.

Only a local HTTPX MockTransport is used; no external IdP or app database.
"""

import base64
import json

import httpx
import pytest
from fastapi import Depends, FastAPI

from ai_osop.api import deps
from ai_osop.api.routers.provider_invoices import _verified_senior
from ai_osop.api.routers.report_attestations import _report_operator
from ai_osop.core.config import settings
from tests.test_operator_oidc_jwks import oidc


@pytest.fixture
def introspection(oidc, monkeypatch):
    monkeypatch.setattr(
        settings,
        "oidc_introspection_url",
        "https://idp.example.test/realm/introspect",
    )
    monkeypatch.setattr(settings, "oidc_introspection_client_id", "osop-api")
    monkeypatch.setattr(settings, "oidc_introspection_client_secret", "secret-test-only")
    body = {"active": True, "sub": "alice"}
    observed = []
    status = {"code": 200, "exception": None, "raw": None}

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert request.method == "POST"
        assert str(request.url) == settings.oidc_introspection_url
        expected_basic = base64.b64encode(b"osop-api:secret-test-only").decode("ascii")
        assert request.headers.get("Authorization") == "Basic " + expected_basic
        assert b"token_type_hint=access_token" in request.content
        assert b"token=" in request.content
        if status["exception"] is not None:
            raise status["exception"]
        if status["raw"] is not None:
            return httpx.Response(status["code"], content=status["raw"])
        return httpx.Response(status["code"], json=body)

    monkeypatch.setattr(
        deps,
        "_oidc_introspection_http_client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=httpx.Timeout(3.0),
            trust_env=False,
            follow_redirects=False,
        ),
    )
    return {**oidc, "body": body, "observed": observed, "status": status}


@pytest.mark.asyncio
async def test_live_revocation_is_checked_again_for_every_oidc_request(introspection):
    token = introspection["sign"]()
    assert (await introspection["request"](token)).status_code == 200
    assert (await introspection["request"](token)).status_code == 200
    assert len(introspection["observed"]) == 2
    assert introspection["state"]["requests"] == 1  # JWKS cached; token status never cached.
    introspection["body"]["active"] = False
    denied = await introspection["request"](token)
    assert denied.status_code == 401
    assert len(introspection["observed"]) == 3
    assert "secret-test-only" not in denied.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("active", "true", 503),
        ("active", None, 503),
        ("sub", "mallory", 401),
        ("sub", None, 401),
        ("iss", "https://wrong-idp.example.test", 401),
        ("aud", "another-api", 401),
        ("jti", "another-call", 401),
        ("exp", 42, 401),
    ],
)
async def test_inconsistent_provider_active_claim_is_never_access_authority(
    introspection,
    field,
    value,
    expected,
):
    token = introspection["sign"]()
    introspection["body"][field] = value
    response = await introspection["request"](token)
    assert response.status_code == expected, response.text


@pytest.mark.asyncio
async def test_introspection_expires_at_matches_signed_token(introspection):
    token = introspection["sign"]()
    header, claims, sig = token.split(".")
    import json as _json

    decoded = _json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
    introspection["body"]["exp"] = decoded["exp"]
    introspection["body"]["aud"] = settings.oidc_audience
    introspection["body"]["iss"] = settings.oidc_issuer
    assert (await introspection["request"](token)).status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["down", "server", "invalid", "duplicate", "oversize"])
async def test_idp_status_errors_fail_closed_without_jwt_fallback(introspection, failure):
    token = introspection["sign"]()
    if failure == "down":
        introspection["status"]["exception"] = httpx.ConnectError("secret-test-only")
    elif failure == "server":
        introspection["status"]["code"] = 500
    elif failure == "invalid":
        introspection["status"]["raw"] = b"{not-json"
    elif failure == "duplicate":
        introspection["status"]["raw"] = b'{"active":true,"active":false,"sub":"alice"}'
    else:
        introspection["status"]["raw"] = b" " * 9000
    response = await introspection["request"](token)
    assert response.status_code == 503
    assert "secret-test-only" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"oidc_introspection_client_id": None},
        {"oidc_introspection_client_secret": None},
        {"oidc_introspection_url": "http://idp.example.test/introspect"},
        {"oidc_introspection_url": "https://idp.example.test/introspect?token=leak"},
        {"oidc_introspection_url": "https://idp.example.test:8443/introspect"},
        {"oidc_introspection_client_id": "id\r\n"},
    ],
)
async def test_partial_or_insecure_introspection_configuration_is_rejected(
    introspection,
    monkeypatch,
    overrides,
):
    for name, value in overrides.items():
        monkeypatch.setattr(settings, name, value)
    response = await introspection["request"](introspection["sign"]())
    assert response.status_code == 503
    assert len(introspection["observed"]) == 0


@pytest.mark.asyncio
async def test_legacy_jwt_only_mode_does_not_require_idp_network(introspection, monkeypatch):
    for name in (
        "oidc_introspection_url",
        "oidc_introspection_client_id",
        "oidc_introspection_client_secret",
    ):
        monkeypatch.setattr(settings, name, None)
    token = introspection["sign"]()
    assert (await introspection["request"](token)).status_code == 200
    assert introspection["observed"] == []


@pytest.mark.asyncio
async def test_oidc_only_operator_gates_accept_signed_owner_not_shared_token(oidc):
    """Report and invoice routes must support pinned OIDC without local HS key."""
    assert settings.jwt_secret is None
    app = FastAPI()

    @app.get("/report")
    async def report(current=Depends(_report_operator)):
        return {"sub": current["sub"], "role": current["role"]}

    @app.get("/invoice")
    async def invoice(current=Depends(_verified_senior)):
        return {"sub": current["sub"], "role": current["role"]}

    operator = oidc["sign"](groups=["trusted-security"])
    senior = oidc["sign"](groups=["trusted-leads"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        report_ok = await client.get(
            "/report",
            headers={"Authorization": "Bearer " + operator},
        )
        assert report_ok.status_code == 200
        assert report_ok.json()["sub"].startswith("oidc-")
        assert report_ok.json()["role"] == "operator"
        assert (
            await client.get(
                "/invoice",
                headers={"Authorization": "Bearer " + operator},
            )
        ).status_code == 403
        invoice_ok = await client.get(
            "/invoice",
            headers={"Authorization": "Bearer " + senior},
        )
        assert invoice_ok.status_code == 200
        assert invoice_ok.json()["role"] == "senior_operator"
        assert (
            await client.get(
                "/report?token=leak",
                headers={"Authorization": "Bearer " + senior},
            )
        ).status_code == 403
        assert (
            await client.get(
                "/invoice",
                headers={"Authorization": "Bearer shared-does-not-grant-senior"},
            )
        ).status_code == 401
