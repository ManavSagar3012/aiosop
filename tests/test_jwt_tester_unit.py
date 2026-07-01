"""Offline unit tests for JWTTester forging logic (no network)."""
import base64
import json

from ai_osop.core.jwt_tester import JWTTester


def _b64u(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _make_token(header, payload) -> str:
    return f"{_b64u(header)}.{_b64u(payload)}.fakesig"


def _decode_seg(seg: str):
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


SENTINEL = "pwn@attacker.test"


def _tester():
    tok = _make_token(
        {"typ": "JWT", "alg": "RS256"},
        {"data": {"email": "victim@app.com", "role": "customer"}},
    )
    return JWTTester("http://t/whoami", tok, sentinel=SENTINEL)


def test_forged_claims_replaces_email_and_escalates_role():
    claims = _tester()._forged_claims()
    assert claims["data"]["email"] == SENTINEL
    assert claims["data"]["role"] == "admin"


def test_forge_alg_none_has_empty_signature_and_none_alg():
    tok = _tester()._forge_alg_none("none")
    h, p, s = tok.split(".")
    assert s == "", "alg:none token must have an empty signature"
    assert _decode_seg(h)["alg"] == "none"
    assert _decode_seg(p)["data"]["email"] == SENTINEL


def test_hs256_manual_supports_empty_key_for_kid_injection():
    tok = _tester()._forge_hs256("", kid="../../dev/null")
    h, p, s = tok.split(".")
    assert s != "", "HS256 token must carry a signature"
    assert _decode_seg(h)["kid"] == "../../dev/null"
    assert _decode_seg(h)["alg"] == "HS256"
