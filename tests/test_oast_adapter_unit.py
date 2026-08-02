import asyncio
from unittest.mock import MagicMock

import pytest

from ai_osop.adapters.oast_mcp import OASTAdapter
from ai_osop.core.exceptions import ScopeValidationError


class _Resp:
    def __init__(self, status, result):
        self.status = status
        self.result = result
        self.error = ""


class _Registry:
    def __init__(self):
        self.calls = []

    async def execute_tool(self, server_id, tool, params, timeout_override=None):
        self.calls.append((tool, params))
        if tool == "oast_register":
            return _Resp(
                "success", {"token": "abc123", "callback_url": "http://127.0.0.1:8099/abc123"}
            )
        if tool == "oast_drain":
            return _Resp(
                "success",
                {
                    "cursor": 7,
                    "count": 1,
                    "interactions": [
                        {"seq": 7, "token": "abc123", "context": {"engagement_id": "e1"}}
                    ],
                },
            )
        return _Resp(
            "success",
            {"token": params["token"], "hit_count": 1, "interactions": [{"method": "GET"}]},
        )


_CTX_SSRF = {
    "engagement_id": "e1",
    "vuln_class": "ssrf",
    "injection_point": "param:url",
    "payload_hash": "0" * 64,
}


def test_register_returns_token_and_url():
    reg = _Registry()
    a = OASTAdapter(reg)
    token, url = asyncio.run(a.register("ssrf:test", context=dict(_CTX_SSRF)))
    assert token == "abc123" and url.endswith("/abc123")


def test_poll_returns_interactions():
    reg = _Registry()
    a = OASTAdapter(reg)
    hits = asyncio.run(a.poll("abc123"))
    assert hits and hits[0]["method"] == "GET"


def test_register_forwards_context():
    reg = _Registry()
    a = OASTAdapter(reg)
    asyncio.run(a.register("ssrf:x", context=dict(_CTX_SSRF)))
    tool, params = reg.calls[0]
    assert tool == "oast_register"
    assert params["context"]["engagement_id"] == "e1"
    assert params["context"]["vuln_class"] == "ssrf"
    assert params["context"]["injection_point"] == "param:url"
    assert len(params["context"]["payload_hash"]) == 64


def test_register_omits_empty_context():
    # Backward compat: when no context is supplied we forward nothing. The
    # caller-side schema is enforced *when* a context is provided.
    reg = _Registry()
    a = OASTAdapter(reg)
    asyncio.run(a.register("ssrf:x"))
    _, params = reg.calls[0]
    assert "context" not in params


def test_register_rejects_missing_context_keys():
    a = OASTAdapter(registry=MagicMock())
    with pytest.raises(ScopeValidationError):
        asyncio.run(
            a.register(label="t", context={"engagement_id": "e-1"})  # missing required keys
        )


def test_register_rejects_unknown_context_key():
    a = OASTAdapter(registry=MagicMock())
    ctx = dict(_CTX_SSRF)
    ctx["extra_secret"] = "should-not-be-here"
    with pytest.raises(ScopeValidationError):
        asyncio.run(a.register(label="t", context=ctx))


def test_register_rejects_disallowed_vuln_class():
    a = OASTAdapter(registry=MagicMock())
    ctx = dict(_CTX_SSRF)
    ctx["vuln_class"] = "stored_xss"  # not in the blind-oracle class allowlist
    with pytest.raises(ScopeValidationError):
        asyncio.run(a.register(label="t", context=ctx))


def test_register_accepts_all_blind_or_ssrf_classes():
    for cls in ("blind_xss", "blind_sqli", "blind_ssti", "ssrf", "rce"):
        reg = _Registry()
        a = OASTAdapter(reg)
        ctx = dict(_CTX_SSRF)
        ctx["vuln_class"] = cls
        token, _ = asyncio.run(a.register(f"{cls}:p", context=ctx))
        assert token


def test_drain_returns_cursor_and_interactions():
    reg = _Registry()
    a = OASTAdapter(reg)
    cursor, interactions = asyncio.run(a.drain(since=0, engagement_id="e1"))
    assert cursor == 7 and interactions[0]["token"] == "abc123"
    tool, params = reg.calls[0]
    assert tool == "oast_drain" and params["engagement_id"] == "e1"
