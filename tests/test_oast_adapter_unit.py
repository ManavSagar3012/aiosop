import asyncio

from ai_osop.adapters.oast_mcp import OASTAdapter


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
            return _Resp("success", {"token": "abc123", "callback_url": "http://127.0.0.1:8099/abc123"})
        return _Resp("success", {"token": params["token"], "hit_count": 1,
                                 "interactions": [{"method": "GET"}]})


def test_register_returns_token_and_url():
    reg = _Registry()
    a = OASTAdapter(reg)
    token, url = asyncio.run(a.register("ssrf:test"))
    assert token == "abc123" and url.endswith("/abc123")


def test_poll_returns_interactions():
    reg = _Registry()
    a = OASTAdapter(reg)
    hits = asyncio.run(a.poll("abc123"))
    assert hits and hits[0]["method"] == "GET"
