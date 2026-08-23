"""Burp MCP reality gate.

Proves :8081 is the real Burp Suite MCP (not burp_mcp_stub.py, which exposes an
empty toolset and cannot proxy). send_http_request must return a live response.
"""

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def test_real_burp_tools_registered():
    base = require_server("burp")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    # The stub returns an EMPTY tool list; the real Burp MCP registers these.
    assert tools, "burp-mcp exposes no tools -> stub (burp_mcp_stub.py)"
    for expected in ("send_http_request", "send_to_repeater", "get_proxy_history"):
        assert expected in tools, f"missing real Burp tool {expected}; tools={tools}"


def test_send_http_request_proxies_live_response(local_target):
    base = require_server("burp")
    host, open_port, _ = local_target
    res = mcp_execute(
        base,
        "send_http_request",
        {"url": f"http://{host}:{open_port}", "method": "GET"},
        timeout=20.0,
    )
    # Real Burp proxies the request and returns a real status code.
    assert res.get("status") == "success", res
    assert (
        res.get("status_code") == 200
    ), f"expected live 200 via Burp, got {res.get('status_code')}"
