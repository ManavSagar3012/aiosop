"""Turbo Intruder MCP reality gate.

Proves turbo-intruder-mcp executes a REAL raw-socket single-packet (last-byte
synchronization) HTTP/1.1 race attack through /mcp/execute: N raw sockets are
primed with all-but-the-final byte, then the withheld byte is released on every
socket simultaneously via a threading.Barrier. The result reports the actual
send-synchronization window and real per-socket HTTP responses — not a simulated
stub, and not pooled aiohttp requests.
"""

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def test_tools_registered():
    base = require_server("turbo_intruder")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "execute_single_packet_attack" in tools, tools


def test_single_request_completes(local_target):
    """A single request completes via a real socket with a parsed HTTP status."""
    base = require_server("turbo_intruder")
    host, port, _ = local_target
    res = mcp_execute(
        base,
        "execute_single_packet_attack",
        {"target_url": f"http://{host}:{port}/", "method": "GET", "concurrent_requests": 1},
        timeout=15.0,
    )
    assert res.get("real") is True, res
    assert res.get("attack") == "single_packet_last_byte_sync", res
    assert res.get("completed") == 1, res
    results = res.get("results", [])
    assert len(results) == 1 and results[0].get("status") is not None, results


def test_concurrent_release_is_synchronized(local_target):
    """N=5 requests all complete and the synchronized last-byte release window is
    tight (sub-100ms) — the hallmark of a real single-packet attack."""
    base = require_server("turbo_intruder")
    host, port, _ = local_target
    res = mcp_execute(
        base,
        "execute_single_packet_attack",
        {"target_url": f"http://{host}:{port}/", "method": "GET", "concurrent_requests": 5},
        timeout=20.0,
    )
    assert res.get("real") is True, res
    assert res.get("completed") == 5, res
    window = res.get("release_window_ms")
    assert (
        isinstance(window, (int, float)) and window < 100.0
    ), f"release window should be tight for a true single-packet attack: {window}ms"
    assert isinstance(res.get("status_distribution"), dict) and res["status_distribution"], res


def test_response_structure_is_real(local_target):
    """Every per-socket result carries a real HTTP status, byte count, and a body
    fingerprint — proves real execution, not a stub returning empty {}."""
    base = require_server("turbo_intruder")
    host, port, _ = local_target
    res = mcp_execute(
        base,
        "execute_single_packet_attack",
        {"target_url": f"http://{host}:{port}/", "method": "GET", "concurrent_requests": 2},
        timeout=15.0,
    )
    results = res.get("results", [])
    assert results, "no results — stub behavior"
    for r in results:
        assert "status" in r, f"missing status: {r}"
        assert "resp_bytes" in r, f"missing resp_bytes: {r}"
        assert "body_sha1_12" in r, f"missing body fingerprint: {r}"
