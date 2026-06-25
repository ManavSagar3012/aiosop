"""Turbo Intruder MCP reality gate.

Proves turbo-intruder-mcp executes the real timing-attack simulation through
/mcp/execute: concurrent requests are generated, responses are structured, and
the result varies with parameters. Not an empty stub.

Note: This server implements a simulation layer (async HTTP requests), not raw
sockets. The test asserts the simulation is real and produces structured output,
not that raw TCP single-packet attacks are performed.
"""

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def test_tools_registered():
    base = require_server("turbo_intruder")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "execute_single_packet_attack" in tools, tools


def test_single_request_no_race(local_target):
    """With <5 concurrent requests, race_condition_detected must be False."""
    base = require_server("turbo_intruder")
    host, port, _ = local_target
    res = mcp_execute(
        base, "execute_single_packet_attack",
        {"target_url": f"http://{host}:{port}/", "method": "GET", "concurrent_requests": 1},
        timeout=15.0,
    )
    assert res.get("race_condition_detected") is False, (
        f"race_condition_detected should be False for 1 request: {res}"
    )
    assert res.get("requests_sent") == 1, res
    responses = res.get("responses", [])
    assert len(responses) == 1, f"expected 1 response, got {len(responses)}"
    assert responses[0].get("status_code") is not None, responses[0]


def test_concurrent_race_simulation(local_target):
    """With >=5 concurrent requests, race_condition_detected is True and
    responses contain mixed status codes (simulated win/lose)."""
    base = require_server("turbo_intruder")
    host, port, _ = local_target
    res = mcp_execute(
        base, "execute_single_packet_attack",
        {"target_url": f"http://{host}:{port}/", "method": "GET", "concurrent_requests": 5},
        timeout=15.0,
    )
    assert res.get("race_condition_detected") is True, (
        f"race_condition_detected should be True for 5 requests: {res}"
    )
    assert res.get("requests_sent") == 5, res
    responses = res.get("responses", [])
    assert len(responses) == 5, f"expected 5 responses, got {len(responses)}"
    codes = {r.get("status_code") for r in responses}
    assert len(codes) > 1, f"expected mixed status codes (race win/lose), got only {codes}"


def test_response_structure_is_real(local_target):
    """Every response contains latency_ms and response_body — proves real
    execution, not a stub returning empty {}."""
    base = require_server("turbo_intruder")
    host, port, _ = local_target
    res = mcp_execute(
        base, "execute_single_packet_attack",
        {"target_url": f"http://{host}:{port}/", "method": "GET", "concurrent_requests": 2},
        timeout=15.0,
    )
    responses = res.get("responses", [])
    assert responses, "no responses — stub behavior"
    for r in responses:
        assert "latency_ms" in r, f"missing latency_ms: {r}"
        assert "response_body" in r, f"missing response_body: {r}"
        assert "status_code" in r, f"missing status_code: {r}"
