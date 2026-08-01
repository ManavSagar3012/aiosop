"""C1: MCP args can only carry values with declared safe types.

Raises on out-of-schema inputs (command injection attempt via extra params,
path traversal drives on endpoint inputs, etc.) before the MCP client sends
the request to the target MCP server.
"""

import pytest

from ai_osop.core.exceptions import ScopeValidationError
from ai_osop.mcp.protocol import MCPExecutionGate


def _gate():
    return MCPExecutionGate()


@pytest.mark.parametrize(
    "tool,params",
    [
        ("scan_endpoint", {"url": "https://t", "method": "GET"}),
        ("write_report", {"title": "t", "body": "report"}),
        ("fetch_page", {"url": "https://t", "timeout_s": 4}),
    ],
)
def test_structural_schema_accepts_valid_shape(tool, params):
    _gate().check_params(tool, params)


@pytest.mark.parametrize(
    "tool,params,bad_param",
    [
        ("scan_endpoint", {"url": "t;DROP", "method": 1}, "method"),
        ("fetch_page", {"url": "http://x", "timeout_s": "never"}, "timeout_s"),
        ("scan_endpoint", {"url": 7, "method": "GET"}, "url"),
        ("scan_endpoint", {"url": "t", "method": "GET", "extra": "; rm -rf"}, "extra"),
    ],
)
def test_structural_schema_rejects_bad_types(tool, params, bad_param):
    with pytest.raises(ScopeValidationError, match=bad_param):
        _gate().check_params(tool, params)


def test_structural_schema_denies_paths_and_injection_tokens():
    g = _gate()
    bad = {
        "scan_endpoint": {"url": "https://t/../../etc/passwd", "method": "GET"},
        "capture_session": {"target_host": "localhost;echo", "username": "admin' OR 1=1"},
    }
    for tool, params in bad.items():
        with pytest.raises((ValueError, ScopeValidationError)):
            g.check_params(tool, params)


def test_no_params_is_safe():
    _gate().check_params("capture_session", {})
