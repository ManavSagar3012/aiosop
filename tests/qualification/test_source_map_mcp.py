"""Source Map MCP reality gate.

Proves source-map-mcp fetches real JS bundles, parses sourcemaps, and extracts
hardcoded secrets through /mcp/execute — not an empty stub.
"""

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def test_tools_registered():
    base = require_server("source_map")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "fetch_and_parse_sourcemap" in tools, tools


def test_fetch_js_bundle_extracts_secret(js_target):
    """A raw JS file without a .js extension is scanned directly for secrets."""
    base = require_server("source_map")
    host, port = js_target
    res = mcp_execute(base, "fetch_and_parse_sourcemap", {"url": f"http://{host}:{port}/raw"})
    secrets = res.get("secrets", [])
    assert any(
        "sk-t...beef" in str(s.get("value", "")) for s in secrets
    ), f"expected fake apiKey not found in secrets: {secrets}"
    assert res.get("msg", "").startswith("Parsed raw bundle directly"), res.get("msg")


def test_fetch_sourcemap_parsed_and_secrets_extracted(js_target):
    """A .map URL is parsed as JSON sourcemap and sourcesContent is scanned."""
    base = require_server("source_map")
    host, port = js_target
    res = mcp_execute(
        base, "fetch_and_parse_sourcemap", {"url": f"http://{host}:{port}/bundle.js.map"}
    )
    secrets = res.get("secrets", [])
    sources = res.get("sources", [])
    assert "app.js" in sources, f"expected source file not found: {sources}"
    assert any(
        "aws_...3456" in str(s.get("value", "")) for s in secrets
    ), f"expected fake secret not found in secrets: {secrets}"
    assert res.get("msg", "").startswith("Successfully parsed sourcemap"), res.get("msg")
