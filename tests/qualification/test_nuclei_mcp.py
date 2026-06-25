"""Nuclei MCP reality gate.

Proves nuclei-mcp runs the real engine through /mcp/execute: a single template
produces real findings, the severity filter is actually applied, and the template
list is the real store.
"""

import json

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification

TEMPLATE = "http/misconfiguration/http-missing-security-headers.yaml"


def test_tools_registered():
    base = require_server("nuclei")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "scan" in tools, tools


def test_single_template_real_findings(local_target):
    base = require_server("nuclei")
    host, open_port, _ = local_target
    res = mcp_execute(
        base, "scan",
        {"targets": [f"http://{host}:{open_port}"], "templates": [TEMPLATE]},
        timeout=120.0,
    )
    findings = [f for f in res.get("findings", []) if str(f).strip()]
    assert findings, f"no findings from real template scan: {res}"
    parsed = json.loads(findings[0])
    assert parsed.get("template-id") == "http-missing-security-headers", parsed


def test_severity_filter_applied(local_target):
    """critical-only on an info-severity template -> 0; info -> findings."""
    base = require_server("nuclei")
    host, open_port, _ = local_target
    target = f"http://{host}:{open_port}"
    crit = mcp_execute(base, "scan", {"targets": [target], "templates": [TEMPLATE], "severity": "critical"}, timeout=120.0)
    info = mcp_execute(base, "scan", {"targets": [target], "templates": [TEMPLATE], "severity": "info"}, timeout=120.0)
    crit_n = len([f for f in crit.get("findings", []) if str(f).strip()])
    info_n = len([f for f in info.get("findings", []) if str(f).strip()])
    assert crit_n == 0, f"severity filter not applied (critical returned {crit_n})"
    assert info_n > 0, f"info severity returned nothing ({info_n})"


def test_list_templates_real_store():
    base = require_server("nuclei")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    if "list_templates" not in tools:
        pytest.skip("list_templates not exposed by this nuclei-mcp build")
    res = mcp_execute(base, "list_templates", {"tags": "tech", "limit": 5}, timeout=120.0)
    assert res.get("total", 0) > 50, f"template store unexpectedly small: {res.get('total')}"
