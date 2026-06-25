"""Recon MCP reality gate.

Fails if recon-mcp reverts to the old mock (which returned hardcoded
127.0.0.1:80,443 regardless of input). Proves the scan reflects real socket
state and varies per target.
"""

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


def _open_ports(result):
    hosts = result.get("hosts", [])
    return [p["port"] for h in hosts for p in h.get("ports", [])]


def test_tools_registered():
    base = require_server("recon")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "nmap_scan" in tools and "httpx_probe" in tools, tools


def test_connect_scan_finds_open_port(local_target):
    base = require_server("recon")
    host, open_port, _ = local_target
    res = mcp_execute(base, "nmap_scan", {"targets": [host], "ports": str(open_port)})
    assert open_port in _open_ports(res), f"real open port {open_port} not detected: {res}"
    assert res.get("scan_type") == "tcp-connect"


def test_closed_port_is_empty_not_canned(local_target):
    """The mock returned canned 80/443; a real scan of a closed port returns []."""
    base = require_server("recon")
    host, _, closed_port = local_target
    res = mcp_execute(base, "nmap_scan", {"targets": [host], "ports": str(closed_port)})
    ports = _open_ports(res)
    assert ports == [], f"closed port {closed_port} reported open -> mock/canned data: {ports}"
    assert 80 not in ports and 443 not in ports, "old mock signature (80/443) detected"


def test_output_varies_per_target(local_target):
    base = require_server("recon")
    host, open_port, closed_port = local_target
    open_res = _open_ports(mcp_execute(base, "nmap_scan", {"targets": [host], "ports": str(open_port)}))
    closed_res = _open_ports(mcp_execute(base, "nmap_scan", {"targets": [host], "ports": str(closed_port)}))
    assert open_res != closed_res, "scan output identical for open vs closed port -> not real"


def test_nonexistent_host_bounded(local_target):
    """A non-routable host must return gracefully (empty), not hang or fabricate."""
    base = require_server("recon")
    res = mcp_execute(base, "nmap_scan", {"targets": ["10.255.255.1"], "ports": "80"}, timeout=20.0)
    assert _open_ports(res) == [], f"non-routable host returned open ports: {res}"


def test_http_probe_real_and_honest(local_target):
    base = require_server("recon")
    host, open_port, closed_port = local_target
    res = mcp_execute(base, "httpx_probe", {"urls": [f"http://{host}:{open_port}"]})
    results = res.get("results", [])
    assert results and results[0]["status_code"] == 200, f"probe of live fixture failed: {res}"
    assert "Qualification Fixture" in (results[0].get("title") or ""), results[0]
    # Dead port -> honest error, not a fabricated 200.
    dead = mcp_execute(base, "httpx_probe", {"urls": [f"http://{host}:{closed_port}"]})
    d0 = dead.get("results", [{}])[0]
    assert d0.get("status_code") == 0 and d0.get("error"), f"dead port not reported as error: {d0}"
