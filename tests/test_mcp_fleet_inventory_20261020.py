"""Offline, non-executing MCP fleet inventory regression qualification.

Uses AST/source only: no API import/startup, socket, provider, target or DB.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "src/ai_osop/api/main.py"
CONFIG = ROOT / "src/ai_osop/core/config.py"
SDK = ROOT / "mcp-servers/go/sdk/server.go"
DOC = ROOT / "docs/MCP_FLEET_E2E_20261020.md"

EXPECTED = {
    "burp-mcp": 8081,
    "recon-mcp": 8082,
    "payload-mcp": 8083,
    "nuclei-mcp": 8084,
    "shodan-mcp": 8085,
    "threat-intel-mcp": 8086,
    "security-bridge": 8087,
    "browser-mcp": 8091,
    "source-map-mcp": 8096,
    "cloud-mcp": 8097,
    "turbo-intruder-mcp": 8098,
}
CRITICAL = {
    "browser-mcp",
    "nuclei-mcp",
    "source-map-mcp",
    "cloud-mcp",
    "turbo-intruder-mcp",
}


def _registered():
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    func = next(
        node
        for node in tree.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "register_optional_mcp_servers"
    )
    servers = next(
        node.value
        for node in func.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "servers" for t in node.targets)
    )
    critical = next(
        node.value
        for node in func.body
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "critical_mcps" for t in node.targets)
    )
    result = {}
    for item in servers.elts:
        sid, host, port, token = item.elts
        name = ast.literal_eval(sid)
        assert isinstance(host, ast.Attribute) and isinstance(port, ast.Attribute)
        assert isinstance(host.value, ast.Name) and host.value.id == "settings"
        assert isinstance(port.value, ast.Name) and port.value.id == "settings"
        result[name] = (host.attr, port.attr)
    return result, set(ast.literal_eval(critical))


def _defaults():
    tree = ast.parse(CONFIG.read_text(encoding="utf-8"))
    result = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            value = node.value
            if isinstance(value, ast.Call) and getattr(value.func, "id", "") == "Field":
                default = next((k.value for k in value.keywords if k.arg == "default"), None)
                if isinstance(default, ast.Constant):
                    result[node.target.id] = default.value
    return result


def test_all_and_only_actual_main_registry_ids_are_in_inventory():
    entries, critical = _registered()
    assert set(entries) == set(EXPECTED)
    assert critical == CRITICAL
    doc = DOC.read_text(encoding="utf-8")
    for server, port in EXPECTED.items():
        assert f"`{server}`" in doc
        assert f"| {port} |" in doc
    assert "NOT END-TO-END VERIFIED" in doc
    assert "0/11" in doc


def test_config_defaults_match_registered_http_transport_ports():
    entries, _ = _registered()
    defaults = _defaults()
    for server, (host_attr, port_attr) in entries.items():
        assert host_attr.endswith("_host") and port_attr.endswith("_port")
        # The protected SourceMap bearer may only travel over the numeric
        # loopback address: localhost can resolve through a poisoned hosts
        # file. Preserve that intentional post-inventory hardening.
        assert defaults[host_attr] == ("127.0.0.1" if server == "source-map-mcp" else "localhost")
        assert defaults[port_attr] == EXPECTED[server]


def test_service_implementations_and_missing_scratch_launchers_are_disclosed():
    doc = DOC.read_text(encoding="utf-8")
    root = ROOT / "mcp-servers"
    expected_go = {
        "recon-mcp",
        "payload-mcp",
        "nuclei-mcp",
        "shodan-mcp",
        "threat-intel-mcp",
        "security-bridge",
    }
    expected_python = {
        "browser_mcp.py",
        "source_map_mcp.py",
        "cloud_mcp.py",
        "turbo_intruder_mcp.py",
        "session_memory_mcp.py",
        "reporting_mcp.py",
        "attack_graph_mcp.py",
    }
    for server in expected_go:
        assert (root / "go/cmd" / server / "main.go").is_file()
    for file in expected_python:
        assert (root / "python" / file).is_file()
    for absent in ("oast_mcp.py", "payload_mcp_server.py", "mcp_stub.py"):
        assert not (root / "python" / absent).exists()
        assert absent in doc


def test_go_sdk_now_denies_native_execution_without_signed_authority():
    src = SDK.read_text(encoding="utf-8")
    assert 'mux.HandleFunc("/mcp/execute"' in src
    assert "native_execution_not_authorized" in src
    assert "tool.Handler(req.Parameters)" not in src
    assert "http.StatusServiceUnavailable" in src
    assert "SideEffectInvasiveExploit" in src
    assert "Shared Go SDK" in DOC.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "path,marker",
    [
        ("cloud_mcp.py", "status_code=503"),
        ("turbo_intruder_mcp.py", "status_code=503"),
        ("session_memory_mcp.py", '"server_unavailable"'),
        ("reporting_mcp.py", '"server_unavailable"'),
        ("attack_graph_mcp.py", '"server_unavailable"'),
        ("source_map_mcp.py", "trust_env=False"),
    ],
)
def test_mock_or_unsafe_source_is_labeled_as_unverified(path, marker):
    src = (ROOT / "mcp-servers/python" / path).read_text(encoding="utf-8")
    assert marker in src
    assert path in DOC.read_text(encoding="utf-8")
