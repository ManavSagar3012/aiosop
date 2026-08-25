"""Shared fixtures for the MCP tooling-reality qualification suite.

These tests verify that the four core MCP servers (recon, nuclei, browser, burp)
perform REAL work — not that they merely answer /health. They are designed to be
the CI gate described in TOOLING_CERTIFICATE.md: if a server reverts to a stub or
mock, the real-behaviour assertions here fail.

Behaviour when a server is unreachable:
  * default: the test is SKIPPED (so local dev without the tooling stack running
    does not produce false failures).
  * OSOP_QUALIFICATION_STRICT=1: an unreachable required server is a FAILURE.
    CI sets this after starting the stack via launch_real.ps1, turning "down"
    into a hard gate failure.

No external network and no engagement target is used — only a local throwaway
HTTP fixture on 127.0.0.1.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict

import httpx
import pytest

STRICT = os.environ.get("OSOP_QUALIFICATION_STRICT") == "1"

# Endpoints (override via env to match a non-default deployment).
# FIX (qual-follow-env-2026-08-24): port defaults were hardcoded (recon at 8082)
# while the platform resolves them from .env via settings — on this host recon
# runs on 18082, so the suite skipped against a dead port unless OSOP_RECON_MCP_URL
# was exported manually. Derive defaults from settings so tests follow .env.
from ai_osop.core.config import settings as _settings

ENDPOINTS = {
    "recon": os.environ.get("OSOP_RECON_MCP_URL", f"http://127.0.0.1:{_settings.recon_mcp_port}"),
    "nuclei": os.environ.get(
        "OSOP_NUCLEI_MCP_URL", f"http://127.0.0.1:{_settings.nuclei_mcp_port}"
    ),
    "browser": os.environ.get(
        "OSOP_BROWSER_MCP_URL", f"http://127.0.0.1:{_settings.browser_mcp_port}"
    ),
    "burp": os.environ.get("OSOP_BURP_MCP_URL", f"http://127.0.0.1:{_settings.burp_mcp_port}"),
    "source_map": os.environ.get(
        "OSOP_SOURCE_MAP_MCP_URL", f"http://127.0.0.1:{_settings.source_map_mcp_port}"
    ),
    "turbo_intruder": os.environ.get(
        "OSOP_TURBO_INTRUDER_MCP_URL", f"http://127.0.0.1:{_settings.turbo_intruder_mcp_port}"
    ),
}


# Expected server identity per endpoint.
# Identity contract: the Go SDK answers GET /health with
#   {"status": "ready", "server_id": "<id>"}      (key: server_id)
# while the Python MCP servers answer with
#   {"status": "ready", "server": "<name>", ...}  (key: server)
# FIX (qual-identity-schema-2026-08-23): accepting only `server_id` misflagged
# every REAL Python server (browser/source-map/turbo-intruder) as a foreign
# service under STRICT mode even though it was our own tool answering.
SERVER_IDS = {
    "recon": "recon-mcp",
    "nuclei": "nuclei-mcp",
    "browser": "browser-mcp",
    "burp": "burp-mcp",
    "source_map": "source-map-mcp",
    "turbo_intruder": "turbo-intruder-mcp",
}


def _identity(body: Any) -> Any:
    if isinstance(body, dict):
        return body.get("server_id") or body.get("server")
    return None


def require_server(name: str) -> str:
    """Return the base URL if OUR server is reachable; else skip (or fail if STRICT).

    FIX (qual-identity-2026-08-23): the old check only required HTTP 200 on
    /health. On this dev host an unrelated project container (buzz-adminer)
    squats 127.0.0.1:8082 (the recon-mcp port) and answers 200 with an HTML
    login page, so every recon qualification test failed with JSONDecodeError
    instead of skipping. Verify the identity payload matches the expected
    AI-OSOP tool before running reality assertions against it.
    """
    base = ENDPOINTS[name]
    try:
        r = httpx.get(f"{base}/health", timeout=4.0)
        if r.status_code == 200:
            expected = SERVER_IDS.get(name)
            if expected is None:
                return base  # no identity contract for this server; keep old behavior
            try:
                body = r.json()
            except ValueError:
                body = None
            if _identity(body) == expected:
                return base
            msg = (
                f"{name}-mcp at {base} answered /health but is NOT {expected} "
                f"(got: {str(body)[:120]!r}) — foreign service on this port?"
            )
        else:
            msg = f"{name}-mcp at {base} returned HTTP {r.status_code} on /health"
    except Exception as e:  # noqa: BLE001
        msg = f"{name}-mcp at {base} unreachable: {e}"
    if STRICT:
        pytest.fail(msg + " (STRICT mode: required server must be up)")
    pytest.skip(msg)


def mcp_initialize(base: str) -> Dict[str, Any]:
    try:
        r = httpx.post(f"{base}/mcp/initialize", json={}, timeout=6.0)
        return r.json() if r.status_code == 200 else {}
    except Exception:
        r = httpx.get(f"{base}/mcp/initialize", timeout=6.0)
        return r.json() if r.status_code == 200 else {}


def mcp_execute(
    base: str, tool: str, params: Dict[str, Any], timeout: float = 90.0
) -> Dict[str, Any]:
    """Call /mcp/execute and return the `result` payload (or {} on failure)."""
    r = httpx.post(
        f"{base}/mcp/execute",
        json={"tool_name": tool, "parameters": params, "request_id": f"qual-{tool}"},
        timeout=timeout,
    )
    r.raise_for_status()
    body = r.json()
    assert (
        body.get("status") == "success"
    ), f"{tool} execute status={body.get('status')} body={body}"
    return body.get("result", {})


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = (
            b"<html><head><title>AI-OSOP Qualification Fixture</title></head><body>ok</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture(scope="session")
def local_target():
    """A throwaway local HTTP server. Yields (host, open_port, closed_port)."""
    server = HTTPServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        # closed_port: a port we deliberately do not open.
        closed = port + 1 if port + 1 < 65535 else port - 1
        yield "127.0.0.1", port, closed
    finally:
        server.shutdown()


class _JSFixtureHandler(BaseHTTPRequestHandler):
    """Serves a JS bundle + sourcemap with a hardcoded secret for source-map qualification."""

    JS_BUNDLE = (
        'console.log("hello");\n'
        'const apiKey = "sk-test-1234-deadbeef";\n'
        "//# sourceMappingURL=bundle.js.map\n"
    ).encode()

    SOURCE_MAP = json.dumps(
        {
            "version": 3,
            "sources": ["app.js"],
            "sourcesContent": [
                'const secret = "aws_secret_key_abcdef123456";\nconsole.log(secret);'
            ],
            "mappings": "AAAA",
        }
    ).encode()

    def do_GET(self):  # noqa: N802
        if self.path == "/bundle.js":
            body = self.JS_BUNDLE
            ctype = "application/javascript"
        elif self.path == "/bundle.js.map":
            body = self.SOURCE_MAP
            ctype = "application/json"
        elif self.path == "/raw":
            body = self.JS_BUNDLE
            ctype = "application/javascript"
        else:
            body = b"ok"
            ctype = "text/plain"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture(scope="session")
def js_target():
    """A throwaway local HTTP server that serves a JS bundle + sourcemap."""
    server = HTTPServer(("127.0.0.1", 0), _JSFixtureHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        yield "127.0.0.1", port
    finally:
        server.shutdown()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "qualification: MCP tooling-reality gate (real execution, not stub)"
    )
