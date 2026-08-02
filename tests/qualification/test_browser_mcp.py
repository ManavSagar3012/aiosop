"""Browser MCP reality gate.

Proves browser-mcp drives a real Playwright/Chromium session through /mcp/execute:
a navigation completes, the DOM/title reflect the real page, and a screenshot is a
real PNG. Also asserts Playwright actually started.
"""

import os

import httpx
import pytest

from .conftest import ENDPOINTS, mcp_execute, require_server

pytestmark = pytest.mark.qualification


def test_playwright_started():
    base = require_server("browser")
    health = httpx.get(f"{base}/health", timeout=6.0).json()
    assert health.get("playwright_started") is True, f"playwright not started: {health}"


def test_navigate_real_dom(local_target):
    base = require_server("browser")
    host, open_port, _ = local_target
    res = mcp_execute(
        base,
        "execute",
        {"action": "navigate", "url": f"http://{host}:{open_port}", "engagement_id": "qual"},
        timeout=60.0,
    )
    assert res.get("current_url", "").startswith(f"http://{host}:{open_port}"), res
    diag = res.get("state", {}).get("diagnostics", {})
    assert diag.get("readyState") == "complete", diag
    assert "Qualification Fixture" in (diag.get("title") or ""), diag


def test_screenshot_is_real_png(local_target):
    base = require_server("browser")
    host, open_port, _ = local_target
    res = mcp_execute(
        base,
        "execute",
        {"action": "screenshot", "url": f"http://{host}:{open_port}", "engagement_id": "qual"},
        timeout=60.0,
    )
    path = res.get("path") or res.get("screenshot_path")
    assert path, f"no screenshot path returned: {res}"
    # If running on the same host as the server, verify the PNG magic bytes.
    if os.path.exists(path):
        with open(path, "rb") as f:
            assert f.read(8) == b"\x89PNG\r\n\x1a\n", "screenshot is not a valid PNG"
        assert os.path.getsize(path) > 1000, "screenshot suspiciously small"
