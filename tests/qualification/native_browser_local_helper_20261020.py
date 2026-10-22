"""Offline, owned loopback-only fixture for real Browser MCP process qualification.

No external web targets, app data stores or OS-owned Chrome profiles. The
browser's HTTP proxy is a separate owned loopback deny-server, and every page
request is checked by a context-level Playwright interceptor before transport.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import httpx
import pytest
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from playwright.async_api import async_playwright


ENGAGEMENT = "eng-native-local-browser"
FOREIGN = "eng-native-foreign"
TASK = "task-native-local-browser"
LABEL = "user-native-local"
TOKEN = "browser-local-qualification-only-token-20261020"
KID = "browser-local-qualification"


@dataclass
class NativeBrowserFixture:
    native: Any
    browser: Any
    tenant: Path
    journal: Path
    base_url: str
    intercepted: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    # These are requests rejected by our local proxy, NOT remote connections.
    # Chromium itself can attempt background Google time/service lookups even
    # with background networking disabled; all such attempts terminate here.
    proxy_attempts: list[str] = field(default_factory=list)
    page_hits: list[str] = field(default_factory=list)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.native.app),
            base_url="http://browser-mcp-local-only.invalid",
            follow_redirects=False,
            timeout=15.0,
        )

    @staticmethod
    def headers() -> dict[str, str]:
        return {"Authorization": f"Bearer {TOKEN}"}


async def real_chromium_executable() -> tuple[Path | None, str]:
    """Check the Playwright installed browser path; never install/download."""
    try:
        async with async_playwright() as playwright:
            executable = Path(playwright.chromium.executable_path)
        if not executable.is_file():
            return None, f"cached Chromium executable missing: {executable}"
        return executable, "cached_offline_chromium_present"
    except Exception as exc:
        return None, f"offline Playwright runtime unavailable: {type(exc).__name__}"


def _load_browser_module() -> Any:
    path = Path(__file__).resolve().parents[2] / "mcp-servers" / "python" / "browser_mcp.py"
    spec = importlib.util.spec_from_file_location("_native_browser_real_process_20261020", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def _bind_app(app: web.Application) -> tuple[web.AppRunner, int]:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    assert site._server is not None
    address = site._server.sockets[0].getsockname()
    assert address[0] == "127.0.0.1" and 1024 <= address[1] <= 65535
    return runner, address[1]


@asynccontextmanager
async def native_browser_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[NativeBrowserFixture]:
    """Own exactly one headless Chromium and two disposable 127.0.0.1 listeners."""
    executable, status = await real_chromium_executable()
    if executable is None:
        pytest.skip(status)

    tenant_root = tmp_path / "signed_tenants"
    tenant = tenant_root / ENGAGEMENT
    tenant.mkdir(parents=True)
    (tenant_root / FOREIGN).mkdir()
    descriptor = json.dumps({
        "engagement_id": ENGAGEMENT,
        "mount_id": "real-local-chromium-20261020",
        "container_image_sha256": "a" * 64,
    }, separators=(",", ":")).encode("utf-8")
    (tenant / ".osop-har-mount.json").write_bytes(descriptor)
    journal = tmp_path / "signed_journal"
    journal.mkdir()

    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes_raw()
    raw_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv("OSOP_ENVIRONMENT", "production")
    monkeypatch.setenv("OSOP_BROWSER_MCP_BEARER_TOKEN", TOKEN)
    monkeypatch.setenv("OSOP_BROWSER_MCP_RECEIPT_PRIVATE_KEY_B64", base64.b64encode(raw_private).decode())
    monkeypatch.setenv("OSOP_BROWSER_MCP_RECEIPT_KID", KID)
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON", json.dumps({
        "browser-mcp": {KID: base64.b64encode(raw_public).decode()},
    }))
    monkeypatch.setenv("OSOP_BROWSER_MCP_JOURNAL_ROOT", str(journal))
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_ROOT", str(tenant_root))
    monkeypatch.setenv("OSOP_AUTHENTICATED_HAR_MOUNT_DIGESTS", json.dumps({
        ENGAGEMENT: hashlib.sha256(descriptor).hexdigest(),
    }))
    monkeypatch.setenv("OSOP_EVIDENCE_ROOT", str(tmp_path / "unsigned_evidence"))

    state = NativeBrowserFixture(
        native=_load_browser_module(), browser=None, tenant=tenant, journal=journal,
        base_url="",
    )
    state.native.EVIDENCE_ROOT = str(tmp_path / "unsigned_evidence")
    state.native.manager = state.native.BrowserManager()

    async def page(request: web.Request) -> web.Response:
        state.page_hits.append(request.path)
        return web.Response(
            text="<!doctype html><html><head><title>LOCAL_ONLY_BROWSER_PROOF</title></head>"
            "<body><h1 id='test-marker'>LOCAL_ONLY_BROWSER_PROOF</h1>"
            "<button id='safe-button'>local button</button></body></html>",
            content_type="text/html",
        )

    async def redirect(request: web.Request) -> web.Response:
        state.page_hits.append(request.path)
        raise web.HTTPFound(location="http://browser-external-must-not-resolve.invalid/leak")

    async def proxy_deny(request: web.Request) -> web.Response:
        state.proxy_attempts.append(request.raw_path[:256])
        return web.Response(status=403, text="DENIED")

    page_app = web.Application()
    page_app.router.add_get("/", page)
    page_app.router.add_get("/redirect", redirect)
    proxy_app = web.Application()
    proxy_app.router.add_route("*", "/{path:.*}", proxy_deny)

    page_runner, page_port = await _bind_app(page_app)
    try:
        proxy_runner, proxy_port = await _bind_app(proxy_app)
    except BaseException:
        await page_runner.cleanup()
        raise
    state.base_url = f"http://127.0.0.1:{page_port}"
    # An independently configured native tenant-origin constraint is separate
    # from caller request fields and from the source-side Flow authority gap.
    monkeypatch.setenv("OSOP_BROWSER_MCP_SIGNED_ORIGINS_JSON", json.dumps({
        ENGAGEMENT: [state.base_url],
    }))
    playwright = None
    browser = None
    try:
        playwright = await async_playwright().start()
        browser = await playwright.chromium.launch(
            headless=True,
            executable_path=str(executable),
            args=[
                "--disable-background-networking",
                "--disable-component-update",
                "--no-first-run",
                "--no-default-browser-check",
            ],
            proxy={
                "server": f"http://127.0.0.1:{proxy_port}",
                "bypass": "127.0.0.1,localhost",
            },
        )
        state.browser = browser
        real_new_context = browser.new_context

        async def guarded_new_context(**kwargs: Any) -> Any:
            kwargs["service_workers"] = "block"
            context = await real_new_context(**kwargs)

            async def route_guard(route: Any) -> None:
                uri = route.request.url
                state.intercepted.append(uri)
                target = urlsplit(uri)
                if target.scheme == "http" and target.hostname == "127.0.0.1" and target.port == page_port:
                    await route.continue_()
                else:
                    state.blocked.append(uri)
                    await route.abort("blockedbyclient")

            await context.route("**/*", route_guard)
            return context

        # Installs route interception before BrowserManager can create a page;
        # this isolates real Chromium transport without changing source code.
        monkeypatch.setattr(browser, "new_context", guarded_new_context)
        state.native.manager.browser = browser
        state.native.manager.playwright = playwright
        state.native.manager._started = True
        yield state
    finally:
        if browser is not None:
            try:
                await state.native.manager.stop()
            except Exception:
                # Last resort strictly closes the owned process even if native
                # signed HAR cleanup fails; no unrelated browser is touched.
                await browser.close()
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception:
                pass
        await proxy_runner.cleanup()
        await page_runner.cleanup()
