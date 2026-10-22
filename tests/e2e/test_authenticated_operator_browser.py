"""Real Chromium/Vite operator UI journey against an isolated loopback API.

Only installed Playwright/Chromium and Vite are used. The backend is an inert
in-process aiohttp stand-in: this verifies real browser requests, React DOM,
and WebSocket frames, not production JWT verification or persistent revocation.
All listeners and browser processes are disposed when the test returns.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from aiohttp import WSMsgType, web

playwright = pytest.importorskip("playwright.async_api")

PROJECT = Path(__file__).resolve().parents[2]
UI = PROJECT / "ui"
ENGAGEMENT = "eng-ui-browser-qualification"
OPERATOR = "opaque-operator-alpha-e2e"
SENIOR = "opaque-senior-beta-e2e"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return candidate.getsockname()[1]


class IsolatedBackend:
    def __init__(self):
        self.port = 0
        self.http_requests = []
        self.first_frames = []
        self.sockets = []
        self.revocations = []
        self.authorization_status = "active"
        self.allow_ws_ack = True

    @property
    def identities(self):
        return {
            OPERATOR: {"sub": "alice-verified", "role": "operator", "exp": None},
            SENIOR: {"sub": "bob-verified", "role": "senior_operator", "exp": None},
        }

    async def route(self, request: web.Request) -> web.StreamResponse:
        # Record path and authenticated identity, never the secret header.
        bearer = request.headers.get("Authorization", "")
        identity = self.identities.get(bearer.removeprefix("Bearer "))
        self.http_requests.append((request.method, request.path_qs, identity and identity["sub"]))
        if request.method == "OPTIONS":
            return web.Response(status=204)
        if request.path == "/auth/me":
            return web.json_response(
                identity or {"detail": "Unauthenticated"},
                status=200 if identity else 401,
                headers={"Cache-Control": "no-store"},
            )
        if not identity:
            return web.json_response({"detail": "Bearer required"}, status=401)

        path = request.path
        if request.method == "POST" and path == f"/engagements/{ENGAGEMENT}/authorization/revoke":
            payload = await request.json()
            self.revocations.append((identity["sub"], payload))
            if identity["role"] != "senior_operator":
                return web.json_response({"detail": "Senior role required"}, status=403)
            if self.authorization_status != "active" or payload.get("expected_version") != 3:
                return web.json_response({"detail": "Stale policy"}, status=409)
            self.authorization_status = "revoked"
            return web.json_response(
                {
                    "status": "revoked",
                    "authorization_version": 3,
                    "halt_request_accepted": True,
                    "remote_execution_outcome": "unknown",
                }
            )
        if path == "/engagements":
            return web.json_response(
                [
                    {
                        "session_id": ENGAGEMENT,
                        "phase": "reconnaissance",
                        "scope": {"domains": ["example.test"], "authorization_ref": "fixture"},
                    }
                ]
            )
        if path == f"/engagements/{ENGAGEMENT}":
            return web.json_response(
                {
                    "session_id": ENGAGEMENT,
                    "phase": "reconnaissance",
                    "scope": {"domains": ["example.test"], "authorization_ref": "fixture"},
                }
            )
        if path == f"/engagements/{ENGAGEMENT}/authorization/status":
            return web.json_response(
                {
                    "status": self.authorization_status,
                    "version": 3,
                    "key_id": "fixture-kid",
                    "expires_at": "2099-01-01T00:00:00Z",
                    "policy_sha256": "fixture-hash",
                    "remote_execution_outcome": "unknown",
                }
            )
        if path == "/flows":
            return web.json_response([])
        if path == f"/engagements/{ENGAGEMENT}/diagnostics":
            return web.json_response(
                {
                    "engagement_id": ENGAGEMENT,
                    "phase": "reconnaissance",
                    "captured_at": "2026-10-14T08:00:00Z",
                    "tasks": {
                        "source": "fixture",
                        "total": 0,
                        "status_counts": {},
                        "retried": 0,
                        "overdue_running": 0,
                        "items": [],
                        "truncated": False,
                    },
                    "audit": {
                        "source": "fixture",
                        "available": True,
                        "limit": 50,
                        "events_returned": 0,
                        "events": [],
                    },
                }
            )
        if path == "/approvals/pending":
            return web.json_response([])
        if path.endswith("/events"):
            return web.json_response({"events": []})
        if path.endswith("/tasks"):
            return web.json_response({"tasks": []})
        if path.endswith("/mcp-dispatches"):
            return web.json_response({"dispatches": []})
        if path.endswith("/model-usage"):
            return web.json_response(
                {
                    "usage": {
                        "calls": 0,
                        "settled_calls": 0,
                        "unknown_calls": 0,
                        "unpriced_calls": 0,
                        "provider_reported_input_tokens": None,
                        "provider_reported_output_tokens": None,
                        "provider_reported_cost_usd": None,
                        "cost_complete": True,
                    }
                }
            )
        if path == "/agents" or path.endswith(
            ("/findings", "/audit-log", "/diff-auth", "/uncertainty")
        ):
            return web.json_response([])
        if path.endswith("/graph"):
            return web.json_response({"nodes": [], "edges": []})
        if path == "/system/skills/stats":
            return web.json_response({})
        return web.json_response({"detail": "Unknown mock route"}, status=404)

    async def websocket(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.sockets.append(ws)
        try:
            frame = await asyncio.wait_for(ws.receive_json(), timeout=5)
            self.first_frames.append((request.path_qs, frame))
            if set(frame) != {"type", "token"} or frame.get("type") != "auth":
                await ws.close(code=1008)
                return ws
            if frame["token"] not in self.identities or not self.allow_ws_ack:
                await ws.close(code=1008)
                return ws
            await ws.send_json({"type": "auth_ready", "session_id": ENGAGEMENT})
            async for message in ws:
                if message.type == WSMsgType.TEXT:
                    await ws.send_json({"type": "pong"})
        except (asyncio.TimeoutError, ConnectionError):
            await ws.close(code=1008)
        finally:
            if not ws.closed:
                await ws.close()
        return ws


@web.middleware
async def cors(request: web.Request, handler):
    response = await handler(request)
    origin = request.headers.get("Origin", "")
    if origin.startswith("http://127.0.0.1:"):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept"
    return response


@asynccontextmanager
async def isolated_stack():
    api = IsolatedBackend()
    app = web.Application(middlewares=[cors])
    app.router.add_get(f"/ws/engagements/{ENGAGEMENT}", api.websocket)
    app.router.add_route("*", "/{tail:.*}", api.route)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    api.port = site._server.sockets[0].getsockname()[1]
    ui_port = _free_port()
    environment = os.environ.copy()
    environment.update(
        {
            "VITE_API_BASE": f"http://127.0.0.1:{api.port}",
            "VITE_WS_BASE": f"ws://127.0.0.1:{api.port}",
            # A historical build-time token must be ignored even if configured.
            "VITE_OSOP_TOKEN": "build-time-canary-must-never-be-used",
        }
    )
    process = subprocess.Popen(
        [
            "node",
            "node_modules/vite/bin/vite.js",
            "--host",
            "127.0.0.1",
            "--port",
            str(ui_port),
            "--strictPort",
        ],
        cwd=UI,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    try:
        base = f"http://127.0.0.1:{ui_port}"
        for _ in range(100):
            if process.poll() is not None:
                pytest.fail("Disposable Vite process exited before UI became available")
            try:
                with urlopen(base, timeout=0.4) as response:
                    if response.status == 200:
                        break
            except (OSError, URLError):
                await asyncio.sleep(0.1)
        else:
            pytest.fail("Disposable Vite server did not start")
        yield api, base
    finally:
        process.terminate()
        try:
            await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await asyncio.to_thread(process.wait)
        for ws in api.sockets:
            if not ws.closed:
                await ws.close()
        await runner.cleanup()


async def _login(page, token: str, expected_identity: str):
    await page.get_by_label("OPERATOR TOKEN").fill(token)
    await page.get_by_role("button", name="VERIFY AND SIGN IN").click()
    await page.get_by_label("Verified operator identity").filter(
        has_text=expected_identity
    ).wait_for()
    await page.get_by_role("dialog", name="OPERATOR SIGN-IN").wait_for(state="hidden")


@pytest.mark.asyncio
async def test_real_browser_authenticated_signin_websocket_revocation_and_isolation():
    async with isolated_stack() as (backend, frontend):
        async with playwright.async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                page = await context.new_page()
                console = []
                page.on("console", lambda entry: console.append(entry.text))

                await page.goto(frontend + "/", wait_until="domcontentloaded")
                await page.get_by_role("dialog", name="OPERATOR SIGN-IN").wait_for()
                assert not backend.first_frames
                assert not any(identity for _, _, identity in backend.http_requests)

                await page.get_by_label("OPERATOR TOKEN").fill("wrong-token")
                await page.get_by_role("button", name="VERIFY AND SIGN IN").click()
                await page.get_by_role("alert").filter(has_text="rejected or expired").wait_for()
                assert not backend.first_frames

                await _login(page, OPERATOR, "alice-verified / operator")
                await page.get_by_text(
                    f"ID: {ENGAGEMENT.split('-')[-1].upper()}", exact=False
                ).wait_for()
                for _ in range(100):
                    if any(frame.get("token") == OPERATOR for _, frame in backend.first_frames):
                        break
                    await asyncio.sleep(0.05)
                assert any(
                    frame == {"type": "auth", "token": OPERATOR}
                    for _, frame in backend.first_frames
                )
                assert any(identity == "alice-verified" for _, _, identity in backend.http_requests)

                await page.get_by_role("link", name="FLOW OPERATIONS").click()
                await page.get_by_label("Signed authorization status").wait_for()
                await page.get_by_text("Only senior_operator", exact=False).first.wait_for()
                assert (
                    await page.get_by_role("button", name="REVOKE SIGNED ROE (CAS VERSION)").count()
                    == 0
                )

                await page.get_by_role("button", name="SIGN OUT").click()
                await page.get_by_role("dialog", name="OPERATOR SIGN-IN").wait_for()
                assert await page.get_by_label("Verified operator identity").count() == 0
                for _ in range(60):
                    if all(ws.closed for ws in backend.sockets):
                        break
                    await asyncio.sleep(0.05)
                assert all(ws.closed for ws in backend.sockets)
                await _login(page, SENIOR, "bob-verified / senior_operator")
                await page.get_by_role("button", name="REVOKE SIGNED ROE (CAS VERSION)").wait_for()
                assert backend.authorization_status == "active"
                page.once("dialog", lambda dialog: asyncio.create_task(dialog.accept()))
                await page.get_by_label("SENIOR OPERATOR SIGNED ROE REVOCATION REASON").fill(
                    "Operator confirmed policy withdrawal for test E2E"
                )
                await page.get_by_role("button", name="REVOKE SIGNED ROE (CAS VERSION)").click()
                await page.get_by_text("Revocation acknowledged for version 3").wait_for()
                await page.get_by_text(
                    "Remote execution outcome UNKNOWN", exact=False
                ).first.wait_for()
                assert backend.authorization_status == "revoked"
                assert backend.revocations == [
                    (
                        "bob-verified",
                        {
                            "expected_version": 3,
                            "reason": "Operator confirmed policy withdrawal for test E2E",
                        },
                    )
                ]

                # Changing routes does not add bearer credentials to URLs.
                forbidden = (OPERATOR, SENIOR, "build-time-canary-must-never-be-used")
                urls = [path for _, path, _ in backend.http_requests]
                urls.extend(url for url, _ in backend.first_frames)
                urls.append(page.url)
                assert all(not any(secret in url for secret in forbidden) for url in urls)
                assert all(
                    not any(secret in message for secret in forbidden) for message in console
                )
                browser_storage = await page.evaluate(
                    "() => ({local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage)})"
                )
                assert all(
                    not any(secret in content for secret in forbidden)
                    for content in browser_storage.values()
                )

                # Reload and new tabs cannot reuse credentials from an old tab.
                await page.reload(wait_until="domcontentloaded")
                await page.get_by_role("dialog", name="OPERATOR SIGN-IN").wait_for()
                second = await context.new_page()
                await second.goto(frontend + "/flows", wait_until="domcontentloaded")
                await second.get_by_role("dialog", name="OPERATOR SIGN-IN").wait_for()
                assert await second.get_by_label("Verified operator identity").count() == 0
                await context.close()
            finally:
                await browser.close()


@pytest.mark.asyncio
async def test_real_browser_rejects_missing_websocket_auth_ready_ack():
    async with isolated_stack() as (backend, frontend):
        backend.allow_ws_ack = False
        async with playwright.async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(frontend, wait_until="domcontentloaded")
                await _login(page, OPERATOR, "alice-verified / operator")

                # Exercise a real NetworkService in the live browser context.
                # A TCP/WS open by itself must never authorize commands.
                outcome = await page.evaluate(
                    """async (sessionId) => {
                      const { NetworkService } = await import('/src/services/network.ts');
                      const states = [];
                      const net = new NetworkService((status) => states.push(status));
                      net.connect(sessionId);
                      await new Promise((resolve) => setTimeout(resolve, 350));
                      const result = {states, commandAccepted: net.sendCommand('status')};
                      net.disconnect();
                      return result;
                    }""",
                    ENGAGEMENT,
                )
                assert "connected" not in outcome["states"]
                assert outcome["commandAccepted"] is False
                assert len(backend.first_frames) >= 1
                assert all(
                    frame == {"type": "auth", "token": OPERATOR}
                    for _, frame in backend.first_frames
                )
                assert not any("?token=" in path for path, _ in backend.first_frames)
            finally:
                await browser.close()
