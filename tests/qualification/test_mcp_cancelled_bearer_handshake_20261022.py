"""Cancelled local /health must tear down the original bearer session."""

from __future__ import annotations

import asyncio

import pytest
from aiohttp import web

from ai_osop.mcp.protocol import MCPConnection, MCPRegistry


@pytest.mark.asyncio
async def test_direct_handshake_cancellation_closes_owned_bearer_session_no_action() -> None:
    entered = asyncio.Event()
    finish = asyncio.Event()
    incoming: list[tuple[str, str | None]] = []

    async def health(request: web.Request) -> web.Response:
        incoming.append((request.path, request.headers.get("Authorization")))
        entered.set()
        await finish.wait()
        return web.json_response({"status": "healthy"})

    app = web.Application()
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    conn = MCPConnection("browser-mcp", "127.0.0.1", port, "not-a-real-bearer")
    try:
        task = asyncio.create_task(conn.connect())
        await asyncio.wait_for(entered.wait(), timeout=5.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5.0)
        assert incoming == [("/health", "Bearer not-a-real-bearer")]
        assert conn._session is None
        assert conn._initialized is False and not conn._tools
        assert conn._executions == {}
    finally:
        finish.set()
        await conn.close()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_registry_cancelled_handshake_does_not_register_candidate() -> None:
    entered = asyncio.Event()
    finish = asyncio.Event()

    async def health(_: web.Request) -> web.Response:
        entered.set()
        await finish.wait()
        return web.json_response({"status": "healthy"})

    app = web.Application()
    app.router.add_get("/health", health)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    registry = MCPRegistry()
    try:
        task = asyncio.create_task(
            registry.register_server("browser-mcp", "127.0.0.1", port, "inert-bearer")
        )
        await asyncio.wait_for(entered.wait(), timeout=5.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5.0)
        assert registry._servers == {}
    finally:
        finish.set()
        await registry.close_all()
        await runner.cleanup()
