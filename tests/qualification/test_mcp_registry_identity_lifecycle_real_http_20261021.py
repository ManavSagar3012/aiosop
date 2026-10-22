"""Actual ephemeral HTTP registration/reconnection cannot reset Action fences.

Only the existing harmless local `list_tools` fixture may receive an execute.
No production port, provider key, database, scanner, target or external socket.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from ai_osop.core.exceptions import MCPConnectionError
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPRegistry
from tests.qualification.test_mcp_all_eleven_transport_recovery_20261021 import owned_fixture


@pytest.mark.asyncio
async def test_unknown_ack_cannot_be_reexecuted_by_rebinding_same_service() -> None:
    async with owned_fixture("recon-mcp", "truncated") as (original_port, source):
        async with owned_fixture("recon-mcp", "untrusted_success") as (foreign_port, foreign):
            registry = MCPRegistry()
            try:
                connection = await registry.register_server("recon-mcp", "127.0.0.1", original_port)
                await registry.initialize_server("recon-mcp", {}, {}, "fixture")
                request_id = "req-" + uuid.uuid4().hex
                RequestContext.bind(engagement_id="api-bootstrap", task_id="task-inert")
                try:
                    unknown = await registry.execute_tool(
                        "recon-mcp", "list_tools", {}, request_id=request_id
                    )
                    assert unknown.status == "unknown"
                    with pytest.raises(MCPConnectionError, match="already registered"):
                        await registry.register_server("recon-mcp", "127.0.0.1", foreign_port)
                    assert registry._servers["recon-mcp"] is connection
                    assert connection._initialized
                    duplicate = await registry.execute_tool(
                        "recon-mcp", "list_tools", {}, request_id=request_id
                    )
                    assert duplicate.status == "duplicate_request"
                finally:
                    RequestContext.clear()
                assert [event for event, _ in source.calls].count("execute") == 1
                assert not foreign.calls
            finally:
                await registry.close_all()


@pytest.mark.asyncio
async def test_two_concurrent_registrations_allow_only_one_original_identity() -> None:
    async with owned_fixture("browser-mcp", "untrusted_success") as (port_a, a):
        async with owned_fixture("browser-mcp", "untrusted_success") as (port_b, b):
            registry = MCPRegistry()
            try:
                answers = await asyncio.gather(
                    registry.register_server("browser-mcp", "127.0.0.1", port_a),
                    registry.register_server("browser-mcp", "127.0.0.1", port_b),
                    return_exceptions=True,
                )
                assert len([x for x in answers if isinstance(x, MCPConnectionError)]) == 1
                assert len([x for x in answers if not isinstance(x, BaseException)]) == 1
                assert len(registry._servers) == 1
                assert registry._servers["browser-mcp"].port == port_a
                assert sum(1 for source in (a, b) if source.calls) == 1
            finally:
                await registry.close_all()


@pytest.mark.asyncio
async def test_direct_reconnect_revokes_previous_manifest_and_never_replays() -> None:
    async with owned_fixture("payload-mcp", "untrusted_success") as (port, source):
        registry = MCPRegistry()
        try:
            connection = await registry.register_server("payload-mcp", "127.0.0.1", port)
            await registry.initialize_server("payload-mcp", {}, {}, "fixture")
            assert connection._initialized and "list_tools" in connection._tools
            source.healthy = False
            with pytest.raises(MCPConnectionError):
                await connection.connect()
            assert connection._initialized is False
            assert connection._tools == {} and connection._capabilities == []
            assert connection._session is None
            assert not any(event == "execute" for event, _ in source.calls)
            source.healthy = True
            await connection.connect()
            assert connection._initialized is False
            assert connection._tools == {}
            await registry.initialize_server("payload-mcp", {}, {}, "fixture")
            assert connection._initialized
            await connection.close()
            assert not connection._initialized and connection._session is None
            assert connection._tools == {} and connection._capabilities == []
            assert not any(event == "execute" for event, _ in source.calls)
        finally:
            await registry.close_all()
