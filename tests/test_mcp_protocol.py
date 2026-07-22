from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.mcp.protocol import (
    MCPConnection,
    MCPConnectionError,
    MCPException,
    MCPExecuteRequest,
    MCPInitializeRequest,
    MCPRegistry,
)
from tests._mocks import stub_aiohttp_response, stub_async_context_manager


@pytest.fixture
def mock_aiohttp_session():
    with patch("aiohttp.ClientSession") as mock_session_class:
        session_instance = MagicMock()
        session_instance.closed = False
        session_instance.close = AsyncMock()
        mock_session_class.return_value = session_instance
        session_instance.get.return_value = stub_async_context_manager(AsyncMock(status=200))
        yield session_instance


@pytest.mark.asyncio
async def test_mcp_connection_connect(mock_aiohttp_session):
    conn = MCPConnection("test-mcp", "localhost", 8080)
    conn._session = mock_aiohttp_session

    await conn.connect()
    assert conn._session is not None
    mock_aiohttp_session.get.assert_called_once()


def _stub_tool(name: str = "test_tool", timeout: int = 30) -> MagicMock:
    tool = MagicMock()
    tool.name = name
    tool.timeout_seconds = timeout
    return tool


def _init_json_resp(data: dict):
    return stub_aiohttp_response(json_data=data)


def _stub_post_ctx(mock_aiohttp_session, json_data: dict):
    ctx = stub_async_context_manager(_init_json_resp(json_data))
    mock_aiohttp_session.post.return_value = ctx
    return ctx


@pytest.mark.asyncio
async def test_mcp_connection_initialize(mock_aiohttp_session):
    conn = MCPConnection("test-mcp", "localhost", 8080)
    conn._session = mock_aiohttp_session
    await conn.connect()

    _stub_post_ctx(
        mock_aiohttp_session,
        {
            "server_id": "test-mcp",
            "version": "1.0",
            "capabilities": ["scan"],
            "tools": [
                {
                    "name": "test_tool",
                    "description": "test",
                    "parameters": [],
                    "returns": {},
                    "timeout_seconds": 30,
                    "requires_approval": False,
                    "scope_check": False,
                }
            ],
            "status": "ready",
        },
    )

    req = MCPInitializeRequest(scope={}, auth_credentials={}, session_id="test")
    resp = await conn.initialize(req)

    assert resp.server_id == "test-mcp"
    assert "test_tool" in conn._tools
    assert conn._initialized is True


@pytest.mark.asyncio
async def test_mcp_connection_execute(mock_aiohttp_session):
    conn = MCPConnection("test-mcp", "localhost", 8080)
    conn._session = mock_aiohttp_session
    await conn.connect()

    conn._initialized = True
    conn._tools["test_tool"] = _stub_tool()

    _stub_post_ctx(
        mock_aiohttp_session,
        {
            "request_id": "req-1",
            "status": "success",
            "result": {"output": "done"},
        },
    )

    req = MCPExecuteRequest(tool_name="test_tool", parameters={})
    resp = await conn.execute(req)

    assert resp.status == "success"
    assert resp.result["output"] == "done"


@pytest.mark.asyncio
async def test_mcp_registry_register_and_execute(mock_aiohttp_session):
    registry = MCPRegistry()

    conn = await registry.register_server("test-mcp", "localhost", 8080)
    conn._session = mock_aiohttp_session

    assert "test-mcp" in registry._servers

    conn._initialized = True
    conn._tools["test_tool"] = _stub_tool()

    _stub_post_ctx(
        mock_aiohttp_session,
        {
            "request_id": "req-1",
            "status": "success",
            "result": {"data": "registry"},
        },
    )

    resp = await registry.execute_tool("test-mcp", "test_tool", {})
    assert resp.status == "success"
    assert resp.result["data"] == "registry"


@pytest.mark.asyncio
async def test_mcp_registry_broadcast(mock_aiohttp_session):
    registry = MCPRegistry()

    conn1 = await registry.register_server("test-mcp-1", "localhost", 8080)
    conn1._session = mock_aiohttp_session
    conn2 = await registry.register_server("test-mcp-2", "localhost", 8081)
    conn2._session = mock_aiohttp_session

    conn1._initialized = True
    conn1._tools["test_tool"] = _stub_tool()

    conn2._initialized = True

    _stub_post_ctx(
        mock_aiohttp_session,
        {
            "request_id": "req-1",
            "status": "success",
            "result": {},
        },
    )

    results = await registry.broadcast_execute("test_tool", {})

    assert "test-mcp-1" in results
    assert "test-mcp-2" not in results
