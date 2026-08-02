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


@pytest.fixture
def mock_aiohttp_session():
    with patch("aiohttp.ClientSession") as mock_session_class:
        session_instance = MagicMock()
        session_instance.closed = False
        session_instance.close = AsyncMock()
        mock_session_class.return_value = session_instance
        # Mock get as a method that returns an async context manager
        mock_get_ctx = MagicMock()
        session_instance.get.return_value = mock_get_ctx

        yield session_instance


@pytest.mark.asyncio
async def test_mcp_connection_connect(mock_aiohttp_session):
    conn = MCPConnection("test-mcp", "localhost", 8080)

    # Mock response
    mock_resp = AsyncMock()
    mock_resp.status = 200

    # Mock context manager for .get()
    mock_get_ctx = MagicMock()
    mock_get_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get_ctx.__aexit__ = AsyncMock()

    conn._session = mock_aiohttp_session
    mock_aiohttp_session.get.return_value = mock_get_ctx

    await conn.connect()
    assert conn._session is not None
    mock_aiohttp_session.get.assert_called_once()


@pytest.mark.asyncio
async def test_mcp_connection_initialize(mock_aiohttp_session):
    # Mock response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_get_ctx = MagicMock()
    mock_get_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.get.return_value = mock_get_ctx

    conn = MCPConnection("test-mcp", "localhost", 8080)
    conn._session = mock_aiohttp_session
    await conn.connect()

    mock_response = AsyncMock()
    mock_response.json.return_value = {
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
    }

    # Mock context manager for aiohttp.post
    mock_post_ctx = MagicMock()
    mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_post_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.post.return_value = mock_post_ctx

    req = MCPInitializeRequest(scope={}, auth_credentials={}, session_id="test")
    resp = await conn.initialize(req)

    assert resp.server_id == "test-mcp"
    assert "test_tool" in conn._tools
    assert conn._initialized is True


@pytest.mark.asyncio
async def test_mcp_connection_execute(mock_aiohttp_session):
    # Mock response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_get_ctx = MagicMock()
    mock_get_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.get.return_value = mock_get_ctx

    conn = MCPConnection("test-mcp", "localhost", 8080)
    conn._session = mock_aiohttp_session
    await conn.connect()

    # Manually initialize
    conn._initialized = True
    tool_mock = MagicMock()
    tool_mock.name = "test_tool"
    tool_mock.timeout_seconds = 30
    conn._tools["test_tool"] = tool_mock

    mock_response = AsyncMock()
    mock_response.json.return_value = {
        "request_id": "req-1",
        "status": "success",
        "result": {"output": "done"},
    }

    mock_post_ctx = MagicMock()
    mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_post_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.post.return_value = mock_post_ctx

    req = MCPExecuteRequest(tool_name="test_tool", parameters={})
    resp = await conn.execute(req)

    assert resp.status == "success"
    assert resp.result["output"] == "done"


@pytest.mark.asyncio
async def test_mcp_registry_register_and_execute(mock_aiohttp_session):
    # Mock response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_get_ctx = MagicMock()
    mock_get_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.get.return_value = mock_get_ctx

    registry = MCPRegistry()

    # Register server
    conn = await registry.register_server("test-mcp", "localhost", 8080)
    # Patch the session created by register_server
    conn._session = mock_aiohttp_session

    assert "test-mcp" in registry._servers

    # Manually initialize the connection for the registry
    conn._initialized = True
    tool_mock = MagicMock()
    tool_mock.name = "test_tool"
    tool_mock.timeout_seconds = 30
    conn._tools["test_tool"] = tool_mock

    mock_response = AsyncMock()
    mock_response.json.return_value = {
        "request_id": "req-1",
        "status": "success",
        "result": {"data": "registry"},
    }

    mock_post_ctx = MagicMock()
    mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_post_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.post.return_value = mock_post_ctx

    resp = await registry.execute_tool("test-mcp", "test_tool", {})
    assert resp.status == "success"
    assert resp.result["data"] == "registry"


@pytest.mark.asyncio
async def test_mcp_registry_broadcast(mock_aiohttp_session):
    # Mock response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_get_ctx = MagicMock()
    mock_get_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_get_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.get.return_value = mock_get_ctx

    registry = MCPRegistry()

    conn1 = await registry.register_server("test-mcp-1", "localhost", 8080)
    conn1._session = mock_aiohttp_session
    conn2 = await registry.register_server("test-mcp-2", "localhost", 8081)
    conn2._session = mock_aiohttp_session

    # Initialize conn1 with the tool
    conn1._initialized = True
    tool_mock = MagicMock()
    tool_mock.name = "test_tool"
    tool_mock.timeout_seconds = 30
    conn1._tools["test_tool"] = tool_mock

    # Initialize conn2 without the tool
    conn2._initialized = True

    mock_response = AsyncMock()
    mock_response.json.return_value = {"request_id": "req-1", "status": "success", "result": {}}
    mock_post_ctx = MagicMock()
    mock_post_ctx.__aenter__ = AsyncMock(return_value=mock_response)
    mock_post_ctx.__aexit__ = AsyncMock()
    mock_aiohttp_session.post.return_value = mock_post_ctx

    results = await registry.broadcast_execute("test_tool", {})

    # Should only execute on conn1 since it has the tool
    assert "test-mcp-1" in results
    assert "test-mcp-2" not in results
