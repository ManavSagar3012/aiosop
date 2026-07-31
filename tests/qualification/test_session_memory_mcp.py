"""
Session Memory MCP reality gate.
Proves session-memory-mcp executes real Redis and Postgres storage actions.
"""

import pytest

from .conftest import mcp_execute, mcp_initialize, require_server

pytestmark = pytest.mark.qualification


@pytest.mark.asyncio
async def test_session_memory_flow():
    base = require_server("session_memory")
    tools = [t["name"] for t in mcp_initialize(base).get("tools", [])]
    assert "get_session_state" in tools
    assert "store_checkpoint" in tools

    from ai_osop.core.models import ScopeDefinition, SessionState
    from ai_osop.memory.session_memory import SessionMemory

    memory = SessionMemory()
    await memory.connect()

    scope = ScopeDefinition(engagement_id="test-eng-session-mcp", domains=["example.com"], ips=[])
    state = SessionState(session_id="test-session-mcp", scope=scope)

    try:
        await memory.store_session_state(state)

        # Test get_session_state tool. The server's "result" IS the session dict
        # (SessionState.model_dump) on a hit, or None on a miss — there is no
        # {"found": ..., "state": ...} envelope. Assert the contract the server
        # actually keeps so a real regression (e.g. session loss) is caught.
        res = mcp_execute(base, "get_session_state", {"session_id": "test-session-mcp"})
        assert res is not None and res.get("session_id") == "test-session-mcp"

        # Test store_checkpoint tool
        cres = mcp_execute(
            base,
            "store_checkpoint",
            {"session_id": "test-session-mcp", "metadata": {"test": "metadata"}},
        )
        assert cres.get("checkpoint_id") is not None
    finally:
        await memory.close()
