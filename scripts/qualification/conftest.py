import asyncio

import pytest

from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


@pytest.fixture
async def session_memory():
    sm = SessionMemory()
    await sm.connect()
    yield sm
    await sm._pg_engine.dispose()
    if sm._redis:
        await sm._redis.close()


@pytest.fixture
async def orchestrator(session_memory):
    gm = GraphMemory()
    await gm.connect()
    mcp = MCPRegistry()
    orch = Orchestrator(session_memory, gm, mcp, None)
    await orch.recover_state()
    yield orch
    await gm.close()
