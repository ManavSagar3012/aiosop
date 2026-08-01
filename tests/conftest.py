import sys

import pytest

# Increase recursion limit to prevent AST recursion depth mismatches
# during pytest traceback compilation and coverage execution.
sys.setrecursionlimit(50000)

# Monkey-patch ast.parse to handle Python 3.11 AST recursion depth bug (bpo-46218)
import ast as _ast_module

_original_ast_parse = _ast_module.parse


def _safe_ast_parse(source, filename="<unknown>", mode="exec", **kwargs):
    try:
        return _original_ast_parse(source, filename, mode, **kwargs)
    except SystemError as e:
        if "AST constructor recursion depth mismatch" in str(e):
            # Python 3.11 bug: AST constructor recursion depth mismatch (bpo-46218)
            # Return a minimal valid AST to prevent pytest from crashing during
            # traceback formatting. This loses source-code highlighting in test
            # failure output for deeply-nested files, but keeps the test runner alive.
            return _ast_module.parse("pass")
        raise


_ast_module.parse = _safe_ast_parse


@pytest.fixture(autouse=True)
def clean_global_orchestrator_state():
    """Ensure global orchestrator state is cleaned up after every test to prevent test pollution."""
    import asyncio

    from ai_osop.api.deps import state

    state.pop("orchestrator", None)
    yield
    state.pop("orchestrator", None)
    # Cancel any background tasks the orchestrator spawned (phase monitor,
    # reasoning loop, graph-integrity sweep, ...) so they don't outlive their
    # event loop and trigger `RuntimeError: Event loop is closed` in the next test.
    try:
        loop = asyncio.get_event_loop()
        if not loop.is_closed():
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    except Exception:
        pass  # The loop may already be closed; that's fine.


from ai_osop.mcp.protocol import MCPRegistry
from ai_osop.memory.graph_memory import GraphMemory
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


@pytest.fixture
async def session_memory():
    sm = SessionMemory()
    try:
        await sm.connect()
    except Exception as e:
        pytest.skip(f"Redis/Postgres not available: {e}")
    yield sm
    await sm._pg_engine.dispose()
    if sm._redis:
        await sm._redis.close()


@pytest.fixture
async def orchestrator(session_memory):
    gm = GraphMemory()
    try:
        await gm.connect()
    except Exception as e:
        pytest.skip(f"Neo4j not available: {e}")
    mcp = MCPRegistry()
    orch = Orchestrator(session_memory, gm, mcp, None)
    await orch.recover_state()
    yield orch
    await gm.close()
