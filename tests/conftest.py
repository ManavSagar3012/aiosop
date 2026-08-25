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
    from ai_osop.api.deps import state

    state.pop("orchestrator", None)
    yield
    state.pop("orchestrator", None)


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
        await sm._redis.aclose()  # FIX (redis-aclose-2026-08-24)


@pytest.fixture
async def orchestrator(session_memory):
    gm = GraphMemory()
    await gm.connect()
    mcp = MCPRegistry()
    orch = Orchestrator(session_memory, gm, mcp, None)
    await orch.recover_state()
    yield orch
    await gm.close()
