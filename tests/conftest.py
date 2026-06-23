import sys
import pytest

# Increase recursion limit to prevent AST recursion depth mismatches
# during pytest traceback compilation and coverage execution.
sys.setrecursionlimit(3000)

@pytest.fixture(autouse=True)
def clean_global_orchestrator_state():
    """Ensure global orchestrator state is cleaned up after every test to prevent test pollution."""
    from ai_osop.api.deps import state
    state.pop("orchestrator", None)
    yield
    state.pop("orchestrator", None)
