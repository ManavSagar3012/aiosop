"""Handler for open_redirect_scan — extracted from VulnAnalysisAgent.

BLK-4 / MAJ-2 (2026-07-23): this handler is a thin wrapper that delegates to
``agent._execute_open_redirect_scan(payload)``. The implementation stays on VulnAnalysisAgent
so tests that call the method directly still work; only the dispatch changes
from a 25-branch if/elif chain to a registry lookup.
"""

from typing import Any, Dict


async def handle_open_redirect_scan(agent: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle open_redirect_scan task by delegating to the VulnAnalysisAgent method."""
    return await agent._execute_open_redirect_scan(payload)
