"""Handler for correlate_findings — extracted from VulnAnalysisAgent.

BLK-4 / MAJ-2 (2026-07-23): this handler is a thin wrapper that delegates to
``agent._execute_correlation(payload)``. The implementation stays on VulnAnalysisAgent
so tests that call the method directly still work; only the dispatch changes
from a 25-branch if/elif chain to a registry lookup.
"""

from typing import Any, Dict


async def handle_correlate_findings(agent: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle correlate_findings task by delegating to the VulnAnalysisAgent method."""
    return await agent._execute_correlation(payload)
