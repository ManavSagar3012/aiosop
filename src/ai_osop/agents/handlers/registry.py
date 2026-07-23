"""Handler registry — maps task_type strings to handler modules.

BLK-4 / MAJ-2 (2026-07-23): each handler is a thin async function that takes
``(agent, payload)`` and returns a result dict. The handlers are extracted
from the monolithic VulnAnalysisAgent._execute_* methods.

The handler signature mirrors the original: ``async def handle(agent, payload)``
where ``agent`` is the VulnAnalysisAgent instance (so handlers can access
``agent.ctx``, ``agent.get_governed_client()``, ``agent.session_store``,
etc.).
"""

from typing import Any, Callable, Dict

from .burp_handler import handle_burp_scan
from .intruder_handler import handle_intruder_fuzz
from .nuclei_handler import handle_nuclei_scan
from .sqli_handler import handle_sqli_scan
from .xss_handler import handle_xss_scan
from .dom_xss_handler import handle_dom_xss_scan
from .mass_assignment_handler import handle_mass_assignment_scan
from .stored_xss_handler import handle_stored_xss_scan
from .secret_liveness_handler import handle_secret_liveness_scan
from .ssrf_metadata_handler import handle_ssrf_metadata_chain
from .oauth_reset_handler import handle_oauth_reset_scan
from .open_redirect_handler import handle_open_redirect_scan
from .nosql_handler import handle_nosql_scan
from .cache_poisoning_handler import handle_cache_poisoning_scan
from .ai_mcp_handler import handle_ai_mcp_scan
from .correlation_handler import handle_correlate_findings
from .triage_handler import handle_triage_finding

# Map task_type -> handler function
TASK_HANDLERS: Dict[str, Callable] = {
    "burp_scan": handle_burp_scan,
    "intruder_fuzz": handle_intruder_fuzz,
    "nuclei_scan": handle_nuclei_scan,
    "sqli_scan": handle_sqli_scan,
    "xss_scan": handle_xss_scan,
    "dom_xss_scan": handle_dom_xss_scan,
    "mass_assignment_scan": handle_mass_assignment_scan,
    "stored_xss_scan": handle_stored_xss_scan,
    "secret_liveness_scan": handle_secret_liveness_scan,
    "ssrf_metadata_chain": handle_ssrf_metadata_chain,
    "oauth_reset_scan": handle_oauth_reset_scan,
    "open_redirect_scan": handle_open_redirect_scan,
    "nosql_scan": handle_nosql_scan,
    "cache_poisoning_scan": handle_cache_poisoning_scan,
    "ai_mcp_scan": handle_ai_mcp_scan,
    "correlate_findings": handle_correlate_findings,
    "triage_finding": handle_triage_finding,
}
