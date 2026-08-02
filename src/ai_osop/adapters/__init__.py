# Adapter classes are imported directly by module path at every call site
# (e.g. `from ai_osop.adapters.cloud_mcp import CloudMCPAdapter`), so this
# package does not re-export the full set. `__all__` lists only the adapters
# that are referenced via the package namespace; the remaining adapters
# (browser, burp, bug_bounty, cloud, nuclei, payload, recon, security_bridge,
# source_map, turbo_intruder) are intentionally module-path-only. Import those
# from their modules rather than expanding this list (avoids unused surface).
from ai_osop.adapters.attack_graph_mcp import AttackGraphMCPAdapter
from ai_osop.adapters.reporting_mcp import ReportingMCPAdapter
from ai_osop.adapters.session_memory_mcp import SessionMemoryMCPAdapter
from ai_osop.adapters.threat_intel_mcp import ThreatIntelAdapter

__all__ = [
    "AttackGraphMCPAdapter",
    "ReportingMCPAdapter",
    "SessionMemoryMCPAdapter",
    "ThreatIntelAdapter",
]
