"""Per-tool sandboxing policy registry (Phase C2).

Maps each MCP tool to a sandbox class:
  - "none": no isolation (loopback diagnostics, in-process caches)
  - "http_scoped": HTTP-level scope checks only (recon, fetch_page) — CURRENT default
  - "egress_quota": container w/ restricted egress (sqli_oracle, spa_harvest)
  - "full_isolation": read-only rootfs + cap-drop + no new privs (exploit runners)

Design note: this module is the policy table; enforcement lands in
`MCPRegistry.execute_tool` (a per-tool sandbox is provisioned on demand and
torn down after execution). Tools default to "http_scoped".
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

TOOL_SANDBOX_CLASSES: Dict[str, str] = {
    # Wildcard default
    "*": "http_scoped",
    # Recon / information
    "fetch_page": "http_scoped",
    "spa_harvest": "http_scoped",
    "scan_endpoint": "http_scoped",
    "capture_session": "egress_quota",
    # Active probing — needs quota'd egress + network isolation
    "sqli_oracle": "egress_quota",
    "turbo_intruder": "egress_quota",
    "nuclei_scan": "egress_quota",
    # Direct exploit runners — full container isolation
    "exploit_run": "full_isolation",
    "csrf_poc": "full_isolation",
    "jwt_abuse_poc": "full_isolation",
    # Reporting — writing artifacts on the host side
    "write_report": "none",
    "compile_findings": "none",
}


def sandbox_class_for(tool_name: str) -> str:
    return TOOL_SANDBOX_CLASSES.get(tool_name, TOOL_SANDBOX_CLASSES["*"])


def requires_container(tool_name: str) -> bool:
    """True when the tool must run inside a managed sandbox container."""
    return sandbox_class_for(tool_name) in {"egress_quota", "full_isolation"}


def describe_policy(tool_names: Optional[Iterable[str]] = None) -> Dict[str, str]:
    """Dump the effective policy for a set of tools (used by dashboard + tests)."""
    tools = list(tool_names) if tool_names else sorted(TOOL_SANDBOX_CLASSES.keys())
    return {t: sandbox_class_for(t) for t in tools}
