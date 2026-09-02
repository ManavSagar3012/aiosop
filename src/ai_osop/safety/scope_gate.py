"""Fail-closed client-side scope gate for MCP tool executions.

FIX (scope-gate-2026-08-24): before this module existed, `MCPRegistry.execute_tool`
forwarded whatever parameters an agent produced straight to the remote MCP server.
The ONLY enforcement was each server's optional `scope_check` flag set at
initialize — and several agents gated targets with a fail-open pattern
(`if scope is not None`), meaning an engagement without bound scope performed
ZERO target validation while still firing live network traffic.

This gate makes the registry the single choke point required by the platform
security charter:

    extract candidate targets from tool parameters
      -> no targets            -> allow (pure state/intel operations)
      -> targets + scope       -> every target must pass ScopeEnforcer
      -> targets + NO scope    -> DENY for active servers (fail closed);
                                  passive intel servers allowed but flagged

Decisions are structured records so denials are auditable and testable.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from ai_osop.core.models import ScopeDefinition
from ai_osop.safety.scope import ScopeEnforcer

logger = logging.getLogger(__name__)

# Parameter keys whose values are treated as attack targets wherever they appear
# in a tool-parameter tree (case-insensitive match on the key name).
TARGET_KEYS: Set[str] = {
    "url",
    "urls",
    "uri",
    "host",
    "hostname",
    "hosts",
    "domain",
    "domains",
    "target",
    "targets",
    "ip",
    "ips",
    "base_url",
    "endpoint",
    "endpoints",
    "origin",
}

_URL_RE = re.compile(r"https?://[^\s'\"<>\\]+", re.IGNORECASE)

# Servers that are infrastructure-side (read-only intel lookups or callback
# capture): their "target" parameter is a research query or our own callback
# token, never an attacked host.
# Their "target" parameter is a research query subject, not an attacked host,
# and query strings like "org:Example" are not validate_target-shaped. They are
# still audited; they are simply not blocked when no engagement scope is bound,
# because OSINT does not touch the queried party's infrastructure.
PASSIVE_SERVER_IDS: Set[str] = {"shodan-mcp", "threat-intel-mcp", "oast-mcp"}


@dataclass
class ScopeDecision:
    """Structured result of a scope-gate evaluation."""

    server_id: str
    tool_name: str
    targets: List[str] = field(default_factory=list)
    allowed: bool = True
    reason: str = ""
    passive_server: bool = False
    unscooped_passive: bool = False  # passive server called with no scope bound

    def denial_detail(self) -> str:
        return (
            f"server={self.server_id} tool={self.tool_name} "
            f"targets={self.targets[:8]} reason={self.reason}"
        )


def _looks_like_url(value: str) -> bool:
    return bool(_URL_RE.fullmatch(value.strip()))


def extract_targets(parameters: Dict[str, Any]) -> List[str]:
    """Extract candidate attack targets from an arbitrary parameter tree.

    Two extraction rules keep this precise (no false positives on arbitrary
    string args like wordlists or flags):
      1. values under well-known target keys (deep, case-insensitive)
      2. anything anywhere in the tree that is literally an http(s) URL

    Scalar strings under target keys may themselves contain lists ("a,b,c")
    or bare hosts ("example.com", "10.0.0.1"); URLs contribute their origin.
    """
    found: List[str] = []

    def _add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                _add(item)
            return
        text = str(value).strip()
        if not text or len(text) > 2048:
            return
        # A single scalar under a target key may be comma/whitespace separated.
        for part in re.split(r"[,\s]+", text):
            part = part.strip()
            if not part:
                continue
            if _URL_RE.search(part) and part.lower().startswith(("http://", "https://")):
                found.append(part)
            elif _looks_like_host_or_ip(part):
                found.append(part)

    def _walk(node: Any, key_hint: Optional[str] = None) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                k = str(key).lower()
                if k in TARGET_KEYS:
                    _add(value)
                else:
                    _walk(value, key_hint=k)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item, key_hint=key_hint)
        elif isinstance(node, str):
            # URL detection anywhere in the tree (e.g. nested "request" blobs).
            for match in _URL_RE.findall(node):
                found.append(match)

    _walk(parameters)

    # De-duplicate preserving order.
    seen: Set[str] = set()
    unique = []
    for t in found:
        norm = t.rstrip("/,. ")
        if norm and norm.lower() not in seen:
            seen.add(norm.lower())
            unique.append(norm)
    return unique


def _looks_like_host_or_ip(value: str) -> bool:
    """Bare host/IP heuristic applied only to scalars from TARGET_KEYS paths."""
    if _URL_RE.match(value):
        return True
    if value.startswith(("http://", "https://")):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    if "." in value and not any(c in value for c in " /\\:=?#@"):
        labels = value.split(".")
        if all(labels) and all(re.fullmatch(r"[A-Za-z0-9_-]+", lbl) for lbl in labels):
            return True
    return False


class ScopeGate:
    """Evaluate whether an MCP tool call may proceed against its targets."""

    def __init__(self, passive_servers: Optional[Set[str]] = None):
        self.passive_servers = (
            PASSIVE_SERVER_IDS if passive_servers is None else set(passive_servers)
        )

    def check(
        self,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        scope: Optional[Any],
    ) -> ScopeDecision:
        # Normalize scope input: adapters receive either ScopeDefinition models
        # (burp adapter) or raw dicts (recon/browser/...). A malformed scope is a
        # caller bug — FAIL CLOSED with a loud reason instead of proceeding blind.
        normalized: Optional[ScopeDefinition]
        if scope is None:
            normalized = None
        elif isinstance(scope, ScopeDefinition):
            normalized = scope
        elif isinstance(scope, dict):
            try:
                normalized = ScopeDefinition.model_validate(scope)
            except Exception as exc:  # noqa: BLE001
                return ScopeDecision(
                    server_id=server_id,
                    tool_name=tool_name,
                    allowed=False,
                    reason=f"scope_dict_invalid: {exc}",
                )
        else:
            normalized = None

        targets = extract_targets(parameters or {})
        passive = server_id in self.passive_servers
        decision = ScopeDecision(
            server_id=server_id, tool_name=tool_name, targets=targets, passive_server=passive
        )

        # Rule 1: nothing that looks like a target -> inherently safe operation
        # (proxy history reads, stats, report generation, payload math...).
        if not targets:
            decision.reason = "no_target_parameters"
            return decision

        # Rule 2: passive intel servers never touch the queried party's infra;
        # allow but mark for audit trail when running unscooped.
        if passive:
            if normalized is None:
                decision.unscooped_passive = True
            decision.reason = "passive_intel_server"
            return decision

        # Rule 3: active server + no bound scope -> FAIL CLOSED. This is the
        # exact hole the old per-agent opt-in checks left open.
        if normalized is None:
            decision.allowed = False
            decision.reason = "no_scope_bound_for_active_tool"
            return decision

        # Rule 4: every extracted target must be inside the authorized scope.
        enforcer = ScopeEnforcer(normalized)
        for target in targets:
            try:
                enforcer.validate_target(target)
            except Exception as exc:  # OutOfScopeError / ScopeValidationError
                decision.allowed = False
                decision.reason = f"target_rejected: {exc}"
                return decision

        decision.reason = f"all_targets_in_scope ({len(targets)})"
        return decision


_default_gate = ScopeGate()


def check_tool_call(
    server_id: str,
    tool_name: str,
    parameters: Dict[str, Any],
    scope: Optional[ScopeDefinition],
) -> ScopeDecision:
    """Module-level entry point used by MCPRegistry."""
    return _default_gate.check(server_id, tool_name, parameters, scope)


def parse_url_origin(url: str) -> Optional[str]:
    """Return scheme://host[:port] for audit records."""
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            netloc = parsed.netloc or parsed.hostname
            return f"{parsed.scheme}://{netloc}"
    except Exception:  # noqa: BLE001 - audit helper must never raise
        return None
    return None
