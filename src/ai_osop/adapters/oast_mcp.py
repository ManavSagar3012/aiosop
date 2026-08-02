"""OAST Interaction MCP Adapter.

Wraps the oast-mcp server so agents can mint correlation tokens and poll for
captured out-of-band callbacks through the standard MCPRegistry.
"""

from typing import Any, Dict, List, Optional, Tuple

from ai_osop.core.exceptions import MCPException, ScopeValidationError
from ai_osop.mcp.protocol import MCPRegistry

# Caller-side OAST context schema (Piece 3, Task 20). The OAST server itself
# does not care what keys are stored — enforcement happens here at the adapter
# boundary so a blind finding can always be attributed to the exact probe.
REQUIRED_OAST_CONTEXT_KEYS: Tuple[str, ...] = (
    "engagement_id",
    "vuln_class",
    "injection_point",
    "payload_hash",
)
ALLOWED_OAST_VULN_CLASSES = frozenset({"blind_xss", "blind_sqli", "blind_ssti", "ssrf", "rce"})


def _validate_oast_context(context: Dict[str, Any]) -> None:
    """Enforce the caller-side OAST context schema.

    Raises ScopeValidationError on missing/unknown keys or a vuln_class outside
    the blind-oracle allowlist. Callers that omit `context` entirely bypass
    validation (legacy / internal labels); once a caller opts into typed
    provenance they must opt in fully.
    """
    missing = [k for k in REQUIRED_OAST_CONTEXT_KEYS if k not in context]
    if missing:
        raise ScopeValidationError(
            f"OAST context missing required keys: {sorted(missing)} "
            f"(required: {sorted(REQUIRED_OAST_CONTEXT_KEYS)})"
        )
    unknown = sorted(set(context) - set(REQUIRED_OAST_CONTEXT_KEYS))
    if unknown:
        raise ScopeValidationError(
            f"OAST context has unexpected keys: {unknown}. "
            f"Allowed keys are exactly {sorted(REQUIRED_OAST_CONTEXT_KEYS)}."
        )
    vclass = str(context.get("vuln_class", "")).strip().lower()
    if vclass not in ALLOWED_OAST_VULN_CLASSES:
        raise ScopeValidationError(
            f"OAST vuln_class '{context.get('vuln_class')}' not in the blind-oracle allowlist "
            f"{sorted(ALLOWED_OAST_VULN_CLASSES)}"
        )


class OASTAdapter:
    SERVER_ID = "oast-mcp"

    def __init__(self, registry: MCPRegistry):
        self.registry = registry

    async def initialize(self, scope: Dict[str, Any], session_id: str) -> None:
        await self.registry.initialize_server(self.SERVER_ID, scope, {}, session_id)

    async def register(
        self, label: str = "", context: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, str]:
        """Mint a token; returns (token, callback_url).

        `context` carries probe provenance (engagement_id, vuln_class, injection
        point, payload_hash, ...). The OAST server stores it against the token
        and echoes it back on poll/drain, so a captured callback can be attributed
        to the exact probe that caused it even after the injecting scan has
        returned. When provided, `context` is validated against the caller-side
        OAST schema (REQUIRED_OAST_CONTEXT_KEYS / ALLOWED_OAST_VULN_CLASSES) and
        raises ScopeValidationError on any violation.
        """
        params: Dict[str, Any] = {"label": label}
        if context:
            _validate_oast_context(context)
            params["context"] = context
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_register", params)
        if resp.status != "success":
            raise MCPException(f"OAST register failed: {resp.error}")
        r = resp.result or {}
        return r.get("token", ""), r.get("callback_url", "")

    async def poll(self, token: str) -> List[Dict[str, Any]]:
        """Return captured interactions for a token (empty if none yet)."""
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_poll", {"token": token})
        if resp.status != "success":
            raise MCPException(f"OAST poll failed: {resp.error}")
        return (resp.result or {}).get("interactions", []) or []

    async def drain(
        self, since: int = 0, engagement_id: Optional[str] = None
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """Pull all interactions with seq > `since` across every token.

        Returns (cursor, interactions) where each interaction is annotated with
        its `token` and probe `context`. The cursor is the highest seq observed;
        pass it back as `since` next time to page only fresh callbacks. This is
        the slow-path reconciler's entry point — it catches blind callbacks that
        land after the injecting scan's inline poll window closed.
        """
        params: Dict[str, Any] = {"since": since}
        if engagement_id:
            params["engagement_id"] = engagement_id
        resp = await self.registry.execute_tool(self.SERVER_ID, "oast_drain", params)
        if resp.status != "success":
            raise MCPException(f"OAST drain failed: {resp.error}")
        r = resp.result or {}
        return int(r.get("cursor", since) or since), (r.get("interactions", []) or [])
