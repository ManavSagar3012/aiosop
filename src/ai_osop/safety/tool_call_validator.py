"""Tool-Call Allowlist Validator (T1.1)

Runs AFTER the LLM responds with a tool call but BEFORE execution.
Prevents:
  - Out-of-scope target injection via LLM manipulation
  - Inappropriate tool selection for agent type
  - Parameter injection in tool arguments
  - Hallucinated MCP server names
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from ai_osop.core.config import AgentType, settings

logger = logging.getLogger("ai_osop.safety.tool_call_validator")


@dataclass
class ValidationResult:
    """Result of validating a proposed tool call."""

    allowed: bool
    reason: str = ""
    sanitized_params: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


# Agent-type → allowed tool server mappings
AGENT_TOOL_POLICY: Dict[AgentType, Set[str]] = {
    AgentType.RECON: {"recon-mcp", "nuclei-mcp", "shodan-mcp", "browser-mcp", "internal"},
    AgentType.VULN_ANALYSIS: {"nuclei-mcp", "burp-mcp", "browser-mcp", "security-bridge", "internal"},
    AgentType.EXPLOIT_VALIDATION: {"security-bridge", "burp-mcp", "turbo-intruder-mcp", "browser-mcp", "internal"},
    AgentType.PAYLOAD_MUTATION: {"payload-mcp", "internal"},
    AgentType.ATTACK_CHAIN: {"internal"},
    AgentType.REPORTING: {"internal"},
    AgentType.HUMAN_OVERSIGHT: {"internal"},
    AgentType.WORKFLOW: {"browser-mcp", "internal"},
    AgentType.CONTEXT_MANAGER: {"internal"},
    AgentType.SAST_ANALYSIS: {"source-map-mcp", "internal"},
    AgentType.CLOUD_SPECIALIST: {"cloud-mcp", "internal"},
    AgentType.CONCURRENCY: {"internal"},
    AgentType.VISUAL_CONTEXT: {"browser-mcp", "internal"},
    AgentType.NEXTJS_SPECIALIST: {"browser-mcp", "source-map-mcp", "internal"},
    AgentType.REACT_SPECIALIST: {"browser-mcp", "source-map-mcp", "internal"},
    AgentType.STATEFUL_LOGIC: {"browser-mcp", "internal"},
    AgentType.RETRIEVAL: {"internal"},
    AgentType.SELF_PENTEST: {"security-bridge", "browser-mcp", "internal"},
    # LLM red team (AEGIS-LRT, 2026-08-29): reaches target/judge models through
    # the platform's llm_client directly — no external MCP servers.
    AgentType.LLM_RED_TEAM: {"internal"},
}

# Dangerous tool parameters that should be validated against scope
SCOPE_SENSITIVE_PARAMS = {"url", "target", "host", "domain", "ip", "target_url", "endpoint"}

# Maximum parameter value length (prevents oversized payloads)
MAX_PARAM_VALUE_LENGTH = 2048

# Blocked parameter patterns (potential injection)
_INJECTION_PATTERNS = (
    re.compile(r"\|\s*bash", re.I),
    re.compile(r";\s*(?:rm|curl|wget|nc|ncat)\b", re.I),
    re.compile(r"`[^`]+`", re.I),  # backtick command substitution
    re.compile(r"\$\([^)]+\)", re.I),  # $() command substitution),
)


class ToolCallValidator:
    """Validates LLM-proposed tool calls before execution.

    Defense-in-depth: runs after prompt_defense (input sanitization) and
    before mcp_registry.execute_tool (actual execution).
    """

    def __init__(self, mcp_registry: Any = None):
        self.mcp_registry = mcp_registry
        self._known_servers: Set[str] = set()
        if mcp_registry and hasattr(mcp_registry, "_servers"):
            self._known_servers = set(mcp_registry._servers.keys())

    def validate(
        self,
        agent_type: AgentType,
        tool_call: Dict[str, Any],
        engagement_scope: Any = None,
    ) -> ValidationResult:
        """Validate a proposed tool call.

        Args:
            agent_type: The agent attempting the call.
            tool_call: Dict with keys: server, name, parameters.
            engagement_scope: Optional ScopeDefinition for target validation.

        Returns:
            ValidationResult with allowed=True/False and sanitized params.
        """
        server = tool_call.get("server", "")
        tool_name = tool_call.get("name", "")
        params = tool_call.get("parameters", {})
        warnings: List[str] = []

        # 1. Server exists check
        if server != "internal" and self._known_servers:
            if server not in self._known_servers:
                return ValidationResult(
                    allowed=False,
                    reason=f"Unknown MCP server: {server}. Known: {sorted(self._known_servers)}",
                )

        # 2. Agent-type tool policy check
        allowed_servers = AGENT_TOOL_POLICY.get(agent_type)
        if allowed_servers and server not in allowed_servers:
            return ValidationResult(
                allowed=False,
                reason=f"Agent type '{agent_type.value}' cannot use server '{server}'. "
                f"Allowed: {sorted(allowed_servers)}",
            )

        # 3. Parameter sanitization
        sanitized = {}
        for key, value in params.items():
            if isinstance(value, str):
                # Length check
                if len(value) > MAX_PARAM_VALUE_LENGTH:
                    warnings.append(
                        f"Parameter '{key}' truncated from {len(value)} to {MAX_PARAM_VALUE_LENGTH} chars"
                    )
                    value = value[:MAX_PARAM_VALUE_LENGTH]

                # Injection pattern check
                for pattern in _INJECTION_PATTERNS:
                    if pattern.search(value):
                        return ValidationResult(
                            allowed=False,
                            reason=f"Potential command injection in parameter '{key}': {value[:100]}",
                        )

                # Scope-sensitive parameter check
                if key.lower() in SCOPE_SENSITIVE_PARAMS and engagement_scope is not None:
                    from ai_osop.safety.scope import ScopeEnforcer
                    from urllib.parse import urlparse

                    try:
                        parsed = urlparse(value if "://" in value else f"https://{value}")
                        host = parsed.hostname or value
                        ScopeEnforcer(engagement_scope).validate_target(host)
                    except Exception as e:
                        return ValidationResult(
                            allowed=False,
                            reason=f"Scope violation in parameter '{key}': {e}",
                        )

            sanitized[key] = value

        return ValidationResult(
            allowed=True,
            sanitized_params=sanitized,
            warnings=warnings,
        )

    def validate_action_plan(
        self,
        agent_type: AgentType,
        action_plan: Dict[str, Any],
        engagement_scope: Any = None,
    ) -> ValidationResult:
        """Validate a complete action plan from the LLM.

        Handles both 'tool' and 'complete' actions.
        """
        action = action_plan.get("action")

        if action == "complete":
            return ValidationResult(allowed=True)

        if action != "tool":
            return ValidationResult(
                allowed=False,
                reason=f"Unknown action type: {action}",
            )

        tool_call = action_plan.get("tool_call", {})
        if not tool_call:
            return ValidationResult(
                allowed=False,
                reason="Tool action missing tool_call",
            )

        return self.validate(agent_type, tool_call, engagement_scope)
