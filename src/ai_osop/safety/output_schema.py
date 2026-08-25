"""Structured Output Schema Enforcement (T1.2)

Enforces that LLM responses conform to expected schemas before they're
used as tool calls. Catches malformed outputs, hallucinated fields,
and structurally invalid action plans.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("ai_osop.safety.output_schema")


# Action plan schema — the LLM must return one of these shapes
ACTION_PLAN_SCHEMAS = {
    "tool": {
        "required": {"action", "reasoning", "tool_call"},
        "tool_call_required": {"server", "name", "parameters"},
        "reasoning_required": {"observation", "why_chosen"},
        "valid_actions": {"tool", "complete"},
    },
    "complete": {
        "required": {"action", "reasoning"},
        "reasoning_required": {"why_chosen"},
        "valid_actions": {"tool", "complete"},
    },
}

# Known valid MCP tool names per server (populated at runtime)
_KNOWN_TOOLS: Dict[str, Set[str]] = {}


def register_known_tools(server_id: str, tool_names: List[str]) -> None:
    """Register known tool names for a server."""
    _KNOWN_TOOLS[server_id] = set(tool_names)


def validate_action_plan(
    raw_output: str,
    agent_type: str = "unknown",
) -> Dict[str, Any]:
    """Validate and parse an LLM action plan.

    Returns the parsed plan if valid, or raises ValueError with details.
    """
    # 1. JSON parse
    try:
        plan = json.loads(raw_output)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM output is not valid JSON: {e}")

    if not isinstance(plan, dict):
        raise ValueError(f"LLM output must be a JSON object, got {type(plan).__name__}")

    # 2. Action field
    action = plan.get("action")
    if not action:
        raise ValueError("Missing required field 'action'")

    if action not in ("tool", "complete"):
        raise ValueError(f"Invalid action '{action}'. Must be 'tool' or 'complete'")

    # 3. Reasoning field
    reasoning = plan.get("reasoning")
    if not isinstance(reasoning, dict):
        raise ValueError("'reasoning' must be a non-empty object")

    if not reasoning.get("why_chosen"):
        raise ValueError("Missing 'reasoning.why_chosen'")

    # 4. Tool-specific validation
    if action == "tool":
        tool_call = plan.get("tool_call")
        if not isinstance(tool_call, dict):
            raise ValueError("'tool_call' must be a non-empty object for tool action")

        server = tool_call.get("server")
        name = tool_call.get("name")
        params = tool_call.get("parameters")

        if not server:
            raise ValueError("Missing 'tool_call.server'")
        if not name:
            raise ValueError("Missing 'tool_call.name'")
        if params is not None and not isinstance(params, dict):
            raise ValueError("'tool_call.parameters' must be a JSON object")

        # 5. Known-tool check (advisory, not blocking)
        known_for_server = _KNOWN_TOOLS.get(server)
        if known_for_server and name not in known_for_server:
            logger.warning(
                "output_schema_unknown_tool server=%s tool=%s known=%s",
                server,
                name,
                sorted(known_for_server)[:10],
            )

    elif action == "complete":
        if not plan.get("conclusion"):
            # Auto-fill a default conclusion
            plan["conclusion"] = reasoning.get("why_chosen", "Task completed.")

    return plan


def sanitize_tool_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize tool parameters to prevent common issues."""
    sanitized = {}
    for key, value in params.items():
        if isinstance(value, str):
            # Strip control characters
            value = "".join(c for c in value if ord(c) >= 32 or c in "\n\r\t")
            # Truncate extremely long values
            if len(value) > 4096:
                value = value[:4096] + "...[truncated]"
        elif isinstance(value, (list, dict)):
            # Recursively limit depth
            value = _limit_depth(value, max_depth=5)
        sanitized[key] = value
    return sanitized


def _limit_depth(obj: Any, max_depth: int = 5, _depth: int = 0) -> Any:
    """Recursively limit nesting depth."""
    if _depth >= max_depth:
        return str(obj)[:500] if isinstance(obj, str) else "<truncated>"
    if isinstance(obj, dict):
        return {k: _limit_depth(v, max_depth, _depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_limit_depth(v, max_depth, _depth + 1) for v in obj[:50]]
    return obj
