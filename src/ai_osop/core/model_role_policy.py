"""Operator-opted, bounded reasoning parameters for PostgreSQL-owned agent roles.

PentAGI configures reasoning per provider and agent role, including explicit
DeepSeek thinking toggles. This policy deliberately does not discover or
certify provider capabilities. An exact model and configured route must match;
the role is read from the durable Task, never from prompt text, tool output,
HTTP metadata, a caller argument, or an in-memory agent registry.

OSOP_MODEL_ROLE_REASONING_JSON example:
{"version":1,"roles":[{"role":"vuln_analysis","provider":"openai",
"model":"openai/o3-mini","mode":"openai_effort","effort":"medium",
"max_tokens":4096}]}

The model and provider are operator assertions of compatibility, not verified
provider support. Provider errors remain UNKNOWN through LiteLLMClient.
"""

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ai_osop.core.config import AgentType
from ai_osop.core.provider_routing import ProviderRoute, ProviderRouteDenied
from ai_osop.memory.session_memory import SessionMemory

_POLICY_ENV = "OSOP_MODEL_ROLE_REASONING_JSON"
_MAX_BYTES = 8192
_MAX_ENTRIES = 24
_MAX_OUTPUT_TOKENS = 16384
_EFFORTS = frozenset({"low", "medium", "high"})
_MODES = {"openai_effort": "openai", "deepseek_thinking": "deepseek"}
_BLOCKED_COMPLETION_KWARGS = frozenset(
    {
        "reasoning_effort",
        "reasoning",
        "thinking",
        "thinking_budget",
        "thinking_tokens",
        "reasoning_budget",
        "max_reasoning_tokens",
        "budget_tokens",
        "enable_thinking",
        "max_completion_tokens",
        "thinking_mode",
        "reasoning_mode",
        "agent_role",
        "agent_type",
        "role",
        "extra_body",
        "num_retries",
        "max_retries",
        "fallbacks",
        "context_window_fallbacks",
        "model_list",
        "mock_response",
    }
)


class ModelRolePolicyDenied(ProviderRouteDenied):
    """Refused a role-specific provider parameter before model reservation."""


def reject_caller_reasoning_overrides(kwargs: Dict[str, Any]) -> None:
    """Only the operator's exact deployment declaration controls thinking."""
    if _BLOCKED_COMPLETION_KWARGS.intersection(kwargs):
        raise ModelRolePolicyDenied("Caller reasoning or retry overrides are forbidden")


def _unique_fields(pairs: list) -> dict:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate model role policy field")
        result[key] = value
    return result


@dataclass(frozen=True)
class RoleReasoning:
    role: str
    provider: str
    model: str
    mode: str
    max_tokens: int
    effort: Optional[str] = None
    thinking: Optional[bool] = None

    def options(self, current_max_tokens: Any) -> Dict[str, Any]:
        if type(current_max_tokens) is not int or not 1 <= current_max_tokens <= 131072:
            raise ModelRolePolicyDenied("Completion token ceiling is invalid")
        parameters: Dict[str, Any] = {"max_tokens": min(current_max_tokens, self.max_tokens)}
        if self.mode == "openai_effort":
            parameters["reasoning_effort"] = self.effort
        else:
            parameters["extra_body"] = {
                "thinking": {"type": "enabled" if self.thinking else "disabled"}
            }
        return parameters


@dataclass(frozen=True)
class ModelRolePolicy:
    """Locally configured role/model declarations, never provider attestations."""

    roles: Tuple[RoleReasoning, ...]

    @classmethod
    def from_environment(cls) -> Optional["ModelRolePolicy"]:
        raw = os.environ.get(_POLICY_ENV)
        if raw is None:
            return None
        if type(raw) is not str or not 1 <= len(raw.encode("utf-8")) <= _MAX_BYTES:
            raise ModelRolePolicyDenied("Model role policy is invalid")
        try:
            document = json.loads(
                raw,
                object_pairs_hook=_unique_fields,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if (
                type(document) is not dict
                or set(document) != {"version", "roles"}
                or type(document["version"]) is not int
                or document["version"] != 1
                or type(document["roles"]) is not list
                or not 1 <= len(document["roles"]) <= _MAX_ENTRIES
            ):
                raise ValueError("Invalid policy header")
            roles = []
            seen = set()
            for entry in document["roles"]:
                if type(entry) is not dict or not {
                    "role",
                    "provider",
                    "model",
                    "mode",
                    "max_tokens",
                } <= set(entry):
                    raise ValueError("Invalid policy entry")
                role = entry["role"]
                provider = entry["provider"]
                model = entry["model"]
                mode = entry["mode"]
                limit = entry["max_tokens"]
                if (
                    type(role) is not str
                    or role not in {agent.value for agent in AgentType}
                    or type(mode) is not str
                    or mode not in _MODES
                    or type(provider) is not str
                    or provider != _MODES[mode]
                    or type(model) is not str
                    or not 1 <= len(model) <= 90
                    or not model.startswith(provider + "/")
                    or any(
                        char
                        not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:/-"
                        for char in model
                    )
                    or type(limit) is not int
                    or not 1 <= limit <= _MAX_OUTPUT_TOKENS
                    or (role, model) in seen
                ):
                    raise ValueError("Invalid policy provider/model/role")
                if mode == "openai_effort":
                    if (
                        set(entry) != {"role", "provider", "model", "mode", "max_tokens", "effort"}
                        or type(entry["effort"]) is not str
                        or entry["effort"] not in _EFFORTS
                    ):
                        raise ValueError("Invalid OpenAI reasoning declaration")
                    roles.append(
                        RoleReasoning(role, provider, model, mode, limit, effort=entry["effort"])
                    )
                else:
                    if (
                        set(entry)
                        != {"role", "provider", "model", "mode", "max_tokens", "thinking"}
                        or type(entry["thinking"]) is not bool
                    ):
                        raise ValueError("Invalid DeepSeek thinking declaration")
                    roles.append(
                        RoleReasoning(
                            role, provider, model, mode, limit, thinking=entry["thinking"]
                        )
                    )
                seen.add((role, model))
            return cls(tuple(roles))
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
            raise ModelRolePolicyDenied("Model role policy configuration is invalid") from exc

    async def outgoing_parameters(
        self,
        *,
        model: str,
        route: Optional[ProviderRoute],
        ledger: Any,
        engagement_id: str,
        task_id: str,
        max_tokens: Any,
    ) -> Dict[str, Any]:
        """Resolve role from authoritative PG Task after route preflight.

        Usage reserve subsequently rechecks signed ROE, task execution state,
        approvals, and budgets transactionally before any provider request.
        """
        if route is None:
            raise ModelRolePolicyDenied("Role reasoning requires a configured provider route")
        if route.model != model or "completion" not in route.operations:
            raise ModelRolePolicyDenied("Role reasoning route mismatch")
        relevant = tuple(entry for entry in self.roles if entry.model == model)
        if not relevant:
            return {}
        if any(entry.provider != route.provider for entry in relevant):
            raise ModelRolePolicyDenied("Role reasoning provider mismatch")
        memory = getattr(ledger, "session_memory", None)
        if not isinstance(memory, SessionMemory):
            raise ModelRolePolicyDenied("Durable role ownership is unavailable")
        try:
            task = await memory.load_task_authoritative(task_id)
        except Exception as exc:
            raise ModelRolePolicyDenied("Durable role lookup failed") from exc
        if (
            task is None
            or task.id != task_id
            or task.engagement_id != engagement_id
            or task.status not in {"running", "scheduled", "dispatching"}
            or not isinstance(task.agent_type, AgentType)
        ):
            raise ModelRolePolicyDenied("Executing task role is unverified")
        for entry in relevant:
            if entry.role == task.agent_type.value:
                return entry.options(max_tokens)
        return {}


def configured_model_role_policy() -> Optional[ModelRolePolicy]:
    return ModelRolePolicy.from_environment()
