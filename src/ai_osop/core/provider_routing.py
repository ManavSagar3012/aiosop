"""Explicit opt-in model dispatch allowlist, not provider-side verification.

Set OSOP_VERIFIED_PROVIDER_ROUTES_JSON to a JSON object:
{"version":1,"routes":[{"provider":"openai","model":"gpt-4o",
"operations":["completion"],"credential_env":"OPENAI_API_KEY"}]}

Like PentAGI's routing.go, an unchecked endpoint is not proof of a
callable/served model. This module does no network or billable probing.

An OPTIONAL version-2 configuration additionally requires exact role and
operator-declared capabilities, with signed-PostgreSQL budget provenance:
{"version":2,"routes":[{"provider":"openai","model":"openai/model-one",
"operations":["completion"],"credential_env":"OPENAI_API_KEY",
"allowed_roles":["vuln_analysis"],"capabilities":["text_completion","tool_calls"],
"max_output_tokens":4096,"budget_source":"signed_postgres_roe"}]}

Version-2 routes are intentionally not callable by the existing LiteLLM
dispatch path until an authoritative Task role is admitted using
`ProviderRoutes.authorize_task` (async context, see method contract). Even
that preflight NEVER proves the model is served, its tool-calling support, a
provider-native cost cap or a successful durable budget reservation. The
calling dispatch must still atomically reserve in ModelUsageLedger before
every provider call and treat ambiguous execution as UNKNOWN.
"""

import hashlib
import json
import ipaddress
import os
import re
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Optional, Tuple
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ai_osop.memory.model_usage import ModelBudgetExceeded


class ProviderRouteDenied(ModelBudgetExceeded):
    """Fail closed before model provider dispatch."""


class ProviderRouteUnavailable(ProviderRouteDenied):
    """Configured local deployment credentials are unavailable."""


_ROUTE_ENV = "OSOP_VERIFIED_PROVIDER_ROUTES_JSON"
_MAX_CONFIG_BYTES = 16384
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,89}\Z")
_PROVIDER_CREDENTIALS = {
    "openai": frozenset({"OPENAI_API_KEY", "OSOP_LLM_API_KEY"}),
    "anthropic": frozenset({"ANTHROPIC_API_KEY", "OSOP_LLM_API_KEY"}),
    "gemini": frozenset({"GEMINI_API_KEY", "GOOGLE_API_KEY"}),
    "deepseek": frozenset({"DEEPSEEK_API_KEY"}),
    "ollama": frozenset({""}),
}
_OPERATIONS = frozenset({"completion", "embedding"})
_CAPABILITIES = frozenset({"text_completion", "tool_calls", "json_mode", "reasoning", "embeddings"})
_BUDGET_SOURCE = "signed_postgres_roe"
_AUTHORIZED: ContextVar[Optional[tuple[str, str, str, str, str, str]]] = ContextVar(
    "osop_provider_capability_authorized_task", default=None
)


def _strict_object(pairs: list) -> dict:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProviderRouteDenied("Duplicate provider route configuration field")
        result[key] = value
    return result


def _safe_endpoint(value: Any) -> Optional[str]:
    if value is None:
        return None
    if type(value) is not str or not 1 <= len(value) <= 512 or value.strip() != value:
        raise ProviderRouteDenied("Provider route endpoint is invalid")
    try:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.query
            or url.fragment
            or url.port not in (None, 443)
            or not re.fullmatch(r"[A-Za-z0-9.-]+", url.hostname)
            or url.hostname.endswith(".")
            or url.hostname == "localhost"
            or url.hostname.endswith((".localhost", ".local", ".internal"))
        ):
            raise ValueError("Unsafe provider endpoint")
        try:
            ipaddress.ip_address(url.hostname)
        except ValueError:
            pass
        else:
            raise ValueError("Literal IP endpoints are not allowed")
    except (TypeError, ValueError) as exc:
        raise ProviderRouteDenied("Provider route endpoint is invalid") from exc
    return value


@dataclass(frozen=True)
class ProviderRoute:
    model: str
    provider: str
    operations: Tuple[str, ...]
    credential_env: str
    api_base: Optional[str]
    allowed_roles: Tuple[str, ...] = ()
    capabilities: Tuple[str, ...] = ()
    max_output_tokens: Optional[int] = None
    budget_source: Optional[str] = None

    def validate_deployment(self) -> str:
        if self.provider == "ollama":
            if self.credential_env != "" or self.api_base != "http://127.0.0.1:11434":
                raise ProviderRouteUnavailable("Configured local model deployment is unavailable")
            return ""
        credential = os.environ.get(self.credential_env)
        if (
            type(credential) is not str
            or not 8 <= len(credential) <= 4096
            or credential.strip() != credential
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in credential)
        ):
            raise ProviderRouteUnavailable("Configured model deployment is unavailable")
        return credential

    def provider_kwargs(self) -> Dict[str, Any]:
        # Never forward caller-owned credentials to a different provider.
        credential = self.validate_deployment()
        kwargs: Dict[str, Any] = {"num_retries": 0}
        if self.provider != "ollama":
            kwargs["api_key"] = credential
        else:
            # Bound the local KV cache; some installed models advertise a
            # context that exceeds ordinary workstation memory.
            kwargs["num_ctx"] = 4096
        if self.api_base is not None:
            kwargs["api_base"] = self.api_base
        return kwargs


@dataclass(frozen=True)
class ProviderRoutes:
    """Locally configured, bounded routes, not remotely verified models."""

    routes: Tuple[ProviderRoute, ...]
    version: int = 1
    policy_sha256: str = ""

    @classmethod
    def from_environment(cls) -> Optional["ProviderRoutes"]:
        raw = os.environ.get(_ROUTE_ENV)
        if raw is None:
            if _AUTHORIZED.get() is not None:
                # A policy disappearing mid-Task cannot silently turn an
                # already-admitted v2 call into unrestricted legacy routing.
                raise ProviderRouteDenied("Active trusted route policy was revoked")
            return None  # Backward-compatible until explicitly enabled.
        if (
            _AUTHORIZED.get() is not None
            and hashlib.sha256(raw.encode("utf-8")).hexdigest() != _AUTHORIZED.get()[0]
        ):
            raise ProviderRouteDenied("Active trusted route policy was replaced")
        if type(raw) is not str or not 0 < len(raw.encode("utf-8")) <= _MAX_CONFIG_BYTES:
            raise ProviderRouteDenied("Provider route configuration is missing or oversized")
        try:
            document = json.loads(
                raw,
                object_pairs_hook=_strict_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if (
                type(document) is not dict
                or frozenset(document) != {"version", "routes"}
                or type(document["version"]) is not int
                or document["version"] not in (1, 2)
                or type(document["routes"]) is not list
                or not 1 <= len(document["routes"]) <= 16
            ):
                raise ValueError("Invalid route header")
            version = document["version"]
            # Do not infer a role from an in-memory agent or supplied prompt.
            # Validate the allowlist against concrete persisted Task AgentTypes.
            if version == 2:
                from ai_osop.core.config import AgentType

                allowed_agent_roles = frozenset(agent.value for agent in AgentType)
            found = []
            distinct = set()
            for item in document["routes"]:
                if (
                    type(item) is not dict
                    or not {"provider", "model", "operations", "credential_env"} <= frozenset(item)
                    or not frozenset(item)
                    <= (
                        {
                            "provider",
                            "model",
                            "operations",
                            "credential_env",
                            "api_base",
                        }
                        if version == 1
                        else {
                            "provider",
                            "model",
                            "operations",
                            "credential_env",
                            "api_base",
                            "allowed_roles",
                            "capabilities",
                            "max_output_tokens",
                            "budget_source",
                        }
                    )
                ):
                    raise ValueError("Invalid route fields")
                provider = item["provider"]
                model = item["model"]
                env = item["credential_env"]
                operations = item["operations"]
                roles = item.get("allowed_roles")
                capabilities = item.get("capabilities")
                max_output = item.get("max_output_tokens")
                budget_source = item.get("budget_source")
                if (
                    type(provider) is not str
                    or provider not in _PROVIDER_CREDENTIALS
                    or type(model) is not str
                    or not _LABEL.fullmatch(model)
                    or any(part in ("", ".", "..") for part in model.split("/"))
                    or type(env) is not str
                    or env not in _PROVIDER_CREDENTIALS[provider]
                    or type(operations) is not list
                    or not 1 <= len(operations) <= 2
                    or not all(type(op) is str and op in _OPERATIONS for op in operations)
                    or len(set(operations)) != len(operations)
                    or ("/" in model and model.split("/", 1)[0] != provider)
                    or ("/" not in model and provider != "openai")
                    or (provider == "ollama" and item.get("api_base") != "http://127.0.0.1:11434")
                    or model in distinct
                ):
                    raise ValueError("Invalid or duplicate route declaration")
                if version == 2 and (
                    not {
                        "allowed_roles",
                        "capabilities",
                        "max_output_tokens",
                        "budget_source",
                    }
                    <= set(item)
                    or type(roles) is not list
                    or not 1 <= len(roles) <= 24
                    or any(
                        type(role) is not str or role not in allowed_agent_roles for role in roles
                    )
                    or len(set(roles)) != len(roles)
                    or type(capabilities) is not list
                    or not 1 <= len(capabilities) <= len(_CAPABILITIES)
                    or any(type(cap) is not str or cap not in _CAPABILITIES for cap in capabilities)
                    or len(set(capabilities)) != len(capabilities)
                    or ("completion" in operations and "text_completion" not in capabilities)
                    or ("embedding" in operations and "embeddings" not in capabilities)
                    or ("embedding" not in operations and "embeddings" in capabilities)
                    or (
                        "completion" not in operations
                        and any(
                            cap in capabilities
                            for cap in ("text_completion", "tool_calls", "json_mode", "reasoning")
                        )
                    )
                    or type(max_output) is not int
                    or not 1 <= max_output <= 16384
                    or budget_source != _BUDGET_SOURCE
                ):
                    raise ValueError("Invalid trusted model capability/role/budget declaration")
                distinct.add(model)
                found.append(
                    ProviderRoute(
                        model=model,
                        provider=provider,
                        operations=tuple(operations),
                        credential_env=env,
                        api_base=(
                            "http://127.0.0.1:11434"
                            if provider == "ollama"
                            else _safe_endpoint(item.get("api_base"))
                        ),
                        allowed_roles=tuple(roles or ()),
                        capabilities=tuple(capabilities or ()),
                        max_output_tokens=max_output,
                        budget_source=budget_source,
                    )
                )
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            return cls(tuple(found), version=version, policy_sha256=digest)
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            raise ProviderRouteDenied("Provider route configuration is invalid") from exc

    def resolve(self, model: str, operation: str) -> ProviderRoute:
        if type(model) is not str or type(operation) is not str:
            raise ProviderRouteDenied("Configured provider route is not permitted")
        for route in self.routes:
            if route.model == model and operation in route.operations:
                if self.version == 2:
                    # Existing LiteLLM calls must FAIL CLOSED until the prime
                    # integrates the authoritative async Task admission scope.
                    # No role from a model/user kwargs can authorize this.
                    from ai_osop.core.telemetry import RequestContext

                    context = RequestContext.get()
                    assertion = _AUTHORIZED.get()
                    if (
                        assertion is None
                        or assertion[:3] != (self.policy_sha256, model, operation)
                        or assertion[3] != context.get("engagement_id")
                        or assertion[4] != context.get("task_id")
                        or assertion[5] not in route.allowed_roles
                        or hashlib.sha256(
                            os.environ.get(_ROUTE_ENV, "").encode("utf-8")
                        ).hexdigest()
                        != self.policy_sha256
                    ):
                        raise ProviderRouteDenied(
                            "Authoritative capability and Task role admission required"
                        )
                return route
        raise ProviderRouteDenied("Configured provider route is not permitted")

    @asynccontextmanager
    async def authorize_task(
        self,
        *,
        model: str,
        operation: str,
        ledger: Any,
        engagement_id: str,
        task_id: str,
        required_capabilities: Tuple[str, ...],
        max_output_tokens: Optional[int] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """Preflight operator role and capabilities from the authoritative Task.

        Example (PRIME must integrate around *all* complete and embedding
        resolve/provider-dispatch paths):
            async with routes.authorize_task(
                model=model, operation=operation, ledger=usage_store,
                engagement_id=context["engagement_id"],
                task_id=context["task_id"],
                required_capabilities=("text_completion", "tool_calls"),
                max_output_tokens=4096,
            ) as status:
                # routing via routes.resolve / LiteLLMClient._provider_call
                # STILL MUST call usage_store.reserve(...) before any network.

        Never attest remote model support or reserve budget here. The Task
        identity is read from warm PostgreSQL, and the same guarded SQL
        transaction independently checks the current signed ROE, running Flow
        revision and live dispatched lease. Lease owner/ID are read from the
        source PostgreSQL row and must both be present; no caller-supplied
        lease attestation is accepted.

        CRITICAL: This read-side transaction closes BEFORE dispatch, so the
        separate ModelUsageLedger.reserve transaction MUST independently
        recheck current running/lease/Flow state immediately before network.
        This preflight alone never certifies a future provider dispatch.
        """
        if self.version != 2:
            raise ProviderRouteDenied("Trusted model admission requires v2 policy")
        from ai_osop.core.config import AgentType
        from ai_osop.core.telemetry import RequestContext
        from ai_osop.memory.session_memory import ExecutionFlowORM, SessionMemory
        from ai_osop.memory.model_usage import ModelUsageLedger
        from ai_osop.memory.supervision_store import SupervisionExecutionLeaseORM

        routes = tuple(
            entry for entry in self.routes if entry.model == model and operation in entry.operations
        )
        if len(routes) != 1:
            raise ProviderRouteDenied("Trusted model capability route not allowlisted")
        route = routes[0]
        if (
            type(engagement_id) is not str
            or not re.fullmatch(r"eng-[A-Za-z0-9._:-]{1,60}", engagement_id)
            or type(task_id) is not str
            or not re.fullmatch(r"task-[A-Za-z0-9._:-]{1,59}", task_id)
            or type(required_capabilities) is not tuple
            or not required_capabilities
            or any(
                type(capability) is not str or capability not in _CAPABILITIES
                for capability in required_capabilities
            )
            or len(set(required_capabilities)) != len(required_capabilities)
            or set(required_capabilities) != set(route.capabilities)
            or (
                operation == "completion"
                and (
                    "text_completion" not in required_capabilities
                    or type(max_output_tokens) is not int
                    or not 1 <= max_output_tokens <= route.max_output_tokens
                )
            )
            or (
                operation == "embedding"
                and ("embeddings" not in required_capabilities or max_output_tokens is not None)
            )
            or route.budget_source != _BUDGET_SOURCE
            or not callable(getattr(ledger, "reserve", None))
            or not callable(getattr(ledger, "settle", None))
            or not isinstance(getattr(ledger, "session_memory", None), SessionMemory)
            or not isinstance(ledger, ModelUsageLedger)
            or RequestContext.get().get("engagement_id") != engagement_id
            or RequestContext.get().get("task_id") != task_id
            or hashlib.sha256(os.environ.get(_ROUTE_ENV, "").encode("utf-8")).hexdigest()
            != self.policy_sha256
        ):
            raise ProviderRouteDenied("Trusted model capabilities or durable budget source UNKNOWN")
        try:
            task = await ledger.session_memory.load_task_authoritative(task_id)
        except Exception as exc:
            raise ProviderRouteDenied("Authoritative Task role observation unavailable") from exc
        if (
            task is None
            or task.id != task_id
            or task.engagement_id != engagement_id
            or task.status != "running"
            or not isinstance(task.agent_type, AgentType)
            or task.agent_type.value not in route.allowed_roles
            or not isinstance(task.assigned_agent_id, str)
            or not task.assigned_agent_id
            or not isinstance(task.started_at, datetime)
            or task.completed_at is not None
            or not isinstance(task.flow_id, str)
            or not re.fullmatch(r"flow-[A-Za-z0-9._:-]{1,59}", task.flow_id)
            or not isinstance(task.payload, dict)
            or type(task.payload.get("_authorization_version")) is not int
            or task.payload["_authorization_version"] <= 0
        ):
            raise ProviderRouteDenied("Claimed RUNNING Task role and signed source required")
        flow_revision = task.payload.get(
            "planner_flow_revision", task.payload.get("_flow_revision")
        )
        if type(flow_revision) is not int or flow_revision < 0:
            raise ProviderRouteDenied("Task has no pinned signed Flow revision")

        # load_task_authoritative is deliberately only a first gate: it uses
        # its own PostgreSQL snapshot and cannot attest lease/ROE continuity.
        # Read Task, Flow and execution lease behind the real signed ledger
        # guard IN ONE SQL transaction; do not trust caller-supplied status.
        try:
            async with ledger._sessions() as db:
                if not isinstance(db, AsyncSession):
                    raise ProviderRouteDenied("Authoritative PostgreSQL session required")
                async with db.begin():
                    engagement, locked = await ModelUsageLedger._guard(
                        db, engagement_id, task_id, require_window=True
                    )
                    if (
                        engagement is None
                        or locked is None
                        or locked.id != task_id
                        or locked.engagement_id != engagement_id
                        or locked.status != "running"
                        or locked.agent_type != task.agent_type.value
                        or locked.assigned_agent_id != task.assigned_agent_id
                        or locked.started_at != task.started_at
                        or locked.completed_at is not None
                        or locked.flow_id != task.flow_id
                        or locked.payload != task.payload
                    ):
                        raise ProviderRouteDenied("Current claimed Task has changed")
                    flow = (
                        await db.execute(
                            select(ExecutionFlowORM)
                            .where(
                                ExecutionFlowORM.id == task.flow_id,
                                ExecutionFlowORM.engagement_id == engagement_id,
                            )
                            .with_for_update(read=True)
                        )
                    ).scalar_one_or_none()
                    if (
                        flow is None
                        or flow.status != "running"
                        or type(flow.revision) is not int
                        or flow.revision != flow_revision
                    ):
                        raise ProviderRouteDenied("Signed Flow has stopped or changed")
                    active_lease = (
                        await db.execute(
                            select(SupervisionExecutionLeaseORM)
                            .where(
                                SupervisionExecutionLeaseORM.engagement_id == engagement_id,
                                SupervisionExecutionLeaseORM.task_id == task_id,
                            )
                            .with_for_update(read=True)
                        )
                    ).scalar_one_or_none()
                    if (
                        active_lease is None
                        or active_lease.state != "dispatched"
                        or type(active_lease.owner_id) is not str
                        or not re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", active_lease.owner_id
                        )
                        or type(active_lease.lease_id) is not str
                        or not re.fullmatch(r"lease-[A-Za-z0-9._:-]{1,58}", active_lease.lease_id)
                        or not isinstance(active_lease.expires_at, datetime)
                        or active_lease.expires_at <= datetime.utcnow()
                    ):
                        raise ProviderRouteDenied("Live dispatched execution lease unavailable")
        except ProviderRouteDenied:
            raise
        except Exception as exc:
            raise ProviderRouteDenied(
                "Current signed Task/Flow/ROE/lease verification unavailable"
            ) from exc
        token = _AUTHORIZED.set(
            (self.policy_sha256, model, operation, engagement_id, task_id, task.agent_type.value)
        )
        try:
            yield {
                "model": model,
                "provider": route.provider,
                "operation": operation,
                "authoritative_task_role": task.agent_type.value,
                "claimed_task_state": "running",
                "current_flow_revision": flow_revision,
                "lease_observation": "dispatched_at_preflight_only",
                "signed_roe_observation": "current_at_preflight_only",
                "capabilities": list(required_capabilities),
                "capability_provenance": "operator_declared_not_provider_verified",
                "provider_served_model_verified": False,
                "provider_capability_verified": False,
                "provider_native_cost_ceiling_verified": False,
                "budget_source": _BUDGET_SOURCE,
                "budget_state": "signed_postgres_lease_fenced_reservation_still_required",
            }
        finally:
            _AUTHORIZED.reset(token)

    def capability_report(self) -> list[dict]:
        """List configured routes, with TTL-bounded source proof if opted in."""
        from ai_osop.core.provider_capability_discovery import catalog_mode, configured_catalog

        catalog = configured_catalog()
        result = []
        for route in self.routes:
            try:
                route.validate_deployment()
                status = "locally_configured"
            except ProviderRouteUnavailable:
                status = "unavailable"
            entry = {
                "model": route.model,
                "provider": route.provider,
                "operations": list(route.operations),
                "deployment": status,
                "provider_catalog_verified": False,
                "provider_native_cost_ceiling_verified": False,
            }
            if self.version == 2:
                entry.update(
                    {
                        "configured_capabilities": list(route.capabilities),
                        "allowed_roles": list(route.allowed_roles),
                        "capability_provenance": "operator_declared_not_provider_verified",
                        "provider_served_model_verified": False,
                        "provider_capability_verified": False,
                        "budget_source": route.budget_source,
                        "budget_state": "signed_postgres_reservation_still_required",
                    }
                )
            if catalog_mode() == "enforce":
                entry.update(catalog.status(route))
                entry["provider_currently_available_verified"] = False
            result.append(entry)
        return result


def configured_routes() -> Optional[ProviderRoutes]:
    """Always re-read locally configured routes; do not imply signed policy."""
    return ProviderRoutes.from_environment()
