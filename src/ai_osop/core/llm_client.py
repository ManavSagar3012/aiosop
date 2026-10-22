"""
LiteLLM Client
Standardized interface for LLM completions and embeddings with fallback routing.
"""

import asyncio
import hashlib
import json
import math
import re
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

import httpx
import litellm
import structlog

from ai_osop.core.config import settings
from ai_osop.core.embedding_bounds import verify_embedding_request
from ai_osop.core.model_role_policy import (
    configured_model_role_policy,
    reject_caller_reasoning_overrides,
)
from ai_osop.core.provider_routing import (
    ProviderRouteDenied,
    ProviderRouteUnavailable,
    configured_routes,
)
from ai_osop.core.provider_capability_discovery import (
    ProviderCatalogModelAbsent,
    catalog_mode,
    configured_catalog,
)
from ai_osop.core.call_provenance import (
    BestEffortProvenance,
    ProvenanceCallback,
    action_provenance,
    provider_usage,
    safe_label,
)
from ai_osop.safety.prompt_defense import sanitize_messages
from ai_osop.core.telemetry import RequestContext
from ai_osop.memory.model_usage import ModelBudgetExceeded, ModelOutcomeUncertain
from ai_osop.core.provider_credential_dispatch_guard import (
    DispatchBinding,
    ProviderCredentialDispatchGuard,
)

llm_logger = structlog.get_logger("ai_osop.llm")


def _vault_route_deployment_sha256(route: Any) -> str:
    """Hash the exact configured, nonsecret deployment identity; never a key."""
    body = {
        "provider": route.provider,
        "model": route.model,
        "operations": list(route.operations),
        "credential_env": route.credential_env,
        "api_base": route.api_base,
        "allowed_roles": list(route.allowed_roles),
        "capabilities": list(route.capabilities),
        "max_output_tokens": route.max_output_tokens,
        "budget_source": route.budget_source,
    }
    return hashlib.sha256(
        b"ai-osop-provider-runtime-route-v1\x00"
        + json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    ).hexdigest()


async def _local_ollama_embedding(model: str, input_texts: List[str]) -> Dict[str, Any]:
    """Request the existing 1536-dimensional vector format from loopback Ollama."""
    if not model.startswith("ollama/"):
        raise ProviderRouteDenied("Local embedding model is invalid")
    async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=120.0) as client:
        async with client.stream(
            "POST",
            "http://127.0.0.1:11434/api/embed",
            json={
                "model": model.split("/", 1)[1],
                "input": input_texts,
                "dimensions": 1536,
                "options": {"num_ctx": 4096},
            },
        ) as result:
            result.raise_for_status()
            body = bytearray()
            async for chunk in result.aiter_bytes():
                if len(body) + len(chunk) > 1024 * 1024:
                    raise ValueError("Local embedding response exceeds bound")
                body.extend(chunk)
    data = json.loads(body)
    vectors = data.get("embeddings") if isinstance(data, dict) else None
    if (
        not isinstance(vectors, list)
        or len(vectors) != len(input_texts)
        or any(
            not isinstance(vector, list)
            or len(vector) != 1536
            or not any(element != 0 for element in vector)
            or any(
                type(element) not in (int, float) or not math.isfinite(element)
                for element in vector
            )
            for vector in vectors
        )
    ):
        raise ValueError("Local embedding response has invalid dimensions")
    return {
        "data": [{"embedding": vector} for vector in vectors],
        "usage": {"prompt_tokens": data.get("prompt_eval_count")},
    }


class LiteLLMClient:
    """
    LiteLLM-backed reasoning client for context-aware generation and
    semantic embedding generation.
    """

    def __init__(
        self,
        primary_model: Optional[str] = None,
        fallback_model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        provenance_callback: Optional[ProvenanceCallback] = None,
        usage_store: Optional[Any] = None,
        *,
        vault_guard_required: bool = False,
        vault_guard: Optional[ProviderCredentialDispatchGuard] = None,
        vault_binding_factory: Optional[
            Callable[[str, str, str, str, Any, str], Awaitable[DispatchBinding]]
        ] = None,
    ):
        if type(vault_guard_required) is not bool or (
            not vault_guard_required
            and (vault_guard is not None or vault_binding_factory is not None)
        ):
            raise ValueError("Protected host-only vault dispatch configuration is invalid")
        self.primary_model = primary_model or settings.llm_primary_model
        self.fallback_model = fallback_model or settings.llm_fallback_model
        self.temperature = temperature if temperature is not None else settings.llm_temperature
        self.max_tokens = max_tokens or settings.llm_max_tokens
        self._provenance_recorder = BestEffortProvenance(provenance_callback)
        self._usage_store = usage_store
        # Only the host constructing this client can select this mode. None
        # means deliberately unconfigured: required mode DENIES all paid calls
        # rather than accepting a symbolic readiness flag or an API override.
        # Existing installations are unchanged unless explicitly opted in.
        self._vault_guard_required = vault_guard_required
        self._vault_guard = vault_guard
        self._vault_binding_factory = vault_binding_factory

    def set_usage_store(self, store: Any) -> None:
        """Bind authoritative PostgreSQL budget and settlement persistence."""
        if (
            store is None
            or not callable(getattr(store, "reserve", None))
            or not callable(getattr(store, "settle", None))
        ):
            raise ValueError(
                "A durable model usage ledger with admission and settlement is required"
            )
        if self._usage_store is not None and self._usage_store is not store:
            raise RuntimeError("Model usage ledger cannot be replaced after binding")
        self._usage_store = store

    def set_provenance_callback(self, callback: Optional[ProvenanceCallback]) -> None:
        """Attach an asynchronous action-persistence sink."""
        self._provenance_recorder.set_callback(callback)

    async def drain_provenance(self) -> None:
        """Flush already scheduled provenance writes on orderly shutdown."""
        await self._provenance_recorder.drain()

    async def _provider_call(
        self,
        operation: str,
        model: str,
        attempt: int,
        *,
        fallback_used: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Enter opt-in v2 authoritative Task+role admission before precharge.

        No caller-provided role or requested capability can grant itself:
        capability declarations come only from the operator's locally pinned
        route; Task identity and role come from the durable SessionMemory.
        This is NOT evidence that the provider truly serves the model.
        """
        routes = configured_routes()
        if getattr(self, "_vault_guard_required", False) and (
            routes is None
            or routes.version != 2
            or type(self._vault_guard) is not ProviderCredentialDispatchGuard
            or not callable(self._vault_binding_factory)
        ):
            raise ModelBudgetExceeded("Required host vault dispatch authority unavailable")
        if routes is None or routes.version != 2:
            return await self._provider_call_admitted(
                operation, model, attempt, fallback_used=fallback_used, **kwargs
            )
        matches = [
            candidate
            for candidate in routes.routes
            if candidate.model == model and operation in candidate.operations
        ]
        if len(matches) != 1:
            raise ProviderRouteDenied("Trusted provider model/operation was not declared")
        route = matches[0]
        if operation == "completion":
            max_output = kwargs.get("max_tokens")
            if type(max_output) is not int or not 1 <= max_output <= route.max_output_tokens:
                raise ProviderRouteDenied(
                    "Trusted Task output limit exceeds declared model capabilities"
                )
            if kwargs.get("tools") and "tool_calls" not in route.capabilities:
                raise ProviderRouteDenied("Tool-capable model deployment was not declared")
            if kwargs.get("response_format") and "json_mode" not in route.capabilities:
                raise ProviderRouteDenied("JSON-capable model deployment was not declared")
        elif operation == "embedding":
            max_output = None
        else:
            raise ProviderRouteDenied("Trusted provider operation is unsupported")
        usage_store = self._usage_store
        context = RequestContext.get()
        async with routes.authorize_task(
            model=model,
            operation=operation,
            ledger=usage_store,
            engagement_id=context.get("engagement_id"),
            task_id=context.get("task_id"),
            required_capabilities=tuple(route.capabilities),
            max_output_tokens=max_output,
        ):
            # _provider_call_admitted re-resolves this exact route under the
            # ContextVar and rechecks policy digest and signed PG reservation.
            # Remote uncertainty still prevents fallback/automatic replay.
            return await self._provider_call_admitted(
                operation, model, attempt, fallback_used=fallback_used, **kwargs
            )

    async def _provider_call_admitted(
        self,
        operation: str,
        model: str,
        attempt: int,
        *,
        fallback_used: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Record each provider attempt without request or response content."""
        if operation == "embedding":
            # This is the single provider dispatch boundary. Avoid a bypass
            # through direct internal _provider_call before cost reservation.
            verify_embedding_request(kwargs.get("input"))
        elif operation == "completion":
            # Neither prompts nor direct callers may select their own
            # reasoning mode, thinking budget or hidden retry body.
            reject_caller_reasoning_overrides(kwargs)
        routes = configured_routes()
        route = None
        guarded = getattr(self, "_vault_guard_required", False)
        if guarded and (
            routes is None
            or routes.version != 2
            or type(self._vault_guard) is not ProviderCredentialDispatchGuard
            or not callable(self._vault_binding_factory)
        ):
            raise ModelBudgetExceeded("Required host vault dispatch authority unavailable")
        if routes is not None:
            # Even direct _provider_call and embedding calls obey the same
            # allowlist. No caller-provided LiteLLM key/base/fallback can
            # silently override the selected model's configured deployment.
            blocked = {
                "api_key",
                "api_base",
                "api_version",
                "api_type",
                "base_url",
                "api_endpoint",
                "custom_llm_provider",
                "http_client",
                "client_session",
                "organization",
                "azure_ad_token",
                "headers",
                "extra_headers",
                "custom_headers",
                "extra_body",
                "num_retries",
                "max_retries",
                "retry_policy",
                "fallbacks",
                "context_window_fallbacks",
                "model_list",
                "mock_response",
                "deployment_id",
                "vault_guard",
                "vault_guard_required",
                "vault_binding_factory",
                "vault_dispatch_binding",
                "vault_dispatch_permit",
            }
            if blocked.intersection(kwargs):
                raise ProviderRouteDenied("Caller may not override provider routing")
            route = routes.resolve(model, operation)
            if guarded and route is None:
                raise ModelBudgetExceeded("Required guarded provider route unavailable")
            if not guarded:
                kwargs.update(route.provider_kwargs())
        started = time.monotonic()
        response: Any = None
        outcome = "error"
        error_class: Optional[str] = None
        call_id: Optional[str] = None
        engagement_id: Optional[str] = None
        persisted_usage = False
        # Fail closed for every production call path, including ad hoc clients
        # created outside FastAPI and background/planner workers. No provider
        # request is allowed to bypass durable admission merely because the
        # ledger was never wired.
        usage_store = self._usage_store
        if (
            usage_store is None
            or not callable(getattr(usage_store, "reserve", None))
            or not callable(getattr(usage_store, "settle", None))
        ):
            raise ModelBudgetExceeded("Durable model usage admission is not configured")
        context = RequestContext.get()
        engagement_id = context.get("engagement_id")
        task_id = context.get("task_id")
        if (
            not isinstance(engagement_id, str)
            or not engagement_id
            or engagement_id == "api-bootstrap"
            or not isinstance(task_id, str)
            or not task_id
        ):
            raise ModelBudgetExceeded("Provider calls require a persisted engagement and task")
        if operation == "completion":
            policy = configured_model_role_policy()
            if policy is not None:
                # Durable TaskORM.agent_type, not any caller/LLM message,
                # determines the provider-specific role configuration. The
                # signed PG reservation below remains the dispatch gate.
                reasoning = await policy.outgoing_parameters(
                    model=model,
                    route=route,
                    ledger=usage_store,
                    engagement_id=engagement_id,
                    task_id=task_id,
                    max_tokens=kwargs.get("max_tokens"),
                )
                if reasoning:
                    if "reasoning_effort" in reasoning:
                        # Explicitly configured reasoning models may reject
                        # temperature. Do not invent a provider capability:
                        # the operator chose this exact local route/model.
                        kwargs.pop("temperature", None)
                    kwargs.update(reasoning)
        # Catalog discovery is a non-billable, immutable pre-dispatch gate.
        # It can only attest that the route's model ID was listed recently.
        # Run BEFORE signed PostgreSQL precharge; no provider model request is
        # sent on stale/failed/absent listings and never retry after a send.
        require_catalog = catalog_mode() == "enforce"
        if require_catalog and not guarded:
            if route is None:
                raise ProviderRouteDenied("Verified catalog requires explicit routes")
            await configured_catalog().verify(route, credential=kwargs.get("api_key"))
        try:
            call_id = await usage_store.reserve(engagement_id, task_id, model, operation)
        except ModelBudgetExceeded:
            raise
        except Exception as exc:
            # Admission never reached the provider. It is unsafe to mask a
            # database timeout as a normal model error eligible for fallback.
            raise ModelBudgetExceeded("Durable model usage admission is unavailable") from exc
        if (
            not isinstance(call_id, str)
            or not re.fullmatch(r"call-[A-Za-z0-9_-]{1,59}", call_id)
            or len(call_id) > 64
        ):
            raise ModelBudgetExceeded("Model usage admission returned no durable reservation")

        async def settle(delivered: bool) -> None:
            nonlocal persisted_usage
            if call_id is None or engagement_id is None:
                return
            try:
                receipt = await usage_store.settle(
                    call_id, engagement_id, response, delivered=delivered
                )
                if receipt is not True:
                    raise ModelOutcomeUncertain("Provider usage settlement was not accepted")
                persisted_usage = True
            except ModelOutcomeUncertain:
                raise
            except Exception as exc:
                raise ModelOutcomeUncertain("Provider call outcome could not be persisted") from exc

        guard_permit = None
        if guarded:
            # This occurs ONLY after the real durable ledger.reserve and
            # before reading any environment provider key. No public model
            # request may supply a guard, roots, proof, or trusted binding.
            try:
                assert route is not None
                binding = await asyncio.wait_for(
                    self._vault_binding_factory(
                        engagement_id, task_id, model, operation, route, call_id
                    ),
                    timeout=2.0,
                )
                if type(binding) is not DispatchBinding:
                    raise ValueError("Host dispatch binding unavailable")
                observed = binding.readiness_request
                if (
                    binding.call_id != call_id
                    or observed.engagement_id != engagement_id
                    or observed.task_id != task_id
                    or observed.model != model
                    or observed.operation != operation
                    or observed.provider != route.provider
                    or observed.agent_role not in route.allowed_roles
                    or binding.route_policy_sha256 != routes.policy_sha256
                    or binding.route_deployment_sha256 != _vault_route_deployment_sha256(route)
                ):
                    raise ValueError("Host dispatch binding does not match pinned Task and route")
                guard_permit = await self._vault_guard.authorize_reserved(binding)
                # The host-protected current runtime-key attestation is
                # required BEFORE accessing the environment credential.
                kwargs.update(route.provider_kwargs())
                if require_catalog:
                    await configured_catalog().verify(route, credential=kwargs.get("api_key"))
            except asyncio.CancelledError:
                # The reservation exists and may be reported UNKNOWN; do not
                # retry a denied, cancelled or ambiguous postcommit attempt.
                await settle(False)
                raise
            except Exception:
                await settle(False)
                raise ModelOutcomeUncertain(
                    "Guarded provider dispatch was not authorized; reserved call is unknown"
                ) from None

        try:
            if guarded:
                # A permit is an ephemeral one-shot acknowledgment, NOT
                # proof the remote provider will accept or execute this key.
                # Consumption is immediately before the only outbound send.
                await self._vault_guard.consume_for_send(guard_permit)
            if operation == "embedding":
                response = (
                    await _local_ollama_embedding(model, kwargs["input"])
                    if route is not None and route.provider == "ollama"
                    else await litellm.aembedding(model=model, **kwargs)
                )
            else:
                response = await litellm.acompletion(model=model, **kwargs)
            outcome = "success"
            await settle(True)
            return response
        except asyncio.CancelledError:
            outcome = "cancelled"
            error_class = "CancelledError"
            await settle(False)
            raise
        except Exception as exc:
            error_class = type(exc).__name__
            if isinstance(exc, ModelOutcomeUncertain):
                outcome = "unknown"
            if not isinstance(exc, ModelOutcomeUncertain):
                await settle(False)
                if call_id is not None:
                    # The provider might have accepted and billed the
                    # request before the connection was lost. Do not send a
                    # second fallback call until that receipt is reconciled.
                    raise ModelOutcomeUncertain(
                        "Provider request may have executed; usage is unknown"
                    ) from exc
            raise
        finally:
            try:
                from ai_osop.core.observability import (
                    record_engagement_cost,
                    record_llm_call,
                )

                usage = provider_usage(response)
                billed = usage["billed_cost_usd"] if persisted_usage else None
                label = safe_label(model)
                record_llm_call(
                    label,
                    operation,
                    tokens_input=usage["input_tokens"] or 0,
                    tokens_output=usage["output_tokens"] or 0,
                    cost_usd=billed,
                )
                action = action_provenance(
                    f"llm.{operation}",
                    outcome,
                    int((time.monotonic() - started) * 1000),
                    safe_metadata={
                        "provider": label.split("/")[0] if "/" in label else "unknown",
                        "model": label,
                        "attempt": attempt,
                        "fallback_used": fallback_used,
                        "error_class": error_class,
                        **{
                            **usage,
                            "billed_cost_usd": billed,
                            "cost_source": (
                                usage["cost_source"] if billed is not None else "unavailable"
                            ),
                        },
                    },
                )
                if billed is not None and action["engagement_id"] is not None:
                    record_engagement_cost(action["engagement_id"], billed)
                self._provenance_recorder.submit(action)
            except Exception:
                llm_logger.warning("llm_usage_provenance_failed")

    async def complete(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Return assistant text, retrying with the fallback model on failure."""

        safe_messages = sanitize_messages(messages)

        if settings.mock_llm:
            target = "unknown"
            for m in safe_messages:
                if m["role"] == "user":
                    target = m["content"][:100]
            return f"[MOCK REASONING] Analyzing context for {target}. Recommended approach: Adaptive payload mutation using semantic memory."

        selected_model = model or self.primary_model
        timeout = kwargs.pop("timeout", settings.llm_completion_timeout)
        routes = configured_routes()
        preflight_fallback = False
        require_catalog = catalog_mode() == "enforce"
        if getattr(self, "_vault_guard_required", False) and (
            routes is None or routes.version != 2
        ):
            raise ModelBudgetExceeded("Required guarded provider route unavailable")
        if require_catalog:
            # Opt-in discovery must not open external connections in a process
            # without an authoritative ledger and executing task context.
            ledger = self._usage_store
            context = RequestContext.get()
            if (
                ledger is None
                or not callable(getattr(ledger, "reserve", None))
                or not callable(getattr(ledger, "settle", None))
                or not isinstance(context.get("engagement_id"), str)
                or not context["engagement_id"]
                or context["engagement_id"] == "api-bootstrap"
                or not isinstance(context.get("task_id"), str)
                or not context["task_id"]
            ):
                raise ModelBudgetExceeded(
                    "Verified provider catalog requires durable task admission"
                )
        if require_catalog and routes is None:
            raise ProviderRouteDenied("Verified catalog requires explicit routes")
        if routes is not None and routes.version == 2:
            # v2 preflight is within the PG-authoritative Task admission in
            # _provider_call. Do not resolve a model before that async gate or
            # silently select a second model outside the human-selected route.
            if not any(
                r.model == selected_model and "completion" in r.operations for r in routes.routes
            ):
                raise ProviderRouteDenied("Operator-configured model not allowlisted")
        elif routes is not None:
            # A fallback is allowed ONLY for an operator-configured local
            # deployment that fails preflight without sending any provider
            # request. Any provider exception is UNKNOWN and must not retry.
            try:
                primary_route = routes.resolve(selected_model, "completion")
                primary_key = primary_route.validate_deployment()
                if require_catalog:
                    await configured_catalog().verify(primary_route, credential=primary_key)
            except (ProviderRouteUnavailable, ProviderCatalogModelAbsent):
                if model is not None or selected_model == self.fallback_model:
                    raise
                fallback_route = routes.resolve(self.fallback_model, "completion")
                fallback_key = fallback_route.validate_deployment()
                if require_catalog:
                    await configured_catalog().verify(fallback_route, credential=fallback_key)
                selected_model = self.fallback_model
                preflight_fallback = True
        # Route anthropic/* models at the configured Anthropic-compatible
        # endpoint (self-hosted model behind a tunnel). Fallback model is
        # rebuilt fresh below so it never inherits the anthropic creds.
        if routes is None and selected_model.startswith("anthropic/"):
            if settings.llm_api_base:
                kwargs.setdefault("api_base", settings.llm_api_base)
            if settings.llm_api_key:
                kwargs.setdefault("api_key", settings.llm_api_key)
        try:
            response = await self._provider_call(
                "completion",
                model=selected_model,
                attempt=1,
                fallback_used=preflight_fallback,
                messages=safe_messages,
                temperature=kwargs.pop("temperature", self.temperature),
                max_tokens=kwargs.pop("max_tokens", self.max_tokens),
                timeout=timeout,
                **kwargs,
            )
        except (ModelBudgetExceeded, ModelOutcomeUncertain):
            # A budget refusal or ambiguous already-submitted call may not be
            # circumvented by a second provider/fallback request.
            raise
        except Exception:
            if getattr(self, "_vault_guard_required", False):
                # Any failure in guarded mode is a hard stop. In particular
                # missing host signer, rotation/revocation or lost ACK must
                # never trigger a second model or provider credential.
                raise
            response = await self._provider_call(
                "completion",
                model=self.fallback_model,
                attempt=2,
                fallback_used=True,
                messages=safe_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                timeout=timeout,
            )

        try:
            return response.choices[0].message.content or ""
        except (AttributeError, IndexError, KeyError, TypeError) as exc:
            # A provider was already called and its receipt settled. Invalid
            # output is not permission to send another paid request.
            raise ModelOutcomeUncertain("Provider returned an unusable completion") from exc

    async def get_embedding(self, text: str, model: Optional[str] = None) -> List[float]:
        """Generate a semantic embedding for a piece of text."""
        verify_embedding_request([text])
        if settings.mock_llm:
            # Return a deterministic mock embedding
            return [0.1] * 1536

        try:
            response = await self._provider_call(
                "embedding", model=model or settings.llm_embedding_model, attempt=1, input=[text]
            )
            return response["data"][0]["embedding"]
        except (ModelBudgetExceeded, ModelOutcomeUncertain):
            # A refused/ambiguous provider call cannot safely be represented
            # as a genuine semantic vector of zeros. That would poison
            # retrieval while hiding the execution and billing uncertainty.
            raise
        except Exception as e:
            # Malformed results after a real provider response must remain
            # observable errors; a fabricated zero vector corrupts retrieval.
            llm_logger.error("embedding_generation_failed", error_type=type(e).__name__)
            raise ModelOutcomeUncertain("Provider returned an unusable embedding") from e
