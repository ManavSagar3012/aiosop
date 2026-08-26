"""
LLM Client
Standardized interface for LLM completions and embeddings with fallback routing.
Uses httpx directly for OpenAI-compatible APIs (OpenRouter, OpenAI, etc.)
to avoid litellm's async issues on Windows (ProactorEventLoop + httpx hang).
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

import httpx
import structlog

from ai_osop.core.config import settings
from ai_osop.safety.prompt_defense import sanitize_messages

llm_logger = structlog.get_logger("ai_osop.llm")

_EMBED_DIMS = 1536  # default; overridden by settings.llm_embedding_dim

# OpenRouter base URL (OpenAI-compatible)
_OPENROUTER_BASE = "https://openrouter.ai/api/v1"


def _mock_embedding(text: str, dims: Optional[int] = None) -> List[float]:
    """Deterministic, text-dependent pseudo-embedding for mock mode.

    Hashes each token into a bucket and L2-normalizes, so identical text yields
    identical vectors and texts sharing tokens land near each other under cosine
    similarity. This keeps offline/CI runs meaningful for anything that relies on
    semantic search, without contacting an embedding provider.
    """
    import hashlib
    import math

    if dims is None:
        dims = getattr(settings, "llm_embedding_dim", _EMBED_DIMS)
    vec = [0.0] * dims
    for token in (text or "").lower().split():
        bucket = int(hashlib.sha1(token.encode("utf-8")).hexdigest(), 16) % dims
        vec[bucket] += 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return vec
    return [v / norm for v in vec]


def _resolve_api_key() -> str:
    """Get API key from settings or environment."""
    key = getattr(settings, "llm_api_key", None)
    if key:
        return key
    # Fallback to standard env vars
    return os.environ.get("OPENROUTER_API_KEY", os.environ.get("OPENAI_API_KEY", ""))


def _resolve_fallback_api_key() -> str:
    """Get API key for the fallback model (may differ from primary)."""
    # Fallback model uses OpenRouter key
    return os.environ.get("OPENROUTER_API_KEY", os.environ.get("OPENAI_API_KEY", ""))


def _resolve_base_url(model: str) -> str:
    """Determine the API base URL for a given model."""
    base = getattr(settings, "llm_base_url", None)
    if base:
        llm_logger.debug("_resolve_base_url_custom", model=model, url=base)
        return base
    if model.startswith("ollama/"):
        llm_logger.debug("_resolve_base_url_ollama", model=model)
        return "http://localhost:11434/v1"
    llm_logger.debug("_resolve_base_url_openrouter", model=model)
    return _OPENROUTER_BASE


def _strip_provider_prefix(model: str) -> str:
    """Strip 'openrouter/' prefix for the actual API model ID."""
    if model.startswith("openrouter/"):
        return model[len("openrouter/") :]
    return model


async def _call_openai_compatible(
    model: str,
    messages: List[Dict[str, str]],
    *,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    timeout: int = 60,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    response_format: Optional[Dict[str, str]] = None,
) -> str:
    """Call an OpenAI-compatible API directly via httpx."""
    api_key = api_key or _resolve_api_key()
    base_url = base_url or _resolve_base_url(model)
    api_model = _strip_provider_prefix(model)

    url = f"{base_url}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    # OpenRouter-specific headers
    if "openrouter.ai" in base_url:
        headers["HTTP-Referer"] = "https://ai-osop.local"
        headers["X-Title"] = "AI-OSOP Security Platform"

    payload: Dict[str, Any] = {
        "model": api_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    # Only send response_format for OpenRouter/OpenAI endpoints.
    # Custom vLLM/Ollama endpoints (like Kaggle-hosted Qwen) reject this
    # parameter and return empty output.
    if response_format is not None and "openrouter.ai" in (base_url or ""):
        payload["response_format"] = response_format

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=10.0)) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    msg_data = data.get("choices", [{}])[0].get("message", {})
    content = msg_data.get("content") or ""
    # FIX (reasoning-model-2026-08-25): stealth/ox-alpha and similar reasoning
    # models put output in reasoning_content before producing final content.
    if not content.strip():
        content = msg_data.get("reasoning_content") or msg_data.get("reasoning", "") or ""
        # For reasoning models, extract the LAST paragraph which is usually
        # the actual answer after the chain-of-thought
        if content and "\n\n" in content:
            paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
            if len(paragraphs) > 1:
                content = paragraphs[-1]
    llm_logger.debug(
        "llm_completion",
        model=api_model,
        tokens=data.get("usage", {}),
        content_len=len(content),
    )
    # FIX (json-extraction-2026-08-26): models wrap JSON in markdown fences
    # or mix it with prose. Extract the first valid JSON object cleanly so
    # ALL agents receive parseable output regardless of model verbosity.
    stripped = content.strip()
    if stripped.startswith("```"):
        # Strip markdown code fences
        import re as _re

        m = _re.search(r"```(?:json)?\s*(.*?)\s*```", stripped, _re.DOTALL)
        if m:
            content = m.group(1).strip()
    elif "{" in stripped:
        # Try to extract embedded JSON object
        start = stripped.index("{")
        depth = 0
        for i in range(start, len(stripped)):
            if stripped[i] == "{":
                depth += 1
            elif stripped[i] == "}":
                depth -= 1
            if depth == 0:
                content = stripped[start : i + 1]
                break

    return content or ""


async def _call_ollama(
    model: str,
    messages: List[Dict[str, str]],
    *,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    timeout: int = 60,
) -> str:
    """Call a local Ollama model via httpx."""
    api_model = model.replace("ollama/", "")
    url = "http://localhost:11434/api/chat"
    num_ctx = getattr(settings, "llm_ollama_num_ctx", 8192)
    payload = {
        "model": api_model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
            "num_ctx": num_ctx,
        },
    }
    if getattr(settings, "llm_keep_alive", None):
        payload["keep_alive"] = settings.llm_keep_alive

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=10.0)) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

    return data.get("message", {}).get("content", "")


class LiteLLMClient:
    """
    LLM reasoning client for context-aware generation and
    semantic embedding generation. Supports OpenRouter, OpenAI, Ollama,
    and any OpenAI-compatible API.
    """

    def __init__(
        self,
        primary_model: Optional[str] = None,
        fallback_model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ):
        self.primary_model = primary_model or settings.llm_primary_model
        self.fallback_model = fallback_model or settings.llm_fallback_model
        self.temperature = temperature if temperature is not None else settings.llm_temperature
        self.max_tokens = max_tokens or settings.llm_max_tokens
        # Shared rate limiter across ALL instances (same API key = same bucket).
        # 20 req/min free tier -> enforce 4s minimum between any two calls.
        if not hasattr(LiteLLMClient, "_shared_lock"):
            LiteLLMClient._shared_lock = asyncio.Lock()
            LiteLLMClient._shared_last_call = 0.0
            LiteLLMClient._shared_interval = 4.0

    async def _call_model(
        self,
        model: str,
        messages: List[Dict[str, str]],
        *,
        temperature: float,
        max_tokens: int,
        timeout: int,
        response_format: Optional[Dict[str, str]] = None,
        api_key: Optional[str] = None,
    ) -> str:
        """Route to the right backend based on model prefix."""
        base_url = _resolve_base_url(model)
        llm_logger.info("_call_model_route", model=model, base_url=base_url, is_ollama=model.startswith("ollama/"))
        if model.startswith("ollama/"):
            return await _call_ollama(
                model,
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
            )
        else:
            return await _call_openai_compatible(
                model,
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                response_format=response_format,
                api_key=api_key,
                base_url=base_url,
            )

    async def _rate_limit(self) -> None:
        """Shared rate limiter: enforce minimum interval between LLM calls
        only for OpenRouter endpoints (free tier has 20 req/min limit).
        Custom endpoints (Kaggle, local Ollama) have no such limit."""
        import time as _time

        # Only rate-limit OpenRouter endpoints
        base = getattr(settings, "llm_base_url", None) or ""
        if "openrouter" not in base:
            return  # no limit for custom endpoints

        async with LiteLLMClient._shared_lock:
            now = _time.monotonic()
            elapsed = now - LiteLLMClient._shared_last_call
            if elapsed < LiteLLMClient._shared_interval:
                await asyncio.sleep(LiteLLMClient._shared_interval - elapsed)
            LiteLLMClient._shared_last_call = _time.monotonic()

    async def complete(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Return assistant text, retrying with the fallback model on failure."""

        await self._rate_limit()

        safe_messages = sanitize_messages(messages)

        selected_model = model or self.primary_model
        # Extract kwargs before the try block so fallback receives the same values
        temperature = kwargs.pop("temperature", self.temperature)
        max_tokens = kwargs.pop("max_tokens", self.max_tokens)
        # AIOSOP-LLM-TIMEOUT-001: bound the HTTP call so a stalled provider raises
        # instead of blocking forever. Without this, a hang never triggers the
        # fallback branch below and burns the whole task budget.
        timeout = kwargs.pop("timeout", settings.llm_completion_timeout)
        response_format = kwargs.pop("response_format", None)

        # Retry loop: handle 429 rate limits with exponential backoff
        # instead of immediately falling back to a different model.
        import time as _time

        primary_key = _resolve_api_key()
        fallback_key = _resolve_fallback_api_key()

        max_retries = 3
        last_err = None
        for attempt in range(max_retries + 1):
            try:
                content = await self._call_model(
                    selected_model,
                    safe_messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                    response_format=response_format,
                    api_key=primary_key,
                )
                return content
            except Exception as e:
                err_str = str(e)
                last_err = e
                if "429" in err_str or "rate" in err_str.lower():
                    wait = min(2 ** (attempt + 1), 30)  # 2, 4, 8 seconds
                    llm_logger.warning(
                        "llm_rate_limited_retrying",
                        model=selected_model,
                        attempt=attempt + 1,
                        wait_seconds=wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                # Non-rate-limit error: fall through to fallback
                break

        # All retries exhausted or non-429 error: try fallback model
        llm_logger.warning(
            "primary_llm_failed_falling_back",
            primary_model=selected_model,
            fallback_model=self.fallback_model,
            error=str(last_err),
        )
        content = await self._call_model(
            self.fallback_model,
            safe_messages,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            response_format=response_format,
            api_key=fallback_key,
        )

        return content

    async def warm_up(self) -> Dict[str, Any]:
        """Pre-load the primary chat model so the first real engagement call hits
        an already-resident model instead of eating a cold load.
        """
        report: Dict[str, Any] = {}
        model = self.primary_model
        if model:
            import time as _t

            start = _t.monotonic()
            try:
                await self.complete(
                    [{"role": "user", "content": "ok"}],
                    model=model,
                    max_tokens=1,
                    timeout=max(settings.llm_completion_timeout, 180),
                )
                report[model] = {"seconds": round(_t.monotonic() - start, 1), "ok": True}
            except Exception as e:  # noqa: BLE001
                report[model] = {
                    "seconds": round(_t.monotonic() - start, 1),
                    "ok": False,
                    "error": str(e)[:160],
                }
        llm_logger.info("llm_warm_up_complete", report=report)
        return report

    async def get_embedding(self, text: str, model: Optional[str] = None) -> List[float]:
        """Generate a semantic embedding for a piece of text.

        The model defaults to ``settings.llm_embedding_model`` so it is
        configurable per provider (OSOP_LLM_EMBEDDING_MODEL) instead of being
        hardcoded to an OpenAI model. In mock mode a deterministic *text-dependent*
        pseudo-embedding is returned.
        """
        selected = (
            model or getattr(settings, "llm_embedding_model", None) or "text-embedding-3-small"
        )
        if settings.mock_llm:
            return _mock_embedding(text)

        # For OpenAI-compatible embedding APIs
        api_key = _resolve_api_key()
        base_url = _resolve_base_url(selected)
        api_model = _strip_provider_prefix(selected)

        url = f"{base_url}/embeddings"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        if "openrouter.ai" in base_url:
            headers["HTTP-Referer"] = "https://ai-osop.local"
            headers["X-Title"] = "AI-OSOP Security Platform"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10.0)) as client:
                resp = await client.post(
                    url,
                    json={"model": api_model, "input": text},
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
            return data["data"][0]["embedding"]
        except Exception as e:
            # Fallback to mock embedding if API fails
            llm_logger.warning(
                "embedding_api_failed_falling_back_to_mock",
                model=selected,
                error=str(e),
            )
            return _mock_embedding(text)
