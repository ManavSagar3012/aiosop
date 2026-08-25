"""
LiteLLM Client
Standardized interface for LLM completions and embeddings with fallback routing.
"""

from typing import Any, Dict, List, Optional

import litellm
import structlog

from ai_osop.core.config import settings
from ai_osop.safety.prompt_defense import sanitize_messages

llm_logger = structlog.get_logger("ai_osop.llm")

_EMBED_DIMS = 1536  # default; overridden by settings.llm_embedding_dim


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
    ):
        self.primary_model = primary_model or settings.llm_primary_model
        self.fallback_model = fallback_model or settings.llm_fallback_model
        self.temperature = temperature if temperature is not None else settings.llm_temperature
        self.max_tokens = max_tokens or settings.llm_max_tokens

    async def complete(
        self,
        messages: List[Dict[str, str]],
        *,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Return assistant text, retrying with the fallback model on failure."""

        safe_messages = sanitize_messages(messages)

        selected_model = model or self.primary_model
        # Extract kwargs before the try block so fallback receives the same values
        temperature = kwargs.pop("temperature", self.temperature)
        max_tokens = kwargs.pop("max_tokens", self.max_tokens)
        # AIOSOP-LLM-TIMEOUT-001: bound the HTTP call so a stalled provider raises
        # (litellm.Timeout) instead of blocking forever. Without this, a hang never
        # triggers the fallback branch below and burns the whole task budget.
        timeout = kwargs.pop("timeout", settings.llm_completion_timeout)

        def _extra(model_name: str) -> Dict[str, Any]:
            # AIOSOP-LLM-WARM-001: keep the Ollama model resident so it loads once
            # instead of cold-loading (~60s) on every call. Only ollama/* accepts
            # keep_alive; passing it to a cloud provider would error, so gate on prefix.
            if str(model_name).startswith("ollama"):
                extra: Dict[str, Any] = {"keep_alive": settings.llm_keep_alive}
                if getattr(settings, "llm_ollama_num_ctx", None):
                    # FIX (llm-ollama-numctx-2026-08-23): pin the context window for
                    # local Ollama models. Some hosts run OLLAMA_CONTEXT_LENGTH=262144;
                    # without an explicit num_ctx every load then tries to allocate a
                    # multi-GB KV cache (observed: ~48GB request -> llama-server OOM)
                    # and EVERY completion fails regardless of model size.
                    extra["num_ctx"] = int(settings.llm_ollama_num_ctx)
                return extra
            return {}

        try:
            response = await litellm.acompletion(
                model=selected_model,
                messages=safe_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                **_extra(selected_model),
                **kwargs,
            )
        except Exception as primary_err:
            llm_logger.warning(
                "primary_llm_failed_falling_back",
                primary_model=selected_model,
                fallback_model=self.fallback_model,
                error=str(primary_err),
            )
            response = await litellm.acompletion(
                model=self.fallback_model,
                messages=safe_messages,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                **_extra(self.fallback_model),
                **kwargs,
            )

        return response.choices[0].message.content or ""

    async def warm_up(self) -> Dict[str, Any]:
        """Pre-load ONLY the primary chat model so the first real engagement call hits
        an already-resident model instead of eating a ~60s cold load.

        AIOSOP-LLM-WARM-001: deliberately warms the primary only. On a memory-constrained
        host the primary (e.g. qwen3:8b, ~5.2GB) and fallback (phi3, ~2.2GB) cannot be
        co-resident — warming both while keep_alive pins the primary makes the second
        load OOM (observed at runtime). The fallback is an on-demand *degradation* path:
        it is needed precisely when the primary has failed/unloaded, at which point its
        memory is free. Best-effort and non-fatal — a down provider just leaves the model
        cold and think() degrades gracefully (the platform stays up). Returns a
        {seconds, ok} report for observability.
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
        pseudo-embedding is returned — the previous constant ``[0.1]*1536`` made
        every item identical, which silently broke similarity search (skill
        selection, payload recall, findings knowledge) whenever mocks were on.
        """
        selected = (
            model or getattr(settings, "llm_embedding_model", None) or "text-embedding-3-small"
        )
        if settings.mock_llm:
            return _mock_embedding(text)

        try:
            response = await litellm.aembedding(model=selected, input=[text])
            return response["data"][0]["embedding"]
        except Exception as e:
            llm_logger.error("embedding_generation_failed", error=str(e))
            raise RuntimeError(f"Embedding generation failed for model {selected}: {e}") from e
