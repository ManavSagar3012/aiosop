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

        if settings.mock_llm:
            target = "unknown"
            for m in safe_messages:
                if m["role"] == "user":
                    target = m["content"][:100]
            return f"[MOCK REASONING] Analyzing context for {target}. Recommended approach: Adaptive payload mutation using semantic memory."

        selected_model = model or self.primary_model
        try:
            response = await litellm.acompletion(
                model=selected_model,
                messages=safe_messages,
                temperature=kwargs.pop("temperature", self.temperature),
                max_tokens=kwargs.pop("max_tokens", self.max_tokens),
                **kwargs,
            )
        except Exception:
            response = await litellm.acompletion(
                model=self.fallback_model,
                messages=safe_messages,
                temperature=kwargs.pop("temperature", self.temperature),
                max_tokens=kwargs.pop("max_tokens", self.max_tokens),
                **kwargs,
            )

        return response.choices[0].message.content or ""

    async def get_embedding(self, text: str, model: str = "text-embedding-3-small") -> List[float]:
        """Generate a semantic embedding for a piece of text."""
        if settings.mock_llm:
            # Return a deterministic mock embedding
            return [0.1] * 1536

        try:
            response = await litellm.aembedding(model=model, input=[text])
            return response["data"][0]["embedding"]
        except Exception as e:
            llm_logger.error("embedding_generation_failed", error=str(e))
            return [0.0] * 1536
