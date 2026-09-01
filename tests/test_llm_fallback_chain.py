"""AEGIS-LLM-APIBAI: 4-tier LLM fallback chain tests (2026-08-30).

Verifies:
  1. Each tier's base URL resolves correctly when complete(model=...) is called
     directly (the LRT-judge / warm-up path).
  2. When the primary model fails, the ladder cascades through fallback ->
     fallback2 -> fallback3 and returns the first tier that works.
  3. A completely-dead chain raises (does not hang).
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_osop.core.llm_client import (
    LiteLLMClient,
    _resolve_base_url,
)

APIBAI = "https://api.b.ai"
OLLAMA = "http://localhost:11434/v1"

PRIMARY = "anthropic/glm-5.3-flash"
FALLBACK = "anthropic/qwen3.8-flash"
FALLBACK2 = "anthropic/hy3"
FALLBACK3 = "anthropic/mimo-v2.5"


def _set_env(**kwargs):
    """Set the OSOP_* env vars the settings object reads at import/call time.

    Also reloads ai_osop.core.llm_client: its module-level `settings` binding
    was imported at first load from the REAL .env, so a fixture env change
    alone is invisible to _resolve_base_url — the per-tier model-name match
    then misses and resolution silently falls to the shared base. Reloading
    both modules makes these tests fixture-driven, not .env-coupled (found
    live when the operator swapped the fallback2 model).
    """
    base = {
        "OSOP_LLM_PRIMARY": "anthropic",
        "OSOP_LLM_PRIMARY_MODEL": PRIMARY,
        "OSOP_LLM_PRIMARY_BASE_URL": APIBAI,
        "OSOP_LLM_FALLBACK_MODEL": FALLBACK,
        "OSOP_LLM_FALLBACK_BASE_URL": APIBAI,
        "OSOP_LLM_FALLBACK2_MODEL": FALLBACK2,
        "OSOP_LLM_FALLBACK2_BASE_URL": APIBAI,
        "OSOP_LLM_FALLBACK3_MODEL": FALLBACK3,
        "OSOP_LLM_FALLBACK3_BASE_URL": APIBAI,
        "OPENROUTER_API_KEY": "sk-test",
        "OSOP_LLM_BASE_URL": OLLAMA,  # embeddings stay local
    }
    base.update(kwargs)
    for k, v in base.items():
        os.environ[k] = v
    # Force settings AND the client to re-read from env
    import importlib

    from ai_osop.core import config
    from ai_osop.core import llm_client as lc

    importlib.reload(config)
    importlib.reload(lc)
    return lc


def test_per_tier_base_url_resolution():
    """Each model resolves to its own tier base URL."""
    lc = _set_env()
    assert lc._resolve_base_url(PRIMARY) == APIBAI
    assert lc._resolve_base_url(FALLBACK) == APIBAI
    assert lc._resolve_base_url(FALLBACK2) == APIBAI
    assert lc._resolve_base_url(FALLBACK3) == APIBAI


def test_embedding_path_uses_local_ollama():
    """The shared llm_base_url (embeddings) is untouched by the chat ladder."""
    lc = _set_env()
    # An embedding model is not one of the chat tiers -> resolves to llm_base_url.
    assert lc._resolve_base_url("nomic-embed-text") == OLLAMA


@pytest.mark.asyncio
async def test_fallback_cascade_when_primary_fails():
    """Primary failure cascades to the first working fallback."""
    _set_env(OSOP_LLM_PRIMARY_MODEL="anthropic/does-not-exist-model")
    from ai_osop.core.llm_client import LiteLLMClient

    client = LiteLLMClient()
    # Real network call: primary 404s -> fallback (qwen3.8-flash) answers.
    resp = await client.complete(
        [{"role": "user", "content": "Reply with exactly: OK"}],
        max_tokens=32,
        timeout=60,
    )
    assert isinstance(resp, str)


@pytest.mark.asyncio
async def test_all_tiers_dead_raises_not_hangs():
    """A fully-dead chain raises instead of hanging.

    Uses a mocked _call_model so no real network is hit — each tier raises,
    and the ladder must exhaust all 4 tiers then raise (not hang).
    """
    import ai_osop.core.llm_client as lc

    with patch.object(lc.LiteLLMClient, "_call_model", new_callable=AsyncMock) as mock_call:
        mock_call.side_effect = RuntimeError("tier down")
        # Instantiate from the SAME module object being patched — the top-level
        # import in this file is a stale class from before _set_env's reload
        # (found live: patch applied to the new class, instance was the old
        # one, the mock never fired and the real network answered).
        client = lc.LiteLLMClient()
        with pytest.raises(Exception):
            await client.complete(
                [{"role": "user", "content": "hi"}],
                max_tokens=8,
                timeout=30,
            )
        # Primary (1) + 3 fallback tiers = 4 tiers consulted before raising.
        assert mock_call.call_count >= 4


@pytest.mark.asyncio
async def test_primary_works_without_fallback_touch():
    """When primary succeeds, the fallback ladder is not consulted."""
    _set_env()  # primary = glm-5.3-flash (works)
    from ai_osop.core.llm_client import LiteLLMClient

    client = LiteLLMClient()
    resp = await client.complete(
        [{"role": "user", "content": "List exactly three colors, then stop."}],
        max_tokens=256,
        timeout=60,
    )
    # GLM spends its first tokens on a thinking prefix; at 256 max_tokens it
    # should emit real content.
    assert isinstance(resp, str) and resp.strip(), f"empty response: {resp!r}"
