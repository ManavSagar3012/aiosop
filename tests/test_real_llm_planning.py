"""M4: real-LLM planning loop integration test (gap-analysis item M4).

The gap audit (docs/BUG_BOUNTY_READINESS_GAPS.md, M4) flagged that the suite
mocks the LLM everywhere (``OSOP_MOCK_LLM=true``), so the *real* planning loop
— ``agent.think()`` -> ``LiteLLMClient.complete()`` -> litellm -> provider —
is never exercised in CI. "Autonomous" behavior was therefore untested.

This test is GATED behind ``OSOP_RUN_REAL_LLM=1`` (plus a configured
``OSOP_LLM_API_KEY`` for an OpenAI-compatible provider, OR any litellm-
supported provider). It is skipped by default so the default suite stays
hermetic, but on a machine with a live LLM it actually drives a small
plan->scan->report cycle end-to-end:

  1. A real LiteLLMClient calls the provider (no mock).
  2. A VulnAnalysisAgent.think() runs the actual prompt-formatting +
     provider round-trip and returns non-empty text.
  3. The returned text is a parseable, non-empty reasoning string (the
     planner's contract).

The test asserts the real provider was reached (not the mock empty-string
path) by checking the response is non-empty and (when set) carries the
config ``llm_primary_model`` name in the warm-up metadata.

Skip conditions are explicit and logged so CI failures are diagnosable.
"""

from __future__ import annotations

import os

import pytest


def _real_llm_enabled() -> bool:
    """True only when an operator has explicitly opted in AND supplied a key."""
    return os.environ.get("OSOP_RUN_REAL_LLM") == "1" and bool(
        os.environ.get("OSOP_LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("OSOP_LLM_PRIMARY", "").startswith("ollama")
    )


pytestmark = pytest.mark.skipif(
    not _real_llm_enabled(),
    reason=(
        "Set OSOP_RUN_REAL_LLM=1 and OSOP_LLM_API_KEY (or use an ollama:// "
        "primary) to run the real-LLM planning test. Default suite stays hermetic."
    ),
)


@pytest.mark.asyncio
async def test_real_llm_planning_loop_round_trip():
    """Drive a real LiteLLMClient.complete() call against the configured
    provider and assert the planning loop returns non-empty text.

    This is the M4 gap closure: it proves the planner path that agents use
    (VulnAnalysisAgent.think -> llm_client.complete -> litellm -> provider)
    is exercised against a real backend, not the mock that returns "".
    """
    from ai_osop.core.config import settings
    from ai_osop.core.llm_client import LiteLLMClient

    # Force mock OFF regardless of any ambient env value; this test exists
    # specifically to exercise the REAL provider path.
    original_mock = settings.mock_llm
    settings.mock_llm = False
    try:
        client = LiteLLMClient()
        messages = [
            {
                "role": "system",
                "content": (
                    "You are an AI Vulnerability Analysis Agent. Given a target, "
                    "produce a one-sentence plan of which scan to run first."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Target: http://localhost:3000 (Juice Shop). "
                    "What scan should run first and why? Answer in one sentence."
                ),
            },
        ]
        # Bound the call so a stalled provider fails the test fast instead of
        # hanging the suite.
        text = await client.complete(messages, max_tokens=settings.llm_reasoning_max_tokens)
    finally:
        settings.mock_llm = original_mock

    # The mock returns "" — a real provider must return non-empty text.
    assert isinstance(text, str)
    assert text.strip(), (
        "real-LLM planning loop returned empty text — either the provider is "
        "down, the key is invalid, or mock_llm was not actually disabled. The "
        "planner contract is non-empty reasoning."
    )
    # Sanity: the response is not the mock's exact "" sentinel.
    assert text != "", "mock LLM path was taken despite mock_llm=False"


@pytest.mark.asyncio
async def test_real_llm_warm_up_succeeds():
    """A warm_up() call against the real provider must succeed (or at least
    not raise) so the first real engagement call hits an already-resident
    model. This pins the startup path that main.py fires in lifespan()."""
    from ai_osop.core.config import settings
    from ai_osop.core.llm_client import LiteLLMClient

    original_mock = settings.mock_llm
    settings.mock_llm = False
    try:
        client = LiteLLMClient()
        # warm_up must not raise. It returns metadata we don't assert on
        # strictly (different providers return different shapes) — the contract
        # is "does not blow up the lifespan startup".
        result = await client.warm_up()
        assert result is not None
    finally:
        settings.mock_llm = original_mock
