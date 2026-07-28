"""Tests for W7 reasoning-path model routing in agent think().

W7: think() previously ran on the shared primary model with a 512-token cap —
too shallow to reason through a multi-step chain. The routing half of W7 lets an
operator pin a capable reasoning model (OSOP_LLM_REASONING_MODEL) and a larger
budget (OSOP_LLM_REASONING_MAX_TOKENS) WITHOUT touching the bulk/local path.
These tests pin the contract: think() forwards the reasoning model + token cap
to llm_client.complete, and the default (no pin) preserves the legacy behavior
(primary model, no model kwarg override).
"""

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType


class _CapturingLLM:
    """Fake llm_client that records the model/max_tokens think() forwards."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    async def complete(self, messages, *, model=None, max_tokens=None, **kwargs):
        self.calls.append({"model": model, "max_tokens": max_tokens})
        return "ok"


class _MinimalAgent(BaseAgent):
    """Smallest concrete BaseAgent so think() can be exercised offline."""

    def __init__(self, llm: Any) -> None:
        self.ctx = SimpleNamespace(
            agent_id="a1",
            agent_type=AgentType.RECON,
            llm_client=llm,
            scope=None,
            rate_limiter=None,
        )

    def agent_type(self) -> AgentType:  # type: ignore[override]
        return AgentType.RECON

    async def _setup_resources(self) -> None:
        return None

    async def _cleanup_resources(self) -> None:
        return None

    async def _execute(self, task) -> Dict[str, Any]:  # noqa: ANN001 - minimal stub
        return {}


@pytest.mark.asyncio
async def test_think_uses_primary_when_no_reasoning_model_pinned(monkeypatch):
    """No OSOP_LLM_REASONING_MODEL -> model kwarg is None (client falls back to
    its primary), only the token cap is forwarded. Legacy behavior preserved."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 1536, raising=False)

    llm = _CapturingLLM()
    agent = _MinimalAgent(llm)
    with patch.object(BaseAgent, "_load_skill", lambda self, s: ""):
        out = await agent.think("ctx", [])
    assert out == "ok"
    assert llm.calls == [{"model": None, "max_tokens": 1536}]


@pytest.mark.asyncio
async def test_think_routes_to_pinned_reasoning_model(monkeypatch):
    """OSOP_LLM_REASONING_MODEL=capable -> think() forwards that model so
    reasoning runs on the pinned (frontier) model while bulk stays local."""
    from ai_osop.core import config

    monkeypatch.setattr(
        config.settings, "llm_reasoning_model", "claude-opus-4-8", raising=False
    )
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 4096, raising=False)

    llm = _CapturingLLM()
    agent = _MinimalAgent(llm)
    with patch.object(BaseAgent, "_load_skill", lambda self, s: ""):
        await agent.think("ctx", [])
    assert llm.calls == [{"model": "claude-opus-4-8", "max_tokens": 4096}]


def test_reasoning_model_config_default_empty_and_env_override():
    """The setting exists, defaults to empty (no behavior change), and reads
    OSOP_LLM_REASONING_MODEL from the environment."""
    import os

    from ai_osop.core.config import Settings

    os.environ.pop("OSOP_LLM_REASONING_MODEL", None)
    assert Settings().llm_reasoning_model == ""
    os.environ["OSOP_LLM_REASONING_MODEL"] = "gpt-4o"
    try:
        assert Settings().llm_reasoning_model == "gpt-4o"
    finally:
        os.environ.pop("OSOP_LLM_REASONING_MODEL", None)
