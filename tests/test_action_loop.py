"""Tests for the ActionLoop real reasoning loop.

Requires an LLM client that returns structured JSON actions, a tool registry
that executes them, and an observation-inducing cycle that re-invokes the LLM
with results. This is the *decision loop* that makes AI-OSOP agentic, not a
scanner.
"""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.action_loop import Action, ActionLoop, ActionResult, LoopState


class _FakeLLM:
    """Deterministic LLM stub for tests: returns canned responses by request."""

    def __init__(self, responses: List[str]):
        self._responses = iter(responses)
        self.calls: List[Dict[str, Any]] = []

    async def complete(self, messages: Any, **kwargs: Any) -> str:
        self.calls.append({"messages": messages, **kwargs})
        try:
            return next(self._responses)
        except StopIteration:  # pragma: no cover
            return '{"action": "done", "reasoning": "no more"}'


class _ToyTools:
    """Selectable tools for testing."""

    def __init__(self):
        self.calls: List[Dict[str, Any]] = []

    async def scan_endpoint(self, endpoint: str, technique: str) -> Dict[str, Any]:
        self.calls.append({"tool": "scan_endpoint", "endpoint": endpoint, "technique": technique})
        return {
            "endpoint": endpoint,
            "technique": technique,
            "found": technique == "sqli" and endpoint == "/rest/user/login",
            "evidence": "sqlite error: syntax error" if technique == "sqli" else None,
        }

    async def fetch_page(self, endpoint: str) -> Dict[str, Any]:
        self.calls.append({"tool": "fetch_page", "endpoint": endpoint})
        return {"endpoint": endpoint, "status": 200, "size": 1234}

    async def done(self, reasoning: str = "") -> Dict[str, Any]:
        self.calls.append({"tool": "done", "reasoning": reasoning})
        return {"done": True, "reasoning": reasoning}


@pytest.mark.asyncio
async def test_actionloop_runs_llm_tool_cycle_and_returns_findings():
    llm = _FakeLLM(
        [
            '{"action": "scan_endpoint", "endpoint": "/", "technique": "default", "reasoning": "recon first"}',
            '{"action": "fetch_page", "endpoint": "/", "reasoning": "inspect surface"}',
            '{"action": "scan_endpoint", "endpoint": "/rest/user/login", "technique": "sqli", "reasoning": "looks injectable"}',
            '{"action": "done", "reasoning": "found sqli evidence"}',
        ]
    )
    tools = _ToyTools()
    loop = ActionLoop(llm=llm, tools=tools)
    state = LoopState(
        target="https://example.local",
        goal="find SQLi on login forms",
        allowed_tools={"scan_endpoint", "fetch_page", "done"},
    )

    result = await loop.run(state, max_steps=8)

    # 3 LLM invocations (initial + two observations)
    assert len(llm.calls) == 4
    # 2 tools called (despite 4 LLM steps; 'done' is still executed as a no-op action)
    tool_names = [c["tool"] for c in tools.calls]
    assert "scan_endpoint" in tool_names
    assert "fetch_page" in tool_names
    assert "done" in tool_names

    sqli_hits = [
        c
        for c in tools.calls
        if c.get("technique") == "sqli" and c.get("endpoint", "").endswith("/login")
    ]
    assert len(sqli_hits) == 1

    assert result.steps_taken == 4
    assert result.completed is True
    assert any(f.get("found") and f.get("endpoint", "").endswith("/login") for f in result.findings)


@pytest.mark.asyncio
async def test_actionloop_rejects_tool_not_in_allowed_set():
    llm = _FakeLLM(
        [
            '{"action": "exfiltrate", "data": "secrets", "reasoning": "escalate"}',
            '{"action": "done", "reasoning": "bailing out"}',
        ]
    )
    tools = MagicMock()
    # exfiltrate is defined but not in allowed set
    tools.exfiltrate = AsyncMock(return_value={"leaked": True})
    tools.done = AsyncMock(return_value={"done": True})

    loop = ActionLoop(llm=llm, tools=tools)
    state = LoopState(
        target="https://example.local",
        goal="test",
        allowed_tools={"done"},
    )

    result = await loop.run(state, max_steps=4)

    tools.exfiltrate.assert_not_called()
    assert result.steps_taken == 2
    assert result.aborted is False
    assert result.error is None


@pytest.mark.asyncio
async def test_actionloop_feeds_observation_back_into_next_prompt():
    llm = _FakeLLM(
        [
            '{"action": "fetch_page", "endpoint": "/", "reasoning": "look"}',
            '{"action": "fetch_page", "endpoint": "/privacy", "reasoning": "seen /privacy in obs"}',
            '{"action": "done", "reasoning": "done"}',
        ]
    )
    tools = _ToyTools()
    loop = ActionLoop(llm=llm, tools=tools)
    state = LoopState(
        target="https://example.local",
        goal="explore",
        allowed_tools={"fetch_page", "done"},
    )

    await loop.run(state, max_steps=5)

    # Second call should include the observation from step 1 in user or system content
    assert len(llm.calls) == 3
    second_call_content = ""
    for msg in llm.calls[1]["messages"]:
        second_call_content += str(msg.get("content", "")) + "\n"
    assert "fetch_page" in second_call_content  # the tool call we just made
    assert (
        "200" in second_call_content
        or "/privacy" in second_call_content
        or "observation" in second_call_content.lower()
    )


@pytest.mark.asyncio
async def test_actionloop_handles_malformed_json_with_fallback():
    llm = _FakeLLM(['{"not_valid": true', '{"action": "done", "reasoning": "giving up"}'])
    tools = MagicMock()
    tools.done = AsyncMock(return_value={"done": True})

    loop = ActionLoop(llm=llm, tools=tools)
    state = LoopState(
        target="https://example.local",
        goal="test",
        allowed_tools={"done"},
    )

    result = await loop.run(state, max_steps=4)

    assert result.error is not None
    assert (
        "invalid" in result.error.lower()
        or "parse" in result.error.lower()
        or "json" in result.error.lower()
    )
    tools.done.assert_called_once()


@pytest.mark.asyncio
async def test_actionloop_aborts_when_max_steps_reached():
    llm = _FakeLLM(['{"action": "fetch_page", "endpoint": "/", "reasoning": "more"}'] * 10)
    tools = _ToyTools()
    loop = ActionLoop(llm=llm, tools=tools)
    state = LoopState(
        target="https://example.local",
        goal="test infinite loop protection",
        allowed_tools={"fetch_page", "done"},
    )

    result = await loop.run(state, max_steps=3)

    assert result.aborted is True
    assert result.steps_taken == 3
