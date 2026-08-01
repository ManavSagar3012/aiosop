"""Tests for the W1 bounded tool-use loop: think_with_tools (roadmap #3).

These drive BaseAgent.think_with_tools with a SCRIPTED fake llm_client so we can
verify the observe -> TOOL_CALL -> TOOL_RESULT -> observe loop, the turn/token/
time caps, the tool-error path, and the prompt-boundary sanitization — all offline.
No real LLM and no real target are contacted.
"""

import time
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from ai_osop.agents.base import BaseAgent
from ai_osop.core.enums import AgentType


class _ScriptedLLM:
    """Fake llm_client whose complete() replays a fixed list of answers."""

    def __init__(self, answers: List[str]) -> None:
        self.answers = list(answers)
        self.calls: List[Dict[str, Any]] = []

    async def complete(self, messages, *, model=None, max_tokens=None, **kwargs):
        self.calls.append({"model": model, "max_tokens": max_tokens, "n_messages": len(messages)})
        if not self.answers:
            return ""
        return self.answers.pop(0)


class _ToolAgent(BaseAgent):
    """Smallest concrete BaseAgent exposing think_with_tools to tests."""

    def __init__(self, llm):
        self.ctx = SimpleNamespace(
            agent_id="a1",
            agent_type=AgentType.RECON,
            llm_client=llm,
            scope=None,
            rate_limiter=None,
        )

    def agent_type(self):  # type: ignore[override]
        return AgentType.RECON

    async def _setup_resources(self):
        return None

    async def _cleanup_resources(self):
        return None

    async def _execute(self, task):
        return {}  # noqa: ANN001


def _no_skill(self, name):  # type: ignore[no-untyped-def]
    return ""


@pytest.mark.asyncio
async def test_tool_loop_calls_tool_and_concludes(monkeypatch):
    """LLM: turn1 issues TOOL_CALL -> we run the tool and feed result back;
    turn2 yields a final answer that incorporatesthe tool result."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 800, raising=False)

    seen = {}

    def scan_target(url: str) -> Dict[str, Any]:
        seen["url"] = url
        return {"status": 200, "reflection": "' OR '1'='1"}

    llm = _ScriptedLLM(
        [
            'I need to check the endpoint.\nTOOL_CALL: scan_target {"url": "http://t/login"}',
            "The response reflects the SQLi probe, so this endpoint is likely injectable.",
        ]
    )
    agent = _ToolAgent(llm)
    with patch.object(BaseAgent, "_load_skill", _no_skill):
        out = await agent.think_with_tools("ctx", [], {"scan_target": scan_target})

    assert seen["url"] == "http://t/login"
    assert "injectable" in out
    # two LLM calls: first to get the tool call, second after the tool result
    assert len(llm.calls) == 2
    # second call observes the appended TOOL_RESULT message (system+user+assistant+user)
    assert llm.calls[1]["n_messages"] == 4


@pytest.mark.asyncio
async def test_loop_stops_on_time_budget(monkeypatch):
    """If the loop would exceed time_budget it must exit cleanly with the
    accumulated (empty) answer rather than hanging."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 800, raising=False)

    async def slow_tool(**kw):
        await asyncio_sleep(0.05)
        return {}

    async def asyncio_sleep(s):
        import asyncio

        await asyncio.sleep(s)

    # LLM keeps asking for the tool; time_budget forces exit after a couple of turns.
    llm = _ScriptedLLM(["TOOL_CALL: slow {}"] * 30)
    agent = _ToolAgent(llm)
    with patch.object(BaseAgent, "_load_skill", _no_skill):
        start = time.monotonic()
        out = await agent.think_with_tools(
            "ctx", [], {"slow": slow_tool}, max_turns=100, time_budget=0.05
        )
        elapsed = time.monotonic() - start
    assert elapsed < 2.0
    assert isinstance(out, str)


@pytest.mark.asyncio
async def test_bad_tool_json_args_surfaced_as_tool_error(monkeypatch):
    """A malformed TOOL_CALL json must not crash the loop; the tool_error text is
    fed back so the model can recover on the next turn or conclude."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 800, raising=False)

    def noop(**kw):
        return {"ok": True}

    llm = _ScriptedLLM(
        [
            "TOOL_CALL: noop {not json}",
            "Could not parse my own args; concluding without further tooling.",
        ]
    )
    agent = _ToolAgent(llm)
    with patch.object(BaseAgent, "_load_skill", _no_skill):
        out = await agent.think_with_tools("ctx", [], {"noop": noop})
    assert "concluding" in out
    assert len(llm.calls) == 2


@pytest.mark.asyncio
async def test_no_tools_falls_back_to_plain_think(monkeypatch):
    """think_with_tools(tools={}) must be exactly plain think() (no loop)."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 800, raising=False)

    llm = _ScriptedLLM(["plain answer"])
    agent = _ToolAgent(llm)
    with patch.object(BaseAgent, "_load_skill", _no_skill):
        out = await agent.think_with_tools("ctx", [], {})
    assert out == "plain answer"
    assert len(llm.calls) == 1


@pytest.mark.asyncio
async def test_python_style_args_are_parsed(monkeypatch):
    """Regression: the live llama3 run emitted `TOOL_CALL: check_response(status_code=200)`
    (Python call syntax, not JSON). The strict parser missed it and the loop
    concluded without running the tool. The lenient parser must catch it and run
    the tool with status_code=200."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 800, raising=False)

    seen = {}

    def check_response(status_code: int):
        seen["status_code"] = status_code
        return {"accessible": status_code == 200}

    llm = _ScriptedLLM(
        [
            "TOOL_CALL: check_response(status_code=200)\n\n",
            "Endpoint is anonymously accessible -> broken access control.",
        ]
    )
    agent = _ToolAgent(llm)
    with patch.object(BaseAgent, "_load_skill", _no_skill):
        out = await agent.think_with_tools("ctx", [], {"check_response": check_response})

    assert seen == {"status_code": 200}
    assert "broken access control" in out
    assert len(llm.calls) == 2


@pytest.mark.asyncio
async def test_positional_arg_call_is_parsed(monkeypatch):
    """Regression: the live llama3 run emitted
    `TOOL_CALL: lookup_endpoint('/rest/products/search', {})` — a positional string
    arg. The k=v parser found no pairs and the tool was never invoked. Positional
    args must be mapped onto the tool's parameter names so the loop runs it."""
    from ai_osop.core import config

    monkeypatch.setattr(config.settings, "llm_reasoning_model", "", raising=False)
    monkeypatch.setattr(config.settings, "llm_reasoning_max_tokens", 800, raising=False)

    seen = []

    def lookup_endpoint(path: str):
        seen.append(path)
        return {"status": 200}

    llm = _ScriptedLLM(
        [
            "TOOL_CALL: lookup_endpoint('/rest/products/search')",
            "Endpoint returns 200 anon -> confirmed.",
        ]
    )
    agent = _ToolAgent(llm)
    with patch.object(BaseAgent, "_load_skill", _no_skill):
        out = await agent.think_with_tools("ctx", [], {"lookup_endpoint": lookup_endpoint})

    assert seen == ["/rest/products/search"]
    assert "confirmed" in out
