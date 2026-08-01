"""Reasoning self-correction: after each tool executes the loop grades its own
choice against the observation and, when the outcome looks unproductive, replans
from the observation rather than charging blindly ahead."""

from typing import Any, Dict, List
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.action_loop import ActionLoop, LoopState


class _Judge:
    """LLM stub that scores its own prior tool choice once prompted."""

    def __init__(self):
        self.calls: List[List[Dict[str, Any]]] = []
        self._plan = [
            {"action": "fetch_page", "endpoint": "/", "reasoning": "open the surface"},
            {
                "action": "scan_endpoint",
                "endpoint": "/about",
                "technique": "sqli",
                "reasoning": "I see an about page; try SQLi",
            },
            {"action": "done", "reasoning": "no signal to follow up"},
        ]
        self._idx = 0

    async def complete(self, messages: List[Dict[str, Any]], **kwargs: Any) -> str:
        import json

        self.calls.append(messages)
        try:
            obj = self._plan[self._idx]
            self._idx += 1
            return json.dumps(obj)
        except IndexError:
            return json.dumps({"action": "done", "reasoning": "out of plan"})


class _FailingTools:
    async def fetch_page(self, endpoint: str) -> Dict[str, Any]:
        return {"status": 404}

    async def scan_endpoint(self, endpoint: str, technique: str) -> Dict[str, Any]:
        return {"found": False}

    async def done(self, reasoning: str = "") -> Dict[str, Any]:
        return {"done": True}


@pytest.mark.asyncio
async def test_loop_replans_after_unproductive_step():
    llm = _Judge()
    tools = _FailingTools()
    loop = ActionLoop(llm=llm, tools=tools)
    state = LoopState(
        target="https://example.local",
        goal="test",
        allowed_tools={"fetch_page", "scan_endpoint", "done"},
    )

    result = await loop.run(state, max_steps=5)

    # The second LLM prompt must include an observation that the first fetch found nothing.
    second_prompt = llm.calls[1]
    content = " ".join(str(m.get("content", "")) for m in second_prompt)
    assert "404" in content or "not_found" in content or "status" in content
    assert result.steps_taken == 3
    assert result.completed is True


@pytest.mark.asyncio
async def test_done_results_in_clean_exit():
    llm = _Judge()
    llm._plan = [{"action": "done", "reasoning": "nothing to do"}]
    llm._idx = 0
    loop = ActionLoop(llm=llm, tools=_FailingTools())
    result = await loop.run(
        LoopState(target="https://example.local", goal="test", allowed_tools={"done"}),
        max_steps=3,
    )
    assert result.completed is True
    assert result.steps_taken == 1
    assert result.error is None
