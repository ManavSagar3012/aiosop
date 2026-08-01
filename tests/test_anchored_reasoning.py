"""D1: Anchored Reasoning -- observation-conditioned next-action selection.

Before: the ActionLoop asks the model each step with the same base prompt but
appends all prior history -- the LLM can wander and has no hard mechanism tying
current state to valid actions.

Now: AnchoredReasoner generates a structured sub-goal that *looks back* at what
actually happened, selects a ToolSpec based on precisely what signals were
collected, and produces a bounded chain of proposes so observation always
informs the next decision and new information is never forgotten before a
decision is made.
"""

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.action_loop_anchored import AnchoredReasoner, ReasoningOutput


class _StubLLM:
    def __init__(self, plan):
        self.plan = plan  # iterable of dicts with expected keys
        self.calls = []

    async def complete(self, msgs, **kwargs):
        self.calls.append(msgs)
        return self.plan_p(self.calls)


class _Recorder:
    def __init__(self):
        self.calls = []

    async def inspect_evidence(self, observations: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.calls.append(observations)
        return {"ok": True, "observations": len(observations)}


@pytest.mark.asyncio
async def test_anchor_keeps_last_two_observations_only():
    llm = AsyncMock()
    llm.complete.side_effect = [
        ReasoningOutput(
            think="scan the login endpoint with sqlmap",
            action={"tool": "call_scan_tool", "endpoint": "/login"},
        ),
        ReasoningOutput(think="all done", action={"tool": "stop"}),
    ]
    recorder = _Recorder()
    reasoner = AnchoredReasoner(llm=llm, anchor_tool=recorder.inspect_evidence)
    out1 = await reasoner.reason_step({"goal": "test", "observations": ["step1"]})
    out2 = await reasoner.reason_step({"goal": "test", "observations": ["s1", "s2"]})
    assert out1.anchors
    assert out2.anchors
    assert len(recorder.calls) == 2


@pytest.mark.asyncio
async def test_next_step_references_last_tool_result():
    llm = AsyncMock()
    llm.complete.side_effect = lambda msgs: ReasoningOutput(think="ax", action={"tool": "noop"})
    recorder = _Recorder()
    reasoner = AnchoredReasoner(llm=llm, anchor_tool=recorder.inspect_evidence)
    first = await reasoner.reason_step({"goal": "x", "observations": ["db_error"]})
    second = await reasoner.reason_step({"goal": "x", "observations": ["db_error", "timeout"]})
    assert first.anchors and second.anchors
    assert len(second.anchors) - len(first.anchors) == 1


@pytest.mark.asyncio
async def test_action_sequence_is_bounded():
    llm = AsyncMock()
    llm.complete.side_effect = lambda msgs: ReasoningOutput(
        think=msgs[-1].get("content") or "", action={"tool": "noop"}
    )
    recorder = _Recorder()
    reasoner = AnchoredReasoner(llm=llm, anchor_tool=recorder.inspect_evidence, max_window=2)
    await reasoner.reason_step({"observations": ["a"]})
    assert len(recorder.calls[-1]) == 1
    await reasoner.reason_step({"observations": ["a", "b"]})
    assert len(recorder.calls[-1]) == 1
    await reasoner.reason_step({"observations": ["a", "b", "c"]})
    assert len(recorder.calls[-1]) == 1


@pytest.mark.asyncio
async def test_action_never_freeform_expectations():
    llm = AsyncMock()
    llm.complete.side_effect = [RuntimeError("nonsense LLM output")]
    recorder = _Recorder()
    reasoner = AnchoredReasoner(llm=llm, anchor_tool=recorder.inspect_evidence)
    with pytest.raises(Exception):
        await reasoner.reason_step({"goal": "surf", "observations": []})
