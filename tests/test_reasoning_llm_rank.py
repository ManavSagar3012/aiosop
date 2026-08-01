"""Tests for roadmap #4 / W2: LLM-assisted hypothesis ranking in ReasoningLoop.

The review's W2 finding was that the ReasoningLoop ranked hypotheses by pure
arithmetic (confidence + novelty + prior recall) and never consulted the LLM for
the decide step — "rule engine with an LLM hood ornament". #4 wires the reasoning
model into hypothesis selection: it ranks candidates by ATTACK-CHAIN value, and the
arithmetic score is the documented fallback so a degraded LLM call never stalls the
loop and the decision is auditable against the fallback.

Offline: llm_client is a scripted fake. These pin the contract:
  - a valid LLM pick (a real candidate id) wins over the arithmetic top;
  - an absent/degraded/garbled LLM falls back to arithmetic ranking;
  - the model's output is NOT trusted blindly — an id that is not a real candidate
    is discarded and the arithmetic path takes over.
"""

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.orchestrator.reasoning_loop import ReasoningLoop


def _hyp(hid: str, cat: str, conf: float = 0.5, skills=None, status: str = "open"):
    return {
        "id": hid,
        "status": status,
        "category": cat,
        "confidence": conf,
        "target_id": f"target-{hid}",
        "title": f"hypothesis {hid}",
        "recommended_skills": skills or ["sqlmap_scan"],
        "recommended_tests": [cat],
    }


class _ScriptedLLM:
    def __init__(self, answers: List[str]) -> None:
        self.answers = list(answers)
        self.calls: List[Dict[str, Any]] = []

    async def complete(self, messages, *, model=None, max_tokens=None, **kwargs):
        self.calls.append({"n_messages": len(messages), "model": model})
        return self.answers.pop(0) if self.answers else ""


def _loop(llm) -> ReasoningLoop:
    gm = MagicMock()
    gm.findings_knowledge = MagicMock()
    gm.findings_knowledge.recall_similar = AsyncMock(return_value=[])
    orch = SimpleNamespace(
        llm_client=llm,
        graph_memory=gm,
    )
    loop = ReasoningLoop.__new__(ReasoningLoop)
    loop._orch = orch
    loop._tested_hypotheses = set()
    loop.trace = MagicMock()
    loop.trace.record = MagicMock()
    return loop


@pytest.mark.asyncio
async def test_llm_pick_wins_over_arithmetic_top():
    """Arithmetic would rank cand-a first (conf 0.9); the LLM says cand-b which chains.
    The LLM pick must be returned."""
    loop = _loop(_ScriptedLLM(["BEST: cand-b"]))
    hyps = [
        _hyp("cand-a", "sqli", conf=0.9),
        _hyp("cand-b", "idor", conf=0.4, skills=["idor_scan"]),
    ]
    state = {"endpoints": ["http://t/api/users/1"], "finding_types": set(), "focus": ""}
    picked = await loop._select_hypothesis("eng-1", hyps, state)
    assert picked is not None
    assert picked["id"] == "cand-b"
    assert loop._orch.llm_client.calls, "LLM should have been consulted"


@pytest.mark.asyncio
async def test_llm_absent_falls_back_to_arithmetic():
    """No llm_client on the orchestrator -> arithmetic ranking decides (conf 0.9 wins)."""
    loop = _loop(None)
    hyps = [_hyp("cand-a", "sqli", conf=0.9), _hyp("cand-b", "idor", conf=0.2)]
    state = {"endpoints": ["http://t/"], "finding_types": set(), "focus": ""}
    picked = await loop._select_hypothesis("eng-1", hyps, state)
    assert picked["id"] == "cand-a"


@pytest.mark.asyncio
async def test_llm_returns_unknown_id_falls_back_to_arithmetic():
    """The LLM hallucinated an id that isn't a real candidate -> discard it and use
    arithmetic (conf 0.9 wins) instead of trusting the bogus answer."""
    loop = _loop(_ScriptedLLM(["BEST: not-a-candidate"]))
    hyps = [_hyp("cand-a", "sqli", conf=0.9), _hyp("cand-b", "idor", conf=0.2)]
    state = {"endpoints": ["http://t/"], "finding_types": set(), "focus": ""}
    picked = await loop._select_hypothesis("eng-1", hyps, state)
    assert picked["id"] == "cand-a"


@pytest.mark.asyncio
async def test_llm_raises_falls_back_to_arithmetic():
    """LLM provider is down -> exception -> arithmetic ranking must still decide."""

    class _Boom:
        async def complete(self, *a, **k):
            raise RuntimeError("llm down")

    loop = _loop(_Boom())
    hyps = [_hyp("cand-a", "sqli", conf=0.3), _hyp("cand-b", "idor", conf=0.8)]
    state = {"endpoints": ["http://t/"], "finding_types": set(), "focus": ""}
    picked = await loop._select_hypothesis("eng-1", hyps, state)
    assert picked["id"] == "cand-b"


@pytest.mark.asyncio
async def test_no_open_candidates_returns_none():
    """All candidates closed or already-tested -> None, regardless of LLM."""
    loop = _loop(_ScriptedLLM(["BEST: cand-a"]))
    hyps = [_hyp("cand-a", "sqli", conf=0.9, status="confirmed")]
    state = {"endpoints": ["http://t/"], "finding_types": set(), "focus": ""}
    assert await loop._select_hypothesis("eng-1", hyps, state) is None
    # all-tested also yields None
    loop2 = _loop(_ScriptedLLM(["BEST: cand-a"]))
    loop2._tested_hypotheses = {"cand-a"}
    assert (
        await loop2._select_hypothesis("eng-1", [_hyp("cand-a", "sqli", conf=0.9)], state) is None
    )
