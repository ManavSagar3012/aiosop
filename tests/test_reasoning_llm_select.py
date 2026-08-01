"""Tests for W4 / roadmap #4: LLM-assisted hypothesis ranking in ReasoningLoop.

The reasoning loop ranked hypotheses by arithmetic (confidence + novelty + prior)
with the LLM decorative in the decision path. #4 wires the reasoning model into
the SELECT step to rank candidates by attack-chain value, with the arithmetic
score as the documented fallback so a bad/degraded LLM call never stalls the loop.

These are offline: the llm_client is a scripted fake. They pin three contracts:
  1. When the LLM picks a real candidate id, that hypothesis is selected.
  2. When the LLM is absent / raises / returns an unknown id, we fall back to the
     arithmetic ranking (highest arithmetic score wins) without error.
  3. The LLM is consulted with a sanitized, bounded candidate list.
"""

from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.orchestrator.reasoning_loop import ReasoningLoop


def _cand(cid: str, cat: str, conf: float = 0.5) -> Dict[str, Any]:
    return {
        "id": cid,
        "status": "open",
        "category": cat,
        "confidence": conf,
        "target_id": f"t-{cid}",
        "title": f"hyp {cid}",
        "recommended_skills": ["skill_x"],
    }


class _ScriptedLLM:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls: List[Dict[str, Any]] = []

    async def complete(self, messages, *, model=None, max_tokens=None, **kwargs):
        self.calls.append({"messages": messages, "model": model, "max_tokens": max_tokens})
        return self.answers.pop(0) if self.answers else ""


def _orch_with_llm(llm) -> Any:
    gm = MagicMock()
    gm.findings_knowledge = MagicMock()
    gm.findings_knowledge.recall_similar = AsyncMock(return_value=[])
    return SimpleNamespace(llm_client=llm, graph_memory=gm, coordination_bus=MagicMock())


def _make_loop(orch) -> ReasoningLoop:
    loop = ReasoningLoop.__new__(ReasoningLoop)
    loop._orch = orch
    loop._tested_hypotheses = set()
    loop.trace = MagicMock()
    loop.trace.record = MagicMock()
    return loop


@pytest.mark.asyncio
async def test_llm_picks_valid_candidate_wins():
    """LLM names the high-chain candidate (not the arithmetic top) -> it wins."""
    # candidates: arithmetic would rank cand-a first (higher conf); LLM says cand-b.
    cands = [_cand("cand-a", "sqli", 0.9), _cand("cand-b", "idor", 0.4)]
    llm = _ScriptedLLM(["BEST: cand-b"])
    loop = _make_loop(_orch_with_llm(llm))
    state = {"endpoints": ["http://t/x"], "finding_types": set(), "focus": ""}

    picked = await loop._select_hypothesis("eng-1", cands, state)
    assert picked["id"] == "cand-b"
    assert llm.calls, "LLM should have been consulted"
    # the candidate list was capped + presented to the model
    assert "cand-b" in llm.calls[0]["messages"][1]["content"]


@pytest.mark.asyncio
async def test_llm_unusable_id_falls_back_to_arithmetic():
    """LLM returns an id that is NOT a candidate -> arithmetic ranking decides."""
    cands = [_cand("cand-a", "sqli", 0.9), _cand("cand-b", "idor", 0.4)]
    llm = _ScriptedLLM(["BEST: not-a-real-id"])
    loop = _make_loop(_orch_with_llm(llm))
    state = {"endpoints": ["http://t/x"], "finding_types": set(), "focus": ""}

    picked = await loop._select_hypothesis("eng-1", cands, state)
    # arithmetic: cand-a (0.9 conf) beats cand-b (0.4 conf + novelty 0.1 = 0.5)
    assert picked["id"] == "cand-a"


@pytest.mark.asyncio
async def test_llm_raises_falls_back_cleanly(monkeypatch):
    """LLM call raises (provider down) -> arithmetic fallback, no exception."""

    class _Boom:
        async def complete(self, *a, **k):
            raise RuntimeError("provider unreachable")

    cands = [_cand("cand-a", "sqli", 0.3), _cand("cand-b", "idor", 0.8)]
    loop = _make_loop(_orch_with_llm(_Boom()))
    state = {"endpoints": ["http://t/x"], "finding_types": set(), "focus": ""}

    picked = await loop._select_hypothesis("eng-1", cands, state)
    assert picked["id"] == "cand-b"  # higher arithmetic confidence


@pytest.mark.asyncio
async def test_no_llm_client_uses_arithmetic():
    """No llm_client on the orchestrator at all -> pure arithmetic path."""
    cands = [_cand("cand-a", "sqli", 0.2), _cand("cand-b", "idor", 0.9)]
    orch = _orch_with_llm(None)
    orch.llm_client = None
    loop = _make_loop(orch)
    state = {"endpoints": ["http://t/x"], "finding_types": set(), "focus": ""}

    picked = await loop._select_hypothesis("eng-1", cands, state)
    assert picked["id"] == "cand-b"


@pytest.mark.asyncio
async def test_empty_or_tested_candidates_return_none():
    loop = _make_loop(_orch_with_llm(_ScriptedLLM(["BEST: cand-a"])))
    # all tested
    loop._tested_hypotheses = {"cand-a"}
    state = {"endpoints": [], "finding_types": set(), "focus": ""}
    assert await loop._select_hypothesis("eng-1", [_cand("cand-a", "sqli")], state) is None
    # closed
    assert (
        await loop._select_hypothesis(
            "eng-1", [_cand("cand-a", "sqli") | {"status": "closed"}], state
        )
        is None
    )
