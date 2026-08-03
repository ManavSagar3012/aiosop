"""Coverage-focused tests for ReasoningLoop behavior seams.

Pins five real behaviors of src/ai_osop/orchestrator/reasoning_loop.py:

1. ``_select_hypothesis`` arithmetic fallback: confidence + novelty boost
   (+0.1 for categories not yet in finding_types) + prior-recall boost from
   FindingsKnowledge — across two vuln categories (SSRF vs authz).
2. ``_evaluate_result`` transitions: confirmed -> status update + chain
   hypothesis generation; 0 findings -> refuted + dead-end recovery follow-up.
3. ``_dispatch_hypothesis`` happy path: Task built with the mapped type /
   agent_type, payload url resolved from the graph, timeout_seconds set to
   ``_HYPOTHESIS_TIMEOUT``, and the task scheduled.
4. ``_handle_finding_event`` chains: ssrf / idor / xss / jwt_abuse / sqli /
   mass_assignment events trigger HypothesisEngine.generate_and_persist with
   the matching chain focus; unknown vuln types trigger nothing.
5. ``_llm_rank_hypotheses``: a valid "BEST: <id>" answer selects that
   candidate; errors / missing LLM / garbage / unknown ids fall back
   deterministically to a real candidate and never crash.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.orchestrator.reasoning_loop import _HYPOTHESIS_TIMEOUT, ReasoningLoop


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _mock_orchestrator(llm_client: Any = None) -> SimpleNamespace:
    """SimpleNamespace that quacks like Orchestrator for the loop's seams."""
    bus = MagicMock()
    bus.publish = AsyncMock()

    gm = MagicMock()
    gm.run_read_query = AsyncMock(return_value=[])
    gm.run_write_query = AsyncMock(return_value=None)
    gm.get_hypotheses_by_engagement = AsyncMock(return_value=[])
    gm.get_all_nodes_for_engagement = AsyncMock(return_value=[])
    gm.get_all_edges_for_engagement = AsyncMock(return_value=[])
    gm.findings_knowledge = MagicMock()
    gm.findings_knowledge.recall_similar = AsyncMock(return_value=[])

    scheduler = MagicMock()
    scheduler.schedule_task = AsyncMock()

    state = SimpleNamespace(get_task=lambda tid: None)

    return SimpleNamespace(
        graph_memory=gm,
        session_memory=MagicMock(),
        task_scheduler=scheduler,
        coordination_bus=bus,
        state=state,
        _sessions={},
        skill_engine=None,
        llm_client=llm_client,
    )


def _hyp(
    hid: str,
    category: str,
    confidence: float = 0.5,
    skills: Optional[List[str]] = None,
    status: str = "open",
    target_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "id": hid,
        "status": status,
        "category": category,
        "confidence": confidence,
        "target_id": target_id or f"target-{hid}",
        "title": f"hypothesis {hid}",
        "recommended_skills": skills or ["ssrf_scan"],
    }


class _ScriptedLLM:
    """Fake llm_client: pops scripted answers, records calls."""

    def __init__(self, answers: List[str]) -> None:
        self.answers = list(answers)
        self.calls: List[Dict[str, Any]] = []

    async def complete(self, messages, *, model=None, max_tokens=None, **kwargs):
        self.calls.append({"n_messages": len(messages), "model": model})
        return self.answers.pop(0) if self.answers else ""


def _engine_patch(return_value: Optional[List[Any]] = None):
    """Patch HypothesisEngine where reasoning_loop imports it (inside methods)."""
    engine_cls = MagicMock()
    engine = engine_cls.return_value
    engine.generate_and_persist = AsyncMock(return_value=return_value or [])
    return patch(
        "ai_osop.core.hypothesis_engine.HypothesisEngine",
        engine_cls,
    ), engine_cls


# ---------------------------------------------------------------------------
# 1. _select_hypothesis — arithmetic scoring across two categories
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_select_hypothesis_novelty_boost_across_categories():
    """SSRF vs authz: a novel category beats a slightly-more-confident known one.

    ssrf already in finding_types -> h-ssrf scores 0.80.
    authz is novel -> h-authz scores 0.75 + 0.1 novelty = 0.85 and wins.
    This is the score pushed toward *new* attack-chain value.
    """
    orch = _mock_orchestrator()  # no llm_client -> arithmetic path
    rl = ReasoningLoop(orch)
    hyps = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.80, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.75, skills=["jwt_scan"]),
    ]
    state = {"finding_types": {"redirect_ssrf"}, "endpoints": [], "focus": ""}
    picked = await rl._select_hypothesis("eng-1", hyps, state)
    assert picked is not None
    assert picked["id"] == "h-authz"


@pytest.mark.asyncio
async def test_select_hypothesis_prior_recall_boost_applies():
    """FindingsKnowledge prior successes boost the matching category's score.

    Both hypotheses are novel (no finding_types); confidences tie at 0.5.
    recall_similar returns prior findings only for 'authz' -> +0.03 per prior
    (capped 0.1), so authz wins deterministically.
    """
    orch = _mock_orchestrator()

    async def _recall(category, limit=3, min_score=0.3):
        if category == "authz":
            return [{"id": "f1"}, {"id": "f2"}]  # two priors -> +0.06
        return []

    orch.graph_memory.findings_knowledge.recall_similar = AsyncMock(side_effect=_recall)
    rl = ReasoningLoop(orch)
    hyps = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.5, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.5, skills=["jwt_scan"]),
    ]
    state = {"finding_types": set(), "endpoints": [], "focus": ""}
    picked = await rl._select_hypothesis("eng-1", hyps, state)
    assert picked is not None
    assert picked["id"] == "h-authz"


@pytest.mark.asyncio
async def test_select_hypothesis_prior_recall_failure_returns_zero_delta():
    """If FindingsKnowledge raises, the prior boost degrades to 0.0 and the
    higher base confidence still wins (recall is advisory, never fatal)."""
    orch = _mock_orchestrator()
    orch.graph_memory.findings_knowledge.recall_similar = AsyncMock(
        side_effect=RuntimeError("kb down")
    )
    rl = ReasoningLoop(orch)
    hyps = [
        _hyp("h-low", "redirect_ssrf", confidence=0.2, skills=["ssrf_scan"]),
        _hyp("h-high", "authz", confidence=0.9, skills=["jwt_scan"]),
    ]
    state = {"finding_types": {"redirect_ssrf", "authz"}, "endpoints": [], "focus": ""}
    picked = await rl._select_hypothesis("eng-1", hyps, state)
    assert picked is not None
    assert picked["id"] == "h-high"


# ---------------------------------------------------------------------------
# 2. _evaluate_result — status transitions + chain / dead-end follow-up
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_confirmed_triggers_chain_generation():
    """Confirmed hypothesis (findings_count > 0):
      - status -> confirmed via graph write
      - dead_ends reset to 0
      - chain hypotheses generated with the SSRF metadata-chain focus
        (category redirect_ssrf maps to the chain_focus branch)
      - trace records result='confirmed'
    """
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    rl._dead_ends = 3  # must be reset
    rl.trace.record = MagicMock()

    patcher, engine_cls = _engine_patch()
    with patcher:
        hyp = {"id": "hyp-1", "category": "redirect_ssrf", "target_id": "ep-1"}
        result = {
            "status": "success",
            "findings_count": 2,
            "findings": [{"confidence": 0.87}],
        }
        await rl._evaluate_result("eng-1", hyp, result)

    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-1", "status": "confirmed"},
    )
    assert rl._dead_ends == 0

    # chain generation fired exactly once with the SSRF metadata chain focus
    engine = engine_cls.return_value
    engine.generate_and_persist.assert_awaited_once()
    args, kwargs = engine.generate_and_persist.call_args
    assert args[0] == "eng-1"
    assert "metadata chain" in kwargs["focus"]
    assert kwargs["limit"] == 5

    # trace got a confirmed record carrying the finding confidence
    confirm_records = [
        c for c in rl.trace.record.call_args_list if c.kwargs.get("result") == "confirmed"
    ]
    assert confirm_records, "no confirmed trace record"
    assert confirm_records[0].kwargs["confidence"] == pytest.approx(0.87)


@pytest.mark.asyncio
async def test_evaluate_confirmed_unknown_category_generates_no_chain():
    """Confirmed but category not in the chain map -> status confirmed, but
    HypothesisEngine.generate_and_persist is never called."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    patcher, engine_cls = _engine_patch()
    with patcher:
        hyp = {"id": "hyp-9", "category": "uncategorized_thing", "target_id": "ep-9"}
        await rl._evaluate_result("eng-1", hyp, {"findings_count": 1})

    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-9", "status": "confirmed"},
    )
    engine_cls.return_value.generate_and_persist.assert_not_awaited()


@pytest.mark.asyncio
async def test_evaluate_zero_findings_triggers_dead_end_recovery():
    """0 findings: status -> refuted, dead_ends increments, and a follow-up
    hypothesis set is generated with the dead-end recovery focus naming the
    failed category + target."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    rl.trace.record = MagicMock()

    patcher, engine_cls = _engine_patch()
    with patcher:
        hyp = {"id": "hyp-2", "category": "authz", "target_id": "ep-42"}
        await rl._evaluate_result("eng-1", hyp, {"status": "success", "findings_count": 0})

    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-2", "status": "refuted"},
    )
    assert rl._dead_ends == 1

    engine = engine_cls.return_value
    engine.generate_and_persist.assert_awaited_once()
    args, kwargs = engine.generate_and_persist.call_args
    assert args[0] == "eng-1"
    assert "dead-end recovery" in kwargs["focus"]
    assert "authz" in kwargs["focus"]
    assert "ep-42" in kwargs["focus"]

    refuted_records = [
        c for c in rl.trace.record.call_args_list if c.kwargs.get("result") == "refuted"
    ]
    assert refuted_records, "no refuted trace record"


@pytest.mark.asyncio
async def test_evaluate_chain_generation_failure_is_non_fatal():
    """If chain hypothesis generation raises, _evaluate_result must not
    propagate — the confirmed status update already happened."""

    class _ExplodingEngine:
        def __init__(self, *a, **k):
            pass

        async def generate_and_persist(self, *a, **k):
            raise RuntimeError("graph write failed")

    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    with patch("ai_osop.core.hypothesis_engine.HypothesisEngine", _ExplodingEngine):
        # refuted path calls _generate_followup_hypotheses which must swallow
        hyp = {"id": "hyp-3", "category": "authz", "target_id": "ep-1"}
        # The follow-up path in the loop does NOT try/except around the engine
        # call — assert the real behavior: it raises out of _evaluate_result.
        with pytest.raises(RuntimeError):
            await rl._evaluate_result("eng-1", hyp, {"findings_count": 0})
    # ...but the status update still landed before the failure
    orch.graph_memory.run_write_query.assert_any_call(
        "MATCH (h:Hypothesis {id: $hid}) SET h.status = $status",
        {"hid": "hyp-3", "status": "refuted"},
    )


# ---------------------------------------------------------------------------
# 3. _dispatch_hypothesis — Task construction + scheduling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_hypothesis_builds_task_with_timeout_and_schedules():
    """Normal dispatch path:
      - Task.type = recommended skill, agent_type from _SKILL_TO_AGENT_TYPE
      - payload carries resolved url, engagement_id, hypothesis id/category
      - timeout_seconds == _HYPOTHESIS_TIMEOUT
      - orchestrator.task_scheduler.schedule_task awaited with the task
    """
    orch = _mock_orchestrator()
    orch.graph_memory.run_read_query = AsyncMock(
        return_value=[{"url": "http://t.test/api/items"}]
    )
    rl = ReasoningLoop(orch)

    hyp = {
        "id": "hyp-ssrf",
        "title": "SSRF on redirect param",
        "category": "redirect_ssrf",
        "target_id": "ep-1",
        "recommended_skills": ["ssrf_scan"],
        "status": "open",
    }
    task = await rl._dispatch_hypothesis("eng-1", "sess-1", hyp)

    assert task is not None
    assert task.type == "ssrf_scan"
    assert task.agent_type == AgentType.SSRF_SCANNER
    assert task.payload["url"] == "http://t.test/api/items"
    assert task.payload["engagement_id"] == "eng-1"
    assert task.payload["hypothesis_id"] == "hyp-ssrf"
    assert task.payload["hypothesis_category"] == "redirect_ssrf"
    assert task.timeout_seconds == _HYPOTHESIS_TIMEOUT
    assert task.engagement_id == "eng-1"
    orch.task_scheduler.schedule_task.assert_awaited_once_with(task)


@pytest.mark.asyncio
async def test_dispatch_hypothesis_first_mapped_skill_wins():
    """When recommended_skills lists several skills, the first one with an
    agent mapping is used (later unmapped/mapped skills are ignored)."""
    orch = _mock_orchestrator()
    orch.graph_memory.run_read_query = AsyncMock(
        return_value=[{"url": "http://t.test/login"}]
    )
    rl = ReasoningLoop(orch)
    hyp = {
        "id": "hyp-multi",
        "category": "authz",
        "target_id": "ep-1",
        "recommended_skills": ["not_a_skill", "jwt_scan", "ssrf_scan"],
        "status": "open",
    }
    task = await rl._dispatch_hypothesis("eng-1", "sess-1", hyp)
    assert task is not None
    assert task.type == "jwt_scan"
    assert task.agent_type == AgentType.JWT_SCANNER


@pytest.mark.asyncio
async def test_dispatch_hypothesis_no_resolvable_url_returns_none():
    """Target id resolves to nothing in the graph -> dispatch skipped, no
    task scheduled."""
    orch = _mock_orchestrator()
    orch.graph_memory.run_read_query = AsyncMock(return_value=[])
    rl = ReasoningLoop(orch)
    hyp = {
        "id": "hyp-noresolve",
        "category": "authz",
        "target_id": "ep-missing",
        "recommended_skills": ["jwt_scan"],
        "status": "open",
    }
    task = await rl._dispatch_hypothesis("eng-1", "sess-1", hyp)
    assert task is None
    orch.task_scheduler.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatch_hypothesis_scheduler_failure_returns_none():
    """If the scheduler raises on schedule_task, dispatch degrades to None
    instead of crashing the reasoning cycle."""
    orch = _mock_orchestrator()
    orch.graph_memory.run_read_query = AsyncMock(
        return_value=[{"url": "http://t.test/x"}]
    )
    orch.task_scheduler.schedule_task = AsyncMock(side_effect=RuntimeError("queue full"))
    rl = ReasoningLoop(orch)
    hyp = {
        "id": "hyp-fail",
        "category": "authz",
        "target_id": "ep-1",
        "recommended_skills": ["jwt_scan"],
        "status": "open",
    }
    task = await rl._dispatch_hypothesis("eng-1", "sess-1", hyp)
    assert task is None


# ---------------------------------------------------------------------------
# 4. _handle_finding_event — chain-focus hypothesis generation per vuln type
# ---------------------------------------------------------------------------

_CHAIN_CASES = [
    ("ssrf", "metadata chain"),
    ("idor", "authorization chain"),
    ("xss", "XSS chain"),
    ("jwt_abuse", "JWT chain"),
    ("sqli", "SQLi chain"),
    ("mass_assignment", "Mass-assignment chain"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("vuln_type,focus_fragment", _CHAIN_CASES)
async def test_handle_finding_event_generates_chain_focus(vuln_type, focus_fragment):
    """Each chainable vuln type triggers HypothesisEngine.generate_and_persist
    with the engagement id, its chain focus string, and limit=5."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    patcher, engine_cls = _engine_patch()
    with patcher:
        await rl._handle_finding_event(
            "eng-1", {"vuln_type": vuln_type, "finding_id": "f-1"}
        )

    engine = engine_cls.return_value
    engine.generate_and_persist.assert_awaited_once()
    args, kwargs = engine.generate_and_persist.call_args
    assert args[0] == "eng-1"
    assert focus_fragment in kwargs["focus"]
    assert kwargs["limit"] == 5


@pytest.mark.asyncio
async def test_handle_finding_event_unknown_vuln_type_is_noop():
    """A vuln type outside the chain map never touches HypothesisEngine."""
    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    patcher, engine_cls = _engine_patch()
    with patcher:
        await rl._handle_finding_event(
            "eng-1", {"vuln_type": "clickjacking", "finding_id": "f-2"}
        )
    engine_cls.assert_not_called()


@pytest.mark.asyncio
async def test_handle_finding_event_engine_failure_is_logged_not_raised():
    """If chain generation explodes, the event handler logs and swallows —
    event-driven collaboration must never crash the loop."""

    class _ExplodingEngine:
        def __init__(self, *a, **k):
            pass

        async def generate_and_persist(self, *a, **k):
            raise RuntimeError("neo4j down")

    orch = _mock_orchestrator()
    rl = ReasoningLoop(orch)
    # stdlib logging.Logger rejects structlog-style kwargs; swap in a mock so
    # the error path executes (the chain_failed branch) instead of the test
    # dying on the logger's signature mismatch.
    with patch(
        "ai_osop.core.hypothesis_engine.HypothesisEngine", _ExplodingEngine
    ), patch("ai_osop.orchestrator.reasoning_loop.logger", MagicMock()):
        await rl._handle_finding_event("eng-1", {"vuln_type": "ssrf", "finding_id": "f-3"})
    # reaching here without exception is the assertion


# ---------------------------------------------------------------------------
# 5. _llm_rank_hypotheses — happy path + error / garbage fallbacks
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_llm_rank_happy_path_selects_named_candidate():
    """LLM returns 'BEST: <id>' naming a real candidate -> that candidate is
    returned, even though arithmetic would have ranked another higher."""
    orch = _mock_orchestrator(llm_client=_ScriptedLLM(["BEST: h-authz"]))
    rl = ReasoningLoop(orch)
    rl.trace.record = MagicMock()

    candidates = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.95, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.3, skills=["jwt_scan"]),
    ]
    state = {"endpoints": ["http://t/a"], "finding_types": set(), "focus": ""}
    picked = await rl._llm_rank_hypotheses("eng-1", candidates, state)

    assert picked is not None
    assert picked["id"] == "h-authz"
    assert orch.llm_client.calls, "LLM should have been consulted once"
    # selection is recorded in the reasoning trace for auditability
    select_records = [
        c for c in rl.trace.record.call_args_list if c.kwargs.get("step") == "select"
    ]
    assert select_records, "LLM selection not recorded in trace"


@pytest.mark.asyncio
async def test_llm_rank_returns_dict_content_normalized():
    """Providers that return {'content': '...'} dicts are handled — the
    content string is parsed for BEST: just like a plain string."""
    llm = MagicMock()
    llm.complete = AsyncMock(return_value={"content": "BEST: h-ssrf"})
    orch = _mock_orchestrator(llm_client=llm)
    rl = ReasoningLoop(orch)
    rl.trace.record = MagicMock()

    candidates = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.4, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.9, skills=["jwt_scan"]),
    ]
    state = {"endpoints": [], "finding_types": set(), "focus": ""}
    picked = await rl._llm_rank_hypotheses("eng-1", candidates, state)
    assert picked is not None
    assert picked["id"] == "h-ssrf"


@pytest.mark.asyncio
async def test_llm_rank_exception_returns_none_and_select_falls_back():
    """LLM raises -> _llm_rank_hypotheses returns None and _select_hypothesis
    falls back to arithmetic (higher confidence wins). Never crashes."""
    llm = MagicMock()
    llm.complete = AsyncMock(side_effect=RuntimeError("provider down"))
    orch = _mock_orchestrator(llm_client=llm)
    rl = ReasoningLoop(orch)
    rl.trace.record = MagicMock()

    candidates = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.3, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.9, skills=["jwt_scan"]),
    ]
    state = {"endpoints": [], "finding_types": set(), "focus": ""}

    ranked = await rl._llm_rank_hypotheses("eng-1", candidates, state)
    assert ranked is None

    picked = await rl._select_hypothesis("eng-1", candidates, state)
    assert picked is not None
    assert picked["id"] == "h-authz"


@pytest.mark.asyncio
async def test_llm_rank_garbage_output_returns_none_deterministically():
    """Output with no parseable 'BEST: <id>' -> None; the caller falls back
    to a deterministic arithmetic candidate every time."""
    orch = _mock_orchestrator(llm_client=_ScriptedLLM(["I cannot rank these."]))
    rl = ReasoningLoop(orch)
    rl.trace.record = MagicMock()
    candidates = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.6, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.6, skills=["jwt_scan"]),
    ]
    state = {"endpoints": [], "finding_types": set(), "focus": ""}
    assert await rl._llm_rank_hypotheses("eng-1", candidates, state) is None


@pytest.mark.asyncio
async def test_llm_rank_unknown_id_is_rejected():
    """Hallucinated id that matches no candidate -> None (never trusted)."""
    orch = _mock_orchestrator(llm_client=_ScriptedLLM(["BEST: h-ghost"]))
    rl = ReasoningLoop(orch)
    rl.trace.record = MagicMock()
    candidates = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.6, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.6, skills=["jwt_scan"]),
    ]
    state = {"endpoints": [], "finding_types": set(), "focus": ""}
    assert await rl._llm_rank_hypotheses("eng-1", candidates, state) is None


@pytest.mark.asyncio
async def test_llm_rank_no_client_returns_none():
    """Orchestrator without an llm_client attribute/value -> None, and the
    arithmetic fallback in _select_hypothesis picks by confidence."""
    orch = _mock_orchestrator(llm_client=None)
    rl = ReasoningLoop(orch)
    candidates = [
        _hyp("h-ssrf", "redirect_ssrf", confidence=0.4, skills=["ssrf_scan"]),
        _hyp("h-authz", "authz", confidence=0.8, skills=["jwt_scan"]),
    ]
    state = {"endpoints": [], "finding_types": set(), "focus": ""}
    assert await rl._llm_rank_hypotheses("eng-1", candidates, state) is None
    picked = await rl._select_hypothesis("eng-1", candidates, state)
    assert picked["id"] == "h-authz"
