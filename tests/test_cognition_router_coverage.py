"""Coverage tests for ai_osop.api.routers.cognition.

Drives every cognition route through the real FastAPI router mounted on a
bare app, with ``verify_token`` dependency-overridden and ``deps.state``
bound to a fake orchestrator. Mirrors the fixture pattern from
tests/test_findings_router_coverage.py and the mocked-orchestrator style
from tests/test_engagement_manager_coverage.py: the route handlers execute
end-to-end against an in-memory ReasoningLoop / GraphMemory double.

Routes covered:
  - GET /engagements/{sid}/reasoning-trace
  - GET /engagements/{sid}/uncertainties
  - GET /engagements/{sid}/business-context
  - GET /engagements/{sid}/attack-chains
  - GET /engagements/{sid}/critic-review
  - GET /engagements/{sid}/cognition-summary

NOTE: the round-up in the task referenced /learning-dashboard and
/mission-summary — those paths do not exist in
src/ai_osop/api/routers/cognition.py. The router's actual surface is the
six GETs above, so that's what is driven here.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers import cognition as cognition_router
from ai_osop.core.enums import EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


def _session(short_id: str = "eng-1", full_id: str = "eng-20260802-eng-1") -> SessionState:
    """Real SessionState so engagement_id_forms produces multiple forms."""
    return SessionState(
        session_id=full_id,
        phase=EngagementPhase.RECONNAISSANCE.value,
        scope=ScopeDefinition(engagement_id=short_id, domains=["example.test"]),
        roe={},
    )


def _fake_graph(read_rows: Optional[List[Dict[str, Any]]] = None):
    """GraphMemory double: run_read_query returns canned records (or [])."""
    gm = MagicMock()
    gm.run_read_query = AsyncMock(return_value=list(read_rows or []))
    return gm


def _fake_session_memory():
    sm = MagicMock()
    sm.load_session_state = AsyncMock(return_value=None)
    return sm


def _fake_reasoning_loop(
    *,
    trace_entries: Optional[List[Dict[str, Any]]] = None,
    trace_summary: Optional[Dict[str, Any]] = None,
    open_uncertainties: Optional[List[Any]] = None,
    uncertainty_summary: Optional[Dict[str, Any]] = None,
    dead_ends: int = 0,
    tested_hypotheses: Optional[set] = None,
):
    """Mock ReasoningLoop exposing just what cognition.py touches.

    ``rl.trace.get_trace(*forms)`` and ``rl.trace.get_summary(*forms)`` are
    attribute lookups on the loop; ``rl._uncertainty_tracker`` is duck-typed.
    """
    trace = MagicMock()
    trace.get_trace = MagicMock(return_value=list(trace_entries or []))
    trace.get_summary = MagicMock(
        return_value=dict(
            trace_summary
            or {"total_steps": 0, "confirmed": 0, "refuted": 0, "chains": 0, "pivots": 0}
        )
    )

    tracker = MagicMock()
    tracker.get_open_uncertainties = MagicMock(return_value=list(open_uncertainties or []))
    tracker.get_summary = MagicMock(
        return_value=dict(uncertainty_summary or {"total": 0, "resolved": 0, "open": 0})
    )

    rl = MagicMock()
    rl.trace = trace
    rl._uncertainty_tracker = tracker
    rl._dead_ends = dead_ends
    rl._tested_hypotheses = set(tested_hypotheses or set())
    return rl


def _fake_orch(
    *,
    session: Optional[SessionState] = None,
    graph=None,
    session_memory=None,
    reasoning_loop=None,
):
    """Fake Orchestrator namespace for deps.state['orchestrator']."""
    orch = SimpleNamespace()
    orch.graph_memory = graph or _fake_graph()
    orch.session_memory = session_memory or _fake_session_memory()
    orch.reasoning_loop = reasoning_loop
    orch._sessions = {}
    if session is not None:
        orch._sessions[session.session_id] = session
        if session.scope.engagement_id != session.session_id:
            orch._sessions[session.scope.engagement_id] = session
    return orch


def _operator(role: str = "senior_operator", sub: str = "op-1") -> Dict[str, Any]:
    return {"sub": sub, "role": role, "claims": {}, "tenant_id": "default"}


# --------------------------------------------------------------------------- #
# App / fixtures                                                              #
# --------------------------------------------------------------------------- #


@pytest.fixture
def app_with_cognition():
    """Bare FastAPI app with ONLY the cognition router, verify_token overridden."""
    app = FastAPI(title="cognition-test-app")
    app.include_router(cognition_router.router)

    async def _fake_verify_token():
        return _operator()

    app.dependency_overrides[verify_token] = _fake_verify_token

    yield app

    app.dependency_overrides.clear()


@pytest.fixture
def bound_state(monkeypatch):
    """Bind a fake orchestrator into deps.state for the duration of a test."""
    original = dict(state)

    def _bind(orch):
        monkeypatch.setitem(state, "orchestrator", orch)

    yield _bind

    state.clear()
    state.update(original)


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/reasoning-trace                                      #
# --------------------------------------------------------------------------- #


class TestReasoningTrace:
    async def test_no_reasoning_loop_returns_empty_trace(self, app_with_cognition, bound_state):
        """orch.reasoning_loop is None — the route returns the documented empty shape."""
        session = _session()
        orch = _fake_orch(session=session, reasoning_loop=None)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/reasoning-trace")

        assert resp.status_code == 200
        body = resp.json()
        assert body == {"session_id": session.session_id, "count": 0, "trace": []}

    async def test_returns_trace_entries_from_loop(self, app_with_cognition, bound_state):
        """With a ReasoningLoop attached, entries flow through unchanged and
        get_trace is called with the id forms of this engagement."""
        session = _session()
        entries = [
            {
                "step": "hypothesize",
                "decision": "test /api/users for IDOR",
                "rationale": "sequential ids",
                "confidence": 0.7,
                "alternatives_considered": ["csrf", "xss"],
                "alternatives_rejected": ["csrf"],
                "result": "pending",
            },
            {
                "step": "evaluate",
                "decision": "confirm IDOR",
                "rationale": "user A read user B record",
                "confidence": 0.95,
                "alternatives_considered": [],
                "alternatives_rejected": [],
                "result": "confirmed",
            },
        ]
        rl = _fake_reasoning_loop(trace_entries=entries)
        orch = _fake_orch(session=session, reasoning_loop=rl)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/reasoning-trace")

        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == session.session_id
        assert body["count"] == 2
        assert body["trace"] == entries

        # get_trace was called with the id forms (session_id + scope short id)
        rl.trace.get_trace.assert_called_once()
        forms_used = rl.trace.get_trace.call_args.args
        assert session.session_id in forms_used
        assert session.scope.engagement_id in forms_used

    async def test_trace_absent_on_loop_returns_empty(self, app_with_cognition, bound_state):
        """A loop object without a ``trace`` attribute falls into the empty branch."""
        session = _session()
        rl = SimpleNamespace()  # no .trace
        orch = _fake_orch(session=session, reasoning_loop=rl)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/reasoning-trace")

        assert resp.status_code == 200
        assert resp.json() == {"session_id": session.session_id, "count": 0, "trace": []}


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/uncertainties                                        #
# --------------------------------------------------------------------------- #


class TestUncertainties:
    async def test_no_reasoning_loop_returns_empty(self, app_with_cognition, bound_state):
        session = _session()
        orch = _fake_orch(session=session, reasoning_loop=None)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/uncertainties")

        assert resp.status_code == 200
        assert resp.json() == {
            "session_id": session.session_id,
            "count": 0,
            "uncertainties": [],
            "summary": {},
        }

    async def test_returns_open_uncertainties_and_summary(self, app_with_cognition, bound_state):
        """Open uncertainties are dumped via __dict__; summary is passed through."""
        session = _session()
        unc1 = SimpleNamespace(
            id="unc-1", kind="auth", question="is /admin authenticated?", resolved=False
        )
        unc2 = SimpleNamespace(
            id="unc-2", kind="framework", question="what framework?", resolved=False
        )
        rl = _fake_reasoning_loop(
            open_uncertainties=[unc1, unc2],
            uncertainty_summary={"total": 5, "resolved": 3, "open": 2},
        )
        orch = _fake_orch(session=session, reasoning_loop=rl)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/uncertainties")

        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == session.session_id
        assert body["count"] == 2
        assert body["summary"] == {"total": 5, "resolved": 3, "open": 2}
        # __dict__ keys round-tripped
        questions = {u["question"] for u in body["uncertainties"]}
        assert questions == {"is /admin authenticated?", "what framework?"}

    async def test_loop_without_tracker_returns_empty(self, app_with_cognition, bound_state):
        """hasattr(rl, '_uncertainty_tracker') is False — return the stub."""
        session = _session()
        rl = SimpleNamespace()  # no _uncertainty_tracker
        orch = _fake_orch(session=session, reasoning_loop=rl)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/uncertainties")

        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 0
        assert body["uncertainties"] == []


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/business-context                                     #
# --------------------------------------------------------------------------- #


class TestBusinessContext:
    async def test_no_endpoints_returns_zero_count(self, app_with_cognition, bound_state):
        session = _session()
        graph = _fake_graph(read_rows=[])
        orch = _fake_orch(session=session, graph=graph)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/business-context")

        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == session.session_id
        assert body["count"] == 0
        assert body["endpoints"] == []
        assert body["high_value_count"] == 0

    async def test_categorizes_payment_endpoint_as_high_value(
        self, app_with_cognition, bound_state
    ):
        """Real batch_categorize runs against the records graph returns:
        /api/payment/checkout matches the payment domain (criticality 10),
        /about is uncategorized (criticality 3)."""
        session = _session()
        rows = [
            {
                "url": "https://example.test/api/payment/checkout",
                "path": "/api/payment/checkout",
                "method": "POST",
                "query_keys": [],
                "status_code": 200,
                "technologies": [],
                "auth_required": True,
                "id": "ep-1",
            },
            {
                "url": "https://example.test/about",
                "path": "/about",
                "method": "GET",
                "query_keys": [],
                "status_code": 200,
                "technologies": [],
                "auth_required": False,
                "id": "ep-2",
            },
        ]
        graph = _fake_graph(read_rows=rows)
        orch = _fake_orch(session=session, graph=graph)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/business-context")

        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 2
        # /api/payment/checkout is a payment endpoint (criticality 10) — counted HV.
        assert body["high_value_count"] == 1
        categories = {ep["url"]: ep["category"] for ep in body["endpoints"]}
        assert categories["https://example.test/api/payment/checkout"] == "payment"
        # "/about" contains the substring "out" which matches the redirect
        # domain's patterns — the batch_categorize heuristic is substring-based,
        # so the surfaced category is the redirect bucket. The criticality is
        # 5 (< 7), which is what keeps it out of high_value_count.
        assert categories["https://example.test/about"] == "redirect"
        assert body["high_value_count"] == 1  # only the payment endpoint clears 7.

        # The graph was queried with the engagement id forms, not just one.
        graph.run_read_query.assert_awaited_once()
        params = graph.run_read_query.await_args.args[1]
        assert set(params["ids"]) >= {session.session_id, session.scope.engagement_id}

    async def test_graph_failure_returns_empty_not_500(self, app_with_cognition, bound_state):
        """The try/except around run_read_query swallows the failure and the
        route still returns the empty shape — operators shouldn't see a 500
        because Neo4j hiccuped."""
        session = _session()
        graph = _fake_graph()
        graph.run_read_query = AsyncMock(side_effect=ConnectionError("neo4j down"))
        orch = _fake_orch(session=session, graph=graph)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/business-context")

        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 0
        assert body["endpoints"] == []


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/attack-chains                                        #
# --------------------------------------------------------------------------- #


class TestAttackChains:
    async def test_no_chains_on_empty_graph(self, app_with_cognition, bound_state):
        """Real GraphPathfinder against an empty graph returns zero chains.

        This is the 'real counts, not stubs' assertion — the route isn't
        hardcoded to 0; the pathfinder actually iterated and found nothing.
        """
        session = _session()
        graph = _fake_graph(read_rows=[])
        orch = _fake_orch(session=session, graph=graph)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/attack-chains")

        assert resp.status_code == 200
        body = resp.json()
        assert body == {"session_id": session.session_id, "count": 0, "chains": []}
        # Pathfinder actually ran queries against the graph.
        assert graph.run_read_query.await_count > 0


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/critic-review                                        #
# --------------------------------------------------------------------------- #


class TestCriticReview:
    async def test_no_critiques_on_empty_graph(self, app_with_cognition, bound_state):
        """Real PostEngagementCriticAgent against an empty graph returns []."""
        session = _session()
        graph = _fake_graph(read_rows=[])
        session_memory = _fake_session_memory()
        orch = _fake_orch(session=session, graph=graph, session_memory=session_memory)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/critic-review")

        assert resp.status_code == 200
        body = resp.json()
        assert body == {"session_id": session.session_id, "count": 0, "critiques": []}


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/cognition-summary                                    #
# --------------------------------------------------------------------------- #


class TestCognitionSummary:
    async def test_all_zeros_when_no_loop_and_empty_graph(
        self, app_with_cognition, bound_state
    ):
        """No reasoning loop + empty graph: every counter is the documented default."""
        session = _session()
        orch = _fake_orch(session=session, reasoning_loop=None)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/cognition-summary")

        assert resp.status_code == 200
        body = resp.json()
        assert body["session_id"] == session.session_id
        assert body["reasoning_trace"] == {
            "total_steps": 0,
            "confirmed": 0,
            "refuted": 0,
            "chains": 0,
            "pivots": 0,
        }
        assert body["uncertainties"] == {"total": 0, "resolved": 0, "open": 0}
        assert body["attack_chains"] == 0
        assert body["critic_issues"] == 0
        assert body["high_value_endpoints"] == 0
        assert body["dead_ends"] == 0
        assert body["tested_hypotheses"] == 0

    async def test_aggregates_from_reasoning_loop(self, app_with_cognition, bound_state):
        """With a populated ReasoningLoop the summary surfaces its counters."""
        session = _session()
        rl = _fake_reasoning_loop(
            trace_summary={
                "total_steps": 12,
                "confirmed": 3,
                "refuted": 1,
                "chains": 0,
                "pivots": 2,
            },
            uncertainty_summary={"total": 4, "resolved": 1, "open": 3},
            dead_ends=2,
            tested_hypotheses={"h1", "h2", "h3"},
        )
        orch = _fake_orch(session=session, reasoning_loop=rl)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/cognition-summary")

        assert resp.status_code == 200
        body = resp.json()
        assert body["reasoning_trace"]["total_steps"] == 12
        assert body["reasoning_trace"]["confirmed"] == 3
        assert body["reasoning_trace"]["pivots"] == 2
        assert body["uncertainties"] == {"total": 4, "resolved": 1, "open": 3}
        assert body["dead_ends"] == 2
        assert body["tested_hypotheses"] == 3
        # Downstream aggregations against an empty graph still resolve to 0.
        assert body["attack_chains"] == 0
        assert body["critic_issues"] == 0

    async def test_survives_business_context_graph_failure(
        self, app_with_cognition, bound_state
    ):
        """The business-context block is wrapped in try/except — a Neo4j failure
        there must not 500 the endpoint; high_value_endpoints just stays 0."""
        session = _session()
        graph = _fake_graph()
        graph.run_read_query = AsyncMock(side_effect=RuntimeError("graph down"))
        rl = _fake_reasoning_loop(
            trace_summary={
                "total_steps": 1,
                "confirmed": 0,
                "refuted": 0,
                "chains": 0,
                "pivots": 0,
            }
        )
        orch = _fake_orch(session=session, graph=graph, reasoning_loop=rl)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/cognition-summary")

        assert resp.status_code == 200
        body = resp.json()
        # Trace summary still flowed through.
        assert body["reasoning_trace"]["total_steps"] == 1
        # Graph-dependent counters failed safe to 0.
        assert body["high_value_endpoints"] == 0
        assert body["attack_chains"] == 0

    async def test_survives_pathfinder_and_critic_failures(
        self, app_with_cognition, bound_state, monkeypatch
    ):
        """Both the attack-chains and critic-review sub-blocks in
        get_cognition_summary have their own try/except. Force both to raise
        so the ``except Exception: pass`` lines run, and confirm the route
        still returns 200 with zeroed counters."""
        session = _session()
        rl = _fake_reasoning_loop()
        orch = _fake_orch(session=session, reasoning_loop=rl)
        bound_state(orch)

        # Patch GraphPathfinder.find_chains and PostEngagementCriticAgent.audit_findings
        # to raise. They're imported lazily inside the handler, so patching the
        # source-module attributes intercepts before the ``from X import Y``.
        from ai_osop.core import graph_pathfinder
        from ai_osop.agents import critic_agent

        async def _boom_find_chains(self, engagement_id, max_depth=5, min_confidence=0.3):
            raise ConnectionError("pathfinder neo4j dead")

        async def _boom_audit(self, engagement_id):
            raise RuntimeError("critic blew up")

        monkeypatch.setattr(
            graph_pathfinder.GraphPathfinder, "find_chains", _boom_find_chains
        )
        monkeypatch.setattr(
            critic_agent.PostEngagementCriticAgent, "audit_findings", _boom_audit
        )

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get(f"/engagements/{session.session_id}/cognition-summary")

        assert resp.status_code == 200
        body = resp.json()
        # Both sub-blocks failed safe to 0 rather than propagating.
        assert body["attack_chains"] == 0
        assert body["critic_issues"] == 0


# --------------------------------------------------------------------------- #
# Authorization smoke tests (mirror of the findings router's access checks)   #
# --------------------------------------------------------------------------- #


class TestCognitionAuth:
    async def test_unknown_engagement_returns_404(self, app_with_cognition, bound_state):
        """assert_engagement_access runs before any of the handler — bind an
        orchestrator with no sessions to land on the 404 branch."""
        orch = _fake_orch(session=None)
        bound_state(orch)

        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get("/engagements/nope/reasoning-trace")

        assert resp.status_code == 404
        assert "Engagement not found" in resp.json()["detail"]

    async def test_orchestrator_unbound_returns_503(self, app_with_cognition):
        """state['orchestrator'] = None hits the 503 guard in assert_engagement_access."""
        # Deliberately do NOT bind state — fixture guarantees the original None.
        async with AsyncClient(
            transport=ASGITransport(app=app_with_cognition), base_url="http://t"
        ) as client:
            resp = await client.get("/engagements/any/reasoning-trace")
        assert resp.status_code == 503
        assert "Orchestrator not initialized" in resp.json()["detail"]
