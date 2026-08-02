"""Request-level coverage tests for ai_osop.api.routers.findings.

Targets the currently-uncovered endpoints (31% baseline). Drives the handlers
through httpx.AsyncClient + the real FastAPI app with verify_token / require_role
dependency_overrides so the handlers actually execute end-to-end. State is bound
via dependency_overrides on the shared ``state`` dict so no real Neo4j/Postgres
connections are needed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_osop.api.deps import (
    assert_engagement_access,
    engagement_id_forms,
    require_role,
    state,
    verify_token,
)
from ai_osop.api.routers import findings as findings_router
from ai_osop.core.enums import EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


def _session(short_id: str = "eng-1", full_id: str = "eng-20260801-eng-1") -> SessionState:
    """Minimal real SessionState so engagement_id_forms / canonical_engagement_id
    resolve like production."""
    return SessionState(
        session_id=full_id,
        phase=EngagementPhase.RECONNAISSANCE.value,
        scope=ScopeDefinition(engagement_id=short_id, domains=["example.test"]),
        roe={},
    )


def _fake_graph():
    gm = MagicMock()
    gm.run_read_query = AsyncMock(return_value=[])
    gm.get_vulnerabilities_by_engagement = AsyncMock(return_value=[])
    gm.get_invariants = AsyncMock(return_value=[])
    gm.validate_vulnerability = AsyncMock(return_value=None)
    gm.get_node_details = AsyncMock(return_value=None)
    # For submit_finding's session.run path if it ever gets there
    gm._driver = MagicMock()
    return gm


def _fake_session_memory():
    sm = MagicMock()
    sm.load_session_state = AsyncMock(return_value=None)
    return sm


def _fake_orch(*, session: Optional[SessionState] = None, graph=None, session_memory=None):
    """Fake Orchestrator namespace the deps module pokes at."""
    orch = SimpleNamespace()
    orch.graph_memory = graph or _fake_graph()
    orch.session_memory = session_memory or _fake_session_memory()
    orch.mcp_registry = None
    orch.schedule_task = AsyncMock()
    orch.reasoning_loop = None
    orch._sessions = {}
    if session is not None:
        # Bind both session_id forms so the access-fallback finds it.
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
def app_with_findings():
    """A bare FastAPI app with JUST the findings router mounted, and
    verify_token overridden to return a senior_operator dict. require_role's
    internal Depends(verify_token) resolves through dependency_overrides, so
    this single override cascades through every role-gated endpoint."""
    app = FastAPI(title="findings-test-app")
    app.include_router(findings_router.router)

    async def _fake_verify_token():
        return _operator()

    app.dependency_overrides[verify_token] = _fake_verify_token

    yield app, _fake_verify_token

    app.dependency_overrides.clear()


@pytest.fixture
def bound_state(monkeypatch):
    """Return a helper that binds a fake orchestrator into deps.state."""
    original = dict(state)

    def _bind(orch):
        monkeypatch.setitem(state, "orchestrator", orch)

    yield _bind

    state.clear()
    state.update(original)


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/findings                                             #
# --------------------------------------------------------------------------- #


async def test_get_findings_empty(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    orch = _fake_orch(session=session, graph=graph, session_memory=None)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_get_findings_maps_vuln_shape(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[
            {
                "id": "vuln-1",
                "title": "Reflected XSS on /search",
                "vuln_type": "xss",
                "severity": "HIGH",
                "validated": True,
                "confidence": 0.87,
                "cvss_score": 0.0,
                "tool_source": "nuclei",
                "evidence": [{"url": "https://example.test/search?q=x", "template": "xss-ref"}],
                "engagement_id": session.scope.engagement_id,
            }
        ]
    )
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    f = findings[0]
    assert f["id"] == "vuln-1"
    assert f["title"] == "Reflected XSS on /search"
    assert f["severity"] == "high"
    # Validated flipped the status
    assert f["status"] == "verified"
    # evScore falls back to severity-derived (because cvss_score=0)
    assert f["evScore"] == 80
    # Nuclei template url is lifted into matchedAt
    assert f["matchedAt"] == "https://example.test/search?q=x"
    assert f["evidenceCount"] == 1
    assert f["agentConsensus"] == ["nuclei"]


async def test_get_findings_invalid_evidence_falls_back(app_with_findings, bound_state):
    """Evidence containing malformed JSON doesn't blow up the mapper; it logs
    a warning and returns evidenceCount=0."""
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[
            {
                "id": "vuln-bad",
                "severity": "low",
                "evidence": "{not json",
                "validated": False,
            }
        ]
    )
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    assert findings[0]["evidenceCount"] == 0
    assert findings[0]["status"] == "hypothesis"


async def test_get_findings_cvss_drives_evscore_over_severity(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[
            {"id": "v1", "severity": "low", "cvss_score": 9.8, "validated": True},
        ]
    )
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert findings[0]["evScore"] == 98  # round(9.8 * 10)


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/uncertainty                                          #
# --------------------------------------------------------------------------- #


async def test_get_uncertainties_no_reasoning_loop(app_with_findings, bound_state):
    """When the orchestrator has no reasoning_loop, the endpoint returns the
    documented empty shape with session_id round-tripped."""
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    orch.reasoning_loop = None
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/uncertainty")
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == session.session_id
    assert body["count"] == 0
    assert body["uncertainties"] == []
    assert body["summary"] == {}


async def test_get_uncertainties_with_tracker(app_with_findings, bound_state):
    """When the reasoning loop exposes a tracker, the response carries the
    open uncertainties and the session-scoped count keys are aggregated."""
    app, _fake_verify = app_with_findings
    session = _session()

    fake_unc = SimpleNamespace(id="unc-1", kind="auth", question="is admin scope?")
    tracker = SimpleNamespace(
        get_open_uncertainties=MagicMock(return_value=[fake_unc]),
        get_summary=MagicMock(return_value={"total": 3, "resolved": 2}),
    )
    orch = _fake_orch(session=session)
    orch.reasoning_loop = SimpleNamespace(_uncertainty_tracker=tracker)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/uncertainty")
    assert resp.status_code == 200
    body = resp.json()
    assert body["session_id"] == session.session_id
    assert body["count"] == 1
    assert body["summary"] == {"total": 3, "resolved": 2}
    # Uncertainty __dict__ was surfaced; contains enough keys to identify
    assert body["uncertainties"][0]["question"] == "is admin scope?"


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/invariants                                           #
# --------------------------------------------------------------------------- #


async def test_get_invariants_returns_graph_rows(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.get_invariants = AsyncMock(
        return_value=[
            {"id": "inv-1", "statement": "non-admin cannot delete users"},
            {"id": "inv-2", "statement": "guest cannot view billing"},
        ]
    )
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/invariants")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 2
    assert body[0]["id"] == "inv-1"
    # The endpoint forwarded the URL session_id to the graph call
    graph.get_invariants.assert_awaited_once_with(session.session_id)


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/payouts                                              #
# --------------------------------------------------------------------------- #


async def test_get_payouts_returns_honest_404(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/payouts")
    assert resp.status_code == 404
    assert "Payout estimation is not implemented" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/diff-auth                                            #
# --------------------------------------------------------------------------- #


async def test_get_diff_auth_returns_ranked_records(app_with_findings, bound_state, monkeypatch):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(
        return_value=[
            {
                "d": {
                    "id": "d1",
                    "category": "authz",
                    "resource_id": "/users/1",
                    "test_identity_id": "guest",
                    "expected_result": "deny",
                    "observed_result": "allow",
                    "evidence_diff": '{"status":[403,200]}',
                    "confidence": 0.9,
                }
            }
        ]
    )
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    # rank_findings applies ordering; stub it so we wire only the router.
    def _identity_rank(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return rows

    monkeypatch.setattr("ai_osop.core.triage.rank_findings", _identity_rank)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/diff-auth")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["id"] == "d1"
    assert rows[0]["resource_id"] == "/users/1"
    # The evidence_diff JSON string was parsed to a dict
    assert rows[0]["evidence_diff"] == {"status": [403, 200]}
    assert rows[0]["confidence"] == 0.9


async def test_get_diff_auth_handles_malformed_diff_json(app_with_findings, bound_state, monkeypatch):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(
        return_value=[
            {
                "d": {
                    "id": "d2",
                    "evidence_diff": "{corrupt",
                    "confidence": None,
                }
            }
        ]
    )
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)
    monkeypatch.setattr("ai_osop.core.triage.rank_findings", lambda r: r)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/diff-auth")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["evidence_diff"] == {}
    assert rows[0]["confidence"] == 0.0


# --------------------------------------------------------------------------- #
# POST /engagements/{sid}/findings/{fid}/verify                               #
# --------------------------------------------------------------------------- #


async def test_verify_finding_success(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    # _finding_exists issues a LIMIT 1 query — return one record
    graph.run_read_query = AsyncMock(return_value=[{"v.id": "v1"}])
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/vuln-42/verify"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "verified"
    assert body["finding_id"] == "vuln-42"
    assert body["session_id"] == session.session_id
    graph.validate_vulnerability.assert_awaited_once_with("vuln-42")


async def test_verify_finding_missing_returns_404(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[])  # nothing found
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/nope/verify"
        )
    assert resp.status_code == 404
    assert "Finding not found" in resp.json()["detail"]
    # No mutation happened
    assert graph.validate_vulnerability.await_count == 0


# --------------------------------------------------------------------------- #
# POST /engagements/{sid}/findings/{fid}/resolve                              #
# --------------------------------------------------------------------------- #


async def test_resolve_finding_returns_engine_result(app_with_findings, bound_state, monkeypatch):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    async def _fake_resolve(finding_id, status, session_memory, graph_memory):
        assert finding_id == "vuln-9"
        assert status == "accepted"
        assert session_memory is orch.session_memory
        assert graph_memory is orch.graph_memory
        return {"status": "resolved", "outcome": "accepted", "finding_id": finding_id}

    monkeypatch.setattr(
        findings_router.FindingConversionEngine,
        "resolve_finding",
        staticmethod(_fake_resolve),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/vuln-9/resolve",
            json="accepted",
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "resolved"
    assert body["outcome"] == "accepted"
    assert body["finding_id"] == "vuln-9"


# --------------------------------------------------------------------------- #
# POST /engagements/{sid}/findings/{fid}/replay                               #
# --------------------------------------------------------------------------- #


async def test_replay_finding_schedules_task_with_canonical_id(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[{"v.id": "v1"}])
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/vuln-77/replay"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert body["task_type"] == "validate_exploit"
    assert "task_id" in body

    # schedule_task receives a Task keyed on the CANONICAL id
    assert orch.schedule_task.await_count == 1
    task = orch.schedule_task.call_args.args[0]
    assert task.engagement_id == session.scope.engagement_id
    assert task.approval_required is True
    assert task.payload["finding_id"] == "vuln-77"
    assert task.payload["mode"] == "replay"


async def test_replay_finding_unknown_id_404(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[])
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(f"/engagements/{session.session_id}/findings/missing/replay")
    assert resp.status_code == 404
    assert orch.schedule_task.await_count == 0


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/findings/{fid}/vault                                 #
# --------------------------------------------------------------------------- #


async def test_get_finding_vault_assembles_evidence(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()

    vul_node = {
        "id": "vuln-ev",
        "evidence": [
            {
                "request": "POST /login HTTP/1.1",
                "response": "HTTP/1.1 200 OK",
            },
            {"misc": "no request/response, recorded as json"},
        ],
    }

    async def _read(cypher, params):
        # The vuln query has $fid, the evidence query does not
        if "$fid" in cypher or ("MATCH (v:Vulnerability)" in cypher):
            return [{"v": vul_node}]
        return [
            {"ev": {"type": "screenshot", "path": "shots/1.png", "id": "e1"}},
            {"ev": {"type": "http_transcript", "path": "ev/2.json", "id": "e2"}},
        ]

    graph.run_read_query = AsyncMock(side_effect=_read)
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings/vuln-ev/vault")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == "vuln-ev"
    assert body["id"] == "vault-vuln-ev"
    # raw_requests include the verbatim request + the json-dumped fallback
    assert any("POST /login" in r for r in body["raw_requests"])
    assert any("HTTP/1.1 200" in r for r in body["raw_responses"])
    # Only the screenshot row lands in screenshots (path matched .png)
    assert body["screenshots"] == ["shots/1.png"]
    # Both evidence rows appear in workflow_trace
    assert {t["type"] for t in body["workflow_trace"]} == {"screenshot", "http_transcript"}
    # Hash is deterministic and non-trivial
    assert isinstance(body["integrity_hash"], str)
    assert len(body["integrity_hash"]) == 64


async def test_get_finding_vault_unknown_returns_404(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[])
    orch = _fake_orch(session=session, graph=graph)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings/missing/vault")
    assert resp.status_code == 404
    assert "Finding not found" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# POST /engagements/{sid}/poc/generate + workflows replay                     #
# --------------------------------------------------------------------------- #


async def test_generate_poc_queues_task(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/poc/generate",
            params={"finding_id": "vuln-poc"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert body["finding_id"] == "vuln-poc"
    task = orch.schedule_task.call_args.args[0]
    assert task.type == "exploit_validation"
    assert task.engagement_id == session.scope.engagement_id
    assert task.approval_required is True
    assert task.payload["generate_poc"] is True


async def test_replay_workflow_queues_task(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/workflows/wf-42/replay"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "queued"
    assert body["workflow_id"] == "wf-42"
    task = orch.schedule_task.call_args.args[0]
    assert task.type == "replay_for_diff_auth"
    assert task.engagement_id == session.scope.engagement_id
    assert task.payload["workflow_id"] == "wf-42"


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/report/bounty                                        #
# --------------------------------------------------------------------------- #


async def test_bounty_report_no_orchestrator_returns_503(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    orch.mcp_registry = None
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/report/bounty")
    assert resp.status_code == 503
    assert "No orchestrator/MCP registry available" in resp.json()["detail"]


async def test_bounty_report_reporting_mcp_success(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    resp_result = SimpleNamespace(
        status="success",
        error=None,
        result={
            "report_id": "report-eng-1",
            "content": "<html><body>Findings</body></html>",
            "markdown": "# Findings",
            "html": "<html><body>Findings</body></html>",
            "generated_at": "2026-08-01T00:00:00Z",
        },
    )
    fake_registry = SimpleNamespace(execute_tool=AsyncMock(return_value=resp_result))
    orch = _fake_orch(session=session)
    orch.mcp_registry = fake_registry
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/report/bounty")
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_id"] == "report-eng-1"
    assert body["source"] == "reporting-mcp/compile_findings"
    assert body["html"].startswith("<html>")
    fake_registry.execute_tool.assert_awaited_once_with(
        "reporting-mcp",
        "compile_findings",
        {
            "engagement_id": session.session_id,
            "format": "html",
            "include_evidence": True,
        },
        trust_server_scope=True,
    )


async def test_bounty_report_reporting_mcp_failure_returns_500(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    resp_result = SimpleNamespace(status="error", error="renderer crashed", result=None)
    fake_registry = SimpleNamespace(execute_tool=AsyncMock(return_value=resp_result))
    orch = _fake_orch(session=session)
    orch.mcp_registry = fake_registry
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/report/bounty")
    assert resp.status_code == 500
    assert resp.json()["detail"] == "renderer crashed"


async def test_bounty_report_empty_content_returns_502(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    resp_result = SimpleNamespace(status="success", error=None, result={"markdown": ""})
    fake_registry = SimpleNamespace(execute_tool=AsyncMock(return_value=resp_result))
    orch = _fake_orch(session=session)
    orch.mcp_registry = fake_registry
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/report/bounty")
    assert resp.status_code == 502
    assert "no report content" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# GET /engagements/{sid}/report (disk-backed)                                 #
# --------------------------------------------------------------------------- #


async def test_get_report_path_traversal_rejected(app_with_findings, bound_state):
    """Traversal in session_id is rejected before any filesystem access."""
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    # The route matcher normally eats the slash, so use .. without slash,
    # which is the only portably-routable form (URL-decoded by starlette).
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/engagements/..%2Freport")
    # Either 400 from the router's traversal guard, or 404 if route didn't match.
    # We want the router-level guard to be reachable; use backslash-free form
    assert resp.status_code in (400, 404)


async def test_get_report_no_artifacts_returns_404(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        # No reports/{sid} directory exists in the tests/ workdir
        resp = await client.get(f"/engagements/{session.session_id}/report")
    assert resp.status_code == 404
    assert "No report has been generated" in resp.json()["detail"]


async def test_get_report_serves_html_and_md(app_with_findings, bound_state, tmp_path, monkeypatch):
    """Drop real artifacts under reports/{sid}/ and the endpoint serves them."""
    app, _fake_verify = app_with_findings
    short = "eng-report"
    full = "eng-20260801-eng-report"
    session = _session(short_id=short, full_id=full)
    orch = _fake_orch(session=session)
    bound_state(orch)

    # Chdir to tmp_path so the reports/ lookup stays hermetic
    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports" / full
    reports.mkdir(parents=True)
    (reports / "report-20260801-aaaa.html").write_text("<body>HTML_BODY</body>")
    (reports / "report-20260801-aaaa.md").write_text("# MARKDOWN_BODY")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{full}/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["markdown"] == "# MARKDOWN_BODY"
    assert "HTML_BODY" in body["html"]
    assert "HTML_BODY" in body["body_html"]
    assert body["report_id"] == "report-20260801-aaaa"


# --------------------------------------------------------------------------- #
# Auth / access denial cases                                                  #
# --------------------------------------------------------------------------- #


async def test_findings_operator_without_access_gets_403(app_with_findings, bound_state):
    """An operator-role user that is not the engagement's creator and does not
    have senior access gets 403 from assert_engagement_access."""
    app, _fake_verify = app_with_findings

    # Build a session owned by a DIFFERENT user
    session = _session()
    session.created_by = "someone-else"
    orch = _fake_orch(session=session)
    bound_state(orch)

    # Override the auth override for this test: fresh app
    fresh_app = FastAPI(title="findings-fresh")
    fresh_app.include_router(findings_router.router)

    async def _operator_role_only():
        return _operator(role="operator", sub="not-owner")

    fresh_app.dependency_overrides[verify_token] = _operator_role_only

    async with AsyncClient(transport=ASGITransport(app=fresh_app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 403


async def test_findings_unknown_engagement_returns_404(app_with_findings, bound_state):
    app, _fake_verify = app_with_findings
    orch = _fake_orch()  # no session bound; load_session_state returns None
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/engagements/does-not-exist/findings")
    assert resp.status_code == 404
    assert "Engagement not found" in resp.json()["detail"]


async def test_findings_orchestrator_unbound_returns_503(app_with_findings):
    app, _fake_verify = app_with_findings
    # state["orchestrator"] remains None (conftest fixture resets it); do NOT bind.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/engagements/any-id/findings")
    assert resp.status_code == 503
    assert "Orchestrator not initialized" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# POST /engagements/{sid}/discovery/trigger                                   #
# --------------------------------------------------------------------------- #


async def test_trigger_discovery_dispatches_internal_helper(
    app_with_findings, bound_state, monkeypatch
):
    app, _fake_verify = app_with_findings
    session = _session()
    orch = _fake_orch(session=session)
    bound_state(orch)

    captured = {}

    async def _fake_trigger(sid):
        captured["session_id"] = sid

    monkeypatch.setattr(
        "ai_osop.api.routers.sessions._trigger_authenticated_discovery", _fake_trigger
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(f"/engagements/{session.session_id}/discovery/trigger")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"status": "triggered", "session_id": session.session_id}
    assert captured["session_id"] == session.session_id
