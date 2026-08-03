"""Deep-coverage tests for ai_osop.api.routers.findings.

Complements test_findings_router_coverage.py by driving the router endpoints
through REAL response shapes rather than just status codes. Targets the
uncovered branches identified via coverage:

  * _vuln_node_to_finding severity normalization fallback (line 39)
  * evidence wrap branch for non-list non-empty evidence (line 47)
  * get_report path-traversal guard (line 136)
  * get_report OSError fallback inside _read (lines 155-156)
  * get_diff_auth_findings skip-when-d-falsy branch (line 230)
  * get_finding_vault JSON-decode fallback + non-dict item branch (404-405, 415)
  * submit_finding_to_bounty full success path (lines 500-547)
  * verify / replay role-403 branches via require_role
  * schedule_task payload shape for replay / poc / workflow endpoints
  * reasoning-loop uncertainty tracker passthrough

Auth + engagement access is provided by dependency_overrides; the orchestrator
is bound into deps.state with only the two memory tiers every handler reads.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from ai_osop.api.deps import (
    assert_engagement_access,
    require_role,
    state,
    verify_token,
)
from ai_osop.api.routers import findings as findings_router
from ai_osop.core.enums import EngagementPhase
from ai_osop.core.models import ScopeDefinition, SessionState


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #


def _session(short_id: str = "eng-1", full_id: str = "eng-20260801-eng-1") -> SessionState:
    return SessionState(
        session_id=full_id,
        phase=EngagementPhase.RECONNAISSANCE.value,
        scope=ScopeDefinition(engagement_id=short_id, domains=["example.test"]),
        roe={},
    )


def _fake_graph() -> MagicMock:
    gm = MagicMock()
    gm.run_read_query = AsyncMock(return_value=[])
    gm.get_vulnerabilities_by_engagement = AsyncMock(return_value=[])
    gm.get_invariants = AsyncMock(return_value=[])
    gm.validate_vulnerability = AsyncMock(return_value=None)
    gm.get_node_details = AsyncMock(return_value=None)
    return gm


def _fake_session_memory() -> MagicMock:
    sm = MagicMock()
    sm.load_session_state = AsyncMock(return_value=None)
    return sm


def _fake_orch(
    *,
    session: Optional[SessionState] = None,
    graph: Optional[Any] = None,
    session_memory: Optional[Any] = None,
) -> SimpleNamespace:
    orch = SimpleNamespace()
    orch.graph_memory = graph or _fake_graph()
    orch.session_memory = session_memory or _fake_session_memory()
    orch.mcp_registry = None
    orch.schedule_task = AsyncMock()
    orch.reasoning_loop = None
    orch._sessions = {}
    if session is not None:
        orch._sessions[session.session_id] = session
        if session.scope.engagement_id != session.session_id:
            orch._sessions[session.scope.engagement_id] = session
    return orch


def _operator(role: str = "senior_operator", sub: str = "op-1") -> Dict[str, Any]:
    return {"sub": sub, "role": role, "claims": {}, "tenant_id": "default"}


# --------------------------------------------------------------------------- #
# App fixture                                                                  #
# --------------------------------------------------------------------------- #


@pytest.fixture
def app(monkeypatch):
    """FastAPI app with ONLY the findings router mounted and verify_token
    replaced by a senior_operator short-circuit."""
    app = FastAPI(title="findings-deep-coverage")
    app.include_router(findings_router.router)

    async def _op() -> Dict[str, Any]:
        return _operator()

    app.dependency_overrides[verify_token] = _op
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
def bind(monkeypatch):
    """Helper binding a fake orchestrator into deps.state so handlers find it."""

    def _bind(orch: Any) -> None:
        monkeypatch.setitem(state, "orchestrator", orch)

    return _bind


# --------------------------------------------------------------------------- #
# Severity-normalization and evidence wrapping in _vuln_node_to_finding        #
# --------------------------------------------------------------------------- #


async def test_findings_invalid_severity_normalized_to_low(app, bind):
    """Line 39: an unrecognized severity is coerced to 'low' rather than
    propagating. The endpoint must not 500 and must surface the fallback."""
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[
            {
                "id": "v-weird",
                "title": "Weird sev",
                "severity": "WEIRDLY-HIGH",  # not in low/medium/high/critical
                "validated": False,
                "cvss_score": 0.0,
            }
        ]
    )
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "low"
    # evScore falls back to _SEVERITY_EV_SCORE["low"] == 20 because cvss=0
    assert f["evScore"] == 20
    assert f["status"] == "hypothesis"


async def test_findings_evidence_string_dict_wrapped_into_list(app, bind):
    """Line 47: evidence can be a non-list, non-string truthy value (e.g. dict);
    it must be wrapped in a list so len() is 1, not blow up."""
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[
            {
                "id": "v-dict-ev",
                "severity": "medium",
                "validated": False,
                # A raw dict (not a list, not a string) - exercised line 47 wrap
                "evidence": {"matched_at": "https://example.test/x"},
            }
        ]
    )
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    f = resp.json()[0]
    assert f["evidenceCount"] == 1
    # matched_at surfaces because the wrapper preserved the dict content
    assert f["matchedAt"] == "https://example.test/x"


async def test_findings_no_severity_defaults_to_low(app, bind):
    """severity=None takes the 'or \"low\"' branch on line 37."""
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[{"id": "v-nosev", "severity": None, "validated": False}]
    )
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    f = resp.json()[0]
    assert f["severity"] == "low"
    assert f["evScore"] == 20


async def test_findings_evidence_string_json_parsed_into_list(app, bind):
    """Evidence stored as a JSON-encoded string is parsed before counting."""
    session = _session()
    graph = _fake_graph()
    graph.get_vulnerabilities_by_engagement = AsyncMock(
        return_value=[
            {
                "id": "v-str-ev",
                "severity": "high",
                "validated": True,
                "evidence": '[{"matched_at": "https://a.test"}, {"matched_at": "https://b.test"}]',
            }
        ]
    )
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/findings")
    assert resp.status_code == 200
    f = resp.json()[0]
    assert f["evidenceCount"] == 2
    assert f["matchedAt"] == "https://a.test"
    assert f["status"] == "verified"


# --------------------------------------------------------------------------- #
# Report endpoint: traversal guard, OSError fallback                           #
# --------------------------------------------------------------------------- #


async def test_report_traversal_guard_rejects_dotdot(app, bind, monkeypatch, tmp_path):
    """Line 136: session_id containing '..' is rejected before any disk access.

    Starlette normalizes route params, so we call the handler directly through
    its router-level function. assert_engagement_access runs BEFORE the guard,
    so register SessionStates under the traversal-form ids to pass access."""
    from ai_osop.core.models import ScopeDefinition, SessionState

    def _sess(sid):
        return SessionState(
            session_id=sid,
            scope=ScopeDefinition(engagement_id=sid, domains=["x.test"]),
            created_by="op-1",
        )

    class _Orch:
        def __init__(self):
            self._sessions = {}
            self.session_memory = AsyncMock()
            self.graph_memory = AsyncMock()

    orch = _Orch()
    for sid in ("..\\escape", "..", "a/b"):
        orch._sessions[sid] = _sess(sid)
    bind(orch)

    # Import the underlying function to bypass ASGI path normalization.
    with pytest.raises(HTTPException) as exc:
        await findings_router.get_report(session_id="..\\escape", operator=_operator())
    assert exc.value.status_code == 400
    assert "invalid engagement id" in exc.value.detail

    with pytest.raises(HTTPException) as exc2:
        await findings_router.get_report(session_id="..", operator=_operator())
    assert exc2.value.status_code == 400

    # Forward slash form (never routable but directly callable)
    with pytest.raises(HTTPException) as exc3:
        await findings_router.get_report(session_id="a/b", operator=_operator())
    assert exc3.value.status_code == 400


async def test_report_read_oserror_falls_back_to_empty_string(
    app, bind, tmp_path, monkeypatch
):
    """Lines 155-156: OSError inside _read is swallowed and treated as empty.
    Both markdown and html come back as "", but report_id still resolves."""
    short = "eng-oserr"
    full = "eng-20260801-eng-oserr"
    session = _session(short_id=short, full_id=full)
    bind(_fake_orch(session=session))

    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports" / full
    reports.mkdir(parents=True)
    html = reports / "report-20260801-broken.html"
    md = reports / "report-20260801-broken.md"
    html.write_text("<p>exists</p>")
    md.write_text("# exists")

    import builtins

    real_open = builtins.open

    def _boom(path, *args, **kwargs):
        # glob yields paths under the CWD since we chdir'd. Normalize both
        # sides; the only files we want to break are the ones we created.
        if os.path.basename(str(path)).startswith("report-20260801-broken"):
            raise OSError("simulated locked file")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _boom)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{full}/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_id"] == "report-20260801-broken"
    assert body["markdown"] == ""
    assert body["html"] == ""
    assert body["body_html"] == ""


async def test_report_serves_only_html_when_no_md(app, bind, tmp_path, monkeypatch):
    """If only report-*.html exists, report_id still resolves from html."""
    short = "eng-htmlonly"
    full = "eng-20260801-eng-htmlonly"
    session = _session(short_id=short, full_id=full)
    bind(_fake_orch(session=session))

    monkeypatch.chdir(tmp_path)
    reports = tmp_path / "reports" / full
    reports.mkdir(parents=True)
    (reports / "report-20260801-only.html").write_text("<p>hi</p>")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{full}/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["report_id"] == "report-20260801-only"
    assert body["markdown"] == ""
    assert "<p>hi</p>" in body["html"]
    assert body["body_html"] == "<p>hi</p>"


async def test_report_traversal_guard_asgi_path(app, bind, monkeypatch):
    """Line 156 driven through ASGI so coverage records it: a %2e%2e%5cescape
    session_id reaches the handler post-normalization and the 400 fires."""
    from ai_osop.core.models import ScopeDefinition, SessionState

    sid = "..\\escape"
    session = SessionState(
        session_id=sid,
        scope=ScopeDefinition(engagement_id=sid, domains=["x.test"]),
        created_by="op-1",
    )

    class _Orch:
        def __init__(self):
            self._sessions = {sid: session}
            self.session_memory = AsyncMock()
            self.graph_memory = AsyncMock()

    bind(_Orch())

    from urllib.parse import quote

    encoded = quote(sid, safe="")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{encoded}/report")
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid engagement id"


# --------------------------------------------------------------------------- #
# Diff-auth: skip empty row, real rank results propagate                       #
# --------------------------------------------------------------------------- #


async def test_diff_auth_skips_records_with_falsy_d(app, bind, monkeypatch):
    """Line 230: a record where 'd' is None is dropped rather than exploding."""
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(
        return_value=[
            {"d": None},
            {
                "d": {
                    "id": "d-keep",
                    "category": "authz",
                    "resource_id": "/x",
                    "test_identity_id": "guest",
                    "expected_result": "deny",
                    "observed_result": "allow",
                    "evidence_diff": None,  # -> becomes {}
                    "confidence": 0.5,
                }
            },
        ]
    )
    bind(_fake_orch(session=session, graph=graph))
    monkeypatch.setattr("ai_osop.core.triage.rank_findings", lambda rows: rows)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/diff-auth")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["id"] == "d-keep"
    # evidence_diff None -> {} via the `or {}` fallback
    assert rows[0]["evidence_diff"] == {}


async def test_diff_auth_real_rank_enriches_rows_with_triage_block(app, bind):
    """Without stubbing rank_findings, every out-row gains a 'triage' block
    carrying the deterministic score fields from score_finding."""
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
                    "confidence": 0.95,
                }
            },
            {
                "d": {
                    "id": "d2",
                    "category": "authz",
                    "resource_id": "/users/2",
                    "test_identity_id": "guest",
                    "expected_result": "deny",
                    "observed_result": "allow",
                    "evidence_diff": None,
                    "confidence": 0.2,
                }
            },
        ]
    )
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/diff-auth")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 2
    # ranked best-first: d1 (higher confidence) sorts ahead of d2
    assert rows[0]["id"] == "d1"
    assert rows[1]["id"] == "d2"
    # triage block attached by rank_findings
    for r in rows:
        assert "triage" in r
        assert "score" in r["triage"]
        assert "severity" in r["triage"]
        assert "tier" in r["triage"]
    # Higher confidence row outranks the other
    assert rows[0]["triage"]["score"] >= rows[1]["triage"]["score"]


async def test_diff_auth_empty_returns_empty_list(app, bind):
    """No records -> rank_findings on an empty list -> empty list back."""
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[])
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/diff-auth")
    assert resp.status_code == 200
    assert resp.json() == []


# --------------------------------------------------------------------------- #
# Vault endpoint: corrupt evidence JSON, non-dict evidence                     #
# --------------------------------------------------------------------------- #


async def test_vault_malformed_evidence_json_yields_empty_request_trails(
    app, bind,
):
    """Lines 404-405: malformed evidence JSON on the vuln node falls back to
    empty items, so the vault has no raw_requests/raw_responses but still
    produces a valid integrity_hash from the empty state."""
    session = _session()
    graph = _fake_graph()

    async def _read(cypher, params):
        if "$fid" in cypher:
            return [{"v": {"id": "v-vault-bad", "evidence": "{broken json"}}]
        return []  # no Evidence rows

    graph.run_read_query = AsyncMock(side_effect=_read)
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.session_id}/findings/v-vault-bad/vault"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_id"] == "v-vault-bad"
    assert body["raw_requests"] == []
    assert body["raw_responses"] == []
    assert body["screenshots"] == []
    assert body["workflow_trace"] == []
    assert body["replay_script"] is None
    # sha256 of an empty-state dict is still a well-formed hex string
    assert isinstance(body["integrity_hash"], str)
    assert len(body["integrity_hash"]) == 64
    int(body["integrity_hash"], 16)  # parses as hex


async def test_vault_non_dict_evidence_item_stringified(app, bind):
    """Line 415: a non-dict entry inside the evidence list is stringified
    into raw_requests (never crashes the assembly loop)."""
    session = _session()
    graph = _fake_graph()

    async def _read(cypher, params):
        if "$fid" in cypher:
            return [
                {
                    "v": {
                        "id": "v-str-item",
                        "evidence": [
                            "plain string evidence",
                            {"request": "GET / HTTP/1.1"},
                            12345,
                        ],
                    }
                }
            ]
        return []

    graph.run_read_query = AsyncMock(side_effect=_read)
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.session_id}/findings/v-str-item/vault"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert "plain string evidence" in body["raw_requests"]
    assert "GET / HTTP/1.1" in body["raw_requests"]
    # int was stringified into raw_requests via the non-dict path
    assert "12345" in body["raw_requests"]
    assert body["raw_responses"] == []


async def test_vault_evidence_dict_without_request_response_dumped_to_raw(
    app, bind,
):
    """Line 413: a dict lacking both 'request' and 'response' keys is dumped
    as JSON into raw_requests so downstream tooling sees SOMETHING."""
    session = _session()
    graph = _fake_graph()

    async def _read(cypher, params):
        if "$fid" in cypher:
            return [
                {
                    "v": {
                        "id": "v-dict-no-req",
                        "evidence": [{"template": "cve-2024-1", "score": 9.1}],
                    }
                }
            ]
        return []

    graph.run_read_query = AsyncMock(side_effect=_read)
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.session_id}/findings/v-dict-no-req/vault"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["raw_requests"]) == 1
    # JSON-serialized dict contains both keys
    assert '"template"' in body["raw_requests"][0]
    assert '"cve-2024-1"' in body["raw_requests"][0]


# --------------------------------------------------------------------------- #
# Verify / replay role gating                                                  #
# --------------------------------------------------------------------------- #


async def test_verify_finding_rejects_operator_role_with_403(bind):
    """require_role('senior_operator') blocks an operator-role request before
    the handler runs; no graph mutation occurs."""

    fresh = FastAPI(title="findings-verify-deny")
    fresh.include_router(findings_router.router)

    async def _lowpriv():
        return _operator(role="operator", sub="op-low")

    fresh.dependency_overrides[verify_token] = _lowpriv

    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[{"v.id": "v1"}])
    bind(_fake_orch(session=_session(), graph=graph))

    async with AsyncClient(transport=ASGITransport(app=fresh), base_url="http://t") as client:
        resp = await client.post("/engagements/eng-20260801-eng-1/findings/v1/verify")
    assert resp.status_code == 403
    assert "not permitted" in resp.json()["detail"]
    assert graph.validate_vulnerability.await_count == 0


async def test_replay_finding_rejects_operator_role(bind):
    fresh = FastAPI(title="findings-replay-deny")
    fresh.include_router(findings_router.router)

    async def _lowpriv():
        return _operator(role="operator", sub="op-low")

    fresh.dependency_overrides[verify_token] = _lowpriv

    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[{"v.id": "v1"}])
    orch = _fake_orch(session=_session(), graph=graph)
    bind(orch)

    async with AsyncClient(transport=ASGITransport(app=fresh), base_url="http://t") as client:
        resp = await client.post("/engagements/eng-20260801-eng-1/findings/v1/replay")
    assert resp.status_code == 403
    assert orch.schedule_task.await_count == 0


# --------------------------------------------------------------------------- #
# Replay/PoC/Workflow task-keyed under canonical engagement id                 #
# --------------------------------------------------------------------------- #


async def test_replay_finding_task_id_is_uuid_and_engagement_keyed(app, bind):
    """Task ids are generated (not derived from input); engagement_id follows
    canonical id rules so the phase monitor finds the finding without a
    dual-key lookup."""
    session = _session()
    graph = _fake_graph()
    graph.run_read_query = AsyncMock(return_value=[{"v.id": "v1"}])
    orch = _fake_orch(session=session, graph=graph)
    bind(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/abc/replay"
        )
    assert resp.status_code == 200
    body = resp.json()
    # Task.id is generated at construction time with the "task-" prefix + 12 hex
    # chars (NOT derived from the finding id), so two replays never collide.
    assert isinstance(body["task_id"], str)
    assert body["task_id"].startswith("task-")
    suffix = body["task_id"][len("task-"):]
    assert len(suffix) == 12
    assert all(c in "0123456789abcdef" for c in suffix)
    # The Task the orchestrator received is the one the response reports
    task = orch.schedule_task.call_args.args[0]
    assert task.id == body["task_id"]
    assert task.agent_type.value == "exploit_validation"
    assert task.engagement_id == session.canonical_engagement_id


async def test_generate_poc_requires_finding_id_query_param(app, bind):
    """Missing finding_id query param -> 422 from FastAPI validation, before
    any orchestrator call."""
    orch = _fake_orch(session=_session())
    bind(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(f"/engagements/eng-20260801-eng-1/poc/generate")
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert any(err["loc"][-1] == "finding_id" for err in detail)
    assert orch.schedule_task.await_count == 0


async def test_submit_finding_unknown_returns_404(app, bind):
    """graph_memory.get_node_details returns None -> 404."""
    session = _session()
    graph = _fake_graph()
    graph.get_node_details = AsyncMock(return_value=None)
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/missing/submit"
        )
    assert resp.status_code == 404
    assert "not found in graph" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# Submit-to-bounty full happy path (covers lines 500-547)                      #
# --------------------------------------------------------------------------- #


async def test_submit_finding_happy_path_persists_external_id(app, bind, monkeypatch):
    """Covers the whole /submit handler: lookup, adapter call, Neo4j SET."""
    session = _session()
    graph = _fake_graph()
    graph.get_node_details = AsyncMock(
        return_value={
            "id": "v-sub",
            "title": "Stored XSS in profile",
            "description": "xss desc",
            "impact": "high",
            "severity": "high",
            "program_handle": "acme",
        }
    )

    # Fake the neo4j driver.session() async context manager used to persist
    # the external id back onto the Vulnerability node.
    session_runner = MagicMock()
    session_runner.run = AsyncMock(return_value=None)

    class _SessionCM:
        async def __aenter__(self):
            return session_runner

        async def __aexit__(self, exc_type, exc, tb):
            return False

    fake_driver = MagicMock()
    fake_driver.session = MagicMock(return_value=_SessionCM())
    graph._driver = fake_driver

    bind(_fake_orch(session=session, graph=graph))

    # Replace the BugBountyAdapter class the handler instantiates
    captured_call: Dict[str, Any] = {}

    class _FakeAdapter:
        async def submit_finding(self, finding, platform, *, live_submit_approved):
            captured_call["finding"] = finding
            captured_call["platform"] = platform
            captured_call["live_submit_approved"] = live_submit_approved
            return {
                "status": "submitted",
                "external_id": "H1-SIM-v-sub",
                "platform": platform,
                "simulated": True,
            }

    monkeypatch.setattr(
        "ai_osop.adapters.bug_bounty_adapter.BugBountyAdapter", _FakeAdapter
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/v-sub/submit",
            params={"platform": "h1"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "submitted"
    assert body["external_id"] == "H1-SIM-v-sub"
    assert body["simulated"] is True

    # Adapter saw the node fields mapped into the submit-shape dict
    assert captured_call["platform"] == "h1"
    assert captured_call["live_submit_approved"] is True
    assert captured_call["finding"]["id"] == "v-sub"
    assert captured_call["finding"]["title"] == "Stored XSS in profile"
    assert captured_call["finding"]["program_handle"] == "acme"

    # The SET query ran once against the bound session runner
    assert session_runner.run.await_count == 1
    cypher_call = session_runner.run.call_args
    assert "MATCH (v:Vulnerability" in cypher_call.args[0]
    assert cypher_call.kwargs["fid"] == "v-sub"
    assert cypher_call.kwargs["ext_id"] == "H1-SIM-v-sub"
    assert "now" in cypher_call.kwargs


async def test_submit_finding_blocked_status_skips_graph_write(app, bind, monkeypatch):
    """If the adapter returns a non-'submitted' status (blocked/error), the
    handler returns the result verbatim WITHOUT touching neo4j."""
    session = _session()
    graph = _fake_graph()
    graph.get_node_details = AsyncMock(
        return_value={"id": "v-blocked", "title": "t"}
    )
    fake_driver = MagicMock()  # driver.session must NOT be called
    graph._driver = fake_driver
    bind(_fake_orch(session=session, graph=graph))

    class _BlockedAdapter:
        async def submit_finding(self, finding, platform, *, live_submit_approved):
            return {
                "status": "blocked",
                "error": "no approval",
                "platform": platform,
            }

    monkeypatch.setattr(
        "ai_osop.adapters.bug_bounty_adapter.BugBountyAdapter", _BlockedAdapter
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/v-blocked/submit"
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "blocked"
    assert body["error"] == "no approval"
    # Critical: no driver.session() call happened
    fake_driver.session.assert_not_called()


async def test_submit_finding_title_default_applies_when_missing(app, bind, monkeypatch):
    """finding_node without title/vuln_type uses the default 'Vulnerability
    Report'; missing program_handle defaults to 'security'."""
    session = _session()
    graph = _fake_graph()
    graph.get_node_details = AsyncMock(
        return_value={"id": "v-min"}  # no title / description / etc
    )
    fake_driver = MagicMock()
    graph._driver = fake_driver
    bind(_fake_orch(session=session, graph=graph))

    captured: Dict[str, Any] = {}

    class _SpyAdapter:
        async def submit_finding(self, finding, platform, *, live_submit_approved):
            captured["finding"] = finding
            return {"status": "blocked", "platform": platform}

    monkeypatch.setattr(
        "ai_osop.adapters.bug_bounty_adapter.BugBountyAdapter", _SpyAdapter
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/v-min/submit"
        )
    assert resp.status_code == 200
    # Adapter received the defaulted shape
    f = captured["finding"]
    assert f["title"] == "Vulnerability Report"
    assert f["description"] == ""
    assert f["impact"] == "Not specified"
    assert f["severity"] == "low"
    assert f["program_handle"] == "security"


# --------------------------------------------------------------------------- #
# Uncertainty endpoint: reasoning-loop tracker passthrough                     #
# --------------------------------------------------------------------------- #


async def test_uncertainty_returns_tracker_listing_and_summary(app, bind):
    """When reasoning_loop exists with _uncertainty_tracker, the listing comes
    from tracker.get_open_uncertainties(*forms) and count == len(listing)."""
    session = _session()
    unc1 = SimpleNamespace(
        id="u1",
        question="is /admin externally reachable?",
        context={"surface": "admin"},
    )
    unc2 = SimpleNamespace(
        id="u2",
        question="does CSRF apply to mobile app?",
        context={"surface": "mobile"},
    )
    tracker = SimpleNamespace(
        get_open_uncertainties=MagicMock(return_value=[unc1, unc2]),
        get_summary=MagicMock(
            return_value={"total": 5, "open": 2, "resolved": 3, "avg_age_s": 41.2}
        ),
    )
    orch = _fake_orch(session=session)
    orch.reasoning_loop = SimpleNamespace(_uncertainty_tracker=tracker)
    bind(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/uncertainty")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert body["session_id"] == session.session_id
    # __dict__ surface keeps id + question + context keys
    assert {u["id"] for u in body["uncertainties"]} == {"u1", "u2"}
    assert body["uncertainties"][0]["question"] == "is /admin externally reachable?"
    assert body["summary"]["open"] == 2
    # Tracker was called with the engagement id forms so cross-key data appears
    assert tracker.get_open_uncertainties.call_count == 1
    forms_arg = tracker.get_open_uncertainties.call_args.args
    assert session.session_id in forms_arg
    assert session.scope.engagement_id in forms_arg


async def test_uncertainty_falls_back_to_zero_loop_config(app, bind):
    """Reasoning loop present but missing the tracker attribute -> empty shape."""
    session = _session()
    orch = _fake_orch(session=session)
    # object() has no _uncertainty_tracker
    orch.reasoning_loop = object()
    bind(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/uncertainty")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "session_id": session.session_id,
        "count": 0,
        "uncertainties": [],
        "summary": {},
    }


# --------------------------------------------------------------------------- #
# Invariants: graph row passthrough                                            #
# --------------------------------------------------------------------------- #


async def test_invariants_empty_list_when_no_invariants_in_graph(app, bind):
    session = _session()
    graph = _fake_graph()
    graph.get_invariants = AsyncMock(return_value=[])
    bind(_fake_orch(session=session, graph=graph))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.session_id}/invariants")
    assert resp.status_code == 200
    assert resp.json() == []
    graph.get_invariants.assert_awaited_once_with(session.session_id)


# --------------------------------------------------------------------------- #
# Resolve finding: real engine result round-trips through HTTP                  #
# --------------------------------------------------------------------------- #


async def test_resolve_finding_engine_real_success_shape(app, bind):
    """Run the real FindingConversionEngine.resolve_finding to confirm the
    handler returns its exact shape across the wire."""
    session = _session()
    graph = _fake_graph()
    sm = _fake_session_memory()
    orch = _fake_orch(session=session, graph=graph, session_memory=sm)
    bind(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/v-real/resolve",
            json="accepted",
        )
    assert resp.status_code == 200
    body = resp.json()
    # Real engine returns {status:"success", finding_id, outcome:status_enum.value}
    assert body["status"] == "success"
    assert body["finding_id"] == "v-real"
    assert body["outcome"] == "accepted"


async def test_resolve_finding_invalid_status_returns_engine_value_error(app, bind):
    """OutcomeStatus(status.lower()) raises ValueError for unknown status;
    the request fails (FastAPI surfaces as 500). The engine is the source
    of truth for allowed statuses, so the handler does NOT whitelist them."""
    session = _session()
    bind(_fake_orch(session=session))

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://t"
    ) as client:
        resp = await client.post(
            f"/engagements/{session.session_id}/findings/v-x/resolve",
            json="not-a-status",
        )
    # FastAPI converts the uncaught ValueError into a 500 response when
    # raise_app_exceptions=False
    assert resp.status_code == 500
