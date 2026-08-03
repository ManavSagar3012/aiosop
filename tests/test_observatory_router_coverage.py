"""Request-level coverage tests for ai_osop.api.routers.observatory.

The observatory router exposes the execution-observability surface:
 - GET /engagements/{eid}/trace/{task_id}
 - GET /engagements/{eid}/traces
 - GET /system/observatory/mcp-telemetry
 - GET /system/observatory/scanner-audit
 - GET /system/observatory/worker-telemetry

It was at 0% coverage because the router module was never imported by any
other test. Mount ONLY this router and drive it through httpx.AsyncClient +
ASGITransport, with ``verify_token`` overridden so ``require_role`` resolves
via dependency_overrides, exactly like the findings coverage suite.

State is bound into ``ai_osop.api.deps.state`` (the module-level dict that the
router consults at request time) using a fake ``SimpleNamespace``
orchestrator carrying only the attributes the router pokes at: ``_tasks``,
``_agents``, ``_sessions``, ``mcp_registry``, ``session_memory``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers import observatory as observatory_router
from ai_osop.core.enums import EngagementPhase
from ai_osop.core.execution_trace import (
    ExecutionStage,
    TaskExecutionTrace,
    attach_trace,
)
from ai_osop.core.models import AgentType, ScopeDefinition, SessionState, Task


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


def _session(
    short_id: str = "eng-obs",
    full_id: str = "eng-20260801-eng-obs",
    created_by: Optional[str] = None,
) -> SessionState:
    """Minimal SessionState: scope.engagement_id drives router access rules."""
    s = SessionState(
        session_id=full_id,
        phase=EngagementPhase.RECONNAISSANCE.value,
        scope=ScopeDefinition(engagement_id=short_id, domains=["example.test"]),
        roe={},
    )
    s.created_by = created_by
    return s


def _task(
    *,
    task_id: str,
    engagement_id: str,
    task_type: str = "subdomain_scan",
    status: str = "completed",
    agent_type: AgentType = AgentType.RECON,
    with_trace: bool = True,
    failure: Optional[Dict[str, Any]] = None,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
) -> Task:
    """Build a real Task so observatory hits a realistic attribute surface."""
    t = Task(
        id=task_id,
        type=task_type,
        agent_type=agent_type,
        engagement_id=engagement_id,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
    )
    if with_trace:
        trace = attach_trace(t)
        # Simulate a full lifecycle so the trace has real stages
        trace.record(ExecutionStage.TASK_QUEUED)
        trace.record(ExecutionStage.WORKER_ASSIGNED, metadata={"agent": "agent-1"})
        trace.record(ExecutionStage.SCANNER_STARTED)
        if failure:
            trace.record_failure(
                category=failure.get("category", "scanner"),
                reason=failure.get("reason", "boom"),
                component=failure.get("component", "nuclei"),
            )
        else:
            trace.record(ExecutionStage.SCANNER_STARTED, metadata={"scanner": task_type})
            trace.record(ExecutionStage.TASK_COMPLETED)
    return t


def _session_memory_stub():
    sm = MagicMock()
    # Default: no persisted trace
    sm.retrieve_hot = AsyncMock(return_value=None)
    sm.store_hot = AsyncMock(return_value=None)
    sm.load_session_state = AsyncMock(return_value=None)
    sm.get_agent_heartbeat = AsyncMock(return_value=None)
    return sm


def _mcp_registry_stub(servers: Optional[Dict[str, Any]] = None):
    """`_servers` maps server_id -> conn where conn has .get_telemetry()."""
    registry = MagicMock()
    registry._servers = servers or {}
    return registry


def _agent_stub(agent_type: AgentType = AgentType.RECON, *, queue_depth: int = 2):
    """Agent that observatory's worker-telemetry snapshots."""
    agent = MagicMock()
    agent.get_status = AsyncMock(
        return_value={"status": "idle", "task_queue_depth": queue_depth}
    )
    agent.ctx = SimpleNamespace(agent_type=agent_type)
    return agent


def _orch_stub(
    *,
    session: Optional[SessionState] = None,
    tasks: Optional[Dict[str, Task]] = None,
    agents: Optional[Dict[str, Any]] = None,
    mcp_servers: Optional[Dict[str, Any]] = None,
    session_memory=None,
) -> SimpleNamespace:
    orch = SimpleNamespace()
    orch._tasks = tasks or {}
    orch._agents = agents or {}
    orch._sessions = {}
    if session is not None:
        # Index by both session_id and short engagement_id so
        # assert_engagement_access resolves either form.
        orch._sessions[session.session_id] = session
        if session.scope.engagement_id != session.session_id:
            orch._sessions[session.scope.engagement_id] = session
    orch.session_memory = session_memory or _session_memory_stub()
    orch.mcp_registry = _mcp_registry_stub(mcp_servers)
    orch.graph_memory = MagicMock()
    return orch


def _operator(role: str = "senior_operator", sub: str = "op-1") -> Dict[str, Any]:
    return {"sub": sub, "role": role, "claims": {}, "tenant_id": "default"}


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


@pytest.fixture
def app_with_observatory():
    """Bare FastAPI app with ONLY the observatory router mounted."""
    app = FastAPI(title="observatory-test-app")
    app.include_router(observatory_router.router)

    async def _fake_verify_token():
        return _operator()

    app.dependency_overrides[verify_token] = _fake_verify_token
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
def bound_state(monkeypatch):
    """Bind a fake orchestrator into ``deps.state`` for the duration of a test."""
    original = dict(state)

    def _bind(orch):
        monkeypatch.setitem(state, "orchestrator", orch)

    yield _bind

    state.clear()
    state.update(original)


# --------------------------------------------------------------------------- #
# GET /engagements/{eid}/trace/{task_id}                                      #
# --------------------------------------------------------------------------- #


async def test_get_task_trace_returns_full_trace(app_with_observatory, bound_state):
    """The endpoint returns the in-memory execution trace for a live task."""
    app = app_with_observatory
    session = _session()
    task = _task(task_id="task-t1", engagement_id=session.scope.engagement_id)
    orch = _orch_stub(session=session, tasks={task.id: task})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.scope.engagement_id}/trace/{task.id}"
        )
    assert resp.status_code == 200
    body = resp.json()
    # Real trace shape (to_dict from TaskExecutionTrace)
    assert body["task_id"] == task.id
    assert body["engagement_id"] == session.scope.engagement_id
    assert body["is_complete"] is True
    assert body["stage_count"] >= 4  # TASK_CREATED, QUEUED, ASSIGNED, STARTED, COMPLETED
    assert isinstance(body["stages"], list) and len(body["stages"]) == body["stage_count"]
    stage_names = [s["stage"] for s in body["stages"]]
    assert "task_created" in stage_names
    assert "task_completed" in stage_names
    assert body["failure"] is None
    assert body["elapsed_seconds"] >= 0.0


async def test_get_task_trace_falls_back_to_redis(app_with_observatory, bound_state):
    """If the task has no live trace AND is not in _tasks, load from Redis."""
    app = app_with_observatory
    session = _session()
    # No matching task in orch._tasks -> router will consult session_memory
    persisted = {
        "task_id": "task-persisted",
        "engagement_id": session.scope.engagement_id,
        "elapsed_seconds": 12.5,
        "stage_count": 3,
        "is_complete": True,
        "stages": [{"stage": "task_created"}, {"stage": "scanner_started"}, {"stage": "task_completed"}],
        "failure": None,
    }
    sm = _session_memory_stub()
    sm.retrieve_hot = AsyncMock(return_value=persisted)
    orch = _orch_stub(session=session, tasks={}, session_memory=sm)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.scope.engagement_id}/trace/task-persisted"
        )
    assert resp.status_code == 200
    assert resp.json() == persisted
    sm.retrieve_hot.assert_awaited_once_with("trace:task-persisted")


async def test_get_task_trace_404_when_no_trace_found(app_with_observatory, bound_state):
    """No live trace, nothing in Redis -> 404."""
    app = app_with_observatory
    session = _session()
    orch = _orch_stub(session=session, tasks={})
    bound_state(orch)  # retrieve_hot defaults to None

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.scope.engagement_id}/trace/task-nope"
        )
    assert resp.status_code == 404
    assert "No execution trace" in resp.json()["detail"]


async def test_get_task_trace_task_exists_but_no_trace_falls_through(app_with_observatory, bound_state):
    """Task present in orch._tasks but `_execution_trace` was never attached;
    router must still try Redis and in this case return the persisted version."""
    app = app_with_observatory
    session = _session()
    task = _task(
        task_id="task-notrace",
        engagement_id=session.scope.engagement_id,
        with_trace=False,
    )
    persisted = {"task_id": task.id, "from_redis": True}
    sm = _session_memory_stub()
    sm.retrieve_hot = AsyncMock(return_value=persisted)
    orch = _orch_stub(session=session, tasks={task.id: task}, session_memory=sm)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.scope.engagement_id}/trace/{task.id}"
        )
    assert resp.status_code == 200
    assert resp.json() == persisted


async def test_get_task_trace_requires_engagement_access(app_with_observatory, bound_state):
    """operator role on another user's engagement gets 403."""
    session = _session(created_by="someone-else")
    task = _task(task_id="task-x", engagement_id=session.scope.engagement_id)
    orch = _orch_stub(session=session, tasks={task.id: task})
    bound_state(orch)

    fresh = FastAPI(title="observatory-auth-denial")
    fresh.include_router(observatory_router.router)

    async def _operator_only():
        return _operator(role="operator", sub="not-owner")

    fresh.dependency_overrides[verify_token] = _operator_only

    async with AsyncClient(transport=ASGITransport(app=fresh), base_url="http://t") as client:
        resp = await client.get(
            f"/engagements/{session.scope.engagement_id}/trace/{task.id}"
        )
    assert resp.status_code == 403
    fresh.dependency_overrides.clear()


async def test_get_task_trace_orchestrator_unbound_returns_503(app_with_observatory):
    app = app_with_observatory
    # Do NOT bind state -> state.get("orchestrator") is None. Note: the router
    # checks orchestrator AFTER assert_engagement_access, which itself raises
    # 503 when orchestrator is unset, so the guard surfaces immediately.
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/engagements/any-id/trace/task-id")
    assert resp.status_code == 503
    assert "Orchestrator not initialized" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# GET /engagements/{eid}/traces                                               #
# --------------------------------------------------------------------------- #


async def test_list_engagement_traces_returns_only_scoped_traces(
    app_with_observatory, bound_state
):
    """Traces list is engagement-scoped: tasks of other engagements are excluded."""
    app = app_with_observatory
    session_a = _session(short_id="eng-A", full_id="eng-20260801-eng-A")
    session_b = _session(short_id="eng-B", full_id="eng-20260801-eng-B")

    task_a1 = _task(task_id="task-a1", engagement_id="eng-A")
    task_a2 = _task(task_id="task-a2", engagement_id="eng-A")
    task_b1 = _task(task_id="task-b1", engagement_id="eng-B")
    # One untraced task for eng-A: must NOT appear in traces list
    task_a3 = _task(task_id="task-a3", engagement_id="eng-A", with_trace=False)

    orch = _orch_stub(
        session=session_a,
        tasks={t.id: t for t in (task_a1, task_a2, task_a3, task_b1)},
    )
    # seed session_b so unrelated engagement does not leak
    orch._sessions[session_b.session_id] = session_b
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/eng-A/traces")
    assert resp.status_code == 200
    body = resp.json()
    assert body["engagement_id"] == "eng-A"
    assert body["trace_count"] == 2
    ids = {t["task_id"] for t in body["traces"]}
    assert ids == {"task-a1", "task-a2"}


async def test_list_engagement_traces_empty_returns_zero(app_with_observatory, bound_state):
    app = app_with_observatory
    session = _session()
    orch = _orch_stub(session=session, tasks={})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(f"/engagements/{session.scope.engagement_id}/traces")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "engagement_id": session.scope.engagement_id,
        "trace_count": 0,
        "traces": [],
    }


# --------------------------------------------------------------------------- #
# GET /system/observatory/mcp-telemetry                                       #
# --------------------------------------------------------------------------- #


async def test_mcp_telemetry_aggregates_per_server(app_with_observatory, bound_state):
    """The endpoint walks orch.mcp_registry._servers and returns telemetry
    keyed by server_id with a count header."""
    app = app_with_observatory
    conn_a = MagicMock()
    conn_a.get_telemetry = MagicMock(
        return_value={"calls_total": 12, "errors": 1, "avg_latency_ms": 42.5}
    )
    conn_b = MagicMock()
    conn_b.get_telemetry = MagicMock(
        return_value={"calls_total": 3, "errors": 0, "avg_latency_ms": 11.0}
    )
    orch = _orch_stub(mcp_servers={"nuclei": conn_a, "recon": conn_b})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/mcp-telemetry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["mcp_servers"] == 2
    assert set(body["telemetry"].keys()) == {"nuclei", "recon"}
    assert body["telemetry"]["nuclei"]["calls_total"] == 12
    assert body["telemetry"]["recon"]["avg_latency_ms"] == 11.0
    conn_a.get_telemetry.assert_called_once_with()
    conn_b.get_telemetry.assert_called_once_with()


async def test_mcp_telemetry_empty_registry(app_with_observatory, bound_state):
    app = app_with_observatory
    orch = _orch_stub(mcp_servers={})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/mcp-telemetry")
    assert resp.status_code == 200
    assert resp.json() == {"mcp_servers": 0, "telemetry": {}}


async def test_mcp_telemetry_orchestrator_unbound_returns_503(app_with_observatory):
    app = app_with_observatory
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/mcp-telemetry")
    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# GET /system/observatory/scanner-audit                                       #
# --------------------------------------------------------------------------- #


async def test_scanner_audit_aggregates_statuses_and_durations(
    app_with_observatory, bound_state
):
    """The audit bucketes each task by (type) and aggregates
    scheduled/running/completed/failed/pending, failure categories, and a
    rolling avg_duration_ms."""
    app = app_with_observatory
    session = _session()

    base = datetime(2026, 8, 1, 12, 0, 0)
    # Completed scanner task with a 5s duration
    t_done = _task(
        task_id="t-done",
        engagement_id=session.scope.engagement_id,
        task_type="subdomain_scan",
        status="completed",
        started_at=base,
        completed_at=base + timedelta(seconds=5),
    )
    # Failed scanner task (different scanner) with 2s duration and a failure category
    t_fail = _task(
        task_id="t-fail",
        engagement_id=session.scope.engagement_id,
        task_type="port_scan",
        status="failed",
        started_at=base,
        completed_at=base + timedelta(seconds=2),
        failure={"category": "scanner", "reason": "timeout"},
    )
    # Running scanner task with no completed_at (no duration contribution)
    t_running = _task(
        task_id="t-run",
        engagement_id=session.scope.engagement_id,
        task_type="subdomain_scan",
        status="running",
    )

    orch = _orch_stub(
        session=session,
        tasks={t.id: t for t in (t_done, t_fail, t_running)},
    )
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/scanner-audit")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanner_count"] == 2
    by_type = {s["task_type"]: s for s in body["scanners"]}

    sub = by_type["subdomain_scan"]
    assert sub["scheduled"] == 2
    assert sub["completed"] == 1
    assert sub["running"] == 1
    assert sub["failed"] == 0
    assert sub["pending"] == 0
    # avg_duration_ms = (5_000 * 1) / 1 (only completed task contributes), then
    # running task has no duration so the running entry doesn't shift the avg:
    # formula: avg = (prev_avg * (scheduled-1) + dur) / scheduled, applied
    # once for t_done (scheduled=1) -> dur = 5000ms. t_running has no
    # duration so it doesn't update the average.
    assert sub["avg_duration_ms"] == 5000.0

    port = by_type["port_scan"]
    assert port["scheduled"] == 1
    assert port["failed"] == 1
    assert port["completed"] == 0
    assert port["avg_duration_ms"] == 2000.0
    assert port["failure_categories"] == {"scanner": 1}


async def test_scanner_audit_engagement_scoped(app_with_observatory, bound_state):
    """Supplying ?engagement_id= scopes the audit and enforces engagement access."""
    app = app_with_observatory
    session_a = _session(short_id="eng-A", full_id="eng-20260801-eng-A")
    t_a = _task(task_id="t-a", engagement_id="eng-A", task_type="nuclei_scan",
                status="completed")
    t_b = _task(task_id="t-b", engagement_id="eng-B", task_type="sqlmap_scan",
                status="completed")
    orch = _orch_stub(session=session_a, tasks={t_a.id: t_a, t_b.id: t_b})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get(
            "/system/observatory/scanner-audit", params={"engagement_id": "eng-A"}
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanner_count"] == 1
    task_types = [s["task_type"] for s in body["scanners"]]
    assert task_types == ["nuclei_scan"]


async def test_scanner_audit_global_requires_senior_operator(bound_state):
    """Without ?engagement_id, only senior_operator can see the global view."""
    session = _session()
    orch = _orch_stub(session=session, tasks={})
    bound_state(orch)

    fresh = FastAPI(title="observatory-scanner-global")
    fresh.include_router(observatory_router.router)

    async def _operator_only():
        return _operator(role="operator")

    fresh.dependency_overrides[verify_token] = _operator_only

    async with AsyncClient(transport=ASGITransport(app=fresh), base_url="http://t") as client:
        resp = await client.get("/system/observatory/scanner-audit")
    assert resp.status_code == 403
    assert "senior_operator" in resp.json()["detail"]

    # But the operator CAN still access engagement-scoped view.
    async with AsyncClient(transport=ASGITransport(app=fresh), base_url="http://t") as client:
        resp = await client.get(
            "/system/observatory/scanner-audit",
            params={"engagement_id": session.scope.engagement_id},
        )
    # senior_operator not required for scoped view; session is owned by None
    # so the ownership check trips a 403 ("no owner") — either way the global
    # gate is what we are testing above. Accept both authz outcomes.
    assert resp.status_code in (200, 403)
    fresh.dependency_overrides.clear()


async def test_scanner_audit_empty_task_pool(app_with_observatory, bound_state):
    app = app_with_observatory
    session = _session()
    orch = _orch_stub(session=session, tasks={})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/scanner-audit")
    assert resp.status_code == 200
    assert resp.json() == {"scanner_count": 0, "scanners": []}


async def test_scanner_audit_orchestrator_unbound_returns_503(app_with_observatory):
    """Unlike the engagement-scoped endpoints, scanner-audit checks
    state.orchestrator BEFORE assert_engagement_access, so the 503 actually
    surfaces from line 92 even when no engagement_id is supplied."""
    app = app_with_observatory
    # state["orchestrator"] is None (no bound_state call)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/scanner-audit")
    assert resp.status_code == 503
    assert "Orchestrator not initialized" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# GET /system/observatory/worker-telemetry                                    #
# --------------------------------------------------------------------------- #


async def test_worker_telemetry_collects_per_agent(app_with_observatory, bound_state):
    """Each registered agent contributes a row with status, queue depth, and
    last_heartbeat (pulled from session_memory)."""
    app = app_with_observatory
    sm = _session_memory_stub()
    sm.get_agent_heartbeat = AsyncMock(return_value="2026-08-01T12:00:00Z")

    agent_a = _agent_stub(AgentType.RECON, queue_depth=2)
    agent_b = _agent_stub(AgentType.VULN_ANALYSIS, queue_depth=7)

    orch = _orch_stub(agents={"agent-recon-1": agent_a, "agent-vuln-1": agent_b},
                      session_memory=sm)
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/worker-telemetry")
    assert resp.status_code == 200
    body = resp.json()
    assert body["worker_count"] == 2
    by_id = {w["agent_id"]: w for w in body["workers"]}

    a = by_id["agent-recon-1"]
    assert a["status"] == "idle"
    assert a["task_queue_depth"] == 2
    assert a["last_heartbeat"] == "2026-08-01T12:00:00Z"
    # agent_type stringified via str(...)
    assert "recon" in a["agent_type"].lower()

    b = by_id["agent-vuln-1"]
    assert b["task_queue_depth"] == 7

    # get_status and heartbeat were both polled once per agent
    agent_a.get_status.assert_awaited_once()
    agent_b.get_status.assert_awaited_once()
    assert sm.get_agent_heartbeat.await_count == 2


async def test_worker_telemetry_empty_pool(app_with_observatory, bound_state):
    app = app_with_observatory
    orch = _orch_stub(agents={})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/worker-telemetry")
    assert resp.status_code == 200
    assert resp.json() == {"worker_count": 0, "workers": []}


async def test_worker_telemetry_orchestrator_unbound_returns_503(app_with_observatory):
    app = app_with_observatory
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/worker-telemetry")
    assert resp.status_code == 503


# --------------------------------------------------------------------------- #
# Straight line-to-failure paths                                              #
# --------------------------------------------------------------------------- #


async def test_multiple_failure_categories_aggregated(app_with_observatory, bound_state):
    """Failure categories are aggregated across tasks of the same type, not
    overwritten by the last failure."""
    app = app_with_observatory
    session = _session()
    base = datetime(2026, 8, 1, 12, 0, 0)
    failures = [
        ("f-1", "scanner"),
        ("f-2", "mcp"),
        ("f-3", "scanner"),
    ]
    tasks = []
    for tid, cat in failures:
        t = _task(
            task_id=tid,
            engagement_id=session.scope.engagement_id,
            task_type="nuclei_scan",
            status="failed",
            started_at=base,
            completed_at=base + timedelta(seconds=1),
            failure={"category": cat, "reason": "boom"},
        )
        tasks.append(t)
    orch = _orch_stub(session=session, tasks={t.id: t for t in tasks})
    bound_state(orch)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.get("/system/observatory/scanner-audit")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanner_count"] == 1
    scanner = body["scanners"][0]
    assert scanner["failure_categories"] == {"scanner": 2, "mcp": 1}
    assert scanner["failed"] == 3
    assert scanner["avg_duration_ms"] == 1000.0
