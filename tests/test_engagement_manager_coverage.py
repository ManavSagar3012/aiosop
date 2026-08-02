"""Coverage-focused unit tests for ``EngagementManager``.

Real behavior tests for engagement lifecycle: creation (canonical engagement_id,
scope signing contract, tenant/organization propagation), phase transitions
(valid, invalid, exploitation gating, compare-and-set, phase-enter hook),
halt semantics (task cancel, queue drain, agent release), and authenticated
discovery claiming. SessionMemory / GraphMemory are mocked at the boundary;
``ScopeDefinition`` and ``SessionState`` are real Pydantic models.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType, EngagementPhase
from ai_osop.core.exceptions import WorkflowException, WorkflowTransitionError
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.orchestrator.engagement_manager import EngagementManager

# The real phase transition table the orchestrator uses.
VALID_TRANSITIONS = {
    EngagementPhase.INITIALIZED: [EngagementPhase.RECONNAISSANCE, EngagementPhase.HALTED],
    EngagementPhase.RECONNAISSANCE: [
        EngagementPhase.VULNERABILITY_DISCOVERY,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.VULNERABILITY_DISCOVERY: [
        EngagementPhase.EXPLOITATION,
        EngagementPhase.REPORTING,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.EXPLOITATION: [
        EngagementPhase.POST_EXPLOITATION,
        EngagementPhase.REPORTING,
        EngagementPhase.HALTED,
    ],
    EngagementPhase.POST_EXPLOITATION: [EngagementPhase.REPORTING, EngagementPhase.HALTED],
    EngagementPhase.REPORTING: [EngagementPhase.COMPLETED, EngagementPhase.HALTED],
    EngagementPhase.COMPLETED: [],
    EngagementPhase.HALTED: [],
}


def _scope(engagement_id: str = "eng-canonical-001", **overrides) -> ScopeDefinition:
    """Build a real ScopeDefinition with sane test defaults."""
    data = {
        "engagement_id": engagement_id,
        "organization_id": "org-acme",
        "domains": ["app.example.com"],
        "allowed_techniques": ["active-scan"],
    }
    data.update(overrides)
    return ScopeDefinition(**data)


def _session(scope: ScopeDefinition, session_id: str = "eng-20260801-sess-1", **over) -> SessionState:
    data = {
        "session_id": session_id,
        "scope": scope,
        "roe": {"signed_by": "operator-1"},
        "phase": EngagementPhase.INITIALIZED.value,
        "agents": {},
        "checkpoint_id": None,
        "audit_log_position": "0",
        "created_by": "operator-1",
    }
    data.update(over)
    return SessionState(**data)


def _manager(
    *,
    sessions=None,
    tasks=None,
    agents=None,
    task_handles=None,
    graph_stats=None,
    claim_result=True,
    read_query_records=None,
    phase_enter_error=None,
    pop_items=None,
):
    """Build an EngagementManager over a fully mocked orchestrator."""
    orch = MagicMock()
    orch.VALID_TRANSITIONS = VALID_TRANSITIONS
    orch._sessions = sessions if sessions is not None else {}
    orch._tasks = tasks if tasks is not None else {}
    orch._agents = agents if agents is not None else {}
    orch._task_handles = task_handles if task_handles is not None else {}

    # SessionMemory boundary mock — records every call for assertions.
    orch.session_memory = MagicMock()
    orch.session_memory.store_session_state = AsyncMock()
    orch.session_memory.persist_session_state = AsyncMock()
    orch.session_memory.store_engagement_id_mapping = AsyncMock()
    items = list(pop_items or [])
    orch.session_memory.pop_task_queue = AsyncMock(side_effect=items or [None])

    # GraphMemory boundary mock.
    orch.graph_memory = MagicMock()
    orch.graph_memory.get_graph_stats = AsyncMock(return_value=graph_stats or {})
    orch.graph_memory.claim_auto_discovery = AsyncMock(return_value=claim_result)
    orch.graph_memory.run_read_query = AsyncMock(return_value=read_query_records or [])

    # Phase monitor hook.
    orch.phase_monitor = MagicMock()
    orch.phase_monitor._on_phase_enter = AsyncMock(side_effect=phase_enter_error)

    orch._audit_log = AsyncMock()
    orch._release_agent = AsyncMock()
    orch.schedule_task = AsyncMock()

    return EngagementManager(orch), orch


# ── __init__ ─────────────────────────────────────────────────────────────────


class TestInit:
    def test_explicit_state_machine_used(self):
        orch = MagicMock()
        sm = MagicMock(name="state_machine")
        mgr = EngagementManager(orch, state_machine=sm)
        assert mgr.state_machine is sm

    def test_state_machine_falls_back_to_orchestrator_attr(self):
        orch = MagicMock()
        orch.engagement_state_machine = "sm-from-orch"
        mgr = EngagementManager(orch)
        assert mgr.state_machine == "sm-from-orch"


# ── create_engagement ────────────────────────────────────────────────────────


class TestCreateEngagement:
    async def test_creates_session_with_canonical_engagement_id(self):
        mgr, orch = _manager()
        scope = _scope()
        session = await mgr.create_engagement(scope, roe={"signed_by": "op"}, created_by="op-7")

        assert session.scope.engagement_id == "eng-canonical-001"
        assert session.canonical_engagement_id == "eng-canonical-001"
        assert session.session_id.endswith("-eng-canonical-001")
        assert session.session_id.startswith("eng-")
        assert session.phase == EngagementPhase.INITIALIZED.value
        assert session.created_by == "op-7"
        assert session.roe == {"signed_by": "op"}

        # Persisted to both tiers and indexed by engagement_id -> session_id.
        orch.session_memory.store_session_state.assert_awaited_once_with(session)
        orch.session_memory.persist_session_state.assert_awaited_once_with(session)
        orch.session_memory.store_engagement_id_mapping.assert_awaited_once_with(
            "eng-canonical-001", session.session_id
        )
        assert orch._sessions[session.session_id] is session

        # Audit event written with canonical engagement id
        orch._audit_log.assert_awaited_once()
        event = orch._audit_log.await_args.args[0]
        assert event.event_type == "engagement_created"
        assert event.engagement_id == "eng-canonical-001"
        assert event.result["session_id"] == session.session_id

    async def test_scope_contract_signed_when_unsigned(self):
        """GAP-2-4 scope contract: creation signs an unsigned scope manifest."""
        mgr, _ = _manager()
        scope = _scope()
        assert scope.signature is None
        session = await mgr.create_engagement(scope, roe={})
        assert session.scope.signature is not None
        assert len(session.scope.signature) == 64  # sha256 hexdigest

    async def test_presigned_scope_signature_left_intact(self):
        """An externally-supplied signature must not be replaced at creation."""
        mgr, _ = _manager()
        scope = _scope()
        scope.signature = "deadbeef" * 8
        session = await mgr.create_engagement(scope, roe={})
        assert session.scope.signature == "deadbeef" * 8

    async def test_tenant_organization_id_propagates_to_session(self):
        """Tenant gating input (organization_id) rides through on the scope."""
        mgr, _ = _manager()
        scope = _scope(organization_id="org-tenant-42")
        session = await mgr.create_engagement(scope, roe={})
        assert session.scope.organization_id == "org-tenant-42"

    async def test_creation_failure_logs_and_reraises(self):
        """create_engagement wraps _unsafe: exceptions are logged and re-raised."""
        mgr, orch = _manager()
        orch.session_memory.store_session_state = AsyncMock(side_effect=RuntimeError("redis down"))
        with pytest.raises(RuntimeError, match="redis down"):
            await mgr.create_engagement(_scope(), roe={})


# ── halt_engagement ──────────────────────────────────────────────────────────


class TestHaltEngagement:
    async def test_halt_unknown_session_returns_silently(self):
        mgr, orch = _manager(sessions={})
        await mgr.halt_engagement("sess-missing", reason="not here")
        orch.session_memory.store_session_state.assert_not_awaited()
        orch._audit_log.assert_not_awaited()

    async def test_halt_sets_phase_halted_and_persists(self):
        scope = _scope()
        session = _session(scope)
        mgr, orch = _manager(sessions={"sess-1": session})
        await mgr.halt_engagement("sess-1", reason="operator kill")

        assert session.phase == EngagementPhase.HALTED.value
        orch.session_memory.store_session_state.assert_awaited_once_with(session)

        event = orch._audit_log.await_args.args[0]
        assert event.event_type == "engagement_halted"
        assert event.severity == "critical"
        assert event.action["reason"] == "operator kill"
        assert event.engagement_id == "eng-canonical-001"

    async def test_halt_cancels_pending_and_running_tasks_and_handles(self):
        scope = _scope()
        session = _session(scope, session_id="eng-9")
        mgr_tasks = {
            "t1": Task(
                id="t1", type="scan", agent_type=AgentType.RECON,
                engagement_id="eng-9", status="running",
            ),
            "t2": Task(
                id="t2", type="scan", agent_type=AgentType.RECON,
                engagement_id="eng-9", status="pending",
            ),
            # completed task on the halted engagement: must NOT be touched
            "t3": Task(
                id="t3", type="scan", agent_type=AgentType.RECON,
                engagement_id="eng-9", status="completed",
            ),
            # pending task on a DIFFERENT engagement: untouched
            "t4": Task(
                id="t4", type="scan", agent_type=AgentType.RECON,
                engagement_id="eng-other", status="pending",
            ),
        }
        handle = MagicMock()
        handle.done.return_value = False
        handles = {"t1": handle}
        # both t1 (running) and t2 (pending) are cancelled when present in handles
        handle2 = MagicMock()
        handle2.done.return_value = False
        handles["t2"] = handle2
        mgr, orch = _manager(
            sessions={"eng-9": session}, tasks=mgr_tasks, task_handles=handles
        )

        await mgr.halt_engagement("eng-9", reason="kill switch")

        assert mgr_tasks["t1"].status == "cancelled"
        assert mgr_tasks["t2"].status == "cancelled"
        assert mgr_tasks["t3"].status == "completed"
        assert mgr_tasks["t4"].status == "pending"
        handle.cancel.assert_called_once()
        handle2.cancel.assert_called_once()
        # handles popped so a later halt doesn't double-cancel
        assert mgr._orch._task_handles == {}

    async def test_halt_drains_task_queue(self):
        scope = _scope()
        session = _session(scope, session_id="eng-drain")
        mgr, orch = _manager(
            sessions={"eng-drain": session},
            pop_items=[{"task": 1}, {"task": 2}, None],
        )
        await mgr.halt_engagement("eng-drain", reason="drain test")
        assert orch.session_memory.pop_task_queue.await_count == 3
        orch.session_memory.pop_task_queue.assert_awaited_with("tasks:eng-drain")

    async def test_halt_survives_queue_drain_failure(self):
        """A Redis failure during draining is logged as a warning, not raised."""
        scope = _scope()
        session = _session(scope, session_id="eng-redis-broken")
        mgr, orch = _manager(sessions={"eng-redis-broken": session})
        orch.session_memory.pop_task_queue = AsyncMock(side_effect=ConnectionError("redis gone"))

        await mgr.halt_engagement("eng-redis-broken", reason="x")  # must not raise
        assert session.phase == EngagementPhase.HALTED.value

    async def test_halt_releases_running_agents_on_this_engagement(self):
        scope = _scope()
        session = _session(scope, session_id="eng-agents")
        agent_running_here = SimpleNamespace(
            ctx=SimpleNamespace(session_id="eng-agents", status="running",
                                agent_id="agent-1", current_task=Task(
                                    id="tq", type="scan", agent_type=AgentType.RECON,
                                    engagement_id="eng-agents"))
        )
        agent_running_elsewhere = SimpleNamespace(
            ctx=SimpleNamespace(session_id="eng-other", status="running",
                                agent_id="agent-2", current_task=None)
        )
        agent_idle_here = SimpleNamespace(
            ctx=SimpleNamespace(session_id="eng-agents", status="idle",
                                agent_id="agent-3", current_task=None)
        )
        mgr, orch = _manager(
            sessions={"eng-agents": session},
            agents={
                "agent-1": agent_running_here,
                "agent-2": agent_running_elsewhere,
                "agent-3": agent_idle_here,
            },
        )

        await mgr.halt_engagement("eng-agents", reason="stop")

        # Only the running agent on the halted engagement is released and reset.
        assert agent_running_here.ctx.current_task is None
        orch._release_agent.assert_awaited_once_with("agent-1")


# ── transition_phase ─────────────────────────────────────────────────────────


class TestTransitionPhase:
    async def test_unknown_session_raises(self):
        mgr, _ = _manager(sessions={})
        with pytest.raises(WorkflowException, match="Session nope not found"):
            await mgr.transition_phase("nope", EngagementPhase.RECONNAISSANCE)

    async def test_invalid_transition_raises_workflow_transition_error(self):
        scope = _scope()
        session = _session(scope, phase=EngagementPhase.INITIALIZED.value)
        mgr, orch = _manager(sessions={"s1": session})

        with pytest.raises(WorkflowTransitionError, match="Invalid transition"):
            await mgr.transition_phase("s1", EngagementPhase.COMPLETED)

        # Phase unchanged, nothing persisted.
        assert session.phase == EngagementPhase.INITIALIZED.value
        orch.session_memory.persist_session_state.assert_not_awaited()
        orch.ph_failure = None
        orch.phase_monitor._on_phase_enter.assert_not_awaited()

    async def test_valid_transition_persists_and_audits(self):
        scope = _scope()
        session = _session(scope, phase=EngagementPhase.INITIALIZED.value)
        mgr, orch = _manager(sessions={"s1": session})
        before = session.updated_at

        result = await mgr.transition_phase("s1", EngagementPhase.RECONNAISSANCE)

        assert result is session
        assert session.phase == EngagementPhase.RECONNAISSANCE.value
        assert session.updated_at >= before
        orch.phase_monitor._on_phase_enter.assert_awaited_once_with(
            session, EngagementPhase.RECONNAISSANCE
        )
        # GAP-3-4 persistence of the transition: hot tier AND durable tier.
        orch.session_memory.store_session_state.assert_awaited_once_with(session)
        orch.session_memory.persist_session_state.assert_awaited_once_with(session)
        event = orch._audit_log.await_args.args[0]
        assert event.event_type == "phase_transition"
        assert event.action == {"from_phase": "initialized", "to_phase": "reconnaissance"}
        assert event.engagement_id == "eng-canonical-001"

    async def test_exploitation_blocked_without_vulnerabilities(self):
        scope = _scope()
        session = _session(scope, phase=EngagementPhase.VULNERABILITY_DISCOVERY.value)
        mgr, orch = _manager(
            sessions={"s1": session}, graph_stats={"vulnerabilities": 0}
        )
        with pytest.raises(WorkflowException, match="without vulnerabilities"):
            await mgr.transition_phase("s1", EngagementPhase.EXPLOITATION)
        assert session.phase == EngagementPhase.VULNERABILITY_DISCOVERY.value

    async def test_exploitation_allowed_with_vulnerabilities(self):
        scope = _scope()
        session = _session(scope, phase=EngagementPhase.VULNERABILITY_DISCOVERY.value)
        mgr, orch = _manager(
            sessions={"s1": session}, graph_stats={"vulnerabilities": 3}
        )
        result = await mgr.transition_phase("s1", EngagementPhase.EXPLOITATION)
        assert result.phase == EngagementPhase.EXPLOITATION.value
        # AIOSOP-GRAPH-KEY-002: stats queried by canonical engagement id.
        orch.graph_memory.get_graph_stats.assert_awaited_once_with("eng-canonical-001")

    async def test_exploitation_gate_uses_canonical_id_for_graph_stats(self):
        """Graph stats are queried with scope.engagement_id, not the session PK."""
        scope = _scope(engagement_id="juice-e2e-xyz")
        session = _session(
            scope, session_id="eng-20260801-juice-e2e-xyz",
            phase=EngagementPhase.VULNERABILITY_DISCOVERY.value,
        )
        mgr, orch = _manager(
            sessions={"eng-20260801-juice-e2e-xyz": session},
            graph_stats={"vulnerabilities": 1},
        )
        await mgr.transition_phase("eng-20260801-juice-e2e-xyz", EngagementPhase.EXPLOITATION)
        args = orch.graph_memory.get_graph_stats.await_args.args
        assert args[0] == "juice-e2e-xyz"

    async def test_concurrent_phase_change_aborts_with_transition_error(self):
        """GAP-3-4 compare-and-set: if the phase changed during the graph-stats
        await, the transition must not clobber the concurrent write."""
        scope = _scope()
        session = _session(scope, phase=EngagementPhase.VULNERABILITY_DISCOVERY.value)
        mgr, orch = _manager(sessions={"s1": session})

        async def _halt_during_query(eid):
            session.phase = EngagementPhase.HALTED.value
            return {"vulnerabilities": 5}

        orch.graph_memory.get_graph_stats = AsyncMock(side_effect=_halt_during_query)

        with pytest.raises(WorkflowTransitionError, match="Concurrent phase change"):
            await mgr.transition_phase("s1", EngagementPhase.EXPLOITATION)
        # Halt preserved — transition did not clobber it.
        assert session.phase == EngagementPhase.HALTED.value
        orch.session_memory.persist_session_state.assert_not_awaited()

    async def test_phase_enter_hook_failure_reverts_phase(self):
        """AIOSOP-PHASE-ENTER-FIRST: hook failure rolls back the in-memory phase."""
        scope = _scope()
        session = _session(scope, phase=EngagementPhase.INITIALIZED.value)
        mgr, orch = _manager(
            sessions={"s1": session}, phase_enter_error=RuntimeError("dispatch boom")
        )

        with pytest.raises(WorkflowException, match="Phase entry hook failed"):
            await mgr.transition_phase("s1", EngagementPhase.RECONNAISSANCE)

        assert session.phase == EngagementPhase.INITIALIZED.value  # reverted
        orch.session_memory.store_session_state.assert_not_awaited()
        orch.session_memory.persist_session_state.assert_not_awaited()
        orch._audit_log.assert_not_awaited()


# ── engagement status/authentication helpers ─────────────────────────────────


class TestEngagementIsAuthenticated:
    async def test_true_when_graph_session_authenticated(self):
        mgr, orch = _manager(read_query_records=[{"authenticated": True}])
        assert await mgr._engagement_is_authenticated("eng-x") is True
        orch.graph_memory.run_read_query.assert_awaited_once()
        call = orch.graph_memory.run_read_query.await_args
        assert call.args[1] == {"eid": "eng-x"}

    async def test_false_when_not_authenticated(self):
        mgr, _ = _manager(read_query_records=[{"authenticated": False}])
        assert await mgr._engagement_is_authenticated("eng-x") is False

    async def test_false_when_no_records(self):
        mgr, _ = _manager(read_query_records=[])
        assert await mgr._engagement_is_authenticated("eng-x") is False

    async def test_false_on_graph_error(self):
        """Graph failures fail closed: engagement treated as unauthenticated."""
        mgr, orch = _manager()
        orch.graph_memory.run_read_query = AsyncMock(side_effect=Exception("neo4j down"))
        assert await mgr._engagement_is_authenticated("eng-x") is False


class TestPickAuthUserLabel:
    async def test_returns_username(self):
        mgr, _ = _manager(read_query_records=[{"username": "alice@example.com"}])
        assert await mgr._pick_auth_user_label("eng-x") == "alice@example.com"

    async def test_none_when_no_records(self):
        mgr, _ = _manager(read_query_records=[])
        assert await mgr._pick_auth_user_label("eng-x") is None

    async def test_none_on_graph_error(self):
        mgr, orch = _manager()
        orch.graph_memory.run_read_query = AsyncMock(side_effect=Exception("neo4j down"))
        assert await mgr._pick_auth_user_label("eng-x") is None


# ── claim_auto_discovery / ensure_authenticated_discovery ────────────────────


class TestClaimAutoDiscovery:
    async def test_lost_claim_returns_none_without_scheduling(self):
        mgr, orch = _manager(claim_result=False)
        result = await mgr.claim_auto_discovery("eng-x", "alice", "task-src-1")
        assert result is None
        orch.schedule_task.assert_not_awaited()
        orch._audit_log.assert_not_awaited()

    async def test_won_claim_builds_and_schedules_map_workflow_task(self):
        mgr, orch = _manager(claim_result=True)
        task = await mgr.claim_auto_discovery(
            "eng-x", "alice", "task-src-1", url_hint="http://localhost:3000"
        )
        assert task is not None
        assert task.type == "map_workflow"
        assert task.agent_type == AgentType.WORKFLOW
        assert task.priority == 7
        assert task.engagement_id == "eng-x"
        assert task.payload["url"] == "http://localhost:3000"
        assert task.payload["user_label"] == "alice"
        assert task.payload["source_task_id"] == "task-src-1"

        orch.graph_memory.claim_auto_discovery.assert_awaited_once_with("eng-x")
        orch.schedule_task.assert_awaited_once_with(task)
        event = orch._audit_log.await_args.args[0]
        assert event.event_type == "auto_map_dispatch"
        assert event.engagement_id == "eng-x"

    async def test_url_derived_from_scope_domains_when_no_hint(self):
        scope = _scope(domains=["localhost:3000"])
        session = _session(scope, session_id="eng-x")
        mgr, orch = _manager(sessions={"eng-x": session}, claim_result=True)

        task = await mgr.claim_auto_discovery("eng-x", "bob", "src-2", url_hint=None)
        assert task.payload["url"] == "http://localhost:3000/"

    async def test_url_empty_when_no_hint_and_no_scope_domains(self):
        mgr, _ = _manager(claim_result=True)
        task = await mgr.claim_auto_discovery("eng-unknown", "bob", "src-3")
        assert task.payload["url"] == ""


class TestEnsureAuthenticatedDiscovery:
    async def test_noop_when_engagement_not_authenticated(self):
        mgr, orch = _manager(read_query_records=[{"authenticated": False}])
        result = await mgr.ensure_authenticated_discovery("eng-x")
        assert result is None
        orch.schedule_task.assert_not_awaited()

    async def test_noop_when_no_username_label(self):
        mgr, orch = _manager()
        orch.graph_memory.run_read_query = AsyncMock(
            side_effect=[
                [{"authenticated": True}],   # _engagement_is_authenticated
                [{"username": None}],        # _pick_auth_user_label
            ]
        )
        result = await mgr.ensure_authenticated_discovery("eng-x")
        assert result is None
        orch.schedule_task.assert_not_awaited()

    async def test_dispatches_when_authenticated_and_labelled(self):
        mgr, orch = _manager(claim_result=True)
        orch.graph_memory.run_read_query = AsyncMock(
            side_effect=[
                [{"authenticated": True}],
                [{"username": "carol@example.com"}],
            ]
        )
        task = await mgr.ensure_authenticated_discovery(
            "eng-x", url_hint="https://app.example.com"
        )
        assert task is not None
        assert task.type == "map_workflow"
        assert task.payload["user_label"] == "carol@example.com"
        assert task.payload["url"] == "https://app.example.com"
        # source task id is the hardcoded session-import marker
        assert task.payload["source_task_id"] == "session-import"
        orch.schedule_task.assert_awaited_once_with(task)
