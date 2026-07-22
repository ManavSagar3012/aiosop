"""M2 unification test: every task writer now keys under the CANONICAL
engagement id (scope.engagement_id), eliminating the dual-key split-brain
that stranded findings (AIOSOP-FINDINGS-KEY-2026-07-20).

These tests pin the unification hermetically (no data tier):

  1. SessionState.canonical_engagement_id resolves to scope.engagement_id
     regardless of the session_id form.
  2. phase_monitor._auto_advance_phase keys its phase-completion check on the
     CANONICAL id (so tasks written under scope.engagement_id are matched
     without a dual-form fallback).
  3. The findings/tasks/sessions routers construct Tasks/UserSessions under
     the canonical id (not the URL session_id).
  4. Orchestrator._is_phase_complete still tolerates tasks written under BOTH
     forms (legacy compatibility) but matches a canonical-id task directly.

The earlier ``test_findings_dual_key_retrieval.py`` pinned the *symptom patch*
(WHERE engagement_id IN $ids). This test pins the *root-cause fix* (writers
emit one canonical id), so the dual-key reader's fallback branch becomes
defense-in-depth rather than load-bearing.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType, EngagementPhase, Severity, VulnClass
from ai_osop.core.models import ScopeDefinition, SessionState, Task, Vulnerability


def _session(short="juice-e2e-abc", full="eng-20260721-juice-e2e-abc"):
    return SessionState(
        session_id=full,
        scope=ScopeDefinition(engagement_id=short, domains=["x.test"]),
        phase=EngagementPhase.RECONNAISSANCE.value,
    )


def test_canonical_engagement_id_is_scope_engagement_id():
    """The canonical id is scope.engagement_id — the SHORT operator-supplied id,
    NOT the timestamped session_id. This is the one every writer must use."""
    s = _session()
    assert s.canonical_engagement_id == "juice-e2e-abc"
    assert s.canonical_engagement_id != s.session_id


def test_canonical_id_stable_across_session_id_regen():
    """Two sessions with different timestamps but the same scope.engagement_id
    resolve to the SAME canonical id — so findings/tasks survive a re-create."""
    s1 = _session(full="eng-20260720-juice-e2e-abc")
    s2 = _session(full="eng-20260721-juice-e2e-abc")
    assert s1.canonical_engagement_id == s2.canonical_engagement_id == "juice-e2e-abc"


@pytest.mark.asyncio
async def test_phase_monitor_uses_canonical_id_for_phase_completion():
    """_auto_advance_phase passes the CANONICAL id to _is_phase_complete. A task
    written under the canonical id is matched DIRECTLY (no dual-form fallback
    needed) — this is the proof the unification holds at the phase gate."""
    from ai_osop.orchestrator.phase_monitor import PhaseMonitor

    session = _session()
    captured = {}

    async def _is_phase_complete(session_id, phase):
        captured["session_id"] = session_id
        captured["phase"] = phase
        return False  # don't actually transition

    # _resolve_auto_next must also be awaited; return a phase so the flow
    # proceeds past _is_phase_complete (which we drive True here to exercise
    # the canonical-id path past the gate).
    async def _is_phase_complete_true(session_id, phase):
        captured["session_id"] = session_id
        captured["phase"] = phase
        return True

    async def _resolve_auto_next(session_id, phase, desired):
        return None  # None => no transition attempted, return cleanly

    orch = SimpleNamespace(
        _is_phase_complete=_is_phase_complete_true,
        _resolve_auto_next=_resolve_auto_next,
        _auto_transition_ready=lambda *a, **k: True,
        engagement_manager=SimpleNamespace(transition_phase=AsyncMock()),
        PHASE_POLICY={
            EngagementPhase.RECONNAISSANCE: {"auto_next": EngagementPhase.VULNERABILITY_DISCOVERY}
        },
        _record_auto_transition_failure=lambda *a, **k: None,
        _auto_transition_failures={},
    )
    pm = PhaseMonitor.__new__(PhaseMonitor)
    pm._orch = orch
    pm._tick = 1

    await pm._auto_advance_phase(session)
    assert (
        captured["session_id"] == "juice-e2e-abc"
    ), f"phase monitor must key on canonical id; got {captured['session_id']!r}"
    assert captured["phase"] == EngagementPhase.RECONNAISSANCE


@pytest.mark.asyncio
async def test_is_phase_complete_matches_canonical_task_directly():
    """A task written under the canonical id is matched by _is_phase_complete
    without requiring the dual-form fallback. This is the steady-state contract
    after M2."""
    from ai_osop.orchestrator.orchestrator import Orchestrator

    session = _session()
    canonical_task = Task(
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="juice-e2e-abc",  # canonical form
        status="completed",
    )

    class _State:
        def get_all_tasks(self):
            return {canonical_task.id: canonical_task}

        def get_task(self, tid):
            return canonical_task

    orch = SimpleNamespace(
        _sessions={"juice-e2e-abc": session},
        state=_State(),
        session_memory=SimpleNamespace(load_all_active_tasks=AsyncMock(return_value=[])),
    )

    # Call the unbound method directly with the orchestrator instance.
    complete = await Orchestrator._is_phase_complete(
        orch, "juice-e2e-abc", EngagementPhase.RECONNAISSANCE
    )
    assert complete is True, (
        "a canonical-id task must match _is_phase_complete directly (the dual-key "
        "fallback is legacy-only now)"
    )


@pytest.mark.asyncio
async def test_is_phase_complete_legacy_dual_form_still_matched():
    """Defense-in-depth: a task written under the FULL session_id form (legacy
    writer, recovered from Postgres, etc.) is STILL matched by
    _is_phase_complete so a migration gap can't strand the phase. The canonical
    form is the steady state; the legacy match is the safety net."""
    from ai_osop.orchestrator.orchestrator import Orchestrator

    session = _session()
    legacy_task = Task(
        type="full_recon",
        agent_type=AgentType.RECON,
        engagement_id="eng-20260721-juice-e2e-abc",  # full session_id form
        status="completed",
    )

    class _State:
        def get_all_tasks(self):
            return {legacy_task.id: legacy_task}

        def get_task(self, tid):
            return legacy_task

    orch = SimpleNamespace(
        _sessions={"juice-e2e-abc": session},  # lookup by canonical id
        state=_State(),
        session_memory=SimpleNamespace(load_all_active_tasks=AsyncMock(return_value=[])),
    )

    # _is_phase_complete is called with the CANONICAL id (per test above), and
    # the legacy-form task is matched via the _full_sid fallback branch.
    complete = await Orchestrator._is_phase_complete(
        orch, "juice-e2e-abc", EngagementPhase.RECONNAISSANCE
    )
    assert complete is True


@pytest.mark.asyncio
async def test_findings_router_replay_task_uses_canonical_id(monkeypatch):
    """The findings router's replay endpoint constructs its validate_exploit
    task under the CANONICAL id, not the URL session_id. Verified by capturing
    the scheduled task."""
    from ai_osop.api.routers import findings as findings_router

    session = _session()
    scheduled = []

    async def _fake_assert(operator, session_id):
        return session

    async def _fake_schedule(task):
        scheduled.append(task)

    async def _finding_exists(session_id, finding_id, id_forms=None):
        return True

    monkeypatch.setattr(findings_router, "assert_engagement_access", _fake_assert)
    monkeypatch.setattr(findings_router, "_finding_exists", _finding_exists)
    # Patch the orchestrator on the shared state dict directly (dict, not obj).
    monkeypatch.setitem(
        findings_router.state,
        "orchestrator",
        SimpleNamespace(schedule_task=_fake_schedule),
    )

    await findings_router.replay_finding(
        session_id="eng-20260721-juice-e2e-abc",  # URL carries FULL form
        finding_id="vuln-1",
        operator={"sub": "op", "role": "senior_operator"},
    )
    assert scheduled, "task was not scheduled"
    assert (
        scheduled[0].engagement_id == "juice-e2e-abc"
    ), f"replay task must be keyed canonically; got {scheduled[0].engagement_id!r}"


@pytest.mark.asyncio
async def test_sessions_router_save_uses_canonical_id(monkeypatch):
    """The sessions router persists UserSessions under the CANONICAL id so every
    reader (workflow_agent, csrf_agent, phase_monitor list_sessions) finds them
    without a dual-form lookup."""
    from ai_osop.api.routers import sessions as sessions_router

    session = _session()
    saved = {}

    class _FakeStore:
        async def save_session(self, *, engagement_id, user_label, **kw):
            saved["engagement_id"] = engagement_id
            saved["user_label"] = user_label
            # Return a real UserSession so the router's _session_response mapper
            # finds every attribute it touches.
            from ai_osop.auth.session_store import UserSession

            return UserSession(
                engagement_id=engagement_id,
                user_label=user_label,
                cookies=kw.get("cookies") or [],
                bearer_token=kw.get("bearer_token") or "",
                local_storage=kw.get("local_storage") or {},
                session_storage=kw.get("session_storage") or {},
                csrf_token=kw.get("csrf_token") or "",
                extra_headers=kw.get("extra_headers") or {},
                user_agent=kw.get("user_agent") or "",
            )

    async def _fake_assert(operator, session_id):
        return session

    async def _project(*a, **k):
        return None

    async def _trigger(*a, **k):
        return None

    monkeypatch.setattr(sessions_router, "assert_engagement_access", _fake_assert)
    monkeypatch.setattr(sessions_router, "_project_session_to_graph", _project)
    monkeypatch.setattr(sessions_router, "_trigger_authenticated_discovery", _trigger)
    monkeypatch.setitem(sessions_router.state, "session_store", _FakeStore())

    body = SimpleNamespace(
        user_label="alice",
        cookies=[],
        bearer_token="",
        local_storage={},
        session_storage={},
        csrf_token="",
        extra_headers={},
        user_agent="",
        metadata={},
    )
    await sessions_router.put_user_session(
        session_id="eng-20260721-juice-e2e-abc",
        user_label="alice",
        body=body,
        operator={"sub": "op", "role": "operator"},
    )
    assert (
        saved["engagement_id"] == "juice-e2e-abc"
    ), f"UserSession must be saved under canonical id; got {saved['engagement_id']!r}"
