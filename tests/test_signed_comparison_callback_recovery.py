"""Recover signed provider-only comparisons from committed PG terminal pairs.

No tests run an application DB, browser, Temporal worker or model provider.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.memory.session_memory import SessionMemory, TaskORM
from ai_osop.memory.supervision_store import (
    SupervisionAttemptORM,
    SupervisionControlORM,
    SupervisionExecutionLeaseORM,
)
from ai_osop.memory.terminal_lifecycle import (
    TerminalLifecycleStore,
    _continuation_metadata,
    _signed_replay_terminal_receipt,
)
from ai_osop.orchestrator.terminal_dispatcher import TerminalCallbackDispatcher
from ai_osop.memory.supervision_store import SupervisionConflict
from tests.test_signed_replay_comparison import pair, verdict


ENGAGEMENT = "eng-owned"
SOURCE = "task-source"
TARGET = "task-target"


def terminal_task():
    return SimpleNamespace(
        id=TARGET,
        type="navigate",
        engagement_id=ENGAGEMENT,
        flow_id="flow-owned",
        parent_task_id="task-parent",
        approval_required=True,
        max_retries=0,
        payload={
            "_comparison_role": "target",
            "_authorization_version": 7,
            "_flow_revision": 3,
            "method": "GET",
        },
    )


def test_real_map_workflow_terminal_source_keeps_admissible_status_and_workflow_id():
    """Both diff-auth admission and signed GET execution read PG result.status."""
    continuation = _continuation_metadata("map_workflow", {
        "status": "workflow_recorded",
        "workflow_id": "wf-owned",
        "cookies": "PRIVATE",
        "raw_response": "PRIVATE",
    })
    # commit_terminal uses this exact merge for successful non-replay tasks.
    pg_result = {"status": "completed", **continuation}
    assert pg_result == {"status": "workflow_recorded", "workflow_id": "wf-owned"}
    assert pg_result["status"] in {"workflow_recorded", "success"}
    assert _continuation_metadata(
        "map_workflow",
        {"status": "execution_unknown", "workflow_id": "wf-owned"},
    ) == {"workflow_id": "wf-owned"}
    assert _continuation_metadata(
        "map_workflow",
        {"status": "workflow_recorded", "workflow_id": "../invalid"},
    ) == {}
    assert _continuation_metadata(
        "extract_har_api_inventory",
        {"status": "success", "workflow_id": "wf-owned"},
    ) == {"workflow_id": "wf-owned"}


@pytest.mark.asyncio
async def test_commit_terminal_then_authoritative_task_readback_retains_signed_map_source():
    """Exercise the actual terminal writer and SessionMemory PG reader contract."""
    now = datetime.utcnow()
    task = TaskORM(
        id="task-original",
        type="map_workflow",
        priority=5,
        agent_type="workflow",
        status="running",
        engagement_id=ENGAGEMENT,
        flow_id=None,
        payload={
            "_authorization_version": 7,
            "url": "https://authorized.test/workflow",
            "user_label": "alice",
        },
        dependencies=[],
        retry_count=0,
        max_retries=0,
        timeout_seconds=90,
        scope_check=True,
        approval_required=False,
        started_at=now,
        created_at=now,
    )
    attempt = SimpleNamespace(status="running", revision=4)
    engagement = SimpleNamespace(scope={
        "engagement_id": ENGAGEMENT,
        "authorization_ref": "signed-source",
        "domains": ["authorized.test"],
    })

    class Db:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        def begin(self):
            return self

        async def execute(self, statement):
            entity = statement.column_descriptions[0]["entity"]
            rows = {
                SupervisionAttemptORM: attempt,
                SupervisionExecutionLeaseORM: None,
                SupervisionControlORM: None,
                TaskORM: task,
            }
            assert entity in rows, entity
            return SimpleNamespace(scalar_one_or_none=lambda: rows[entity])

        def add(self, _value):
            pass

        async def flush(self):
            pass

    db = Db()
    writer = TerminalLifecycleStore.__new__(TerminalLifecycleStore)
    writer._sessions = lambda: db
    writer._guard = AsyncMock(return_value=(engagement, task))
    writer._append_event = AsyncMock()
    committed = await writer.commit_terminal(
        ENGAGEMENT,
        task.id,
        "attempt-1",
        4,
        "succeeded",
        continuation={
            "status": "workflow_recorded",
            "workflow_id": "wf-owned",
            "headers": {"Authorization": "PRIVATE"},
            "cookies": "PRIVATE",
        },
    )
    assert committed is not None and committed["created"] is True
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = lambda: db
    original = await memory.load_task_authoritative(task.id)
    assert original is not None
    assert original.status == "completed"
    assert original.result == {"status": "workflow_recorded", "workflow_id": "wf-owned"}
    assert original.result["status"] in {"success", "workflow_recorded"}
    assert "PRIVATE" not in str(original.result)


def provider_result():
    return {
        "status": "success",
        "source_task_id": SOURCE,
        "replay_parent_task_id": "task-parent",
        "comparison_role": "target",
        "verification_status": "provider_testimony_only",
        "authorization_violation_verified": False,
        "remote_effect_verified": False,
        "http_status_code": 200,
        "redirected": False,
        "response_body_sha256": "b" * 64,
        "provider_evidence": {
            "provider_event_id": "evt-owned",
            "provider_receipt_sha256": "a" * 64,
            "source_authenticity_verified": False,
            "target_effect_verified": False,
            "finding_verified": False,
            "secret": "DO-NOT-PERSIST",
        },
        "body": "PRIVATE BODY",
        "cookies": "PRIVATE COOKIE",
        "headers": {"Authorization": "PRIVATE"},
        "findings": [{"secret": "PRIVATE"}],
    }


def test_completed_comparison_result_survives_terminal_commit_as_redacted_provider_testimony():
    receipt = _signed_replay_terminal_receipt(terminal_task(), provider_result())
    assert receipt["status"] == "success"
    assert receipt["verification_status"] == "provider_testimony_only"
    assert receipt["authorization_violation_verified"] is False
    assert receipt["remote_effect_verified"] is False
    assert receipt["http_status_code"] == 200
    assert receipt["response_body_sha256"] == "b" * 64
    assert receipt["provider_evidence"] == {
        "provider_event_id": "evt-owned",
        "provider_receipt_sha256": "a" * 64,
        "source_authenticity_verified": False,
        "target_effect_verified": False,
        "finding_verified": False,
    }
    assert all(word not in str(receipt) for word in (
        "PRIVATE", "DO-NOT-PERSIST", "Authorization", "findings"
    ))


def test_sanitized_terminal_receipts_are_sufficient_for_actual_pair_classifier():
    source, target = pair()
    source.result = _signed_replay_terminal_receipt(source, source.result)
    target.result = _signed_replay_terminal_receipt(target, target.result)
    decision = verdict(source, target)
    assert decision["source_observed"] is True
    assert decision["target_observed"] is True
    assert decision["status"] == "candidate_needs_independent_review"
    assert decision["authorization_violation_verified"] is False
    assert decision["provider_testimony_only"] is True


@pytest.mark.parametrize("mutation", [
    lambda task, result: result.update(verification_status="verified"),
    lambda task, result: result.update(authorization_violation_verified=True),
    lambda task, result: result.update(remote_effect_verified=True),
    lambda task, result: result["provider_evidence"].update(finding_verified=True),
    lambda task, result: result["provider_evidence"].update(provider_receipt_sha256="forged"),
    lambda task, result: result.update(status="execution_unknown"),
    lambda task, result: task.payload.update(method="POST"),
    lambda task, result: result.update(replay_parent_task_id="task-other"),
])
def test_result_rejects_unverified_or_unsafe_remote_provenance(mutation):
    task, result = terminal_task(), provider_result()
    mutation(task, result)
    with pytest.raises(SupervisionConflict):
        _signed_replay_terminal_receipt(task, result)


def test_pg_pair_scan_requires_two_confirmed_terminal_attempts_and_absent_action():
    statement = TerminalLifecycleStore._completed_comparison_query(
        engagement_id=ENGAGEMENT, target_task_id=TARGET
    ).limit(1)
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "supervision_terminal_callbacks" in sql
    assert "comparison_source_callback" in sql
    assert "comparison_target_callback" in sql
    assert "execution_actions" in sql
    assert "signed_diff_auth_compare" not in sql  # SQL parameter, not literal injection
    assert "NOT (EXISTS" in sql
    assert "comparison_source.status =" in sql
    assert "comparison_target.status =" in sql
    assert "comparison_source_callback.outcome =" in sql
    assert "comparison_target_callback.outcome =" in sql
    assert "comparison_source_callback.leased_until <=" in sql
    assert "comparison_target_callback.leased_until <=" in sql


def dispatcher(candidates):
    store = SimpleNamespace(
        claim_callbacks=AsyncMock(return_value=[]),
        list_completed_comparison_pairs=AsyncMock(return_value=candidates),
    )

    @asynccontextmanager
    async def claim(engagement_id, target_id):
        assert (engagement_id, target_id) == (ENGAGEMENT, TARGET)
        yield True

    store.claim_completed_comparison_pair = claim
    orch = SimpleNamespace(
        terminal_store=store,
        session_memory=SimpleNamespace(),
        supervision_store=SimpleNamespace(),
        graph_memory=SimpleNamespace(),
    )
    return TerminalCallbackDispatcher(orch), store


@pytest.mark.asyncio
async def test_lost_peer_callback_and_source_early_callback_are_reconciled_once(monkeypatch):
    """A target terminal callback may be UNKNOWN after source compared too early."""
    worker, store = dispatcher([
        {"engagement_id": ENGAGEMENT, "terminal_task_id": TARGET}
    ])
    verifier = AsyncMock(return_value=True)
    monkeypatch.setattr(
        "ai_osop.core.signed_replay_comparison.persist_verified_replay_comparison",
        verifier,
    )
    assert await worker.flush_once() == 0  # no pending callbacks left
    verifier.assert_awaited_once_with(
        memory=worker.orch.session_memory,
        supervision=worker.orch.supervision_store,
        graph=worker.orch.graph_memory,
        engagement_id=ENGAGEMENT,
        terminal_task_id=TARGET,
    )
    # Action exists now: the SQL NOT EXISTS excludes the same candidate on
    # the next restart/poll even if a callback receipt ACK was lost.
    store.list_completed_comparison_pairs.return_value = []
    assert await worker.flush_once() == 0
    verifier.assert_awaited_once()


@pytest.mark.asyncio
async def test_revoked_roe_and_unknown_verification_cannot_append_recovery_receipt(monkeypatch):
    worker, _ = dispatcher([
        {"engagement_id": ENGAGEMENT, "terminal_task_id": TARGET}
    ])
    verifier = AsyncMock(side_effect=PermissionError("signed ROE revoked"))
    monkeypatch.setattr(
        "ai_osop.core.signed_replay_comparison.persist_verified_replay_comparison",
        verifier,
    )
    assert await worker._reconcile_completed_pairs() == 0
    verifier.side_effect = None
    verifier.return_value = False  # provider event/peer source UNKNOWN
    assert await worker._reconcile_completed_pairs() == 0
    assert verifier.await_count == 2


class FakePgSession:
    """Deterministic transaction-scoped advisory lock contention injection."""

    def __init__(self, gate):
        self.gate = gate
        self.held = False
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        if self.held:
            self.gate["locked"] = False

    def begin(self):
        return self

    async def execute(self, statement, params=None):
        rendered = str(statement)
        self.calls.append((rendered, params))
        if "pg_try_advisory_xact_lock" in rendered:
            obtained = not self.gate["locked"]
            if obtained:
                self.gate["locked"] = True
                self.held = True
            return SimpleNamespace(scalar_one=lambda: obtained)
        return SimpleNamespace(first=lambda: ("eng-owned", "task-target"))


@pytest.mark.asyncio
async def test_pg_transaction_claim_fences_duplicate_workers_and_releases_after_crash():
    gate = {"locked": False}
    sessions = []
    store = TerminalLifecycleStore.__new__(TerminalLifecycleStore)

    def session_factory():
        session = FakePgSession(gate)
        sessions.append(session)
        return session

    store._sessions = session_factory
    async with store.claim_completed_comparison_pair(ENGAGEMENT, TARGET) as first:
        assert first is True
        async with store.claim_completed_comparison_pair(ENGAGEMENT, TARGET) as stolen:
            assert stolen is False
        assert gate["locked"] is True
        assert len(sessions[1].calls) == 1  # no readiness query after losing lease
    assert gate["locked"] is False
    async with store.claim_completed_comparison_pair(ENGAGEMENT, TARGET) as replacement:
        assert replacement is True
    assert all(
        call[1]["comparison_lock"] == sessions[0].calls[0][1]["comparison_lock"]
        for session in sessions for call in session.calls[:1]
    )


@pytest.mark.asyncio
async def test_reconciler_rechecks_pg_fence_and_skips_lease_steal(monkeypatch):
    worker, store = dispatcher([
        {"engagement_id": ENGAGEMENT, "terminal_task_id": TARGET}
    ])

    @asynccontextmanager
    async def stolen(*_args):
        yield False

    store.claim_completed_comparison_pair = stolen
    verifier = AsyncMock()
    monkeypatch.setattr(
        "ai_osop.core.signed_replay_comparison.persist_verified_replay_comparison",
        verifier,
    )
    assert await worker.flush_once() == 0
    verifier.assert_not_awaited()


@pytest.mark.asyncio
async def test_keyset_scan_rolls_forward_past_permanent_unknown_peers(monkeypatch):
    worker, store = dispatcher([
        {"engagement_id": ENGAGEMENT, "terminal_task_id": TARGET}
    ] * 12)
    verifier = AsyncMock(return_value=False)
    monkeypatch.setattr(
        "ai_osop.core.signed_replay_comparison.persist_verified_replay_comparison",
        verifier,
    )
    assert await worker._reconcile_completed_pairs() == 0
    assert worker._comparison_cursor == TARGET
    store.list_completed_comparison_pairs.return_value = []
    assert await worker._reconcile_completed_pairs() == 0
    assert worker._comparison_cursor is None
    assert store.list_completed_comparison_pairs.await_args.kwargs == {
        "limit": 12, "after": TARGET
    }
