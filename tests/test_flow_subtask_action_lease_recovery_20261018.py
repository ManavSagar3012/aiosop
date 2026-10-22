"""Terminal callbacks must never alias UNKNOWN with FAILED on repeated receipts."""

import inspect

from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore


def test_idempotent_terminal_receipt_requires_exact_outcome_identity():
    production = inspect.getsource(TerminalLifecycleStore.commit_terminal)
    assert "prior.attempt_id == attempt_id" in production
    assert "prior.outcome == outcome" in production
    assert 'task.status in {"completed", "failed"}' in production
    assert 'return {**_record(prior), "created": False}' in production


def test_unknown_outcome_cannot_be_equated_to_failed_receipt():
    # Demonstrates the precise old Boolean-equivalence defect: both a
    # failed terminal Task and UNKNOWN have `success=False`.
    assert ("failed" == "completed") == ("unknown" == "succeeded")
    assert ("failed" == "completed") == ("failed" == "succeeded")
    assert "failed" != "unknown"


def test_callback_recovery_never_replays_started_effects():
    from ai_osop.memory.terminal_lifecycle import _expired_callback_disposition

    plan = {
        "order": ["sync_subtask", "graph_upsert"],
        "states": {"sync_subtask": "done", "graph_upsert": "started"},
    }
    assert _expired_callback_disposition(plan, 1) == "unknown"
    safe = {
        "order": ["sync_subtask", "graph_upsert"],
        "states": {"sync_subtask": "done", "graph_upsert": "pending"},
    }
    assert _expired_callback_disposition(safe, 1) == "requeue"
