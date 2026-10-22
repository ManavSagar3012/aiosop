"""Legacy DLQ review must never bypass signed task admission or leak tenants."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from ai_osop.api.deps import state
from ai_osop.api.routers import system


@pytest.fixture
def dlq(monkeypatch):
    previous = state.get("orchestrator")
    queue = SimpleNamespace(
        requeue=AsyncMock(side_effect=AssertionError("unsafe retry executed")),
        discard=AsyncMock(),
        list_entries=AsyncMock(return_value=[]),
        _session_memory=SimpleNamespace(get_dlq_entry=AsyncMock(return_value=None)),
    )
    orch = SimpleNamespace(dlq=queue, schedule_task=AsyncMock())
    state["orchestrator"] = orch
    try:
        yield queue, orch
    finally:
        if previous is None:
            state.pop("orchestrator", None)
        else:
            state["orchestrator"] = previous


@pytest.mark.asyncio
async def test_legacy_requeue_is_denied_without_touching_task_or_queue(dlq):
    queue, orch = dlq
    with pytest.raises(HTTPException) as exc:
        await system.requeue_dlq_entry(
            "dlq-unknown",
            {"sub": "owner", "role": "senior_operator"},
        )
    assert exc.value.status_code == 409
    assert "Unsafe" in exc.value.detail
    queue.requeue.assert_not_awaited()
    orch.schedule_task.assert_not_awaited()


@pytest.mark.asyncio
async def test_unscoped_or_shared_key_cannot_list_any_dlq_records(dlq):
    queue, _ = dlq
    for engagement, actor in [
        ("eng-target", {"sub": "owner", "role": "operator"}),
        ("eng-target", {"sub": "owner", "claims": {"exp": "fake"}}),
        ("eng/../../foreign", {"sub": "owner", "claims": {"exp": 123}}),
    ]:
        with pytest.raises(HTTPException) as exc:
            await system.list_dlq_entries(engagement, None, actor)
        assert exc.value.status_code in {403, 503}
    queue.list_entries.assert_not_awaited()


@pytest.mark.asyncio
async def test_owner_scoped_dlq_lists_only_redacted_evidence(dlq, monkeypatch):
    queue, _ = dlq
    monkeypatch.setattr(system, "_dlq_owner", AsyncMock())
    queue.list_entries.return_value = [
        SimpleNamespace(
            id="dlq-approved",
            task_id="task-safe",
            engagement_id="eng-allowed",
            task_type="recon",
            status="pending_review",
            created_at=datetime.utcnow(),
            resolved_at=None,
            final_error="password=DO_NOT_DISCLOSE",
            task_payload={"authorization": "DO_NOT_DISCLOSE"},
        ),
        SimpleNamespace(
            id="dlq-foreign",
            task_id="task-foreign",
            engagement_id="eng-other",
            task_type="recon",
            status="pending_review",
            created_at=datetime.utcnow(),
            resolved_at=None,
            final_error="DO_NOT_DISCLOSE",
            task_payload={"secret": "DO_NOT_DISCLOSE"},
        ),
    ]
    result = await system.list_dlq_entries(
        "eng-allowed",
        None,
        {"sub": "owner", "claims": {"exp": 123}},
    )
    assert len(result["entries"]) == 1
    assert result["entries"][0]["replay_authorized"] is False
    assert "DO_NOT_DISCLOSE" not in str(result)
    queue.list_entries.assert_awaited_once_with(engagement_id="eng-allowed", status=None)


@pytest.mark.asyncio
async def test_discard_wrong_owner_never_mutates_dlq(dlq, monkeypatch):
    from ai_osop.memory.dlq_resolution import DLQResolutionDenied, DLQResolutionStore

    queue, _ = dlq
    monkeypatch.setattr(
        DLQResolutionStore,
        "discard",
        AsyncMock(side_effect=DLQResolutionDenied("Engagement owner required")),
    )
    with pytest.raises(HTTPException) as exc:
        await system.discard_dlq_entry(
            "dlq-foreign",
            "eng-foreign",
            "incident reviewed",
            {"sub": "wrong-owner", "claims": {"exp": 123}},
        )
    assert exc.value.status_code == 403
    queue._session_memory.get_dlq_entry.assert_not_awaited()
    queue.discard.assert_not_awaited()


@pytest.mark.asyncio
async def test_stats_are_scoped_to_current_engagement(dlq, monkeypatch):
    queue, _ = dlq
    monkeypatch.setattr(system, "_dlq_owner", AsyncMock())
    queue.list_entries.return_value = [
        SimpleNamespace(status="pending_review", engagement_id="eng-own"),
        SimpleNamespace(status="discarded", engagement_id="eng-own"),
        SimpleNamespace(status="pending_review", engagement_id="eng-foreign"),
    ]
    result = await system.get_dlq_stats(
        "eng-own",
        {"sub": "owner", "claims": {"exp": 123}},
    )
    assert result == {"pending": 1, "requeued": 0, "discarded": 1}
    queue.list_entries.assert_awaited_once_with(engagement_id="eng-own")
