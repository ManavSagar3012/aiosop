"""Approval timeout is measured from durable creation, not worker uptime."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.models import ApprovalRequest
from ai_osop.orchestrator.approval_coordinator import (
    ApprovalCoordinator, remaining_durable_approval_seconds,
)


def _approval(delta: timedelta) -> ApprovalRequest:
    return ApprovalRequest(
        task_id="task-timeout-1", engagement_id="eng-timeout-1",
        agent_id="", action_type="recon", target="authorized.example",
        payload_summary="fixture", risk_assessment="high",
        requested_at=datetime.utcnow() + delta,
    )


def test_expired_approval_has_zero_remaining_after_restart():
    assert remaining_durable_approval_seconds(
        _approval(-timedelta(hours=1)), 120,
    ) == 0


def test_partial_approval_lifetime_does_not_reset_on_restart():
    remaining = remaining_durable_approval_seconds(
        _approval(-timedelta(seconds=70)), 120,
    )
    assert 45 < remaining < 55


def test_naive_or_aware_future_time_cannot_extend_configured_lifetime():
    for requested in (
        datetime.utcnow() + timedelta(hours=3),
        datetime.now(timezone.utc) + timedelta(hours=3),
    ):
        review = _approval(timedelta())
        review.requested_at = requested
        assert remaining_durable_approval_seconds(review, 120) == 120


@pytest.mark.asyncio
async def test_restored_watcher_expires_stale_request_without_new_grace_period(monkeypatch):
    import ai_osop.orchestrator.approval_coordinator as coordinator_module

    monkeypatch.setattr(coordinator_module.settings, "approval_timeout_seconds", 120)
    review = _approval(-timedelta(minutes=5))
    expire = AsyncMock(return_value=(review, True))
    wait = AsyncMock()
    memory = object()  # fake-memory path won't mutate actual databases
    orch = SimpleNamespace(
        _approval_requests={review.id: review},
        _expire_pending_approval=expire,
        _tasks={}, session_memory=memory,
    )
    coordinator = ApprovalCoordinator(orch)
    coordinator._wait_for_approval = wait
    await coordinator._await_approval_outcome(review.id)
    expire.assert_awaited_once_with(review.id)
