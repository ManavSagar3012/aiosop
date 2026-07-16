"""Agent-starvation observability (AIOSOP-AGENT-STARVATION).

Steady-state assignment latency is sub-second; a task waiting far longer means
no idle agent of its type exists (a pool outage). That condition was previously
silent — a task looped no_agent_found for 610s with zero alerting during an API
restart. _warn_if_starved emits a single WARNING once a task passes the wait
threshold, so the outage is visible. These lock the warn-once semantics.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.task_scheduler import TaskScheduler


def _sched() -> TaskScheduler:
    orch = MagicMock()
    orch._audit_log = AsyncMock()
    return TaskScheduler(orch)


def _task(age_seconds: float) -> Task:
    t = Task(type="sqli_scan", agent_type=AgentType.VULN_ANALYSIS, engagement_id="e1", payload={})
    t.created_at = datetime.utcnow() - timedelta(seconds=age_seconds)
    return t


@pytest.mark.asyncio
async def test_warns_once_past_threshold():
    s = _sched()
    t = _task(TaskScheduler.AGENT_STARVATION_WARN_SECONDS + 60)
    assert await s._warn_if_starved(t) is True  # first time: warns
    assert await s._warn_if_starved(t) is False  # idempotent: not again
    assert t.id in s._starvation_warned


@pytest.mark.asyncio
async def test_no_warn_before_threshold():
    s = _sched()
    t = _task(5)  # just queued
    assert await s._warn_if_starved(t) is False
    assert t.id not in s._starvation_warned


@pytest.mark.asyncio
async def test_discard_allows_rewarn_after_reassignment():
    s = _sched()
    t = _task(TaskScheduler.AGENT_STARVATION_WARN_SECONDS + 5)
    assert await s._warn_if_starved(t) is True
    s._starvation_warned.discard(t.id)  # what the assignment path does on lease grant
    assert await s._warn_if_starved(t) is True  # may warn again if it starves once more


@pytest.mark.asyncio
async def test_audit_is_best_effort_and_never_raises():
    s = _sched()
    s._orch._audit_log = AsyncMock(side_effect=RuntimeError("audit down"))
    t = _task(TaskScheduler.AGENT_STARVATION_WARN_SECONDS + 5)
    # audit failure must not break scheduling; still reports it warned
    assert await s._warn_if_starved(t) is True
