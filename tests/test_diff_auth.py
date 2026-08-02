"""Unit tests for Phase 2: orchestrator retry + differential-authorization analyzer."""

from unittest.mock import AsyncMock

import pytest

import ai_osop.orchestrator.orchestrator as om
from ai_osop.core.config import AgentType
from ai_osop.core.diff_auth_analyzer import (
    DiffAuthAnalyzer,
    _classify_body,
    _jaccard,
    _size_similar,
)
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import Orchestrator

# --------------------------------------------------------------------- Part A: retry


@pytest.mark.asyncio
async def test_maybe_retry_requeues_until_budget():
    orch = Orchestrator(AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock())
    orch._assign_task = AsyncMock()
    orch._audit_log = AsyncMock()
    orch._retry_sleep = AsyncMock()  # no real backoff in tests

    task = Task(
        type="map_workflow",
        priority=5,
        agent_type=AgentType.WORKFLOW,
        payload={},
        engagement_id="e",
        max_retries=2,
    )

    assert await orch._maybe_retry(task, {"error": "boom"}) is True
    assert task.retry_count == 1 and task.status == "pending" and task.assigned_agent_id is None
    assert await orch._maybe_retry(task, {"error": "boom"}) is True
    assert task.retry_count == 2
    # Budget exhausted -> terminal.
    assert await orch._maybe_retry(task, {"error": "boom"}) is False

    assert orch._assign_task.await_count == 2
    assert orch._audit_log.await_count == 2
    ev = orch._audit_log.call_args.args[0]
    assert ev.event_type == "task_retry"
    assert ev.action["task_id"] == task.id and ev.action["max_retries"] == 2


@pytest.mark.asyncio
async def test_maybe_retry_zero_budget_is_terminal():
    orch = Orchestrator(AsyncMock(), AsyncMock(), AsyncMock(), AsyncMock())
    orch._assign_task = AsyncMock()
    orch._audit_log = AsyncMock()
    orch._retry_sleep = AsyncMock()
    task = Task(
        type="x",
        priority=5,
        agent_type=AgentType.WORKFLOW,
        payload={},
        engagement_id="e",
        max_retries=0,
    )
    assert await orch._maybe_retry(task, {"error": "boom"}) is False
    orch._assign_task.assert_not_called()


# --------------------------------------------------------------- Part B: comparison logic


def test_classify_body_extracts_signals():
    sig = _classify_body(b'{"email":"x@y.com","id":5,"name":"a"}', "application/json")
    assert sig["json_keys"] == ["email", "id", "name"]
    assert "email" in sig["sensitive_fields"]
    assert set(sig["ownership_hits"]) == {"email", "id"}


def test_jaccard_and_size_similarity():
    assert _jaccard(["a", "b"], ["a", "b"]) == 1.0
    assert _jaccard(["a"], ["b"]) == 0.0
    assert _size_similar(500, 490) is True
    assert _size_similar(500, 100) is False


def _result(status, size=500, keys=None, sensitive=None, owner=None):
    return {
        "status_code": status,
        "response_size": size,
        "content_type": "application/json",
        "error": "",
        "json_keys": keys or [],
        "sensitive_fields": sensitive or [],
        "ownership_hits": owner or [],
    }


def test_compare_anonymous_open_access():
    an = DiffAuthAnalyzer(None, None)
    base = _result(200, keys=["id", "email"], sensitive=["email"], owner=["id"])
    cmp = an._compare(base, _result(200, keys=["id", "email"], sensitive=["email"]), "anonymous")
    assert cmp["category"] == "broken_access_control"
    assert cmp["confidence"] >= 0.8


def test_compare_user_b_idor():
    an = DiffAuthAnalyzer(None, None)
    base = _result(200, keys=["id", "email"], sensitive=["email"], owner=["id"])
    cmp = an._compare(base, _result(200, 490, keys=["id", "email"], sensitive=["email"]), "user_b")
    assert cmp["category"] == "horizontal_pe"
    assert cmp["confidence"] >= 0.8


def test_compare_forbidden_no_finding():
    an = DiffAuthAnalyzer(None, None)
    base = _result(200, keys=["id"])
    cmp = an._compare(base, _result(403, 10), "user_b")
    assert cmp["category"] == "" and cmp["confidence"] == 0.0


# --------------------------------------------------------------- Part B: analyze() flow


@pytest.mark.asyncio
async def test_analyze_persists_and_flags():
    gm = AsyncMock()
    an = DiffAuthAnalyzer(session_store=AsyncMock(), graph_memory=gm)
    an._load_endpoints = AsyncMock(
        return_value=[
            {"id": "api-1", "method": "GET", "url": "https://t/users/1", "path": "/users/1"}
        ]
    )
    data = _result(200, keys=["id", "email"], sensitive=["email"], owner=["id", "email"])
    an._replay_user = AsyncMock(side_effect=lambda eng, label, m, u: dict(data))
    an._replay_anonymous = AsyncMock(return_value=dict(data))  # anonymous sees the identical public response

    out = await an.analyze("e", "wf", "user_a", "user_b")

    assert out["replay_count"] == 3
    assert out["endpoints_tested"] == 1
    # Identical anonymous access makes this resource public, not an
    # authorization failure. Findings require a privileged difference.
    assert out["findings_count"] == 0
    assert gm.add_replay_result.await_count == 3
    assert gm.add_authorization_test.await_count == 1
    assert gm.add_diff_auth_finding_for_endpoint.await_count == 0


@pytest.mark.asyncio
async def test_analyze_skips_unsafe_methods():
    gm = AsyncMock()
    an = DiffAuthAnalyzer(AsyncMock(), gm)
    an._load_endpoints = AsyncMock(
        return_value=[
            {"id": "api-1", "method": "DELETE", "url": "https://t/users/1", "path": "/users/1"}
        ]
    )
    an._replay_user = AsyncMock()
    an._replay_anonymous = AsyncMock()

    out = await an.analyze("e", "wf", "user_a", "user_b")  # include_unsafe=False

    assert out["skipped_unsafe"] == 1
    assert out["replay_count"] == 0
    an._replay_user.assert_not_called()
    gm.add_replay_result.assert_not_called()


@pytest.mark.asyncio
async def test_analyze_no_finding_when_forbidden():
    gm = AsyncMock()
    an = DiffAuthAnalyzer(AsyncMock(), gm)
    an._load_endpoints = AsyncMock(
        return_value=[
            {"id": "api-1", "method": "GET", "url": "https://t/users/1", "path": "/users/1"}
        ]
    )
    base = _result(200, keys=["id"], owner=["id"])
    forbidden = _result(403, 10)
    an._replay_user = AsyncMock(
        side_effect=lambda eng, label, m, u: dict(base) if label == "user_a" else dict(forbidden)
    )
    an._replay_anonymous = AsyncMock(return_value=dict(forbidden))

    out = await an.analyze("e", "wf", "user_a", "user_b")

    assert out["findings_count"] == 0
    assert gm.add_authorization_test.await_count == 1  # test recorded even when 'ok'
