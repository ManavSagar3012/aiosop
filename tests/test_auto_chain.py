"""Unit tests for the authenticated-surface auto-chaining + auto-dispatch.

Covers the Phase 1 hardening logic in Orchestrator:
  - map_workflow -> capture_authenticated_surface
  - capture_authenticated_surface -> extract_har_api_inventory
  - (:Task)-[:SPAWNED]->(:Task) persistence
  - auto_task_chain audit event creation
  - duplicate-completion protection (idempotency)
  - unauthenticated engagement -> no chain
  - ensure_authenticated_discovery dispatches map_workflow exactly once
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_osop.core.enums import AgentType
from ai_osop.core.models import Task
from ai_osop.orchestrator.orchestrator import Orchestrator


class _AsyncCM:
    """Minimal async context manager wrapping a mock Neo4j session."""

    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


def _authed_session(label="user_a", expired=False):
    s = MagicMock()
    s.is_expired.return_value = expired
    s.user_label = label
    return s


@pytest.fixture
def chain_orch():
    """Orchestrator with graph/session_store/schedule/audit mocked so the chain
    logic can be exercised in isolation (no real Neo4j, no background execution)."""
    # Neo4j session that supports `async with driver.session() as g` + g.run/single.
    res = AsyncMock()
    res.single = AsyncMock(return_value={"c": 0})  # _has_existing_map_workflow -> none
    gsession = AsyncMock()
    gsession.run = AsyncMock(return_value=res)

    graph_memory = AsyncMock()
    graph_memory._driver.session = MagicMock(return_value=_AsyncCM(gsession))
    # Neo4j-backed dedupe defaults: nothing chained/claimed yet.
    graph_memory.task_has_spawned = AsyncMock(return_value=False)
    graph_memory.claim_auto_discovery = AsyncMock(return_value=True)
    graph_memory.upsert_task = AsyncMock()
    graph_memory.run_write_query = AsyncMock()

    orch = Orchestrator(AsyncMock(), graph_memory, AsyncMock(), AsyncMock())
    orch.rate_limiter = AsyncMock()
    orch.session_store = AsyncMock()
    orch.schedule_task = AsyncMock()
    orch._audit_log = AsyncMock()
    orch._gsession = gsession  # exposed for legacy assertions
    return orch


def _map_task(eid="eng-1"):
    return Task(
        type="map_workflow",
        priority=7,
        agent_type=AgentType.WORKFLOW,
        payload={"url": "https://target/", "user_label": "user_a"},
        engagement_id=eid,
    )


def _capture_task(eid="eng-1"):
    return Task(
        type="capture_authenticated_surface",
        priority=6,
        agent_type=AgentType.WORKFLOW,
        payload={"user_label": "user_a", "workflow_id": "wf-1"},
        engagement_id=eid,
    )


@pytest.mark.asyncio
async def test_map_workflow_chains_to_capture_when_authenticated(chain_orch):
    chain_orch.session_store.list_sessions.return_value = [_authed_session("user_a")]
    map_task = _map_task()

    await chain_orch._chain_authenticated_surface(map_task, {"workflow_id": "wf-1"})

    chain_orch.schedule_task.assert_called_once()
    child = chain_orch.schedule_task.call_args.args[0]
    assert child.type == "capture_authenticated_surface"
    assert child.dependencies == [map_task.id]
    assert child.payload["workflow_id"] == "wf-1"
    assert child.payload["url"] == "https://target/"
    assert child.payload["user_label"] == "user_a"


@pytest.mark.asyncio
async def test_capture_chains_to_extract(chain_orch):
    cap_task = _capture_task()

    await chain_orch._chain_authenticated_surface(cap_task, {"har_path": "/vault/user_a.har"})

    chain_orch.schedule_task.assert_called_once()
    child = chain_orch.schedule_task.call_args.args[0]
    assert child.type == "extract_har_api_inventory"
    assert child.payload["har_path"] == "/vault/user_a.har"
    assert child.dependencies == [cap_task.id]
    assert child.payload["workflow_id"] == "wf-1"


@pytest.mark.asyncio
async def test_capture_without_har_does_not_chain(chain_orch):
    cap_task = _capture_task()
    await chain_orch._chain_authenticated_surface(cap_task, {})  # no har_path
    chain_orch.schedule_task.assert_not_called()


def _extract_task(eid="eng-1"):
    return Task(
        type="extract_har_api_inventory",
        priority=6,
        agent_type=AgentType.WORKFLOW,
        payload={"user_label": "user_a", "workflow_id": "wf-1", "har_path": "/vault/user_a.har"},
        engagement_id=eid,
    )


@pytest.mark.asyncio
async def test_extract_chains_to_diff_auth(chain_orch):
    extract_task = _extract_task()

    await chain_orch._chain_authenticated_surface(extract_task, {})

    chain_orch.schedule_task.assert_called_once()
    child = chain_orch.schedule_task.call_args.args[0]
    assert child.type == "replay_for_diff_auth"
    assert child.payload["workflow_id"] == "wf-1"
    assert child.dependencies == [extract_task.id]


@pytest.mark.asyncio
async def test_extract_without_workflow_id_does_not_chain(chain_orch):
    extract_task = _extract_task()
    extract_task.payload["workflow_id"] = ""
    await chain_orch._chain_authenticated_surface(extract_task, {})
    chain_orch.schedule_task.assert_not_called()


@pytest.mark.asyncio
async def test_spawned_relationship_persisted(chain_orch):
    chain_orch.session_store.list_sessions.return_value = [_authed_session()]
    map_task = _map_task()

    await chain_orch._chain_authenticated_surface(map_task, {"workflow_id": "wf-1"})

    assert chain_orch.graph_memory.run_write_query.called
    cypher = chain_orch.graph_memory.run_write_query.call_args.args[0]
    assert "SPAWNED" in cypher
    params = chain_orch.graph_memory.run_write_query.call_args.args[1]
    assert params["parent_id"] == map_task.id


@pytest.mark.asyncio
async def test_auto_task_chain_audit_event_created(chain_orch):
    chain_orch.session_store.list_sessions.return_value = [_authed_session()]
    map_task = _map_task()

    await chain_orch._chain_authenticated_surface(map_task, {"workflow_id": "wf-1"})

    chain_orch._audit_log.assert_called()
    event = chain_orch._audit_log.call_args.args[0]
    assert event.event_type == "auto_task_chain"
    assert event.action["trigger_task_id"] == map_task.id
    assert event.action["created_type"] == "capture_authenticated_surface"


@pytest.mark.asyncio
async def test_duplicate_completion_protection(chain_orch):
    chain_orch.session_store.list_sessions.return_value = [_authed_session()]
    # Graph-backed dedupe: first completion sees no SPAWNED child, second sees one.
    chain_orch.graph_memory.task_has_spawned = AsyncMock(side_effect=[False, True])
    map_task = _map_task()

    await chain_orch._chain_authenticated_surface(map_task, {"workflow_id": "wf-1"})
    # Re-delivered/duplicate completion of the same task must not create a 2nd child.
    await chain_orch._chain_authenticated_surface(map_task, {"workflow_id": "wf-1"})

    assert chain_orch.schedule_task.call_count == 1


@pytest.mark.asyncio
async def test_unauthenticated_engagement_no_chain(chain_orch):
    chain_orch.session_store.list_sessions.return_value = []  # no imported session
    map_task = _map_task()

    await chain_orch._chain_authenticated_surface(map_task, {"workflow_id": "wf-1"})

    chain_orch.schedule_task.assert_not_called()


@pytest.mark.asyncio
async def test_expired_session_engagement_no_chain(chain_orch):
    chain_orch.session_store.list_sessions.return_value = [_authed_session(expired=True)]
    await chain_orch._chain_authenticated_surface(_map_task(), {"workflow_id": "wf-1"})
    chain_orch.schedule_task.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_discovery_dispatches_map_workflow_once(chain_orch):
    chain_orch.session_store.list_sessions.return_value = [_authed_session("user_a")]
    # Atomic Neo4j claim: first caller wins, second loses.
    chain_orch.graph_memory.claim_auto_discovery = AsyncMock(side_effect=[True, False])

    t1 = await chain_orch.ensure_authenticated_discovery("eng-9", url_hint="https://t/")
    # Second call (e.g. other hook firing) must be a no-op.
    t2 = await chain_orch.ensure_authenticated_discovery("eng-9", url_hint="https://t/")

    assert t1 is not None and t1.type == "map_workflow"
    assert t1.payload["url"] == "https://t/"
    assert t2 is None
    chain_orch.schedule_task.assert_called_once()


@pytest.mark.asyncio
async def test_ensure_discovery_skips_unauthenticated(chain_orch):
    chain_orch.session_store.list_sessions.return_value = []
    result = await chain_orch.ensure_authenticated_discovery("eng-x", url_hint="https://t/")
    assert result is None
    chain_orch.schedule_task.assert_not_called()
