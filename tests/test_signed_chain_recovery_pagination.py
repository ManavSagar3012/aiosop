"""Recovery must not strand a PG-authored chain behind 500 ineligible parents."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.orchestrator import Orchestrator


class _Rows:
    def all(self):
        return []


class _DB:
    statement = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def execute(self, statement):
        self.statement = statement
        return _Rows()


@pytest.mark.asyncio
async def test_signed_pg_chain_source_cursor_is_bounded_and_parameterized():
    memory = SessionMemory.__new__(SessionMemory)
    db = _DB()
    memory._async_session = lambda: db
    await memory.list_recoverable_signed_chain_parents(limit=100_000, after_id="task-00499")
    compiled = db.statement.compile(dialect=postgresql.dialect())
    assert "tasks.id >" in str(compiled)
    assert "ORDER BY tasks.id" in str(compiled)
    assert "LIMIT" in str(compiled)
    assert 500 in compiled.params.values()
    assert "task-00499" in compiled.params.values()
    for cursor in ("../task", "", "foreign", "task-" + "x" * 65):
        with pytest.raises(ValueError, match="cursor"):
            await memory.list_recoverable_signed_chain_parents(after_id=cursor)


def _recovery_fixture():
    engagement_id = "eng-signed-page"
    source = Task(
        id="task-00500",
        engagement_id=engagement_id,
        type="map_workflow",
        agent_type=AgentType.WORKFLOW,
        status="completed",
        payload={
            "_authorization_version": 3,
            "url": "https://authorized.example/",
            "user_label": "signed-user",
        },
        result={"status": "workflow_recorded", "workflow_id": "wf-page"},
    )
    state = SessionState(
        session_id=engagement_id,
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id=engagement_id,
            domains=["authorized.example"],
            authorization_ref="signed-test-ref",
        ),
    )
    memory = SessionMemory.__new__(SessionMemory)
    memory.load_task_authoritative = AsyncMock(
        side_effect=lambda task_id: source if task_id == source.id else None
    )
    memory.load_session_state = AsyncMock(return_value=state)
    memory.assert_signed_authorization = AsyncMock()
    graph = SimpleNamespace(find_incomplete_chains=AsyncMock(return_value=[]))
    orch = SimpleNamespace(
        graph_memory=graph,
        session_memory=memory,
        _resume_chain_link=AsyncMock(return_value=None),
    )
    rows = [
        {"id": f"task-{i:05d}", "type": "map_workflow", "engagement_id": engagement_id}
        for i in range(501)
    ]
    return orch, memory, source, rows


@pytest.mark.asyncio
async def test_signed_recovery_scans_second_pg_page_when_first_500_cannot_continue():
    orch, memory, source, rows = _recovery_fixture()

    async def page(*, after_id=None):
        return [r for r in rows if after_id is None or r["id"] > after_id][:500]

    memory.list_recoverable_signed_chain_parents = AsyncMock(side_effect=page)
    result = await Orchestrator.recover_state(orch)
    assert result["reconcile_required"] == 0
    assert orch._resume_chain_link.await_count == 1
    submitted = orch._resume_chain_link.await_args.args[0]
    assert submitted["id"] == source.id
    assert submitted["result_summary"]["url"] == "https://authorized.example/"
    assert memory.list_recoverable_signed_chain_parents.await_count == 2
    assert memory.list_recoverable_signed_chain_parents.await_args_list[1].kwargs == {
        "after_id": "task-00499"
    }


@pytest.mark.asyncio
async def test_nonadvancing_recovery_page_reports_reconciliation_debt():
    orch, memory, _source, rows = _recovery_fixture()
    memory.list_recoverable_signed_chain_parents = AsyncMock(return_value=rows[:500])
    result = await Orchestrator.recover_state(orch)
    assert result["reconcile_required"] == 1
    assert memory.list_recoverable_signed_chain_parents.await_count == 2
    orch._resume_chain_link.assert_not_awaited()
