"""Transactional planner behavior against deterministic PostgreSQL statement mocks."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord
from ai_osop.memory.session_memory import SessionMemory


def _sql(statement):
    # PostgreSQL deliberately cannot inline JSON literals. Compiling INSERTs
    # with bound parameters still verifies their real target table and shape.
    return str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": statement.__visit_name__ != "insert"},
        )
    )


class PgSession:
    def __init__(self, session_state, flow, ids=(), source_id=None):
        self.session_state = session_state
        self.flow = flow
        self.ids = list(ids)
        self.source_id = source_id
        self.execution_task_id = "task-confirmed"
        self.revised_step_id = None
        self.fail_on_insert = None
        self.stale = False
        self.statements = []
        self.commit = AsyncMock()
        self.exited_with = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, error_type, error, traceback):
        self.exited_with = error_type
        # Real AsyncSession closes and rolls back uncommitted changes.
        return False

    async def execute(self, statement):
        sql = _sql(statement)
        self.statements.append(sql)
        response = MagicMock()
        if sql.startswith("SELECT") and "FROM session_states" in sql:
            response.scalar_one_or_none.return_value = self.session_state
        elif sql.startswith("SELECT") and "FROM tasks" in sql:
            response.scalar_one_or_none.return_value = self.execution_task_id
        elif sql.startswith("UPDATE execution_flows"):
            status = (
                "running" if "SET status='running'" in sql else self.flow.status
            )
            response.mappings.return_value.one_or_none.return_value = (
                None
                if self.stale
                else self.flow.model_copy(
                    update={"revision": self.flow.revision + 1, "status": status}
                ).model_dump()
            )
        elif sql.startswith("SELECT") and "FROM execution_subtasks" in sql:
            response.scalars.return_value = iter(self.ids)
        elif sql.startswith("UPDATE execution_subtasks"):
            response.scalar_one_or_none.return_value = (
                self.revised_step_id if "SET title=" in sql else self.source_id
            )
        elif sql.startswith("INSERT INTO execution_subtasks"):
            if self.fail_on_insert is not None and (
                sum(s.startswith("INSERT") for s in self.statements) == self.fail_on_insert
            ):
                raise RuntimeError("injected insert failure")
        else:
            raise AssertionError(f"unexpected SQL: {sql}")
        return response


def _fixture(*, source=False):
    engagement = SessionState(
        session_id="eng-owned",
        phase="reconnaissance",
        scope=ScopeDefinition(
            engagement_id="eng-owned",
            domains=["example.com"],
            authorization_ref="approved-roe",
        ),
    )
    flow = FlowRecord(
        id="flow-owned",
        engagement_id=engagement.session_id,
        objective="Authorized local research",
        status="pending",
        revision=8,
    )
    rows = [
        SubtaskRecord(
            id="subtask-new-a",
            flow_id=flow.id,
            engagement_id=engagement.session_id,
            task_id="task-objective",
            title="Review notes",
            task_type="summarize_context",
            agent_type=AgentType.CONTEXT_MANAGER,
            status="pending",
            order=1 if source else 0,
        ),
        SubtaskRecord(
            id="subtask-new-b",
            flow_id=flow.id,
            engagement_id=engagement.session_id,
            task_id="task-objective",
            title="Prepare report",
            task_type="generate_report",
            agent_type=AgentType.REPORTING,
            status="pending",
            order=2 if source else 1,
            dependencies=["subtask-new-a"],
        ),
    ]
    src = (
        SubtaskRecord(
            id="subtask-source",
            flow_id=flow.id,
            engagement_id=engagement.session_id,
            task_id="task-objective",
            title="Completed review",
            task_type="full_recon",
            status="completed",
            refinement_count=1,
            execution_task_id="task-confirmed",
        )
        if source
        else None
    )
    orm_session = SimpleNamespace(
        session_id=engagement.session_id,
        phase=engagement.phase,
        scope=engagement.scope.model_dump(mode="json"),
        roe=engagement.roe,
    )
    pg = PgSession(orm_session, flow, [src.id] if src else [], src.id if src else None)
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = lambda: pg
    return memory, pg, flow, engagement, rows, src


@pytest.mark.asyncio
async def test_atomic_plan_uses_engagement_lock_flow_cas_and_single_commit():
    memory, pg, flow, eng, rows, src = _fixture(source=True)
    result = await memory.commit_flow_refinement(flow, eng, [src.id], rows, src)
    assert result is not None
    assert result.revision == 9
    assert result.status == "running"
    assert "FOR UPDATE" in pg.statements[0]
    assert "session_states.session_id = 'eng-owned'" in pg.statements[0]
    assert "execution_flows.revision = 8" in pg.statements[1]
    assert "execution_flows.status = 'pending'" in pg.statements[1]
    assert "execution_flows.engagement_id = 'eng-owned'" in pg.statements[1]
    assert "RETURNING execution_flows.id" in pg.statements[1]
    assert "tasks.status = 'completed'" in pg.statements[3]
    assert "FOR SHARE" in pg.statements[3]
    assert "execution_subtasks.refinement_count = 1" in pg.statements[4]
    assert "execution_subtasks.status = 'completed'" in pg.statements[4]
    assert len([sql for sql in pg.statements if sql.startswith("INSERT")]) == 2
    pg.commit.assert_awaited_once_with()
    assert pg.exited_with is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    ["paused", "scope", "phase", "revision", "step_set", "source_revision", "task_revoked"],
)
async def test_stale_plan_cannot_commit_any_steps(change):
    memory, pg, flow, eng, rows, src = _fixture(source=True)
    if change == "paused":
        pg.flow = pg.flow.model_copy(update={"status": "paused"})
        pg.stale = True
    elif change == "scope":
        pg.session_state.scope["domains"] = ["other.invalid"]
    elif change == "phase":
        pg.session_state.phase = "halted"
    elif change == "revision":
        pg.stale = True
    elif change == "step_set":
        pg.ids = ["subtask-other"]
    elif change == "source_revision":
        pg.source_id = None
    elif change == "task_revoked":
        pg.execution_task_id = None
    committed = await memory.commit_flow_refinement(flow, eng, [src.id], rows, src)
    assert committed is None
    pg.commit.assert_not_awaited()
    assert not any(sql.startswith("INSERT") for sql in pg.statements)


@pytest.mark.asyncio
async def test_second_insert_failure_does_not_commit_flow_or_first_step():
    memory, pg, flow, eng, rows, _ = _fixture()
    pg.fail_on_insert = 2
    with pytest.raises(RuntimeError, match="injected insert failure"):
        await memory.commit_flow_refinement(flow, eng, [], rows)
    pg.commit.assert_not_awaited()
    assert pg.exited_with is RuntimeError


@pytest.mark.asyncio
async def test_atomic_plan_rejects_step_ownership_and_budget_before_db():
    memory, pg, flow, eng, rows, _ = _fixture()
    rows[1].engagement_id = "eng-other"
    with pytest.raises(ValueError, match="must belong"):
        await memory.commit_flow_refinement(flow, eng, [], rows)
    assert not pg.statements


@pytest.mark.asyncio
async def test_operator_revision_keeps_pending_plan_and_requires_pending_step():
    memory, pg, flow, eng, _, _ = _fixture()
    step = SubtaskRecord(
        id="subtask-edit",
        flow_id=flow.id,
        engagement_id=eng.session_id,
        task_id="task-objective",
        title="Edited title",
        description="Updated notes",
        status="pending",
    )
    pg.ids = [step.id]
    pg.revised_step_id = step.id
    updated = await memory.commit_flow_refinement(
        flow,
        eng,
        [step.id],
        [],
        revised_step=step,
        activate_flow=False,
    )
    assert updated is not None and updated.status == "pending"
    assert updated.revision == 9
    sql = next(s for s in pg.statements if s.startswith("UPDATE execution_subtasks"))
    assert "execution_subtasks.status = 'pending'" in sql
    assert "execution_subtasks.engagement_id = 'eng-owned'" in sql
    assert "SET title='Edited title'" in sql
    pg.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_operator_edit_claim_race_rolls_back_flow_revision():
    memory, pg, flow, eng, _, _ = _fixture()
    step = SubtaskRecord(
        id="subtask-edit",
        flow_id=flow.id,
        engagement_id=eng.session_id,
        task_id="task-objective",
        title="Denied edit",
        status="pending",
    )
    pg.ids = [step.id]
    pg.revised_step_id = None
    updated = await memory.commit_flow_refinement(
        flow, eng, [step.id], [], revised_step=step, activate_flow=False
    )
    assert updated is None
    pg.commit.assert_not_awaited()
