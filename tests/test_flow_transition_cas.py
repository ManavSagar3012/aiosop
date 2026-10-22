"""PostgreSQL Flow CAS SQL and transaction contract; no live DB required."""

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.dialects import postgresql

from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, ScopeDefinition, SessionState, SubtaskRecord, Task
from ai_osop.memory.session_memory import SessionMemory


class _MockPgSession:
    def __init__(self, updated=None, error=None):
        self.updated = updated
        self.error = error
        self.statements = []
        self.commit = AsyncMock()
        self.exit_exception = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        self.exit_exception = exc_type

    async def execute(self, statement):
        self.statements.append(statement)
        if self.error:
            raise self.error
        result = MagicMock()
        result.mappings.return_value.one_or_none.return_value = self.updated
        result.scalar_one_or_none.return_value = self.updated
        return result


class _SequencePgSession(_MockPgSession):
    def __init__(self, responses, failure_index=None):
        super().__init__()
        self.responses = responses
        self.failure_index = failure_index

    async def execute(self, statement):
        self.statements.append(statement)
        if self.failure_index == len(self.statements):
            raise RuntimeError("forced SQL failure")
        value = self.responses[len(self.statements) - 1]
        result = MagicMock()
        result.scalar_one_or_none.return_value = value
        result.mappings.return_value.one_or_none.return_value = value
        return result


def _engagement():
    scope = ScopeDefinition(
        engagement_id="eng-guarded",
        domains=["example.com"],
        authorization_ref="signed",
    )
    return SessionState(
        session_id="eng-guarded", scope=scope, phase="reconnaissance", roe={"scope": "signed"}
    )


def _locked_session(engagement):
    return SimpleNamespace(
        phase=engagement.phase,
        scope=engagement.scope.model_dump(mode="json"),
        roe=engagement.roe,
    )


def _memory(session):
    memory = SessionMemory.__new__(SessionMemory)
    memory._async_session = lambda: session
    return memory


def _sql(statement):
    return str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )


@pytest.mark.asyncio
async def test_cas_single_update_compares_engagement_status_revision_and_returns_updated_row():
    updated = FlowRecord(
        id="flow-cas",
        engagement_id="eng-mine",
        objective="Authorized review",
        status="paused",
        revision=8,
        updated_at=datetime.utcnow(),
    )
    pg = _MockPgSession(updated=updated.model_dump())
    result = await _memory(pg).transition_flow_status(
        "flow-cas", "eng-mine", 7, ["pending", "running"], "paused"
    )
    assert result is not None
    assert result.model_dump() == updated.model_dump()
    assert len(pg.statements) == 1
    sql = _sql(pg.statements[0])
    assert "UPDATE execution_flows SET status='paused'" in sql
    assert "revision=(execution_flows.revision + 1)" in sql
    assert "execution_flows.id = 'flow-cas'" in sql
    assert "execution_flows.engagement_id = 'eng-mine'" in sql
    assert "execution_flows.revision = 7" in sql
    assert "execution_flows.status IN ('pending', 'running')" in sql
    assert "RETURNING execution_flows.id, execution_flows.engagement_id" in sql
    pg.commit.assert_awaited_once_with()
    assert pg.exit_exception is None


@pytest.mark.asyncio
@pytest.mark.parametrize("expected_revision", [0, 1, 9])
async def test_cas_zero_affected_rows_does_not_report_success(expected_revision):
    pg = _MockPgSession(updated=None)
    changed = await _memory(pg).transition_flow_status(
        "flow-other", "eng-a", expected_revision, ["paused"], "pending"
    )
    assert changed is None
    assert len(pg.statements) == 1
    assert "execution_flows.engagement_id = 'eng-a'" in _sql(pg.statements[0])
    pg.commit.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_cas_database_failure_never_commits_and_propagates():
    pg = _MockPgSession(error=RuntimeError("database unavailable"))
    with pytest.raises(RuntimeError, match="database unavailable"):
        await _memory(pg).transition_flow_status("flow-a", "eng-a", 1, ["paused"], "pending")
    pg.commit.assert_not_awaited()
    assert pg.exit_exception is RuntimeError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("revision", "sources", "target"),
    [
        (-1, ["pending"], "paused"),
        (0, [], "paused"),
        (0, ["pending"], ""),
        (0, ["pending"], "pending"),
    ],
)
async def test_cas_rejects_invalid_transition_without_opening_database(revision, sources, target):
    pg = _MockPgSession()
    with pytest.raises(ValueError):
        await _memory(pg).transition_flow_status("flow", "eng", revision, sources, target)
    assert not pg.statements
    pg.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_existing_store_flow_upsert_remains_available_to_other_callers():
    pg = _MockPgSession()
    flow = FlowRecord(engagement_id="eng-a", objective="Keep upsert unchanged")
    await _memory(pg).store_flow(flow)
    assert len(pg.statements) == 1
    sql = _sql(pg.statements[0])
    assert "INSERT INTO execution_flows" in sql
    assert "ON CONFLICT (id) DO UPDATE" in sql
    assert "status = excluded" not in sql
    assert "status =" in sql
    assert "revision =" in sql
    pg.commit.assert_awaited_once_with()


@pytest.mark.asyncio
@pytest.mark.parametrize("existing", [None, "flow-first"])
async def test_create_flow_if_absent_never_updates_existing_flow(existing):
    pg = _SequencePgSession([existing])
    flow = FlowRecord(
        id="flow-first", objective="Never overwrite status", engagement_id="eng-guarded"
    )
    inserted = await _memory(pg).create_flow_if_absent(flow)
    assert inserted is (existing is not None)
    sql = _sql(pg.statements[0])
    assert "INSERT INTO execution_flows" in sql
    assert "ON CONFLICT (id) DO NOTHING RETURNING execution_flows.id" in sql
    assert "DO UPDATE" not in sql
    pg.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_objective_insert_and_revision_bump_share_transaction_and_engagement_lock():
    engagement = _engagement()
    flow = FlowRecord(id="flow-a", engagement_id=engagement.session_id, objective="Review")
    objective = Task(
        type="flow_objective",
        agent_type=AgentType.RECON,
        engagement_id=engagement.session_id,
        flow_id=flow.id,
        status="planned",
        payload={"title": "Plan only"},
    )
    committed = flow.model_copy(update={"revision": 1})
    pg = _SequencePgSession([_locked_session(engagement), committed.model_dump(), None])
    result = await _memory(pg).create_flow_objective(flow, engagement, objective)
    assert result is not None and result.revision == 1
    assert len(pg.statements) == 3
    session_lock, cas_update = map(_sql, pg.statements[:2])
    # SQLAlchemy's JSON type does not support literal_binds rendering; inspect
    # the compiled INSERT plus parameter values rather than its JSON literals.
    insert_compiled = pg.statements[2].compile(dialect=postgresql.dialect())
    insert_task = str(insert_compiled)
    assert "FROM session_states" in session_lock and "FOR UPDATE" in session_lock
    assert "UPDATE execution_flows" in cas_update
    assert "execution_flows.id = 'flow-a'" in cas_update
    assert "execution_flows.engagement_id = 'eng-guarded'" in cas_update
    assert "execution_flows.revision = 0" in cas_update
    assert "execution_flows.status = 'pending'" in cas_update
    assert "revision=(execution_flows.revision + 1)" in cas_update
    assert "RETURNING execution_flows.id" in cas_update
    assert "INSERT INTO tasks" in insert_task
    assert "flow_objective" in insert_compiled.params.values()
    assert "ON CONFLICT" not in insert_task
    pg.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_objective_insert_rejects_stale_roe_without_writing_or_committing():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    objective = Task(
        type="flow_objective",
        agent_type=AgentType.RECON,
        flow_id=flow.id,
        engagement_id=engagement.session_id,
        status="planned",
    )
    stale = _locked_session(engagement)
    stale.roe = {"scope": "revoked"}
    pg = _SequencePgSession([stale])
    assert await _memory(pg).create_flow_objective(flow, engagement, objective) is None
    assert len(pg.statements) == 1
    pg.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_objective_insert_failure_after_flow_cas_never_commits():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    objective = Task(
        type="flow_objective",
        agent_type=AgentType.RECON,
        flow_id=flow.id,
        engagement_id=engagement.session_id,
        status="planned",
    )
    pg = _SequencePgSession(
        [_locked_session(engagement), flow.model_copy(update={"revision": 1}).model_dump(), None],
        failure_index=3,
    )
    with pytest.raises(RuntimeError, match="forced SQL failure"):
        await _memory(pg).create_flow_objective(flow, engagement, objective)
    assert len(pg.statements) == 3
    pg.commit.assert_not_awaited()
    assert pg.exit_exception is RuntimeError


@pytest.mark.asyncio
async def test_guarded_claim_locks_engagement_then_flow_and_increments_flow_revision():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    subtask = SubtaskRecord(
        engagement_id=engagement.session_id,
        flow_id=flow.id,
        task_id="task-parent",
        title="Authorized scope",
        task_type="recon",
        agent_type=AgentType.RECON,
    )
    pg = _SequencePgSession([_locked_session(engagement), flow, subtask.id, flow.id])
    claimed = await _memory(pg).claim_subtask(
        subtask.id,
        engagement.session_id,
        flow=flow,
        engagement=engagement,
        subtask=subtask,
        payload={"target": "https://example.com/api"},
    )
    assert claimed is True
    assert len(pg.statements) == 4
    lock_engagement, lock_flow, claim_sql, revision_sql = map(_sql, pg.statements)
    assert "FROM session_states" in lock_engagement and "FOR UPDATE" in lock_engagement
    assert "FROM execution_flows" in lock_flow and "FOR UPDATE" in lock_flow
    assert "UPDATE execution_subtasks" in claim_sql
    assert "execution_subtasks.flow_id =" in claim_sql
    assert "execution_subtasks.approval_required = false" in claim_sql.lower()
    assert "execution_subtasks.execution_task_id IS NULL" in claim_sql
    assert "execution_subtasks.status = 'pending'" in claim_sql
    assert "RETURNING execution_subtasks.id" in claim_sql
    assert "UPDATE execution_flows" in revision_sql
    assert "execution_flows.revision = 0" in revision_sql
    assert "revision=(execution_flows.revision + 1)" in revision_sql
    pg.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_guarded_claim_scope_revocation_never_touches_flow_or_step():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    subtask = SubtaskRecord(
        engagement_id=engagement.session_id,
        flow_id=flow.id,
        task_id="task-parent",
        title="Recon",
    )
    stale = _locked_session(engagement)
    stale.scope["authorization_ref"] = None
    pg = _SequencePgSession([stale])
    assert not await _memory(pg).claim_subtask(
        subtask.id,
        engagement.session_id,
        flow=flow,
        engagement=engagement,
        subtask=subtask,
        payload={"target": "example.com"},
    )
    assert len(pg.statements) == 1
    pg.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_guarded_claim_rejects_persisted_expired_testing_window():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    subtask = SubtaskRecord(
        engagement_id=engagement.session_id,
        flow_id=flow.id,
        task_id="task-parent",
        title="Recon",
    )
    current = _locked_session(engagement)
    ended = datetime.utcnow() - timedelta(minutes=2)
    current.scope["testing_window_end"] = ended.isoformat()
    # Make the snapshot match the current scope except for the passage of time.
    engagement.scope.testing_window_end = ended
    pg = _SequencePgSession([current])
    assert not await _memory(pg).claim_subtask(
        subtask.id,
        engagement.session_id,
        flow=flow,
        engagement=engagement,
        subtask=subtask,
        payload={"target": "example.com"},
    )
    assert len(pg.statements) == 1
    pg.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_guarded_claim_rejects_stale_flow_revision_before_step_mutation():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    subtask = SubtaskRecord(
        engagement_id=engagement.session_id,
        flow_id=flow.id,
        task_id="task-parent",
        title="Recon",
    )
    pg = _SequencePgSession([_locked_session(engagement), flow.model_copy(update={"revision": 7})])
    assert not await _memory(pg).claim_subtask(
        subtask.id,
        engagement.session_id,
        flow=flow,
        engagement=engagement,
        subtask=subtask,
        payload={"target": "example.com"},
    )
    assert len(pg.statements) == 2
    assert "FOR UPDATE" in _sql(pg.statements[1])
    pg.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_guarded_claim_revision_update_failure_does_not_commit_claimed_step():
    engagement = _engagement()
    flow = FlowRecord(engagement_id=engagement.session_id, objective="Review")
    subtask = SubtaskRecord(
        engagement_id=engagement.session_id,
        flow_id=flow.id,
        task_id="task-parent",
        title="Recon",
    )
    pg = _SequencePgSession([_locked_session(engagement), flow, subtask.id, None])
    assert not await _memory(pg).claim_subtask(
        subtask.id,
        engagement.session_id,
        flow=flow,
        engagement=engagement,
        subtask=subtask,
        payload={"target": "example.com"},
    )
    assert len(pg.statements) == 4
    pg.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_guarded_claim_requires_snapshots_but_legacy_call_cannot_claim_flow_rows():
    pg = _SequencePgSession([None])
    assert not await _memory(pg).claim_subtask("subtask-a", "eng-guarded")
    sql = _sql(pg.statements[0])
    assert "execution_subtasks.flow_id IS NULL" in sql
    assert "execution_subtasks.status = 'pending'" in sql
    pg.commit.assert_awaited_once()
    with pytest.raises(ValueError):
        await _memory(_SequencePgSession([])).claim_subtask(
            "subtask-a",
            "eng-guarded",
            flow=FlowRecord(engagement_id="eng-guarded", objective="Incomplete"),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["paused", "cancelled"])
async def test_control_sql_refuses_active_subtasks_and_unfinished_execution_tasks(target):
    pg = _MockPgSession(updated=None)
    assert (
        await _memory(pg).transition_flow_status(
            "flow-a", "eng-guarded", 3, ["pending", "running"], target
        )
        is None
    )
    sql = _sql(pg.statements[0])
    assert "NOT (EXISTS (SELECT" in sql
    assert "FROM execution_subtasks" in sql
    assert "LEFT OUTER JOIN tasks ON tasks.id = execution_subtasks.execution_task_id" in sql
    assert "tasks.id IS NULL" in sql
    assert "execution_subtasks.status NOT IN" in sql
    assert "tasks.status NOT IN" in sql
