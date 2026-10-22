"""Real intake route cannot outrun revoked human execution consent.

The SQL transaction is an inert test double. No target and no application DB.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, Response

from ai_osop.api.deps import state
from ai_osop.api.routers import target_authority
from ai_osop.core.config import AgentType
from ai_osop.core.models import FlowRecord, Task


class _Rows:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value

    def scalars(self):
        return self

    def all(self):
        return self.value


class _Database:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []
        self.rolled_back = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, exception_type, exception, traceback):
        self.rolled_back = exception_type is not None

    def begin(self):
        return self

    async def execute(self, statement, params=None):
        self.calls.append(str(statement))
        if not self.rows:
            raise AssertionError("No extra SQL may follow a revoked grant")
        return _Rows(self.rows.pop(0))


def _tasks():
    original = Task(
        id="task-original", engagement_id="eng-demo", flow_id="flow-demo",
        type="map_workflow", agent_type=AgentType.WORKFLOW,
        status="completed", payload={},
    )
    parent = Task(
        id="task-parent", engagement_id="eng-demo", flow_id="flow-demo",
        type="replay_for_diff_auth", agent_type=AgentType.WORKFLOW,
        status="completed", parent_task_id=original.id,
        approval_required=True, payload={"approval_id": "apr-parent"},
    )
    children = [Task(
        id=f"task-{role}", engagement_id="eng-demo", flow_id="flow-demo",
        type="navigate", agent_type=AgentType.WORKFLOW, status="completed",
        parent_task_id=parent.id, approval_required=True,
        payload={"approval_id": f"apr-{role}"},
    ) for role in ("source", "target")]
    return original, parent, children


@pytest.mark.asyncio
async def test_revoked_execution_grant_blocks_verifier_and_nonce(monkeypatch):
    original, parent, children = _tasks()
    flow = FlowRecord(id="flow-demo", engagement_id="eng-demo", objective="approved", status="running")
    db = _Database(["senior-owner", flow, [original, *children], parent, None])

    class _FakeMemory:
        def __init__(self):
            self._async_session = lambda: db

    monkeypatch.setattr(target_authority, "SessionMemory", _FakeMemory)
    # This case isolates execution-grant revocation. The real signed senior
    # JWT/subject revocation dependency is exercised separately; this direct
    # route-call fixture has no HTTP bearer to pass that independent fence.
    monkeypatch.setattr(
        target_authority.FlowArtifactReviewStore,
        "_reviewer_fence",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(target_authority, "guard_sql", AsyncMock(return_value=SimpleNamespace(
        version=4, authorization_id="auth-1", policy_sha256="a" * 64,
    )))
    access = AsyncMock()
    monkeypatch.setattr(target_authority, "assert_engagement_access", access)
    old = state.get("orchestrator")
    state["orchestrator"] = SimpleNamespace(session_memory=_FakeMemory())
    try:
        with pytest.raises(HTTPException) as raised:
            await target_authority.admit_target_authority_assertion(
                "eng-demo", "flow-demo",
                target_authority.TargetAssertionSubmission(
                    original_source_task_id=original.id,
                    source_task_id=children[0].id,
                    target_task_id=children[1].id,
                    claims_json="{}", signature_b64url="A" * 86,
                ),
                Response(), operator={"role": "senior_operator", "sub": "senior-owner"},
            )
        assert raised.value.status_code == 409
        assert "human execution grant" in raised.value.detail.lower()
        assert db.rolled_back
        assert not db.rows
        assert all("INSERT INTO target_authority" not in sql for sql in db.calls)
        access.assert_awaited_once()
    finally:
        if old is None:
            state.pop("orchestrator", None)
        else:
            state["orchestrator"] = old
