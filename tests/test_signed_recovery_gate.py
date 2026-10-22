"""Restart recovery may hydrate history but never requeue revoked policies."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import ScopeDefinition, SessionState, Task
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.orchestrator.recovery_service import RecoveryService


def _harness(*, version=2, task_version=2, denied=False):
    memory = SessionMemory.__new__(SessionMemory)
    scope = ScopeDefinition(
        engagement_id="eng-recovery",
        domains=["authorized.example.test"],
        authorization_ref="signed-ref-is-not-proof",
    )
    engagement = SessionState(
        session_id="eng-recovery", scope=scope, phase="reconnaissance",
    )
    task = Task(
        id="task-recovery", type="full_recon", agent_type=AgentType.RECON,
        engagement_id="eng-recovery", status="pending",
        payload={"domain": "authorized.example.test",
                 **({"_authorization_version": task_version}
                    if task_version is not None else {})},
    )
    memory.list_all_sessions = AsyncMock(return_value=[engagement])
    memory.list_all_tasks = AsyncMock(return_value=[task])
    memory.push_task_queue = AsyncMock()
    memory.load_flow = AsyncMock()
    async def verify(_engagement_id, *, expected_version=None):
        if denied or expected_version != version:
            raise RuntimeError("revoked, stale signature, or DB offline")
        return SimpleNamespace(version=version)

    memory.assert_signed_authorization = AsyncMock(side_effect=verify)
    orch = SimpleNamespace(
        session_memory=memory, _sessions={}, _tasks={},
    )
    return RecoveryService(orch), memory


@pytest.mark.asyncio
@pytest.mark.parametrize("version,denied", [
    (None, False), (0, False), (True, False), (1, False),
    (2, True),
])
async def test_missing_stale_or_revoked_signature_never_requeues(version, denied):
    recovery, memory = _harness(task_version=version, denied=denied)
    result = await recovery.recover_state()
    assert result["engagements"] == 1
    assert result["tasks"] == 0 and result["skipped"] == 1
    memory.push_task_queue.assert_not_awaited()
    if type(version) is int and version > 0:
        memory.assert_signed_authorization.assert_awaited_once_with(
            "eng-recovery", expected_version=version,
        )
    else:
        memory.assert_signed_authorization.assert_not_awaited()


@pytest.mark.asyncio
async def test_authorized_version_queues_only_once():
    recovery, memory = _harness()
    result = await recovery.recover_state()
    assert result["tasks"] == 1 and result["skipped"] == 0
    memory.assert_signed_authorization.assert_awaited_once_with(
        "eng-recovery", expected_version=2,
    )
    memory.push_task_queue.assert_awaited_once()
    assert memory.push_task_queue.await_args.args[0] == "tasks:eng-recovery"


@pytest.mark.asyncio
async def test_active_remote_task_stays_unknown_on_restart_even_with_signature():
    recovery, memory = _harness()
    task = (await memory.list_all_tasks())[0]
    task.status = "dispatch_unknown"
    result = await recovery.recover_state()
    assert result["unresolved"] == 1 and result["tasks"] == 0
    memory.push_task_queue.assert_not_awaited()


@pytest.mark.asyncio
async def test_crash_after_human_approval_recovers_parked_signed_execution():
    recovery, memory = _harness()
    task = (await memory.list_all_tasks())[0]
    task.status = "awaiting_approval"
    task.approval_required = True
    task.payload.update({
        "approval_id": "apr-signed-after-crash",
        "operator_approved": True,
    })
    memory.is_task_approved = AsyncMock(return_value=True)

    result = await recovery.recover_state()
    assert result["tasks"] == 1
    assert task.status == "awaiting_approval"
    memory.is_task_approved.assert_awaited_once_with(
        task.id, task.engagement_id, "apr-signed-after-crash",
    )
    memory.push_task_queue.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("grant,verified", [
    (False, False), (True, False), (True, None),
])
async def test_pending_or_unverified_human_decision_never_recovers_execution(
    grant, verified,
):
    recovery, memory = _harness()
    task = (await memory.list_all_tasks())[0]
    task.status = "awaiting_approval"
    task.approval_required = True
    task.payload["approval_id"] = "apr-signed-after-crash"
    if grant:
        task.payload["operator_approved"] = True
    memory.is_task_approved = AsyncMock(
        side_effect=OSError("Postgres unavailable") if verified is None else None,
        return_value=verified,
    )

    result = await recovery.recover_state()
    assert result["tasks"] == 0 and result["skipped"] == 1
    memory.push_task_queue.assert_not_awaited()
