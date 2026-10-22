"""Exercise real HTTP operator flow planning and dispatch boundaries."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ai_osop.api.deps import state, verify_token
from ai_osop.api.routers.flows import (
    CreateObjectiveRequest,
    DispatchSubtaskRequest,
    FlowControlRequest,
    cancel_flow,
    create_flow_objective,
    dispatch_subtask,
    pause_flow,
    resume_flow,
    router,
)
from ai_osop.core.models import ScopeDefinition, SessionState, SubtaskRecord
from ai_osop.core.exceptions import OutOfScopeError, ScopeValidationError
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets
from ai_osop.core.config import AgentType


class MemoryStub:
    def __init__(self):
        self.flows = {}
        self.tasks = {}
        self.subtasks = {}
        self.actions = []
        self.sessions = {}
        self.transition_lock = asyncio.Lock()
        self.transition_attempts = []

    async def load_session_state(self, session_id):
        return self.sessions.get(session_id)

    async def store_flow(self, flow):
        self.flows[flow.id] = flow.model_copy(deep=True)

    async def create_flow_objective(self, flow, engagement, objective):
        async with self.transition_lock:
            current = self.flows.get(flow.id)
            durable = self.sessions.get(engagement.session_id)
            if (
                current is None
                or current.engagement_id != engagement.session_id
                or current.revision != flow.revision
                or current.status != flow.status
                or current.status not in {"pending", "running"}
                or durable is None
                or durable.phase != engagement.phase
                or durable.phase in {"halted", "completed"}
                or durable.scope != engagement.scope
                or durable.roe != engagement.roe
                or not durable.scope.authorization_ref
                or not (durable.scope.domains or durable.scope.ips)
            ):
                return None
            try:
                ScopeEnforcer(durable.scope).validate_time_window()
            except (OutOfScopeError, ScopeValidationError):
                return None
            changed = current.model_copy(deep=True)
            changed.revision += 1
            changed.updated_at = datetime.utcnow()
            self.flows[flow.id] = changed
            self.tasks[objective.id] = objective.model_copy(deep=True)
            return changed.model_copy(deep=True)

    async def transition_flow_status(
        self, flow_id, engagement_id, expected_revision, allowed_statuses, new_status
    ):
        """Model the atomic PostgreSQL UPDATE's revision/state predicates."""
        async with self.transition_lock:
            current = self.flows.get(flow_id)
            self.transition_attempts.append((flow_id, expected_revision, tuple(allowed_statuses)))
            active = any(
                step.flow_id == flow_id
                and step.engagement_id == engagement_id
                and (
                    step.status not in {"pending", "completed", "failed", "cancelled"}
                    or (
                        step.execution_task_id
                        and (
                            self.tasks.get(step.execution_task_id) is None
                            or self.tasks[step.execution_task_id].status
                            not in {"completed", "failed", "cancelled"}
                        )
                    )
                )
                for step in self.subtasks.values()
            )
            if (
                current is None
                or current.engagement_id != engagement_id
                or current.revision != expected_revision
                or current.status not in allowed_statuses
                or (new_status in {"paused", "cancelled"} and active)
            ):
                return None
            changed = current.model_copy(deep=True)
            changed.status = new_status
            changed.revision += 1
            changed.updated_at = datetime.utcnow()
            self.flows[flow_id] = changed
            return changed.model_copy(deep=True)

    async def commit_flow_refinement(
        self,
        flow,
        engagement,
        expected_subtask_ids,
        additions,
        source=None,
        revised_step=None,
        activate_flow=True,
    ):
        """Model the guarded PostgreSQL transaction for operator plan edits."""
        async with self.transition_lock:
            current = self.flows.get(flow.id)
            durable_engagement = self.sessions.get(flow.engagement_id)
            if (
                current is None
                or current.revision != flow.revision
                or current.status != flow.status
                or current.status not in {"pending", "running"}
                or durable_engagement is None
                or durable_engagement.phase != engagement.phase
                or durable_engagement.scope != engagement.scope
                or not engagement.scope.authorization_ref
                or {s.id for s in self.subtasks.values() if s.flow_id == flow.id}
                != set(expected_subtask_ids)
            ):
                return None
            if revised_step is not None:
                previous = self.subtasks.get(revised_step.id)
                if previous is None or previous.status != "pending":
                    return None
            if any(s.id in self.subtasks for s in additions):
                return None
            for row in additions:
                self.subtasks[row.id] = row.model_copy(deep=True)
            if revised_step is not None:
                self.subtasks[revised_step.id] = revised_step.model_copy(deep=True)
            updated = current.model_copy(deep=True)
            updated.revision += 1
            if updated.status == "pending" and activate_flow:
                updated.status = "running"
            self.flows[flow.id] = updated
            return updated.model_copy(deep=True)

    async def load_flow(self, flow_id):
        return self.flows.get(flow_id)

    async def list_flows(self, engagement_id):
        return [f for f in self.flows.values() if f.engagement_id == engagement_id]

    async def store_task(self, task):
        self.tasks[task.id] = task.model_copy(deep=True)

    async def load_task(self, task_id):
        return self.tasks.get(task_id)

    async def list_flow_tasks(self, flow_id):
        return [
            task
            for task in self.tasks.values()
            if task.flow_id == flow_id and task.parent_task_id is None
        ]

    async def store_subtask(self, subtask):
        self.subtasks[subtask.id] = subtask.model_copy(deep=True)

    async def list_subtasks(self, flow_id, task_id=None):
        return sorted(
            (
                x
                for x in self.subtasks.values()
                if x.flow_id == flow_id and (task_id is None or x.task_id == task_id)
            ),
            key=lambda x: x.order,
        )

    async def claim_subtask(
        self,
        subtask_id,
        engagement_id,
        *,
        flow=None,
        engagement=None,
        subtask=None,
        payload=None,
    ):
        async with self.transition_lock:
            item = self.subtasks.get(subtask_id)
            current_flow = self.flows.get(flow.id) if flow is not None else None
            current_session = self.sessions.get(engagement_id)
            if (
                item is None
                or flow is None
                or engagement is None
                or subtask is None
                or payload is None
                or item.engagement_id != engagement_id
                or item.flow_id != flow.id
                or item.task_id != subtask.task_id
                or item.task_type != subtask.task_type
                or item.agent_type != subtask.agent_type
                or item.approval_required != subtask.approval_required
                or item.execution_task_id is not None
                or item.status != "pending"
                or current_flow is None
                or current_flow.revision != flow.revision
                or current_flow.status != flow.status
                or current_flow.status not in {"pending", "running"}
                or current_session is None
                or current_session.phase != engagement.phase
                or current_session.phase in {"halted", "completed"}
                or current_session.scope != engagement.scope
                or current_session.roe != engagement.roe
                or not current_session.scope.authorization_ref
                or not (current_session.scope.domains or current_session.scope.ips)
            ):
                return False
            try:
                enforcer = ScopeEnforcer(current_session.scope)
                enforcer.validate_time_window()
                validate_payload_targets(
                    enforcer,
                    payload,
                    require_target=item.agent_type
                    in {
                        AgentType.RECON,
                        AgentType.VULN_ANALYSIS,
                    },
                )
            except (ScopeValidationError, OutOfScopeError):
                return False
            item.status = "dispatched"
            current_flow.revision += 1
            return True

    async def list_actions(self, engagement_id, limit=100, flow_id=None):
        return [
            action
            for action in self.actions
            if action.engagement_id == engagement_id
            and (flow_id is None or action.flow_id == flow_id)
        ][:limit]


@pytest.fixture()
def flow_client():
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "alice"}
    sm = MemoryStub()
    engagement = SessionState(
        session_id="eng-one",
        scope=ScopeDefinition(
            engagement_id="eng-one", domains=["example.com"], authorization_ref="signed-roe"
        ),
        created_by="alice",
        phase="reconnaissance",
    )
    sm.sessions[engagement.session_id] = engagement

    class FakeOrchestrator:
        def __init__(self):
            self.session_memory = sm
            self._sessions = {"eng-one": engagement}
            self._tasks = {}
            self.scheduled = []
            self.halted = []
            self.audit_events = []
            self.generate_flow_subtasks = AsyncMock(
                return_value={"status": "proposed", "added_subtask_ids": ["subtask-reviewed"]}
            )
            self.refine_flow_subtask = AsyncMock(
                return_value={"status": "proposed", "refinement_count": 1}
            )

        async def schedule_task(self, task):
            self.scheduled.append(task)
            task.status = "awaiting_approval" if task.approval_required else "pending"
            self._tasks[task.id] = task
            await sm.store_task(task)

        async def halt_engagement(self, engagement_id, reason):
            self.halted.append((engagement_id, reason))
            self._sessions[engagement_id].phase = "halted"

        async def _audit_log(self, event):
            self.audit_events.append(event)

    orch = FakeOrchestrator()
    original = state.get("orchestrator")
    state["orchestrator"] = orch
    with TestClient(app) as client:
        yield client, app, orch, sm
    state["orchestrator"] = original


def _create_flow_and_task(client):
    flow_response = client.post(
        "/flows", json={"engagement_id": "eng-one", "objective": "Assess authorized API"}
    )
    assert flow_response.status_code == 200, flow_response.text
    flow_id = flow_response.json()["id"]
    task_response = client.post(f"/flows/{flow_id}/tasks", json={"title": "Review endpoints"})
    assert task_response.status_code == 200, task_response.text
    return flow_id, task_response.json()["id"]


def test_flow_creation_lineage_and_scope_requirements(flow_client):
    client, _, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    response = client.post(
        f"/flows/{flow_id}/subtasks",
        json={"task_id": task_id, "title": "Analyze endpoint", "task_type": "recon"},
    )
    assert response.status_code == 200, response.text
    subtask_id = response.json()["id"]
    first = client.post(
        f"/flows/{flow_id}/subtasks/{subtask_id}/dispatch",
        json={"payload": {"target": "https://example.com/api"}},
    )
    assert first.status_code == 200, first.text
    assert len(orch.scheduled) == 1
    assert orch.scheduled[0].flow_id == flow_id
    assert orch.scheduled[0].subtask_id == subtask_id
    assert orch.scheduled[0].scope_check is True
    assert (
        client.post(f"/flows/{flow_id}/subtasks/{subtask_id}/dispatch", json={}).status_code == 409
    )
    assert client.get(f"/flows/{flow_id}").status_code == 200


def test_manual_subtask_insert_refuses_concurrent_pause_without_partial_step(flow_client):
    client, _, _, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    original_commit = sm.commit_flow_refinement

    async def pause_before_commit(**kwargs):
        original = kwargs["flow"]
        await sm.transition_flow_status(
            original.id, original.engagement_id, original.revision, ["pending"], "paused"
        )
        return await original_commit(**kwargs)

    sm.commit_flow_refinement = pause_before_commit
    response = client.post(
        f"/flows/{flow_id}/subtasks",
        json={"task_id": task_id, "title": "Should not persist"},
    )
    assert response.status_code == 409
    assert sm.flows[flow_id].status == "paused"
    assert not sm.subtasks


def test_manual_revision_does_not_modify_step_after_concurrent_dispatch_claim(flow_client):
    client, _, _, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks",
        json={"task_id": task_id, "title": "Original title"},
    ).json()
    revision = sm.flows[flow_id].revision
    original_commit = sm.commit_flow_refinement

    async def claim_before_commit(**kwargs):
        item = sm.subtasks[step["id"]]
        item.status = "dispatched"
        return await original_commit(**kwargs)

    sm.commit_flow_refinement = claim_before_commit
    response = client.patch(
        f"/flows/{flow_id}/subtasks/{step['id']}",
        json={"title": "Stale revision must fail", "expected_revision": revision},
    )
    assert response.status_code == 409
    assert sm.subtasks[step["id"]].title == "Original title"
    assert sm.subtasks[step["id"]].status == "dispatched"
    assert sm.flows[flow_id].revision == revision


def test_flow_rejects_cross_tenant_and_requires_authorization(flow_client):
    client, app, orch, _ = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "bob"}
    assert client.get(f"/flows/{flow_id}").status_code == 403
    assert (
        client.post(
            f"/flows/{flow_id}/subtasks",
            json={
                "task_id": task_id,
                "title": "Foreign step",
            },
        ).status_code
        == 403
    )
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "alice"}
    response = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Ready"}
    )
    subtask_id = response.json()["id"]
    orch._sessions["eng-one"].scope.authorization_ref = None
    response = client.post(f"/flows/{flow_id}/subtasks/{subtask_id}/dispatch", json={})
    assert response.status_code == 403
    assert orch.scheduled == []


def test_flow_blocks_unsatisfied_dependencies_and_requires_approval(flow_client):
    client, _, orch, _ = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    first = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Map endpoints"}
    )
    first_id = first.json()["id"]
    second = client.post(
        f"/flows/{flow_id}/subtasks",
        json={
            "task_id": task_id,
            "title": "Validate finding",
            "task_type": "validate_exploit",
            "dependencies": [first_id],
        },
    )
    assert second.status_code == 200, second.text
    second_id = second.json()["id"]
    blocked = client.post(f"/flows/{flow_id}/subtasks/{second_id}/dispatch", json={})
    assert blocked.status_code == 409
    assert orch.scheduled == []
    # The API never allows approval_required=False to override high-impact tasks.
    assert second.json()["approval_required"] is True


def test_flow_rejects_cross_objective_dependencies(flow_client):
    client, _, _, _ = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "First"}
    ).json()
    other = client.post(f"/flows/{flow_id}/tasks", json={"title": "Second objective"}).json()
    bad = client.post(
        f"/flows/{flow_id}/subtasks",
        json={
            "task_id": other["id"],
            "title": "Invalid predecessor",
            "dependencies": [step["id"]],
        },
    )
    assert bad.status_code == 400


def test_scope_check_rejects_foreign_targets_before_dispatch(flow_client):
    client, _, orch, _ = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Scoped recon"}
    ).json()
    response = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "https://evil.example.net"}},
    )
    assert response.status_code == 403
    assert not orch.scheduled


def test_senior_operator_halt_is_engagement_wide(flow_client):
    client, app, orch, _ = flow_client
    flow_id, _ = _create_flow_and_task(client)
    assert client.post(f"/flows/{flow_id}/halt").status_code == 403
    app.dependency_overrides[verify_token] = lambda: {"role": "senior_operator", "sub": "admin"}
    result = client.post(f"/flows/{flow_id}/halt")
    assert result.status_code == 200
    assert result.json()["engagement_halted"] is True
    assert orch.halted[0][0] == "eng-one"


def test_generator_endpoint_requires_owned_objective_and_never_dispatches(flow_client):
    client, app, orch, _ = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    response = client.post(f"/flows/{flow_id}/tasks/{task_id}/generate")
    assert response.status_code == 200
    assert response.json()["status"] == "proposed"
    orch.generate_flow_subtasks.assert_awaited_once_with(flow_id, task_id)
    assert orch.scheduled == []
    assert client.post(f"/flows/{flow_id}/tasks/task-unknown/generate").status_code == 404
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "bob"}
    assert client.post(f"/flows/{flow_id}/tasks/{task_id}/generate").status_code == 403
    orch.generate_flow_subtasks.assert_awaited_once()


def test_refinement_endpoint_checks_step_ownership_before_calling_engine(flow_client):
    client, app, orch, _ = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Safe context"}
    ).json()
    result = client.post(f"/flows/{flow_id}/subtasks/{step['id']}/refine")
    assert result.status_code == 200
    assert result.json()["refinement_count"] == 1
    orch.refine_flow_subtask.assert_awaited_once_with(flow_id, step["id"])
    assert client.post(f"/flows/{flow_id}/subtasks/subtask-foreign/refine").status_code == 404
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "bob"}
    assert client.post(f"/flows/{flow_id}/subtasks/{step['id']}/refine").status_code == 403


def test_pause_resume_are_idempotent_and_block_all_flow_mutations(flow_client):
    client, _, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks",
        json={"task_id": task_id, "title": "Review", "task_type": "recon"},
    ).json()
    revision = sm.flows[flow_id].revision
    paused = client.post(f"/flows/{flow_id}/pause", json={"expected_revision": revision})
    assert paused.status_code == 200, paused.text
    assert paused.json() == {
        "flow_id": flow_id,
        "status": "paused",
        "execution_stopped": False,
    }
    assert sm.flows[flow_id].revision == revision + 1
    assert client.post(f"/flows/{flow_id}/pause").status_code == 200
    assert sm.flows[flow_id].revision == revision + 1
    assert len(orch.audit_events) == 1
    event = orch.audit_events[0]
    assert event.event_type == "flow_paused"
    assert event.actor_id == "alice"
    assert event.engagement_id == "eng-one"
    assert event.action["from"] == "pending"
    assert event.action["to"] == "paused"

    assert (
        client.post(f"/flows/{flow_id}/tasks", json={"title": "stale objective"}).status_code == 409
    )
    assert (
        client.post(
            f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "late step"}
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/flows/{flow_id}/subtasks/{step['id']}",
            json={"expected_revision": revision + 1, "title": "changed"},
        ).status_code
        == 409
    )
    assert client.post(f"/flows/{flow_id}/tasks/{task_id}/generate").status_code == 409
    assert client.post(f"/flows/{flow_id}/subtasks/{step['id']}/refine").status_code == 409
    assert (
        client.post(
            f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
            json={"payload": {"target": "example.com"}},
        ).status_code
        == 409
    )
    assert not orch.scheduled

    assert (
        client.post(f"/flows/{flow_id}/resume", json={"expected_revision": revision}).status_code
        == 409
    )
    resumed = client.post(f"/flows/{flow_id}/resume", json={"expected_revision": revision + 1})
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["status"] == "pending"
    assert sm.flows[flow_id].revision == revision + 2
    assert client.post(f"/flows/{flow_id}/resume").status_code == 200
    assert sm.flows[flow_id].revision == revision + 2
    assert [e.event_type for e in orch.audit_events] == ["flow_paused", "flow_resumed"]

    dispatched = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={
            "expected_revision": revision + 2,
            "payload": {"target": "example.com"},
        },
    )
    assert dispatched.status_code == 200, dispatched.text
    assert len(orch.scheduled) == 1


def test_cancel_senior_only_idempotent_and_prevents_reactivation(flow_client):
    client, app, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    first = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Unsubmitted"}
    ).json()
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 403
    assert sm.flows[flow_id].status == "pending"
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    revision = sm.flows[flow_id].revision
    assert (
        client.post(
            f"/flows/{flow_id}/cancel", json={"expected_revision": revision - 1}
        ).status_code
        == 409
    )
    cancelled = client.post(f"/flows/{flow_id}/cancel", json={"expected_revision": revision})
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["execution_stopped"] is False
    assert sm.flows[flow_id].status == "cancelled"
    assert sm.subtasks[first["id"]].status == "cancelled"
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 200
    assert len(orch.audit_events) == 1
    assert orch.audit_events[0].actor_id == "admin"
    assert orch.audit_events[0].event_type == "flow_cancelled"
    assert client.post(f"/flows/{flow_id}/resume").status_code == 409
    assert (
        client.post(
            f"/flows/{flow_id}/subtasks/{first['id']}/dispatch",
            json={"payload": {"target": "example.com"}},
        ).status_code
        == 409
    )
    assert not orch.scheduled


def test_pause_and_cancel_refuse_queued_or_unresolved_execution(flow_client):
    client, app, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Queued"}
    ).json()
    dispatched = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "example.com"}},
    )
    assert dispatched.status_code == 200, dispatched.text
    assert client.post(f"/flows/{flow_id}/pause").status_code == 409
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 409
    assert sm.flows[flow_id].status == "pending"
    assert sm.subtasks[step["id"]].status == "dispatched"
    assert orch.audit_events == []

    # A completed subtask is not sufficient if its execution task is still
    # marked pending in the durable scheduler store.
    sm.subtasks[step["id"]].status = "completed"
    assert client.post(f"/flows/{flow_id}/pause").status_code == 409


def test_dispatch_unknown_after_partial_schedule_failure_cannot_be_retried(flow_client):
    client, _, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "One attempt"}
    ).json()

    async def accepted_then_failed(task):
        orch.scheduled.append(task)
        await sm.store_task(task)
        raise RuntimeError("an ambiguous Temporal response with secrets")

    orch.schedule_task = accepted_then_failed
    outcome = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "example.com"}},
    )
    assert outcome.status_code == 503
    assert "secrets" not in outcome.text
    assert "do not retry" in outcome.text
    assert sm.subtasks[step["id"]].status == "dispatch_unknown"
    assert sm.subtasks[step["id"]].execution_task_id == orch.scheduled[0].id
    again = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "example.com"}},
    )
    assert again.status_code == 409
    assert len(orch.scheduled) == 1
    assert client.post(f"/flows/{flow_id}/pause").status_code == 409
    assert orch.audit_events == []


def test_dispatch_preserves_early_worker_completion_status(flow_client):
    client, _, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Fast"}
    ).json()

    async def finish_during_schedule(task):
        orch.scheduled.append(task)
        await sm.store_task(task)
        stored = sm.subtasks[step["id"]]
        stored.status = "completed"
        stored.execution_task_id = task.id
        stored.result_summary = "Worker finished before API response"

    orch.schedule_task = finish_during_schedule
    result = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "example.com"}},
    )
    assert result.status_code == 200, result.text
    assert sm.subtasks[step["id"]].status == "completed"
    assert sm.subtasks[step["id"]].result_summary == "Worker finished before API response"


def test_flow_stop_after_claim_prevents_scheduling(flow_client):
    client, _, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks", json={"task_id": task_id, "title": "Stale"}
    ).json()
    original_claim = sm.claim_subtask

    async def claim_then_pause(subtask_id, engagement_id, **kwargs):
        result = await original_claim(subtask_id, engagement_id, **kwargs)
        sm.flows[flow_id].status = "paused"
        return result

    sm.claim_subtask = claim_then_pause
    response = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "example.com"}},
    )
    assert response.status_code == 409
    assert sm.subtasks[step["id"]].status == "cancelled"
    assert orch.scheduled == []


def test_halt_is_senior_owned_verified_and_idempotent_after_restart(flow_client):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    orch._sessions.clear()
    result = client.post(f"/flows/{flow_id}/halt")
    assert result.status_code == 200, result.text
    assert orch._sessions["eng-one"].phase == "halted"
    assert sm.flows[flow_id].status == "halted"
    assert len(orch.halted) == 1
    assert client.post(f"/flows/{flow_id}/halt").status_code == 200
    assert len(orch.halted) == 1
    assert len(orch.audit_events) == 1
    assert orch.audit_events[0].actor_id == "admin"
    assert (
        client.post(
            "/flows", json={"engagement_id": "eng-one", "objective": "stale flow"}
        ).status_code
        == 409
    )
    assert client.post(f"/flows/{flow_id}/resume").status_code == 409


def test_halt_must_confirm_engagement_phase_before_reporting_success(flow_client):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    orch.halt_engagement = AsyncMock(return_value=None)
    response = client.post(f"/flows/{flow_id}/halt")
    assert response.status_code == 503
    assert sm.flows[flow_id].status == "pending"
    assert orch.audit_events == []


def test_control_endpoints_keep_engagement_ownership_and_role_gates(flow_client):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    app.dependency_overrides[verify_token] = lambda: {"role": "operator", "sub": "bob"}
    assert client.post(f"/flows/{flow_id}/pause").status_code == 403
    assert client.post(f"/flows/{flow_id}/resume").status_code == 403
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 403
    assert client.post(f"/flows/{flow_id}/halt").status_code == 403
    app.dependency_overrides[verify_token] = lambda: {
        "role": "viewer",
        "sub": "alice",
    }
    assert client.post(f"/flows/{flow_id}/pause").status_code == 403
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 403
    assert sm.flows[flow_id].status == "pending"
    assert not orch.audit_events


def test_pause_cancel_fail_closed_if_subtask_listing_can_be_truncated(flow_client):
    client, app, orch, sm = flow_client
    flow_id, task_id = _create_flow_and_task(client)
    for number in range(100):
        item = SubtaskRecord(
            engagement_id="eng-one",
            flow_id=flow_id,
            task_id=task_id,
            title=f"history {number}",
            order=number,
            status="completed",
        )
        sm.subtasks[item.id] = item
    assert client.post(f"/flows/{flow_id}/pause").status_code == 409
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 409
    assert sm.flows[flow_id].status == "pending"
    assert not orch.audit_events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("initial_status", "first_transition", "second_transition"),
    [
        ("pending", "pause", "cancel"),
        ("paused", "resume", "cancel"),
    ],
)
async def test_simultaneous_flow_controls_have_exactly_one_cas_winner(
    flow_client, initial_status, first_transition, second_transition
):
    """Simulate two replicas reading the same snapshot before either UPDATE."""
    client, _, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    sm.flows[flow_id].status = initial_status
    starting_revision = sm.flows[flow_id].revision
    load = sm.load_flow
    both_read = asyncio.Event()
    count = 0

    async def synchronize_snapshot(target):
        nonlocal count
        captured = (await load(target)).model_copy(deep=True)
        count += 1
        if count == 2:
            both_read.set()
        await asyncio.wait_for(both_read.wait(), 2)
        return captured

    sm.load_flow = synchronize_snapshot
    transitions = {"pause": pause_flow, "resume": resume_flow, "cancel": cancel_flow}
    actor = {"role": "senior_operator", "sub": "admin"}
    request = FlowControlRequest(expected_revision=starting_revision)
    responses = await asyncio.gather(
        transitions[first_transition](flow_id, request, operator=actor),
        transitions[second_transition](flow_id, request, operator=actor),
        return_exceptions=True,
    )
    successes = [response for response in responses if isinstance(response, dict)]
    failures = [response for response in responses if isinstance(response, HTTPException)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].status_code == 409
    assert "concurrently" in failures[0].detail
    assert sm.flows[flow_id].revision == starting_revision + 1
    assert len(sm.transition_attempts) == 2
    assert len(orch.audit_events) == 1
    assert orch.audit_events[0].actor_id == "admin"
    assert orch.audit_events[0].action["to"] == sm.flows[flow_id].status


def test_stale_expected_revision_is_not_an_idempotent_success(flow_client):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    initial_revision = sm.flows[flow_id].revision
    assert (
        client.post(
            f"/flows/{flow_id}/pause", json={"expected_revision": initial_revision}
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/flows/{flow_id}/pause", json={"expected_revision": initial_revision}
        ).status_code
        == 409
    )
    assert client.post(f"/flows/{flow_id}/pause").status_code == 200
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    revision = sm.flows[flow_id].revision
    assert (
        client.post(f"/flows/{flow_id}/cancel", json={"expected_revision": revision}).status_code
        == 200
    )
    assert (
        client.post(f"/flows/{flow_id}/cancel", json={"expected_revision": revision}).status_code
        == 409
    )
    assert client.post(f"/flows/{flow_id}/cancel").status_code == 200
    assert [event.event_type for event in orch.audit_events] == ["flow_paused", "flow_cancelled"]


def test_resume_rechecks_scope_before_any_atomic_status_update(flow_client):
    client, _, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    paused = client.post(f"/flows/{flow_id}/pause")
    assert paused.status_code == 200
    assert sm.flows[flow_id].status == "paused"
    original_attempts = len(sm.transition_attempts)
    original_revision = sm.flows[flow_id].revision
    orch._sessions["eng-one"].scope.authorization_ref = None

    response = client.post(f"/flows/{flow_id}/resume")
    assert response.status_code == 403
    assert sm.flows[flow_id].status == "paused"
    assert sm.flows[flow_id].revision == original_revision
    assert len(sm.transition_attempts) == original_attempts
    assert [event.event_type for event in orch.audit_events] == ["flow_paused"]


def test_halt_reconciles_concurrent_flow_transition_using_fresh_revision(flow_client):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    app.dependency_overrides[verify_token] = lambda: {
        "role": "senior_operator",
        "sub": "admin",
    }
    original_halt = orch.halt_engagement
    starting_revision = sm.flows[flow_id].revision

    async def halt_during_other_operators_pause(engagement_id, reason):
        await original_halt(engagement_id, reason)
        # Another process has already committed pause before this endpoint
        # performs its CAS. Emergency halt must not resurrect stale revision.
        competing = sm.flows[flow_id]
        competing.status = "paused"
        competing.revision += 1

    orch.halt_engagement = halt_during_other_operators_pause
    response = client.post(f"/flows/{flow_id}/halt")
    assert response.status_code == 200, response.text
    assert sm.flows[flow_id].status == "halted"
    assert sm.flows[flow_id].revision == starting_revision + 2
    assert len(sm.transition_attempts) == 1
    assert sm.transition_attempts[0][1] == starting_revision + 1
    assert orch.audit_events[0].action["from"] == "paused"
    assert orch.audit_events[0].action["to"] == "halted"


@pytest.mark.parametrize("operation", ["pause", "resume", "cancel"])
def test_no_match_from_database_cas_returns_conflict_without_false_audit(flow_client, operation):
    client, app, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    if operation == "resume":
        sm.flows[flow_id].status = "paused"
    if operation == "cancel":
        app.dependency_overrides[verify_token] = lambda: {
            "role": "senior_operator",
            "sub": "admin",
        }
    original_revision = sm.flows[flow_id].revision
    sm.transition_flow_status = AsyncMock(return_value=None)
    response = client.post(f"/flows/{flow_id}/{operation}")
    assert response.status_code == 409
    assert sm.flows[flow_id].revision == original_revision
    assert sm.flows[flow_id].status == ("paused" if operation == "resume" else "pending")
    sm.transition_flow_status.assert_awaited_once()
    assert not orch.audit_events


def test_objective_creation_fails_after_pause_with_no_partial_task(flow_client):
    client, _, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    baseline = set(sm.tasks)
    previous = sm.create_flow_objective

    async def pause_before_commit(flow, engagement, objective):
        current = sm.flows[flow.id]
        await sm.transition_flow_status(
            flow.id, engagement.session_id, current.revision, [current.status], "paused"
        )
        return await previous(flow, engagement, objective)

    sm.create_flow_objective = pause_before_commit
    result = client.post(f"/flows/{flow_id}/tasks", json={"title": "Stale objective"})
    assert result.status_code == 409
    assert set(sm.tasks) == baseline
    assert len(orch._tasks) == len(baseline)
    assert sm.flows[flow_id].status == "paused"


def test_objective_creation_rechecks_current_roe_and_scope(flow_client):
    client, _, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    previous = sm.create_flow_objective
    task_count = len(sm.tasks)
    old_revision = sm.flows[flow_id].revision

    async def revoke_in_database(flow, engagement, objective):
        scoped = sm.sessions["eng-one"].model_copy(deep=True)
        scoped.scope.authorization_ref = None
        sm.sessions["eng-one"] = scoped
        return await previous(flow, engagement, objective)

    sm.create_flow_objective = revoke_in_database
    response = client.post(f"/flows/{flow_id}/tasks", json={"title": "Revoked"})
    assert response.status_code == 409
    assert len(sm.tasks) == task_count
    assert sm.flows[flow_id].revision == old_revision
    assert len(orch._tasks) == task_count


@pytest.mark.asyncio
async def test_objective_creation_and_cancel_same_stale_revision_one_winner(flow_client):
    client, _, orch, sm = flow_client
    flow_id, _ = _create_flow_and_task(client)
    starting_revision = sm.flows[flow_id].revision
    read = sm.load_flow
    barrier = asyncio.Event()
    count = 0

    async def shared_snapshot(identifier):
        nonlocal count
        snapshot = (await read(identifier)).model_copy(deep=True)
        count += 1
        if count == 2:
            barrier.set()
        await asyncio.wait_for(barrier.wait(), 2)
        return snapshot

    sm.load_flow = shared_snapshot
    operator = {"role": "senior_operator", "sub": "admin"}
    responses = await asyncio.gather(
        create_flow_objective(
            flow_id,
            CreateObjectiveRequest(
                title="Concurrent creation", expected_revision=starting_revision
            ),
            operator=operator,
        ),
        cancel_flow(
            flow_id, FlowControlRequest(expected_revision=starting_revision), operator=operator
        ),
        return_exceptions=True,
    )
    successes = [r for r in responses if not isinstance(r, BaseException)]
    errors = [r for r in responses if isinstance(r, HTTPException)]
    assert len(successes) == 1 and len(errors) == 1
    assert errors[0].status_code == 409
    assert sm.flows[flow_id].revision == starting_revision + 1
    if sm.flows[flow_id].status == "cancelled":
        assert len(sm.tasks) == 1
        assert len(orch._tasks) == 1
    else:
        assert len(sm.tasks) == 2
        assert len(orch._tasks) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("control_wins", [True, False])
@pytest.mark.parametrize("control_kind", ["pause", "cancel"])
async def test_dispatch_control_race_single_safe_winner(flow_client, control_wins, control_kind):
    client, _, orch, sm = flow_client
    flow_id, parent_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks",
        json={"task_id": parent_id, "title": "Authorized step"},
    ).json()
    starting_revision = sm.flows[flow_id].revision
    read = sm.load_flow
    barrier = asyncio.Event()
    count = 0

    async def shared_initial_snapshot(identifier):
        nonlocal count
        result = await read(identifier)
        if count >= 2:
            return result
        snapshot = result.model_copy(deep=True)
        count += 1
        if count == 2:
            barrier.set()
        await asyncio.wait_for(barrier.wait(), 2)
        return snapshot

    sm.load_flow = shared_initial_snapshot
    original_claim = sm.claim_subtask
    original_control = sm.transition_flow_status
    claimed = asyncio.Event()
    controlled = asyncio.Event()

    async def controlled_claim(*args, **kwargs):
        if control_wins:
            await asyncio.wait_for(controlled.wait(), 2)
        result = await original_claim(*args, **kwargs)
        claimed.set()
        return result

    async def controlled_transition(*args, **kwargs):
        if not control_wins:
            await asyncio.wait_for(claimed.wait(), 2)
        result = await original_control(*args, **kwargs)
        controlled.set()
        return result

    sm.claim_subtask = controlled_claim
    sm.transition_flow_status = controlled_transition
    actor = {"role": "senior_operator", "sub": "admin"}
    from_flow = pause_flow if control_kind == "pause" else cancel_flow
    outcomes = await asyncio.gather(
        dispatch_subtask(
            flow_id,
            step["id"],
            DispatchSubtaskRequest(
                payload={"target": "https://example.com/api"},
                expected_revision=starting_revision,
            ),
            operator=actor,
        ),
        from_flow(
            flow_id,
            FlowControlRequest(expected_revision=starting_revision),
            operator=actor,
        ),
        return_exceptions=True,
    )
    statuses = [r.status_code for r in outcomes if isinstance(r, HTTPException)]
    assert statuses == [409]
    assert sm.flows[flow_id].revision == starting_revision + 1
    if control_wins:
        assert not orch.scheduled
        assert sm.subtasks[step["id"]].status in {"pending", "cancelled"}
        assert sm.flows[flow_id].status in {"paused", "cancelled"}
        assert len(orch.audit_events) == 1
    else:
        assert len(orch.scheduled) == 1
        assert sm.subtasks[step["id"]].status == "dispatched"
        assert sm.flows[flow_id].status in {"pending", "running"}
        assert not orch.audit_events


def test_guarded_claim_rechecks_persisted_roe_after_api_preflight(flow_client):
    client, _, orch, sm = flow_client
    flow_id, parent_id = _create_flow_and_task(client)
    step = client.post(
        f"/flows/{flow_id}/subtasks",
        json={"task_id": parent_id, "title": "Blocked by updated ROE"},
    ).json()
    old_revision = sm.flows[flow_id].revision
    old_claim = sm.claim_subtask

    async def revoke_before_lock(*args, **kwargs):
        updated = sm.sessions["eng-one"].model_copy(deep=True)
        updated.scope.authorization_ref = None
        sm.sessions["eng-one"] = updated
        return await old_claim(*args, **kwargs)

    sm.claim_subtask = revoke_before_lock
    response = client.post(
        f"/flows/{flow_id}/subtasks/{step['id']}/dispatch",
        json={"payload": {"target": "example.com"}},
    )
    assert response.status_code == 409
    assert sm.flows[flow_id].revision == old_revision
    assert sm.subtasks[step["id"]].status == "pending"
    assert not orch.scheduled
