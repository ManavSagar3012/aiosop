"""PostgreSQL-authoritative signed Task gate for inert Flow worker resources.

The signed Flow artifact store makes a second fresh authorization check when
reading bytes. This gate never grants command execution or AI prompt authority.
"""

from __future__ import annotations

import hmac
import re
from datetime import datetime
from typing import Any, Mapping

from sqlalchemy import text

from ai_osop.memory.authorization_store import guard_sql
from ai_osop.memory.flow_resource_materialization import (
    ResourceAdmissionDenied,
    TaskResourceBinding,
)
from ai_osop.safety.approval_binding import matches_pinned_payload
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets
from ai_osop.core.models import ScopeDefinition

_SESSION = text(
    "SELECT created_by, phase, scope FROM session_states " "WHERE session_id=:eng FOR SHARE"
)
_FLOW = text(
    "SELECT id, engagement_id, revision, status FROM execution_flows "
    "WHERE id=:flow AND engagement_id=:eng FOR SHARE"
)
_TASK = text(
    "SELECT id, engagement_id, flow_id, subtask_id, parent_task_id, "
    "type, status, payload, scope_check, approval_required, "
    "assigned_agent_id, started_at, completed_at "
    "FROM tasks WHERE id=:task AND engagement_id=:eng FOR SHARE"
)
_LEASE = text(
    "SELECT engagement_id, task_id, lease_id, owner_id, state, expires_at "
    "FROM supervision_execution_leases WHERE engagement_id=:eng "
    "AND task_id=:task FOR SHARE"
)
_APPROVAL = text(
    "SELECT id, task_id, engagement_id, status, action_type, target, "
    "operator_id, responded_at, evidence FROM approval_requests "
    "WHERE id=:approval AND engagement_id=:eng AND task_id=:task FOR SHARE"
)
_SUBTASK = text(
    "SELECT id, engagement_id, flow_id, execution_task_id, status "
    "FROM execution_subtasks WHERE id=:step AND engagement_id=:eng "
    "AND flow_id=:flow FOR SHARE"
)


class PostgresApprovedTaskResourceVerifier:
    """Live signed-ROE and human-grant verifier, reloaded on every invocation.

    This deliberately rejects old Tasks that did not pin the resource's SHA
    before the human approved the complete canonical Task payload.
    """

    def __init__(self, session_memory: Any):
        self._session_memory = session_memory

    async def __call__(self, binding: TaskResourceBinding) -> dict[str, object]:
        if not isinstance(binding, TaskResourceBinding):
            raise ResourceAdmissionDenied("Signed Task resource binding required")
        binding.validate()
        maker = getattr(self._session_memory, "_async_session", None)
        if not callable(maker):
            raise ResourceAdmissionDenied("Durable Task approval store unavailable")

        try:
            async with maker() as db:
                async with db.begin():
                    params = {
                        "eng": binding.engagement_id,
                        "flow": binding.flow_id,
                        "task": binding.task_id,
                    }
                    session = (await db.execute(_SESSION, params)).mappings().one_or_none()
                    if (
                        not isinstance(session, Mapping)
                        or session.get("created_by") != binding.owner_id
                        or session.get("phase") in {"halted", "completed"}
                    ):
                        raise ResourceAdmissionDenied("Signed engagement owner unavailable")
                    signed = await guard_sql(
                        db,
                        binding.engagement_id,
                        expected_version=binding.authorization_version,
                        expected_digest=binding.authorization_sha256,
                    )
                    if (
                        signed.session_id != binding.engagement_id
                        or signed.policy.get("created_by") != binding.owner_id
                        or signed.version != binding.authorization_version
                        or not hmac.compare_digest(
                            signed.policy_sha256, binding.authorization_sha256
                        )
                    ):
                        raise ResourceAdmissionDenied("Signed authorization mismatch")
                    flow = (await db.execute(_FLOW, params)).mappings().one_or_none()
                    task = (await db.execute(_TASK, params)).mappings().one_or_none()
                    if (
                        flow is None
                        or flow.get("id") != binding.flow_id
                        or flow.get("engagement_id") != binding.engagement_id
                        or flow.get("status") != "running"
                        or type(flow.get("revision")) is not int
                        or flow["revision"] != binding.flow_revision
                        or task is None
                        or task.get("id") != binding.task_id
                        or task.get("engagement_id") != binding.engagement_id
                        or task.get("flow_id") != binding.flow_id
                        or task.get("status") != "running"
                        or not isinstance(task.get("assigned_agent_id"), str)
                        or not task["assigned_agent_id"].strip()
                        or not isinstance(task.get("started_at"), datetime)
                        or task.get("completed_at") is not None
                        or task.get("scope_check") is not True
                        or task.get("approval_required") is not True
                        or not isinstance(task.get("payload"), dict)
                    ):
                        raise ResourceAdmissionDenied("Approved running Flow Task unavailable")
                    payload = task["payload"]
                    pinned_revision = payload.get(
                        "planner_flow_revision", payload.get("_flow_revision")
                    )
                    if (
                        type(payload.get("_authorization_version")) is not int
                        or payload["_authorization_version"] != signed.version
                        or type(pinned_revision) is not int
                        or pinned_revision != binding.flow_revision
                        or (
                            "planner_flow_revision" in payload
                            and "_flow_revision" in payload
                            and payload["planner_flow_revision"] != payload["_flow_revision"]
                        )
                        or payload.get("resource_artifact_id") != binding.artifact_id
                        or payload.get("resource_artifact_sha256") != binding.artifact_sha256
                        or payload.get("resource_authorization_sha256")
                        != binding.authorization_sha256
                        or not isinstance(payload.get("resource_command_sha256"), str)
                        or re.fullmatch(r"[0-9a-f]{64}", payload["resource_command_sha256"]) is None
                        or payload.get("operator_approved") is not True
                        or not isinstance(payload.get("approval_id"), str)
                    ):
                        raise ResourceAdmissionDenied(
                            "Task resource was not part of the approved payload"
                        )
                    approval = (
                        (
                            await db.execute(
                                _APPROVAL, {**params, "approval": payload["approval_id"]}
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        approval is None
                        or approval.get("id") != payload["approval_id"]
                        or approval.get("task_id") != binding.task_id
                        or approval.get("engagement_id") != binding.engagement_id
                        or approval.get("action_type") != task["type"]
                        or approval.get("status") != "approved"
                        or not isinstance(approval.get("operator_id"), str)
                        or not approval["operator_id"]
                        or approval.get("responded_at") is None
                        or approval.get("target")
                        != str(payload.get("url", payload.get("target", "unknown")))
                        or not matches_pinned_payload(approval.get("evidence"), payload)
                    ):
                        raise ResourceAdmissionDenied("Human approved Task grant unavailable")
                    if task.get("subtask_id") is not None:
                        step = (
                            (
                                await db.execute(
                                    _SUBTASK,
                                    {**params, "step": task["subtask_id"]},
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if (
                            step is None
                            or step.get("id") != task["subtask_id"]
                            or step.get("engagement_id") != binding.engagement_id
                            or step.get("flow_id") != binding.flow_id
                            or step.get("execution_task_id") != binding.task_id
                            or step.get("status") not in {"dispatched", "running"}
                        ):
                            raise ResourceAdmissionDenied("Flow Subtask lineage changed")
                    # A Task status alone is not an execution claim: a queued,
                    # stolen or expired lease must not receive resource bytes.
                    # Read under the same signed-ROE transaction and row locks.
                    lease = (await db.execute(_LEASE, params)).mappings().one_or_none()
                    if (
                        lease is None
                        or lease.get("engagement_id") != binding.engagement_id
                        or lease.get("task_id") != binding.task_id
                        or lease.get("state") != "dispatched"
                        or not isinstance(lease.get("owner_id"), str)
                        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", lease["owner_id"])
                        is None
                        or not isinstance(lease.get("lease_id"), str)
                        or re.fullmatch(r"lease-[A-Za-z0-9._:-]{1,58}", lease["lease_id"]) is None
                        or not isinstance(lease.get("expires_at"), datetime)
                        or lease["expires_at"] <= datetime.utcnow()
                    ):
                        raise ResourceAdmissionDenied("Live claimed execution lease required")
                    scope = ScopeDefinition.model_validate(session["scope"])
                    validate_payload_targets(ScopeEnforcer(scope), payload)
                    return {
                        "approved": True,
                        "active": True,
                        "engagement_id": binding.engagement_id,
                        "flow_id": binding.flow_id,
                        "owner_id": binding.owner_id,
                        "task_id": binding.task_id,
                        "flow_revision": binding.flow_revision,
                        "authorization_version": binding.authorization_version,
                        "authorization_sha256": binding.authorization_sha256,
                        "approved_command_sha256": payload["resource_command_sha256"],
                    }
        except ResourceAdmissionDenied:
            raise
        except Exception as exc:
            raise ResourceAdmissionDenied("Signed Task resource verification unavailable") from exc
