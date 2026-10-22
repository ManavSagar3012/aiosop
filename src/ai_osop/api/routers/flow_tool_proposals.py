"""Turn a live MCP declaration into a signed, inert native Flow planning step.

This is deliberately NOT a generic run-tool API. PentAGI's per-Flow executor
is not equivalent to AI-OSOP's global MCP registry. A selected declaration
must first enter an ordinary persisted Flow Task/Subtask review, with every
real execution path independently rechecking authorization and human consent.
"""

from __future__ import annotations

import re
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifacts import _operator
from ai_osop.core.config import AgentType
from ai_osop.core.models import SubtaskRecord
from ai_osop.mcp.protocol import MCPRegistry, MCPToolDefinition, SideEffectClass
from ai_osop.memory.session_memory import SessionMemory

router = APIRouter(prefix="/flows", tags=["flow-tool-proposals"])
_ID = re.compile(r"flow-[A-Za-z0-9._-]{1,90}\Z")
_SERVER_TOOL = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")
_OBJECTIVE = re.compile(r"task-[A-Za-z0-9._:-]{1,85}\Z")


class CreateToolProposal(BaseModel):
    objective_task_id: str = Field(min_length=6, max_length=96)
    server_id: str = Field(min_length=1, max_length=80)
    tool_name: str = Field(min_length=1, max_length=80)
    expected_flow_revision: int = Field(ge=0)
    expected_authorization_version: int = Field(ge=1)
    explicit_human_confirmation: bool


@router.post("/{flow_id}/tool-proposals", status_code=201)
async def propose_declared_flow_tool(
    flow_id: str,
    body: CreateToolProposal,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Persist a *pending* human-review subtask, never schedule or call MCP.

    In particular, selection of an invasive tool cannot itself stand in for
    the separate Task/Action approval, and a lost HTTP response may mean the
    database committed. Clients MUST GET-readback; never blindly retry POST.
    """
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if (
        not _ID.fullmatch(flow_id)
        or not _OBJECTIVE.fullmatch(body.objective_task_id)
        or not _SERVER_TOOL.fullmatch(body.server_id)
        or not _SERVER_TOOL.fullmatch(body.tool_name)
        or body.explicit_human_confirmation is not True
    ):
        raise HTTPException(422, "Explicit bounded tool proposal confirmation required")
    memory = getattr(state.get("orchestrator"), "session_memory", None)
    registry = getattr(state.get("orchestrator"), "mcp_registry", None)
    if not isinstance(memory, SessionMemory) or not isinstance(registry, MCPRegistry):
        raise HTTPException(503, "Signed Flow tool proposal store unavailable")
    try:
        flow = await memory.load_flow(flow_id)
        if (
            flow is None
            or flow.id != flow_id
            or flow.status not in {"pending", "running"}
            or flow.revision != body.expected_flow_revision
            or not re.fullmatch(r"eng-[A-Za-z0-9._-]{1,60}", flow.engagement_id)
        ):
            raise HTTPException(409, "Signed Flow changed; refresh before proposing")
        engagement_id = flow.engagement_id

        async def current_authority() -> Any:
            signed = await memory.assert_signed_authorization(
                engagement_id, expected_version=body.expected_authorization_version
            )
            engagement = await memory.load_session_state(engagement_id)
            refreshed = await memory.load_flow(flow_id)
            if (
                signed is None
                or signed.version != body.expected_authorization_version
                or not getattr(signed, "policy_sha256", None)
                or engagement is None
                or engagement.session_id != engagement_id
                or engagement.created_by != operator["sub"]
                or engagement.phase in {"halted", "completed"}
                or not engagement.scope.authorization_ref
                or not (engagement.scope.domains or engagement.scope.ips)
                or refreshed is None
                or refreshed.id != flow_id
                or refreshed.engagement_id != engagement_id
                or refreshed.status not in {"pending", "running"}
                or refreshed.revision != body.expected_flow_revision
            ):
                raise HTTPException(409, "Current signed Flow and owner approval required")
            return engagement

        engagement = await current_authority()
        objective = await memory.load_task_authoritative(body.objective_task_id)
        if (
            objective is None
            or objective.id != body.objective_task_id
            or objective.engagement_id != engagement_id
            or objective.flow_id != flow_id
            or objective.type != "flow_objective"
            or objective.status != "planned"
        ):
            raise HTTPException(409, "Persisted Flow objective is unavailable")

        # A negotiated declaration only; no automatic MCP initialization,
        # refresh, status call, connector ping or network request is allowed.
        servers = registry._servers
        if not isinstance(servers, dict) or len(servers) > 32:
            raise HTTPException(503, "MCP registry declarations unavailable")
        connection = servers.get(body.server_id)
        if (
            connection is None
            or connection.server_id != body.server_id
            or connection._initialized is not True
            or connection.get_circuit_state() != "closed"
            or not isinstance(connection._tools, dict)
            or len(connection._tools) > 128
        ):
            raise HTTPException(409, "Initialized MCP declaration unavailable")
        declaration = connection._tools.get(body.tool_name)
        if (
            not isinstance(declaration, MCPToolDefinition)
            or declaration.name != body.tool_name
            or not isinstance(declaration.side_effect_class, SideEffectClass)
            or type(declaration.requires_approval) is not bool
            or type(declaration.scope_check) is not bool
            or not declaration.scope_check
        ):
            raise HTTPException(409, "Tool has no safe scope-checked declaration")

        steps = await memory.list_subtasks(flow_id)
        if (
            not isinstance(steps, list)
            or len(steps) >= 15
            or any(step.flow_id != flow_id or step.engagement_id != engagement_id for step in steps)
        ):
            raise HTTPException(409, "Flow plan changed or is full")
        # DO NOT insert untrusted parameter schemas, target URLs or model text
        # into the future agent task. This step is a review placeholder only.
        label = f"{body.server_id}/{body.tool_name}"
        candidate = SubtaskRecord(
            engagement_id=engagement_id,
            flow_id=flow_id,
            task_id=objective.id,
            title=f"Review declared MCP capability: {label}",
            description=(
                "Operator-selected, inert tool capability proposal. "
                f"Declared side effect: {declaration.side_effect_class.value}. "
                "No parameters supplied; no target tested; runtime health UNKNOWN. "
                "A separate current signed Task/Subtask/Action approval and "
                "verified provider execution boundary are required before use."
            ),
            task_type="operator_mcp_capability_review",
            agent_type=AgentType.HUMAN_OVERSIGHT,
            approval_required=True,
            order=len(steps),
            dependencies=[],
        )
        await current_authority()
        committed = await memory.commit_flow_refinement(
            flow=flow,
            engagement=engagement,
            expected_subtask_ids=[step.id for step in steps],
            additions=[candidate],
            activate_flow=False,
        )
        if committed is None:
            raise HTTPException(409, "Flow changed concurrently; inspect current plan")
        # If postcommit validation fails, mutation outcome is UNKNOWN, not a
        # promise the server rolled back; operator MUST inspect current plan.
        fresh = await memory.load_flow(flow_id)
        if (
            fresh is None
            or fresh.id != flow_id
            or fresh.engagement_id != engagement_id
            or fresh.revision != body.expected_flow_revision + 1
        ):
            raise HTTPException(503, "Proposal outcome UNKNOWN; manually read the Flow")
        signed = await memory.assert_signed_authorization(
            engagement_id, expected_version=body.expected_authorization_version
        )
        if signed is None or signed.version != body.expected_authorization_version:
            raise HTTPException(503, "Proposal outcome UNKNOWN; manually read the Flow")
        return {
            "status": "proposal_recorded_pending_review",
            "flow_id": flow_id,
            "engagement_id": engagement_id,
            "subtask_id": candidate.id,
            "flow_revision": fresh.revision,
            "authorization_version": body.expected_authorization_version,
            "execution_started": False,
            "human_approval_still_required": True,
            "runtime_health_verified": False,
            "target_effect_verified": False,
            "safe_to_automatically_retry": False,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            503, "Tool proposal outcome UNKNOWN; manually read current Flow"
        ) from exc
