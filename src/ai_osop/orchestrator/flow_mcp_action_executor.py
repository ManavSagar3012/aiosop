"""One-shot, signed Flow MCP action admission and execution.

An MCP declaration is not authority.  A separately approved executing Task,
its actual dispatched Subtask, the current signed ROE, and a durable action
reservation are required before an initialized provider can receive a call.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ai_osop.core.models import FlowRecord, SessionState, SubtaskRecord, Task
from ai_osop.core.telemetry import RequestContext
from ai_osop.mcp.protocol import MCPRegistry, MCPToolDefinition, SideEffectClass
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from ai_osop.mcp.tool_budget import _declared_targets, check_tool_authorization
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

_FLOW = re.compile(r"flow-[A-Za-z0-9._-]{1,90}\Z")
_ENG = re.compile(r"eng-[A-Za-z0-9._-]{1,60}\Z")
_TASK = re.compile(r"task-[A-Za-z0-9._:-]{1,85}\Z")
_SUBTASK = re.compile(r"subtask-[A-Za-z0-9._:-]{1,85}\Z")
_ACTION = re.compile(r"action-[0-9a-f]{32}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_TOOL = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")
_PARAM = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_DENY_NAMES = (
    "exploit",
    "attack",
    "intruder",
    "sqlmap",
    "fuzz",
    "scan",
    "probe",
    "crawl",
    "command",
    "shell",
    "execute",
    "delete",
    "upload",
    "write",
    "mutate",
    "modify",
    "send_request",
    "http_request",
    "post_request",
    "put_request",
    "credential",
    "exfil",
    "token",
    "secret",
    "password",
    "cookie",
    "header",
    "script",
    "raw_request",
    "payload",
)
_TYPE_NAMES = {
    "string": "string",
    "integer": "integer",
    "int": "integer",
    "number": "number",
    "boolean": "boolean",
    "bool": "boolean",
}


class FlowMCPActionDenied(RuntimeError):
    """Public, redacted API denial (never interpolate a provider exception)."""

    def __init__(
        self, status: int = 409, message: str = "Signed Flow MCP action unavailable"
    ) -> None:
        super().__init__(message)
        self.status = status


def _bounded_params(parameters: Any, definition: MCPToolDefinition) -> Dict[str, Any]:
    """Match negotiated primitive schema exactly; prohibit opaque nested I/O."""
    if not isinstance(parameters, dict) or len(parameters) > 12:
        raise FlowMCPActionDenied(422, "Bounded MCP parameter object required")
    if not isinstance(definition.parameters, list) or len(definition.parameters) > 12:
        raise FlowMCPActionDenied(409, "MCP primitive parameter schema unavailable")
    declared: Dict[str, Any] = {}
    for item in definition.parameters:
        name = getattr(item, "name", None)
        kind = _TYPE_NAMES.get(getattr(item, "type", None))
        if (
            not isinstance(name, str)
            or not _PARAM.fullmatch(name)
            or kind is None
            or name in declared
            or any(marker in name.lower() for marker in _DENY_NAMES)
            or type(item.required) is not bool
            or (item.enum is not None and (not isinstance(item.enum, list) or len(item.enum) > 16))
        ):
            raise FlowMCPActionDenied(409, "Unsafe MCP primitive parameter schema")
        declared[name] = (kind, item)
    if set(parameters) - set(declared):
        raise FlowMCPActionDenied(422, "Unknown MCP parameter")
    canonical: Dict[str, Any] = {}
    for name, (kind, item) in declared.items():
        if name not in parameters:
            if item.required:
                raise FlowMCPActionDenied(422, "Required MCP parameter missing")
            continue
        value = parameters[name]
        if kind == "string":
            valid = isinstance(value, str) and 0 < len(value) <= 512
            valid = valid and all(ord(ch) >= 32 and ord(ch) != 127 for ch in value)
        elif kind == "integer":
            valid = type(value) is int and -(2**31) <= value <= 2**31 - 1
        elif kind == "number":
            valid = type(value) in (int, float) and math.isfinite(value) and abs(value) <= 1e9
        else:
            valid = type(value) is bool
        if not valid or (item.enum is not None and value not in item.enum):
            raise FlowMCPActionDenied(422, "Invalid bounded MCP parameter value")
        canonical[name] = value
    if len(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)) > 4096:
        raise FlowMCPActionDenied(413, "MCP parameters exceed size limit")
    return canonical


def _tool_definition(registry: MCPRegistry, server_id: str, tool_name: str) -> MCPToolDefinition:
    if not _TOOL.fullmatch(server_id) or not _TOOL.fullmatch(tool_name):
        raise FlowMCPActionDenied(422, "Bounded MCP tool identity required")
    browser_navigation = server_id == "browser-mcp" and tool_name == "execute"
    original_sourcemap = (
        server_id == "source-map-mcp" and tool_name == "inspect_local_original_sourcemap"
    )
    if not browser_navigation and any(marker in tool_name.lower() for marker in _DENY_NAMES):
        raise FlowMCPActionDenied(
            409, "MCP action family requires independent high-risk authorization"
        )
    servers = registry._servers
    if not isinstance(servers, dict) or len(servers) > 32:
        raise FlowMCPActionDenied(503, "MCP registry unavailable")
    conn = servers.get(server_id)
    if (
        conn is None
        or conn.server_id != server_id
        or conn._initialized is not True
        or conn.get_circuit_state() != "closed"
        or not isinstance(conn._tools, dict)
        or len(conn._tools) > 128
    ):
        raise FlowMCPActionDenied(409, "Initialized MCP tool unavailable")
    tool = conn._tools.get(tool_name)
    if (
        not isinstance(tool, MCPToolDefinition)
        or tool.name != tool_name
        or (
            tool.side_effect_class is not SideEffectClass.READ_ONLY
            and not (
                browser_navigation
                and tool.side_effect_class is SideEffectClass.RECON_ACTIVE
                and tool.requires_approval is True
            )
        )
        or tool.scope_check is not True
        or type(tool.requires_approval) is not bool
        or tool.timeout_seconds < 1
        or tool.timeout_seconds > 60
    ):
        raise FlowMCPActionDenied(409, "Only scope-checked READ_ONLY MCP tools are admitted")
    if browser_navigation:
        parameters = tool.parameters
        if (
            tool.side_effect_class is not SideEffectClass.RECON_ACTIVE
            or tool.requires_approval is not True
            or not isinstance(parameters, list)
            or len(parameters) != 4
            or {p.name: (p.type, p.required) for p in parameters}
            != {
                "url": ("string", False),
                "action": ("string", True),
                "user_label": ("string", True),
                "evidence_mode": ("string", False),
            }
        ):
            raise FlowMCPActionDenied(
                409, "Browser declaration differs from reviewed navigation schema"
            )
    if original_sourcemap and (
        tool.side_effect_class is not SideEffectClass.READ_ONLY
        or tool.requires_approval is not True
        or len(tool.parameters) != 1
        or {p.name: (p.type, p.required) for p in tool.parameters}
        != {"artifact_sha256": ("string", True)}
    ):
        raise FlowMCPActionDenied(
            409, "SourceMap declaration differs from reviewed original-byte schema"
        )
    return tool


def _manifest_sha256(server_id: str, declaration: MCPToolDefinition) -> str:
    """Pin complete, negotiated parameter schema and privilege declarations."""
    canonical = json.dumps(
        {"server_id": server_id, "declaration": declaration.model_dump(mode="json")},
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


class FlowMCPActionExecutor:
    """API-call scoped gate; durable PostgreSQL store enforces cross-replica CAS."""

    def __init__(self, memory: SessionMemory, registry: MCPRegistry, store: Any) -> None:
        if not isinstance(memory, SessionMemory) or not isinstance(registry, MCPRegistry):
            raise FlowMCPActionDenied(503, "Production Flow MCP authority unavailable")
        if getattr(registry._budget_callback, "__self__", None) is not memory or not callable(
            registry._execution_event_callback
        ):
            raise FlowMCPActionDenied(503, "MCP signed Task budget and audit gates unavailable")
        self.memory = memory
        self.registry = registry
        self.store = store

    async def _authority(self, binding: Dict[str, Any], operator: Dict[str, Any]) -> SessionState:
        eid = binding.get("engagement_id")
        fid = binding.get("flow_id")
        revision = binding.get("revision")
        version = binding.get("version")
        if (
            not isinstance(eid, str)
            or not _ENG.fullmatch(eid)
            or not isinstance(fid, str)
            or not _FLOW.fullmatch(fid)
            or type(revision) is not int
            or revision < 0
            or type(version) is not int
            or version < 1
            or not isinstance(operator, dict)
            or operator.get("role") not in {"operator", "senior_operator"}
            or not isinstance(operator.get("sub"), str)
            or not operator["sub"]
            or not isinstance(operator.get("claims"), dict)
            or type(operator["claims"].get("exp")) is not int
            or operator["claims"]["exp"] <= int(datetime.now(timezone.utc).timestamp())
        ):
            raise FlowMCPActionDenied(403, "Current signed operator and Flow required")
        signed = await self.memory.assert_signed_authorization(eid, expected_version=version)
        session = await self.memory.load_session_state(eid)
        flow = await self.memory.load_flow(fid)
        if (
            signed is None
            or getattr(signed, "version", None) != version
            or not getattr(signed, "policy_sha256", None)
            or not getattr(signed, "authorization_id", None)
            or not isinstance(session, SessionState)
            or session.session_id != eid
            or session.created_by != operator["sub"]
            or session.phase in {"halted", "completed"}
            or session.scope.engagement_id != eid
            or session.scope.authorization_ref != signed.authorization_id
            or not session.scope.authorization_ref
            or not (session.scope.domains or session.scope.ips)
            or not isinstance(flow, FlowRecord)
            or flow.id != fid
            or flow.engagement_id != eid
            or flow.revision != revision
            or flow.status not in {"pending", "running"}
        ):
            raise FlowMCPActionDenied(409, "Current signed Flow ownership or ROE changed")
        if (
            "authorization_id" in binding and binding["authorization_id"] != signed.authorization_id
        ) or (
            "authorization_sha256" in binding
            and binding["authorization_sha256"] != signed.policy_sha256
        ):
            raise FlowMCPActionDenied(409, "Signed authorization digest changed")
        binding["authorization_id"] = signed.authorization_id
        binding["authorization_sha256"] = signed.policy_sha256
        ScopeEnforcer(session.scope).validate_time_window()
        return session

    async def _task(self, binding: Dict[str, Any], task_id: str, subtask_id: str) -> Task:
        if not _TASK.fullmatch(task_id) or not _SUBTASK.fullmatch(subtask_id):
            raise FlowMCPActionDenied(422, "Bounded Task/Subtask identity required")
        task = await self.memory.load_task_authoritative(task_id)
        if (
            not isinstance(task, Task)
            or task.id != task_id
            or task.engagement_id != binding["engagement_id"]
            or task.flow_id != binding["flow_id"]
            or task.subtask_id != subtask_id
            or task.status not in {"running", "scheduled"}
            or task.type == "operator_mcp_capability_review"
            or task.scope_check is not True
            or task.approval_required is not True
            or not isinstance(task.payload, dict)
            or type(task.payload.get("_authorization_version")) is not int
            or task.payload["_authorization_version"] != binding["version"]
            or task.payload.get("operator_approved") is not True
            or not isinstance(task.payload.get("approval_id"), str)
            or not isinstance(task.payload.get("mcp_action_id"), str)
            or not _ACTION.fullmatch(task.payload["mcp_action_id"])
            or not isinstance(task.payload.get("mcp_server_id"), str)
            or not isinstance(task.payload.get("mcp_tool_name"), str)
            or not isinstance(task.payload.get("mcp_declaration_sha256"), str)
            or not _SHA.fullmatch(task.payload["mcp_declaration_sha256"])
            or not isinstance(task.payload.get("mcp_parameters_sha256"), str)
            or not _SHA.fullmatch(task.payload["mcp_parameters_sha256"])
            or type(task.payload.get("mcp_flow_revision")) is not int
            or task.payload["mcp_flow_revision"] != binding["revision"]
        ):
            raise FlowMCPActionDenied(409, "Persisted signed executing Task approval required")
        steps = await self.memory.list_subtasks(binding["flow_id"])
        if not isinstance(steps, list):
            raise FlowMCPActionDenied(503, "Authoritative Flow lineage unavailable")
        matching = [s for s in steps if isinstance(s, SubtaskRecord) and s.id == subtask_id]
        if len(matching) != 1:
            raise FlowMCPActionDenied(409, "Signed Subtask lineage unavailable")
        step = matching[0]
        if (
            step.engagement_id != binding["engagement_id"]
            or step.flow_id != binding["flow_id"]
            or step.execution_task_id != task_id
            or step.task_id != task.parent_task_id
            or step.task_type == "operator_mcp_capability_review"
            or step.status not in {"dispatched", "running"}
            or step.approval_required is not True
        ):
            raise FlowMCPActionDenied(409, "Executable Subtask approval or lineage changed")
        if (
            await self.memory.is_task_approved(
                task_id, binding["engagement_id"], task.payload["approval_id"]
            )
            is not True
        ):
            raise FlowMCPActionDenied(
                409, "Current independently persisted human approval required"
            )
        return task

    async def _admit(
        self,
        binding: Dict[str, Any],
        operator: Dict[str, Any],
        *,
        task_id: str,
        subtask_id: str,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
    ) -> tuple[Dict[str, Any], str]:
        session = await self._authority(binding, operator)
        task = await self._task(binding, task_id, subtask_id)
        declaration = _tool_definition(self.registry, server_id, tool_name)
        normalized = _bounded_params(parameters, declaration)
        if server_id == "browser-mcp" and tool_name == "execute":
            # This is the *only* consequential tool admitted through the
            # existing independently reviewed 0027 Action lifecycle. The
            # Browser itself still requires a distinct source-authority
            # one-shot before navigation. No clicks, scripts or credentials.
            if (
                set(normalized)
                not in (
                    {"url", "action", "user_label"},
                    {"url", "action", "user_label", "evidence_mode"},
                )
                or normalized["action"] != "navigate"
                or normalized.get("evidence_mode", "none") not in {"none", "screenshot_dom_har"}
                or not isinstance(normalized["url"], str)
                or not re.fullmatch(r"https?://[^?#@\s]{1,240}", normalized["url"])
                or not isinstance(normalized["user_label"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", normalized["user_label"])
            ):
                raise FlowMCPActionDenied(
                    409, "Only exact nonsecret reviewed Browser navigation is admitted"
                )
        # A target verified by the signed executing Task is the only permitted
        # destination. A new in-scope URL is not implicitly the approved one.
        targets = _declared_targets(normalized)
        approved = _declared_targets(task.payload)
        # The native built-in status tool has NO network side effect and NO
        # target input. Still require a separately approved in-scope Task
        # target, so an empty tool argument cannot create a new authorization
        # context or bypass the existing 0027 human approval gate.
        inert_native_status = (
            server_id
            in {
                "recon-mcp",
                "payload-mcp",
                "nuclei-mcp",
                "shodan-mcp",
                "threat-intel-mcp",
                "security-bridge",
            }
            and tool_name == "authority_status"
            and normalized == {}
        )
        original_sourcemap = (
            server_id == "source-map-mcp" and tool_name == "inspect_local_original_sourcemap"
        )
        if original_sourcemap:
            digest = normalized.get("artifact_sha256")
            payload = task.payload
            if (
                set(normalized) != {"artifact_sha256"}
                or type(digest) is not str
                or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                or type(payload.get("resource_artifact_id")) is not str
                or re.fullmatch(r"artifact-[a-f0-9]{32}", payload["resource_artifact_id"]) is None
                or payload.get("resource_artifact_sha256") != digest
                or payload.get("resource_authorization_sha256") != binding["authorization_sha256"]
                or type(payload.get("resource_manifest_sha256")) is not str
                or re.fullmatch(r"[a-f0-9]{64}", payload["resource_manifest_sha256"]) is None
                or type(payload.get("resource_command_sha256")) is not str
                or payload["resource_command_sha256"]
                != hashlib.sha256(
                    json.dumps(
                        normalized,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    ).encode("ascii")
                ).hexdigest()
            ):
                raise FlowMCPActionDenied(
                    409, "Original SourceMap artifact not independently approved in Task"
                )
            # A content-addressed ORIGINAL Flow artifact is not an outbound
            # destination. No caller-supplied URL/Host may be introduced here.
            validate_payload_targets(ScopeEnforcer(session.scope), {}, require_target=False)
        elif inert_native_status:
            if not approved:
                raise FlowMCPActionDenied(409, "Approved Task target required for native admission")
            validate_payload_targets(ScopeEnforcer(session.scope), approved, require_target=True)
        else:
            if (
                not targets
                or not approved
                or not all(isinstance(x, str) and x in approved.values() for x in targets.values())
            ):
                raise FlowMCPActionDenied(409, "MCP target differs from approved Task target")
            validate_payload_targets(ScopeEnforcer(session.scope), targets, require_target=True)
        denial = await check_tool_authorization(
            self.memory.consume_mcp_tool_budget,
            server_id,
            tool_name,
            normalized,
            {
                "engagement_id": binding["engagement_id"],
                "task_id": task_id,
                "flow_id": binding["flow_id"],
                "subtask_id": subtask_id,
            },
            requires_approval=True,
        )
        if denial is not None:
            raise FlowMCPActionDenied(409, "Existing signed MCP scope or approval gate denied")
        await self._authority(binding, operator)
        await self._task(binding, task_id, subtask_id)
        digest = hashlib.sha256(
            json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
        if (
            task.payload["mcp_server_id"] != server_id
            or task.payload["mcp_tool_name"] != tool_name
            or task.payload["mcp_parameters_sha256"] != digest
            or task.payload["mcp_declaration_sha256"] != _manifest_sha256(server_id, declaration)
        ):
            raise FlowMCPActionDenied(409, "Signed Task MCP action manifest or parameters changed")
        return normalized, digest

    async def prepare(
        self,
        binding: Dict[str, Any],
        operator: Dict[str, Any],
        *,
        task_id: str,
        subtask_id: str,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
    ) -> Dict[str, Any]:
        normalized, digest = await self._admit(
            binding,
            operator,
            task_id=task_id,
            subtask_id=subtask_id,
            server_id=server_id,
            tool_name=tool_name,
            parameters=parameters,
        )
        return await self.store.prepare(
            binding,
            operator["sub"],
            task_id=task_id,
            subtask_id=subtask_id,
            server_id=server_id,
            tool_name=tool_name,
            parameters=normalized,
            parameters_sha256=digest,
            manifest_sha256=_manifest_sha256(
                server_id, _tool_definition(self.registry, server_id, tool_name)
            ),
        )

    async def dispatch(
        self,
        binding: Dict[str, Any],
        operator: Dict[str, Any],
        action_id: str,
    ) -> Dict[str, Any]:
        if not _ACTION.fullmatch(action_id):
            raise FlowMCPActionDenied(422, "Bounded MCP action identity required")
        # The PG store verifies a *separate* persisted approving operator,
        # distinct from this engagement owner. The acting owner need not have
        # the senior role when a distinct human already approved the Task.
        await self._authority(binding, operator)
        action = await self.store.get(binding, operator["sub"], action_id)
        if not isinstance(action, dict) or action.get("status") != "prepared":
            raise FlowMCPActionDenied(409, "Action is already reserved or no longer executable")
        task_id = action.get("task_id")
        subtask_id = action.get("subtask_id")
        server_id = action.get("server_id")
        tool_name = action.get("tool_name")
        # The immutable parameters only come from the private PostgreSQL
        # reservation. GET responses must never contain parameter bytes.
        await self._authority(binding, operator)
        approved_task = await self._task(binding, task_id, subtask_id)
        # Resource SHA is only from the independently approved, pinned Task;
        # never a late operator POST or a caller-provided native parameter.
        # Native issue and redeem each re-check original BYTEA/review/lease.
        # Genuine SessionMemory returns a typed Task. Deterministic legacy
        # test doubles may return bool, which can never add resource authority.
        native_resource_sha256: Optional[str] = (
            approved_task.payload.get("mcp_resource_sha256")
            if isinstance(approved_task, Task)
            else None
        )
        if native_resource_sha256 is not None and (
            not isinstance(native_resource_sha256, str)
            or _SHA.fullmatch(native_resource_sha256) is None
            or tool_name != "authority_status"
        ):
            raise FlowMCPActionDenied(409, "Signed inert MCP resource intent is unavailable")
        _tool_definition(self.registry, server_id, tool_name)
        claimed = await self.store.reserve(binding, operator["sub"], action_id)
        if not isinstance(claimed, dict) or claimed.get("admitted_for_dispatch") is not True:
            raise FlowMCPActionDenied(409, "Durable MCP action reservation denied")
        request_id = claimed.get("request_id")
        token = claimed.get("reservation_token")
        if not isinstance(request_id, str) or not re.fullmatch(
            r"req-[a-f0-9]{32,64}\Z", request_id
        ):
            raise FlowMCPActionDenied(503, "MCP dispatch reservation identity UNKNOWN")
        if not isinstance(token, str) or len(token) < 24 or len(token) > 256:
            raise FlowMCPActionDenied(503, "Durable MCP reservation token UNKNOWN")
        outcome = "unknown"
        provider_receipt: Optional[Dict[str, Any]] = None
        try:
            private = claimed.get("parameters")
            normalized, digest = await self._admit(
                binding,
                operator,
                task_id=task_id,
                subtask_id=subtask_id,
                server_id=server_id,
                tool_name=tool_name,
                parameters=private,
            )
            if claimed.get("parameters_sha256") != digest:
                raise FlowMCPActionDenied(409, "Reserved MCP parameter digest changed")
            # Durable UNKNOWN is recorded *before* crossing the MCP transport.
            # A network timeout or process crash can never reopen this action.
            sent = await self.store.mark_dispatched(
                binding,
                operator["sub"],
                action_id,
                request_id,
                token,
            )
            if (
                not isinstance(sent, dict)
                or sent.get("status") != "unknown"
                or sent.get("dispatch_attempt_committed") is not True
            ):
                raise FlowMCPActionDenied(503, "Durable MCP attempt marker unavailable")
            native_grant: Optional[str] = None
            if tool_name == "authority_status":
                # The original one-shot 0027 status is committed UNKNOWN
                # *before* issuing a second short-lived native capability.
                # A failed PG issuance does not reopen or retry this Action.
                if (
                    server_id
                    not in {
                        "recon-mcp",
                        "payload-mcp",
                        "nuclei-mcp",
                        "shodan-mcp",
                        "threat-intel-mcp",
                        "security-bridge",
                    }
                    or normalized != {}
                ):
                    raise FlowMCPActionDenied(409, "Only inert native status is permitted")
                from ai_osop.core.native_mcp_grant_signing import header_value
                from ai_osop.memory.native_mcp_execution_grants import (
                    NativeMCPExecutionGrantStore,
                )

                issued = await NativeMCPExecutionGrantStore(self.store).issue(
                    binding,
                    operator["sub"],
                    action_id,
                    request_id,
                    resource_sha256=native_resource_sha256,
                )
                if issued.get("status") != "issued" or not isinstance(issued.get("token"), dict):
                    raise FlowMCPActionDenied(503, "Native MCP grant outcome UNKNOWN")
                native_grant = header_value(issued["token"])
            original = RequestContext.get()
            try:
                RequestContext.bind(
                    engagement_id=binding["engagement_id"],
                    task_id=task_id,
                    flow_id=binding["flow_id"],
                    subtask_id=subtask_id,
                    user_id=operator["sub"],
                )
                result = await self.registry.execute_tool(
                    server_id,
                    tool_name,
                    normalized,
                    request_id=request_id,
                    **({"native_grant": native_grant} if native_grant is not None else {}),
                )
            finally:
                RequestContext.clear()
                RequestContext.bind(
                    **{
                        key: value
                        for key, value in original.items()
                        if key
                        in {
                            "request_id",
                            "engagement_id",
                            "task_id",
                            "flow_id",
                            "subtask_id",
                            "user_id",
                            "trace_id",
                        }
                        and value
                    }
                )
            response_status = getattr(result, "status", None)
            if response_status == "success":
                # This is provider testimony and may be insufficient for the
                # store's independently validated receipt requirements.
                meta = getattr(result, "metadata", None)
                if isinstance(meta, dict):
                    receipt = meta.get("signed_provider_receipt")
                    if isinstance(receipt, dict):
                        provider_receipt = receipt
                        outcome = "finished"
            # A denied, timed-out or unverified provider response remains
            # UNKNOWN once this Action has crossed the external boundary.
        except Exception:
            # A transport exception may follow a completed external effect.
            # The reservation remains consumed even if settlement also fails.
            outcome = "unknown"
        try:
            settled = await self.store.settle(
                binding,
                operator["sub"],
                action_id,
                request_id,
                outcome,
                provider_receipt=provider_receipt,
            )
            if not isinstance(settled, dict):
                raise ValueError("No authoritative MCP settlement")
            return settled
        except Exception as exc:
            raise FlowMCPActionDenied(
                503, "MCP action outcome UNKNOWN; inspect readback, never retry dispatch"
            ) from exc

    async def reconcile(
        self,
        binding: Dict[str, Any],
        operator: Dict[str, Any],
        action_id: str,
        provider_receipt: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Confirm an existing UNKNOWN attempt only from enrolled Ed25519 proof.

        A receipt is provider status evidence; it can never establish that an
        independent target-authority observer verified a target-side effect.
        """
        if not isinstance(action_id, str) or not _ACTION.fullmatch(action_id):
            raise FlowMCPActionDenied(422, "Bounded MCP action identity required")
        await self._authority(binding, operator)
        record = await self.store.get(binding, operator["sub"], action_id)
        if (
            not isinstance(record, dict)
            or record.get("action_id") != action_id
            or record.get("status") != "unknown"
            or not isinstance(record.get("request_id"), str)
        ):
            raise FlowMCPActionDenied(
                409, "MCP action is not awaiting signed status reconciliation"
            )
        valid = provider_receipt_is_signed(
            provider_receipt,
            record["server_id"],
            record["request_id"],
            binding["engagement_id"],
            record["task_id"],
        )
        if not valid or provider_receipt.get("verified") is not True:
            raise FlowMCPActionDenied(409, "Independently trusted provider status unavailable")
        if provider_receipt.get("status") in {
            "finished",
            "completed",
            "succeeded",
            "failed",
        }:
            outcome = "finished"
        elif provider_receipt.get("stopped") is True and provider_receipt.get("status") in {
            "cancelled",
            "canceled",
            "confirmed_stopped",
        }:
            outcome = "cancelled"
        else:
            raise FlowMCPActionDenied(409, "Provider has not signed terminal action status")
        await self._authority(binding, operator)
        result = await self.store.settle(
            binding,
            operator["sub"],
            action_id,
            record["request_id"],
            outcome,
            provider_receipt=provider_receipt,
        )
        if not isinstance(result, dict) or result.get("status") != outcome:
            raise FlowMCPActionDenied(503, "Signed MCP reconciliation commit unavailable")
        return result
