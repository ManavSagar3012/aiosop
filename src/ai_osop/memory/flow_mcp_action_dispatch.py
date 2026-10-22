"""Durable one-shot, signed, Flow-scoped MCP Action dispatch reservations.

An initialized MCP declaration is only a description. The Task's signed ROE,
independently approved full payload, live PG lease, pinned Action and exact
nonsecret parameter digest are checked in the same transaction as admission.
PREPARE persists inert metadata; RESERVE yields one token exactly once;
dispatch_attempted is committed as UNKNOWN *before* calling an external tool.
UNKNOWN cannot be resubmitted. A trusted, signed provider receipt may resolve
the historical outcome, but never independently verifies a target effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

from sqlalchemy import text

from ai_osop.core.config import settings
from ai_osop.core.models import ScopeDefinition
from ai_osop.mcp.protocol import MCPRegistry, MCPToolDefinition, SideEffectClass
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed
from ai_osop.memory.flow_artifact_reviews import FlowArtifactReviewStore
from ai_osop.memory.session_memory import SessionMemory
from ai_osop.safety.approval_binding import matches_pinned_payload
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+:-]{0,63}\Z")
_AUTH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_ACTION = re.compile(r"action-[0-9a-f]{32}\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_LEASE = re.compile(r"lease-[A-Za-z0-9._:-]{1,58}\Z")
_FORBIDDEN = re.compile(
    r"password|passwd|secret|token|api.?key|credential|authorization|cookie|"
    r"headers?|private|bearer|session|command|shell|script|payload|body|"
    r"response|proxy|certificate|jwt|oauth|webhook",
    re.IGNORECASE,
)
_TARGET_FIELDS = frozenset({"target", "url", "target_url", "domain", "host", "hostname", "ip"})
_SAFE_PARAMETER_FIELDS = _TARGET_FIELDS | frozenset(
    {"depth", "limit", "timeout", "count", "offset", "method", "protocol", "mode"}
)
_FIELDS = frozenset(
    {
        "engagement_id",
        "flow_id",
        "revision",
        "version",
        "authorization_id",
        "authorization_sha256",
    }
)
_DIGEST_DOMAIN = b"ai-osop-flow-mcp-action-v1\x00"
_RECEIPT_DOMAIN = b"ai-osop-signed-mcp-status-v1\x00"


class MCPActionDenied(Exception):
    """Safe, bounded denial carrying the HTTP status for the mounted route."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _canonical(value: Any, *, limit: int) -> bytes:
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError) as exc:
        raise MCPActionDenied(422, "Canonical action metadata unavailable") from exc
    if len(raw) > limit:
        raise MCPActionDenied(422, "Action metadata exceeds durable bound")
    return raw


def _digest(domain: bytes, value: Any, limit: int) -> str:
    return hashlib.sha256(domain + _canonical(value, limit=limit)).hexdigest()


def _id(value: Any, pattern: re.Pattern[str] = _ID) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise MCPActionDenied(422, "Bounded MCP Action identity required")
    return value


def _sha(value: Any) -> str:
    return _id(value, _SHA)


def _binding(binding: Any) -> dict[str, Any]:
    if not isinstance(binding, dict) or not _FIELDS.issubset(binding):
        raise MCPActionDenied(422, "Complete signed Flow binding required")
    result = {
        "engagement_id": _id(binding.get("engagement_id")),
        "flow_id": _id(binding.get("flow_id")),
        "authorization_id": _id(binding.get("authorization_id"), _AUTH),
        "authorization_sha256": _sha(binding.get("authorization_sha256")),
        "revision": binding.get("revision"),
        "version": binding.get("version"),
    }
    if (
        type(result["revision"]) is not int
        or result["revision"] < 0
        or type(result["version"]) is not int
        or result["version"] < 1
    ):
        raise MCPActionDenied(422, "Current signed Flow revision required")
    return result


def _safe_parameters(
    parameters: Any, tool: MCPToolDefinition, *, server_id: Optional[str] = None
) -> dict[str, Any]:
    """Reject arbitrary unreviewed/secret JSON, even when a server advertises it."""
    if type(parameters) is not dict or len(parameters) > 24:
        raise MCPActionDenied(422, "Explicit bounded nonsecret tool parameters required")
    specs = tool.parameters
    if not isinstance(specs, list) or len(specs) > 32:
        raise MCPActionDenied(503, "Initialized MCP parameter declaration unavailable")
    definitions: dict[str, Any] = {}
    for spec in specs:
        if (
            type(spec.name) is not str
            or _NAME.fullmatch(spec.name) is None
            or spec.name in definitions
            or _FORBIDDEN.search(spec.name)
        ):
            raise MCPActionDenied(403, "MCP declaration is not safe for action admission")
        definitions[spec.name] = spec
    browser_navigation = server_id == "browser-mcp" and tool.name == "execute"
    original_sourcemap = (
        server_id == "source-map-mcp" and tool.name == "inspect_local_original_sourcemap"
    )
    if original_sourcemap and (
        tool.side_effect_class is not SideEffectClass.READ_ONLY
        or tool.requires_approval is not True
        or tool.scope_check is not True
        or {key: (spec.type, spec.required) for key, spec in definitions.items()}
        != {"artifact_sha256": ("string", True)}
        or set(parameters) != {"artifact_sha256"}
        or type(parameters.get("artifact_sha256")) is not str
        or _SHA.fullmatch(parameters["artifact_sha256"]) is None
    ):
        raise MCPActionDenied(403, "Only approved original SourceMap SHA admission is permitted")
    if browser_navigation and (
        tool.side_effect_class is not SideEffectClass.RECON_ACTIVE
        or tool.requires_approval is not True
        or tool.scope_check is not True
        or {key: (spec.type, spec.required) for key, spec in definitions.items()}
        != {
            "url": ("string", False),
            "action": ("string", True),
            "user_label": ("string", True),
            "evidence_mode": ("string", False),
        }
        or set(parameters)
        not in (
            {"url", "action", "user_label"},
            {"url", "action", "user_label", "evidence_mode"},
        )
        or parameters.get("action") != "navigate"
        or parameters.get("evidence_mode", "none") not in {"none", "screenshot_dom_har"}
        or type(parameters.get("url")) is not str
        or re.fullmatch(r"https?://[^?#@\s]{1,240}", parameters["url"]) is None
        or type(parameters.get("user_label")) is not str
        or _ID.fullmatch(parameters["user_label"]) is None
    ):
        raise MCPActionDenied(403, "Unreviewed browser operation is prohibited")
    if not set(parameters) <= set(definitions) or any(
        spec.required and key not in parameters for key, spec in definitions.items()
    ):
        raise MCPActionDenied(422, "Parameters differ from initialized declaration")
    checked: dict[str, Any] = {}
    for key, value in parameters.items():
        if (
            type(key) is not str
            or _NAME.fullmatch(key) is None
            or _FORBIDDEN.search(key)
            or key
            not in (
                _SAFE_PARAMETER_FIELDS | {"action", "user_label", "evidence_mode"}
                if browser_navigation
                else (
                    _SAFE_PARAMETER_FIELDS | {"artifact_sha256"}
                    if original_sourcemap
                    else _SAFE_PARAMETER_FIELDS
                )
            )
        ):
            raise MCPActionDenied(422, "Unsafe MCP parameter name")
        declared_type = definitions[key].type
        if declared_type == "string":
            valid = (
                type(value) is str
                and 0 < len(value) <= 256
                and all(32 <= ord(ch) <= 126 for ch in value)
            )
            if valid and ("?" in value or "#" in value or "@" in value):
                valid = False  # URLs with query/userinfo and obvious secret carriers
            if valid and (value.startswith("https://") or value.startswith("http://")):
                try:
                    parsed = urlsplit(value)
                    valid = (
                        parsed.hostname is not None
                        and parsed.username is None
                        and parsed.password is None
                        and not parsed.query
                        and not parsed.fragment
                    )
                except ValueError:
                    valid = False
        elif declared_type in {"integer", "int"}:
            valid = type(value) is int and -1000000 <= value <= 1000000
        elif declared_type in {"boolean", "bool"}:
            valid = type(value) is bool
        elif declared_type == "number":
            valid = type(value) in (int, float) and -1000000 <= value <= 1000000
        else:
            valid = False  # Arrays, objects and unconstrained raw bodies are unreviewable.
        if not valid or (definitions[key].enum is not None and value not in definitions[key].enum):
            raise MCPActionDenied(422, "Parameter is not bounded, nonsecret or declared")
        if (
            type(value) is str
            and key not in _TARGET_FIELDS
            and ("://" in value or re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value))
        ):
            raise MCPActionDenied(422, "Undeclared destination alias prohibited")
        checked[key] = value
    _canonical(checked, limit=4096)
    return checked


class FlowMCPActionStore:
    """PostgreSQL authority for one independent, approved Action invocation."""

    def __init__(self, memory: SessionMemory, registry: MCPRegistry) -> None:
        if type(memory) is not SessionMemory or not isinstance(registry, MCPRegistry):
            raise MCPActionDenied(503, "Production SessionMemory and MCP registry required")
        self.memory = memory
        self.registry = registry

    @staticmethod
    def declaration_sha256(definition: MCPToolDefinition, server_id: str) -> str:
        if not isinstance(definition, MCPToolDefinition):
            raise MCPActionDenied(503, "Initialized MCP declaration required")
        _id(server_id, _NAME)
        # Match the declared signed Task's public registry snapshot digest.
        # Its server identity is part of the canonical bytes, preventing a
        # same-named tool on another server from claiming an approval.
        return hashlib.sha256(
            _canonical(
                {"server_id": server_id, "declaration": definition.model_dump(mode="json")},
                limit=32768,
            )
        ).hexdigest()

    @staticmethod
    def parameters_sha256(parameters: dict[str, Any]) -> str:
        # The request builder pins this canonical SHA in the Task before the
        # independent human grant; the ledger additionally domain-separates
        # the complete signed Action intent below.
        return hashlib.sha256(_canonical(parameters, limit=4096)).hexdigest()

    def _declaration(self, server_id: str, tool_name: str) -> MCPToolDefinition:
        _id(server_id, _NAME)
        _id(tool_name, _NAME)
        servers = self.registry._servers
        if not isinstance(servers, dict) or len(servers) > 32:
            raise MCPActionDenied(503, "MCP server registry unavailable")
        connection = servers.get(server_id)
        if (
            connection is None
            or connection.server_id != server_id
            or connection._initialized is not True
            or connection.get_circuit_state() != "closed"
            or not isinstance(connection._tools, dict)
            or len(connection._tools) > 128
        ):
            raise MCPActionDenied(409, "Initialized healthy MCP declaration unavailable")
        definition = connection._tools.get(tool_name)
        if (
            not isinstance(definition, MCPToolDefinition)
            or definition.name != tool_name
            or definition.scope_check is not True
            or not isinstance(definition.side_effect_class, SideEffectClass)
            or type(definition.requires_approval) is not bool
        ):
            raise MCPActionDenied(403, "MCP declaration cannot grant execution")
        return definition

    def _sessions(self) -> Any:
        maker = getattr(self.memory, "_async_session", None)
        if not callable(maker):
            raise MCPActionDenied(503, "Durable MCP Action PostgreSQL unavailable")
        return maker

    @staticmethod
    async def _authority(
        db: Any, b: dict[str, Any], actor: str, *, dispatch: bool
    ) -> dict[str, Any]:
        _id(actor, _SUBJECT)
        if dispatch:
            current = await FlowArtifactReviewStore._fence(
                db,
                flow_id=b["flow_id"],
                revision=b["revision"],
                version=b["version"],
                authorization_id=b["authorization_id"],
                authorization_sha256=b["authorization_sha256"],
                writing=True,
                expected_engagement_id=b["engagement_id"],
            )
            if current["owner"] != actor:
                raise MCPActionDenied(403, "Signed Flow owner changed")
        session = (
            (
                await db.execute(
                    text(
                        "SELECT created_by,phase,scope FROM session_states "
                        "WHERE session_id=:eng FOR SHARE"
                    ),
                    {"eng": b["engagement_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if session is None or session["created_by"] != actor:
            raise MCPActionDenied(403, "Durable tenant owner required")
        if dispatch and session["phase"] in {"halted", "completed"}:
            raise MCPActionDenied(409, "Signed engagement is not active")
        # Historical readback/reconciliation can continue after an emergency
        # ROE revocation; only PREPARE/RESERVE/DISPATCH use the live ROE grant.
        if not dispatch:
            flow = (
                (
                    await db.execute(
                        text(
                            "SELECT revision,engagement_id FROM execution_flows "
                            "WHERE id=:flow AND engagement_id=:eng FOR SHARE"
                        ),
                        {"flow": b["flow_id"], "eng": b["engagement_id"]},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if flow is None:
                raise MCPActionDenied(404, "Action Flow is unavailable")
        return dict(session)

    @staticmethod
    async def _approved_task(
        db: Any,
        b: dict[str, Any],
        actor: str,
        task_id: str,
        subtask_id: str,
        server_id: str,
        tool_name: str,
        declaration_sha: str,
        parameters_sha: str,
        effect: str,
        scope: ScopeEnforcer,
    ) -> dict[str, Any]:
        task = (
            (
                await db.execute(
                    text(
                        "SELECT id,engagement_id,flow_id,subtask_id,assigned_agent_id,"
                        "status,started_at,completed_at,scope_check,approval_required,"
                        "type,payload FROM tasks WHERE id=:task AND engagement_id=:eng FOR UPDATE"
                    ),
                    {"task": task_id, "eng": b["engagement_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if task is None or not isinstance(task.get("payload"), dict):
            raise MCPActionDenied(403, "Durably approved execution Task required")
        p = task["payload"]
        revision = p.get(
            "planner_flow_revision", p.get("_flow_revision", p.get("mcp_flow_revision"))
        )
        action_id = p.get("mcp_action_id")
        if (
            task["flow_id"] != b["flow_id"]
            or task["subtask_id"] != subtask_id
            or task["status"] != "running"
            or not isinstance(task["assigned_agent_id"], str)
            or not task["assigned_agent_id"].strip()
            or not isinstance(task["started_at"], datetime)
            or task["completed_at"] is not None
            or task["scope_check"] is not True
            or task["approval_required"] is not True
            or type(revision) is not int
            or revision != b["revision"]
            or (
                "planner_flow_revision" in p
                and "_flow_revision" in p
                and p["planner_flow_revision"] != p["_flow_revision"]
            )
            or type(p.get("_authorization_version")) is not int
            or p["_authorization_version"] != b["version"]
            or p.get("mcp_flow_revision") != b["revision"]
            or p.get("mcp_server_id") != server_id
            or p.get("mcp_tool_name") != tool_name
            or p.get("mcp_declaration_sha256") != declaration_sha
            or p.get("mcp_parameters_sha256") != parameters_sha
            or ("mcp_side_effect_class" in p and p["mcp_side_effect_class"] != effect)
            or type(action_id) is not str
            or _ACTION.fullmatch(action_id) is None
            or p.get("operator_approved") is not True
            or not isinstance(p.get("approval_id"), str)
        ):
            raise MCPActionDenied(403, "Approved Task does not pin exact MCP Action intent")
        validate_payload_targets(scope, p, require_target=effect != SideEffectClass.READ_ONLY.value)
        step = (
            (
                await db.execute(
                    text(
                        "SELECT id,engagement_id,flow_id,execution_task_id,task_type,"
                        "approval_required,status FROM execution_subtasks WHERE id=:step "
                        "AND engagement_id=:eng AND flow_id=:flow FOR UPDATE"
                    ),
                    {"step": subtask_id, "eng": b["engagement_id"], "flow": b["flow_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            step is None
            or step["execution_task_id"] != task_id
            or step["status"] not in {"running", "dispatched"}
            or step["approval_required"] is not True
            or step["task_type"] == "operator_mcp_capability_review"
        ):
            raise MCPActionDenied(403, "Signed execution Subtask is unavailable")
        approval = (
            (
                await db.execute(
                    text(
                        "SELECT id,engagement_id,task_id,action_type,target,status,"
                        "operator_id,responded_at,evidence FROM approval_requests "
                        "WHERE id=:approval AND engagement_id=:eng AND task_id=:task FOR SHARE"
                    ),
                    {"approval": p["approval_id"], "eng": b["engagement_id"], "task": task_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            approval is None
            or approval["status"] != "approved"
            or approval["action_type"] != task["type"]
            or not isinstance(approval["operator_id"], str)
            or not approval["operator_id"]
            or approval["operator_id"] == actor
            or approval["responded_at"] is None
            or approval["target"] != str(p.get("url", p.get("target", "unknown")))
            or not matches_pinned_payload(approval["evidence"], p)
        ):
            raise MCPActionDenied(403, "Independent pinned human approval unavailable")
        reviewer = (
            (
                await db.execute(
                    text(
                        "SELECT disabled FROM operator_subject_controls "
                        "WHERE actor_id=:reviewer FOR SHARE"
                    ),
                    {"reviewer": approval["operator_id"]},
                )
            )
            .mappings()
            .one_or_none()
        )
        if reviewer is None and settings.operator_revocation_required:
            raise MCPActionDenied(403, "Current approving operator control unavailable")
        if reviewer is not None and reviewer["disabled"] is not False:
            raise MCPActionDenied(403, "Independent approving operator is disabled")
        lease = (
            (
                await db.execute(
                    text(
                        "SELECT lease_id,owner_id,state,expires_at FROM "
                        "supervision_execution_leases WHERE engagement_id=:eng "
                        "AND task_id=:task FOR UPDATE"
                    ),
                    {"eng": b["engagement_id"], "task": task_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        if (
            lease is None
            or lease["state"] != "dispatched"
            or type(lease["owner_id"]) is not str
            or _ID.fullmatch(lease["owner_id"]) is None
            or type(lease["lease_id"]) is not str
            or _LEASE.fullmatch(lease["lease_id"]) is None
            or not isinstance(lease["expires_at"], datetime)
            or lease["expires_at"] <= datetime.utcnow()
        ):
            raise MCPActionDenied(403, "Active assigned PostgreSQL execution lease required")
        return {
            "action_id": action_id,
            "approval_id": p["approval_id"],
            "lease_id": lease["lease_id"],
            "lease_owner_id": lease["owner_id"],
        }

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        """Never expose invocation parameters or the one-time dispatch token."""
        return {
            key: row[key]
            for key in (
                "action_id",
                "engagement_id",
                "flow_id",
                "task_id",
                "subtask_id",
                "server_id",
                "tool_name",
                "side_effect_class",
                "request_id",
                "status",
                "revision",
                "parameters_sha256",
                "declaration_sha256",
                "intent_sha256",
                "cancel_requested",
                "receipt_sha256",
            )
        }

    @staticmethod
    async def _row(db: Any, action_id: str, *, lock: bool) -> Optional[dict[str, Any]]:
        selected = (
            (
                await db.execute(
                    text(
                        "SELECT * FROM flow_mcp_action_dispatches WHERE action_id=:action "
                        + ("FOR UPDATE" if lock else "FOR SHARE")
                    ),
                    {"action": action_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        return dict(selected) if selected is not None else None

    @staticmethod
    async def _event(db: Any, row: Mapping[str, Any], kind: str) -> None:
        await db.execute(
            text(
                "INSERT INTO flow_mcp_action_dispatch_events "
                "(id,action_id,engagement_id,flow_id,task_id,revision,kind,status,"
                "intent_sha256,receipt_sha256) VALUES "
                "(:id,:action_id,:engagement_id,:flow_id,:task_id,:revision,:kind,:status,"
                ":intent_sha256,:receipt_sha256)"
            ),
            {
                "id": "evt-" + uuid.uuid4().hex,
                **{
                    key: row[key]
                    for key in (
                        "action_id",
                        "engagement_id",
                        "flow_id",
                        "task_id",
                        "revision",
                        "status",
                        "intent_sha256",
                        "receipt_sha256",
                    )
                },
                "kind": kind,
            },
        )

    @staticmethod
    def _same(row: Mapping[str, Any], b: Mapping[str, Any], actor: str) -> None:
        if (
            row.get("engagement_id") != b["engagement_id"]
            or row.get("flow_id") != b["flow_id"]
            or row.get("owner_id") != actor
            or row.get("flow_revision") != b["revision"]
            or row.get("authorization_version") != b["version"]
            or row.get("authorization_id") != b["authorization_id"]
            or row.get("authorization_sha256") != b["authorization_sha256"]
        ):
            raise MCPActionDenied(409, "MCP Action signed lineage changed")

    async def prepare(
        self,
        binding: dict[str, Any],
        actor_id: str,
        task_id: str,
        subtask_id: str,
        server_id: str,
        tool_name: str,
        parameters: dict[str, Any],
        parameters_sha256: str,
        manifest_sha256: str,
    ) -> dict[str, Any]:
        b = _binding(binding)
        _id(actor_id, _SUBJECT)
        _id(task_id)
        _id(subtask_id)
        _sha(parameters_sha256)
        _sha(manifest_sha256)
        definition = self._declaration(server_id, tool_name)
        safe = _safe_parameters(parameters, definition, server_id=server_id)
        declaration_sha = self.declaration_sha256(definition, server_id)
        if not hmac.compare_digest(declaration_sha, manifest_sha256) or not hmac.compare_digest(
            self.parameters_sha256(safe), parameters_sha256
        ):
            raise MCPActionDenied(409, "Initialized declaration or exact parameters changed")
        maker = self._sessions()
        try:
            async with maker() as db:
                async with db.begin():
                    session = await self._authority(db, b, actor_id, dispatch=True)
                    scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
                    scope.validate_time_window()
                    validate_payload_targets(
                        scope,
                        safe,
                        require_target=definition.side_effect_class != SideEffectClass.READ_ONLY,
                    )
                    admission = await self._approved_task(
                        db,
                        b,
                        actor_id,
                        task_id,
                        subtask_id,
                        server_id,
                        tool_name,
                        declaration_sha,
                        parameters_sha256,
                        definition.side_effect_class.value,
                        scope,
                    )
                    # Two independent persisted digests: complete human-approved
                    # Task payload and domain-separated exact tool Action intent.
                    intent = {
                        **b,
                        "task_id": task_id,
                        "subtask_id": subtask_id,
                        "action_id": admission["action_id"],
                        "owner_id": actor_id,
                        "approval_id": admission["approval_id"],
                        "lease_id": admission["lease_id"],
                        "lease_owner_id": admission["lease_owner_id"],
                        "server_id": server_id,
                        "tool_name": tool_name,
                        "side_effect_class": definition.side_effect_class.value,
                        "declaration_sha256": declaration_sha,
                        "parameters_sha256": parameters_sha256,
                    }
                    digest = _digest(_DIGEST_DOMAIN, intent, 4096)
                    request_id = "req-" + digest[:48]
                    existing = await self._row(db, admission["action_id"], lock=True)
                    if existing is None:
                        stored = {
                            "action_id": admission["action_id"],
                            "engagement_id": b["engagement_id"],
                            "flow_id": b["flow_id"],
                            "task_id": task_id,
                            "subtask_id": subtask_id,
                            "owner_id": actor_id,
                            "flow_revision": b["revision"],
                            "authorization_id": b["authorization_id"],
                            "authorization_version": b["version"],
                            "authorization_sha256": b["authorization_sha256"],
                            "approval_id": admission["approval_id"],
                            "lease_id": admission["lease_id"],
                            "lease_owner_id": admission["lease_owner_id"],
                            "server_id": server_id,
                            "tool_name": tool_name,
                            "side_effect_class": definition.side_effect_class.value,
                            "declaration_sha256": declaration_sha,
                            "parameters_sha256": parameters_sha256,
                            "intent_sha256": digest,
                            "request_id": request_id,
                            "reservation_token_sha256": "0" * 64,
                        }
                        inserted = (
                            await db.execute(
                                text(
                                    "INSERT INTO flow_mcp_action_dispatches "
                                    "(action_id,engagement_id,flow_id,task_id,subtask_id,owner_id,"
                                    "flow_revision,authorization_id,authorization_version,authorization_sha256,"
                                    "approval_id,lease_id,lease_owner_id,server_id,tool_name,side_effect_class,"
                                    "declaration_sha256,parameters_sha256,safe_parameters,intent_sha256,"
                                    "request_id,reservation_token_sha256,status,revision,cancel_requested) "
                                    "VALUES (:action_id,:engagement_id,:flow_id,:task_id,:subtask_id,"
                                    ":owner_id,:flow_revision,:authorization_id,:authorization_version,"
                                    ":authorization_sha256,:approval_id,:lease_id,:lease_owner_id,"
                                    ":server_id,:tool_name,:side_effect_class,:declaration_sha256,"
                                    ":parameters_sha256,CAST(:safe_parameters AS jsonb),:intent_sha256,"
                                    ":request_id,:reservation_token_sha256,'prepared',1,false) "
                                    "ON CONFLICT (action_id) DO NOTHING RETURNING action_id"
                                ),
                                {**stored, "safe_parameters": json.dumps(safe, sort_keys=True)},
                            )
                        ).scalar_one_or_none()
                        existing = await self._row(db, admission["action_id"], lock=True)
                        if inserted is not None:
                            if existing is None:
                                raise MCPActionDenied(503, "Prepared Action not durable")
                            await self._event(db, existing, "prepared")
                    if existing is None:
                        raise MCPActionDenied(503, "Prepared Action state unavailable")
                    self._same(existing, b, actor_id)
                    if (
                        any(
                            existing.get(k) != intent[k]
                            for k in (
                                "task_id",
                                "subtask_id",
                                "action_id",
                                "approval_id",
                                "lease_id",
                                "lease_owner_id",
                                "server_id",
                                "tool_name",
                                "side_effect_class",
                                "declaration_sha256",
                                "parameters_sha256",
                            )
                        )
                        or existing["intent_sha256"] != digest
                        or existing["request_id"] != request_id
                        or existing["safe_parameters"] != safe
                    ):
                        raise MCPActionDenied(
                            409, "Action ID already belongs to different approved intent"
                        )
                    return self._public(existing)
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise MCPActionDenied(503, "Durable MCP Action preparation unavailable") from exc

    async def _fetch(
        self, binding: dict[str, Any], actor_id: str, action_id: str, *, lock: bool
    ) -> dict[str, Any]:
        b = _binding(binding)
        _id(actor_id, _SUBJECT)
        _id(action_id, _ACTION)
        maker = self._sessions()
        async with maker() as db:
            async with db.begin():
                await self._authority(db, b, actor_id, dispatch=False)
                row = await self._row(db, action_id, lock=lock)
                if row is None:
                    raise MCPActionDenied(404, "MCP Action not found")
                self._same(row, b, actor_id)
                return row

    async def get(self, binding: dict[str, Any], actor_id: str, action_id: str) -> dict[str, Any]:
        try:
            return self._public(await self._fetch(binding, actor_id, action_id, lock=False))
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise MCPActionDenied(503, "Durable Action readback unavailable") from exc

    async def list(self, binding: dict[str, Any], actor_id: str) -> dict[str, Any]:
        b = _binding(binding)
        _id(actor_id, _SUBJECT)
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    await self._authority(db, b, actor_id, dispatch=False)
                    rows = (
                        (
                            await db.execute(
                                text(
                                    "SELECT * FROM flow_mcp_action_dispatches WHERE "
                                    "engagement_id=:eng AND flow_id=:flow AND owner_id=:owner "
                                    "AND flow_revision=:revision AND authorization_version=:version "
                                    "AND authorization_id=:auth AND authorization_sha256=:sha "
                                    "ORDER BY created_at DESC,action_id DESC LIMIT 101 FOR SHARE"
                                ),
                                {
                                    "eng": b["engagement_id"],
                                    "flow": b["flow_id"],
                                    "owner": actor_id,
                                    "revision": b["revision"],
                                    "version": b["version"],
                                    "auth": b["authorization_id"],
                                    "sha": b["authorization_sha256"],
                                },
                            )
                        )
                        .mappings()
                        .all()
                    )
                    if len(rows) > 100:
                        raise MCPActionDenied(409, "MCP Action readback is truncated")
                    return {
                        "actions": [self._public(row) for row in rows],
                        "count": len(rows),
                        "flow_id": b["flow_id"],
                    }
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise MCPActionDenied(503, "Durable Action catalog unavailable") from exc

    async def _transition(
        self,
        binding: dict[str, Any],
        actor_id: str,
        action_id: str,
        operation: str,
        *,
        request_id: Optional[str] = None,
        reservation_token: Optional[str] = None,
        outcome: Optional[str] = None,
        provider_receipt: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        b = _binding(binding)
        _id(actor_id, _SUBJECT)
        _id(action_id, _ACTION)
        if operation not in {"reserve", "dispatch", "cancel", "settle"}:
            raise MCPActionDenied(422, "Unsupported MCP Action transition")
        if operation in {"dispatch", "settle"}:
            _id(request_id)
        if operation == "dispatch":
            _id(reservation_token, re.compile(r"res-[0-9a-f]{64}\Z"))
        if operation == "settle" and outcome not in {"unknown", "finished", "cancelled"}:
            raise MCPActionDenied(422, "Bounded reconciliation outcome required")
        try:
            async with self._sessions()() as db:
                async with db.begin():
                    await self._authority(
                        db, b, actor_id, dispatch=operation in {"reserve", "dispatch"}
                    )
                    row = await self._row(db, action_id, lock=True)
                    if row is None:
                        raise MCPActionDenied(404, "MCP Action unavailable")
                    self._same(row, b, actor_id)
                    status = row["status"]
                    token: Optional[str] = None
                    if operation in {"reserve", "dispatch"}:
                        declaration = self._declaration(row["server_id"], row["tool_name"])
                        if (
                            self.declaration_sha256(declaration, row["server_id"])
                            != row["declaration_sha256"]
                        ):
                            raise MCPActionDenied(
                                409, "Current initialized MCP declaration changed"
                            )
                        checked = _safe_parameters(
                            row["safe_parameters"], declaration, server_id=row["server_id"]
                        )
                        if self.parameters_sha256(checked) != row["parameters_sha256"]:
                            raise MCPActionDenied(409, "Prepared Action parameters changed")
                        session = (
                            (
                                await db.execute(
                                    text(
                                        "SELECT scope FROM session_states "
                                        "WHERE session_id=:eng FOR SHARE"
                                    ),
                                    {"eng": b["engagement_id"]},
                                )
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if session is None:
                            raise MCPActionDenied(403, "Signed scope unavailable")
                        scope = ScopeEnforcer(ScopeDefinition.model_validate(session["scope"]))
                        scope.validate_time_window()
                        validate_payload_targets(
                            scope,
                            checked,
                            require_target=declaration.side_effect_class
                            != SideEffectClass.READ_ONLY,
                        )
                        admission = await self._approved_task(
                            db,
                            b,
                            actor_id,
                            row["task_id"],
                            row["subtask_id"],
                            row["server_id"],
                            row["tool_name"],
                            row["declaration_sha256"],
                            row["parameters_sha256"],
                            row["side_effect_class"],
                            scope,
                        )
                        if any(
                            row[field] != admission[field]
                            for field in ("action_id", "approval_id", "lease_id", "lease_owner_id")
                        ):
                            raise MCPActionDenied(409, "Current approved Action lease changed")
                    if operation == "reserve":
                        if status != "prepared":
                            return {**self._public(row), "admitted_for_dispatch": False}
                        token = "res-" + uuid.uuid4().hex + uuid.uuid4().hex
                        fields = {
                            "status": "reserved",
                            "reservation_token_sha256": hashlib.sha256(
                                token.encode("ascii")
                            ).hexdigest(),
                        }
                        kind = "reserved"
                    elif operation == "dispatch":
                        if status != "reserved":
                            raise MCPActionDenied(409, "MCP Action has no unused reservation")
                        if row["request_id"] != request_id or not hmac.compare_digest(
                            row["reservation_token_sha256"],
                            hashlib.sha256(reservation_token.encode("ascii")).hexdigest(),
                        ):
                            raise MCPActionDenied(403, "One-time Action reservation differs")
                        fields = {"status": "unknown", "reservation_token_sha256": "0" * 64}
                        kind = "dispatch_attempted"
                    elif operation == "cancel":
                        if status in {"prepared", "reserved"}:
                            fields = {"status": "cancelled", "reservation_token_sha256": "0" * 64}
                            kind = "cancelled_before_dispatch"
                        elif status == "unknown" and row["cancel_requested"] is False:
                            fields = {"cancel_requested": True}
                            kind = "cancel_requested_unknown"
                        else:
                            return self._public(row)
                    else:
                        if row["request_id"] != request_id:
                            raise MCPActionDenied(
                                409, "Reconciliation request does not match Action"
                            )
                        if status != "unknown":
                            return self._public(row)
                        if outcome == "unknown":
                            return self._public(row)
                        # A bare API status, LLM claim or remote HTTP 200 is
                        # never authoritative. Verify current independently
                        # configured provider key and exact original identity.
                        if not provider_receipt_is_signed(
                            provider_receipt,
                            row["server_id"],
                            row["request_id"],
                            row["engagement_id"],
                            row["task_id"],
                        ):
                            raise MCPActionDenied(409, "Trusted signed MCP outcome unavailable")
                        receipt_status = provider_receipt["status"]
                        verified = provider_receipt["verified"] is True
                        if outcome == "finished":
                            allowed = verified and receipt_status in {
                                "finished",
                                "completed",
                                "succeeded",
                                "failed",
                            }
                        else:
                            allowed = (
                                verified
                                and provider_receipt["stopped"] is True
                                and (
                                    receipt_status in {"cancelled", "canceled", "confirmed_stopped"}
                                )
                            )
                        if not allowed:
                            raise MCPActionDenied(409, "Signed MCP result remains UNKNOWN")
                        fields = {
                            "status": outcome,
                            "receipt_sha256": _digest(_RECEIPT_DOMAIN, provider_receipt, 4096),
                        }
                        kind = "reconciled"
                    # The signed Task lease and the Action row are held until
                    # the CAS, event append and commit. A restarted executor
                    # sees UNKNOWN and cannot obtain the consumed token.
                    previous_revision = row["revision"]
                    update_columns = ",".join(f"{k}=:{k}" for k in fields)
                    result = await db.execute(
                        text(
                            "UPDATE flow_mcp_action_dispatches SET "
                            + update_columns
                            + ",revision=revision+1,updated_at=now() WHERE action_id=:action "
                            "AND revision=:prior AND status=:previous RETURNING revision"
                        ),
                        {
                            **fields,
                            "action": action_id,
                            "prior": previous_revision,
                            "previous": status,
                        },
                    )
                    next_revision = result.scalar_one_or_none()
                    if next_revision != previous_revision + 1:
                        raise MCPActionDenied(409, "Action reservation changed concurrently")
                    row.update(fields)
                    row["revision"] = next_revision
                    await self._event(db, row, kind)
                    public = self._public(row)
                    if operation == "reserve" and token is not None:
                        return {
                            **public,
                            "admitted_for_dispatch": True,
                            "reservation_token": token,
                            "parameters": checked,
                        }
                    if operation == "dispatch":
                        return {**public, "dispatch_attempt_committed": True}
                    return public
        except MCPActionDenied:
            raise
        except Exception as exc:
            raise MCPActionDenied(503, "Durable MCP Action transition unavailable") from exc

    async def reserve(
        self, binding: dict[str, Any], actor_id: str, action_id: str
    ) -> dict[str, Any]:
        return await self._transition(binding, actor_id, action_id, "reserve")

    async def mark_dispatched(
        self,
        binding: dict[str, Any],
        actor_id: str,
        action_id: str,
        request_id: str,
        reservation_token: str,
    ) -> dict[str, Any]:
        """Commit UNKNOWN before the executor sends even one network byte."""
        return await self._transition(
            binding,
            actor_id,
            action_id,
            "dispatch",
            request_id=request_id,
            reservation_token=reservation_token,
        )

    async def settle(
        self,
        binding: dict[str, Any],
        actor_id: str,
        action_id: str,
        request_id: str,
        outcome: str,
        provider_receipt: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return await self._transition(
            binding,
            actor_id,
            action_id,
            "settle",
            request_id=request_id,
            outcome=outcome,
            provider_receipt=provider_receipt,
        )

    async def reconcile(
        self,
        binding: dict[str, Any],
        actor_id: str,
        action_id: str,
        request_id: str,
        outcome: str,
        provider_receipt: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        return await self.settle(
            binding,
            actor_id,
            action_id,
            request_id,
            outcome,
            provider_receipt,
        )

    async def cancel(
        self, binding: dict[str, Any], actor_id: str, action_id: str
    ) -> dict[str, Any]:
        return await self._transition(binding, actor_id, action_id, "cancel")


FlowMCPActionDispatch = FlowMCPActionStore
