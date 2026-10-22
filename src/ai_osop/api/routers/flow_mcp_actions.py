"""Signed Flow MCP tool-action prepare, inspection, and one-shot dispatch API.

The endpoint's explicit click is evidence of user intent only: signed Task
approval and a PostgreSQL action reservation are checked independently.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, ValidationError

from ai_osop.api.deps import state, verify_token
from ai_osop.orchestrator.flow_mcp_action_executor import (
    FlowMCPActionDenied,
    FlowMCPActionExecutor,
)
from ai_osop.orchestrator.flow_mcp_action_approval_preflight import (
    FlowMCPActionApprovalPreflight,
)

router = APIRouter(prefix="/flows", tags=["flow-mcp-actions"])


class _StrictBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    expected_engagement_id: StrictStr = Field(min_length=5, max_length=64)
    expected_revision: StrictInt = Field(ge=0)
    expected_authorization_version: StrictInt = Field(ge=1)
    explicit_human_confirmation: StrictBool


class PrepareMCPAction(_StrictBody):
    task_id: StrictStr = Field(min_length=6, max_length=96)
    subtask_id: StrictStr = Field(min_length=9, max_length=96)
    server_id: StrictStr = Field(min_length=1, max_length=80)
    tool_name: StrictStr = Field(min_length=1, max_length=80)
    parameters: Dict[str, Any]


class DispatchMCPAction(_StrictBody):
    pass


class ReconcileMCPAction(_StrictBody):
    provider_receipt: Dict[str, Any]


def _unique_json_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("Duplicate JSON field")
        value[name] = item
    return value


async def _parse(request: Request, body_type: Any) -> Any:
    if (
        request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        != "application/json"
    ):
        raise HTTPException(415, "Signed MCP action requires JSON")
    data = bytearray()
    try:
        async for fragment in request.stream():
            if len(fragment) > 8192 - len(data):
                raise HTTPException(413, "Bounded MCP action body required")
            data.extend(fragment)
        parsed = json.loads(
            data,
            object_pairs_hook=_unique_json_keys,
            parse_constant=lambda *_: (_ for _ in ()).throw(ValueError("Invalid JSON constant")),
        )
        if not isinstance(parsed, dict):
            raise ValueError("MCP action body must be an object")
        result = body_type.model_validate(parsed)
        if result.explicit_human_confirmation is not True:
            raise ValueError("Explicit operator action confirmation missing")
        return result
    except HTTPException:
        raise
    except (ValidationError, TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(422, "Invalid or ambiguous signed MCP action JSON") from exc


async def _operator(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
) -> Dict[str, Any]:
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or "token" in request.query_params
    ):
        raise HTTPException(401, "Current signed operator bearer header required")
    claims = await verify_token(credentials=credentials, token=None)
    jwt = claims.get("claims") if isinstance(claims, dict) else None
    exp = jwt.get("exp") if isinstance(jwt, dict) else None
    sub = claims.get("sub") if isinstance(claims, dict) else None
    if (
        claims.get("role") not in {"operator", "senior_operator"}
        or not isinstance(sub, str)
        or not 1 <= len(sub) <= 64
        or type(exp) is not int
        or exp <= int(datetime.now(timezone.utc).timestamp())
    ):
        raise HTTPException(403, "Current verified human operator required")
    return {
        "role": claims["role"],
        "sub": sub,
        "claims": jwt,
        "token_sha256": hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest(),
    }


def _binding(
    flow_id: str,
    expected_engagement_id: str,
    expected_revision: int,
    expected_authorization_version: int,
) -> Dict[str, Any]:
    return {
        "flow_id": flow_id,
        "engagement_id": expected_engagement_id,
        "revision": expected_revision,
        "version": expected_authorization_version,
    }


def _executor() -> FlowMCPActionExecutor:
    orchestrator = state.get("orchestrator")
    memory = getattr(orchestrator, "session_memory", None)
    registry = getattr(orchestrator, "mcp_registry", None)
    if memory is None or registry is None:
        raise HTTPException(503, "Durable signed MCP action service unavailable")
    try:
        from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore

        return FlowMCPActionExecutor(memory, registry, FlowMCPActionStore(memory, registry))
    except (ImportError, AttributeError, TypeError) as exc:
        raise HTTPException(503, "Durable MCP action reservation unavailable") from exc


def _headers(response: Response) -> None:
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, FlowMCPActionDenied):
        return HTTPException(exc.status, str(exc))
    status = getattr(exc, "status", 503)
    if type(status) is int and status in {403, 404, 409, 422, 503}:
        return HTTPException(status, "Signed MCP action state unavailable or changed")
    return HTTPException(503, "MCP action outcome UNKNOWN; read back before any further request")


_RECORD_FIELDS = frozenset(
    {
        "action_id",
        "flow_id",
        "engagement_id",
        "task_id",
        "subtask_id",
        "server_id",
        "tool_name",
        "status",
        "parameters_sha256",
        "flow_revision",
        "authorization_version",
        "declaration_sha256",
        "request_id",
        "receipt_sha256",
        "side_effect_class",
        "intent_sha256",
        "cancel_requested",
    }
)
_STATUSES = frozenset({"prepared", "reserved", "unknown", "finished", "cancelled"})


def _public_record(record: Any, binding: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(record, dict) or record.get("status") not in _STATUSES:
        raise FlowMCPActionDenied(503, "Authoritative MCP action readback unavailable")
    if (
        record.get("engagement_id") != binding["engagement_id"]
        or record.get("flow_id") != binding["flow_id"]
    ):
        raise FlowMCPActionDenied(503, "MCP action ownership readback changed")
    fields = {key: value for key, value in record.items() if key in _RECORD_FIELDS}
    if not isinstance(fields.get("action_id"), str) or not isinstance(fields.get("task_id"), str):
        raise FlowMCPActionDenied(503, "Authoritative MCP action identity unavailable")
    fields.update(
        {
            "execution_started": record["status"] in {"unknown", "finished"},
            "target_effect_verified": False,
            "safe_to_automatically_retry": False,
            "flow_revision": binding["revision"],
            "authorization_version": binding["version"],
        }
    )
    return fields


@router.get("/{flow_id}/mcp-actions")
async def list_flow_mcp_actions(
    flow_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=5, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    _headers(response)
    binding = _binding(
        flow_id, expected_engagement_id, expected_revision, expected_authorization_version
    )
    service = _executor()
    try:
        await service._authority(binding, operator)
        catalog = await service.store.list(binding, operator["sub"])
        records = catalog.get("actions") if isinstance(catalog, dict) else None
        if not isinstance(records, list) or len(records) > 100:
            raise FlowMCPActionDenied(503, "Bounded MCP action readback unavailable")
        await service._authority(binding, operator)
        return {
            "flow_id": flow_id,
            "engagement_id": expected_engagement_id,
            "flow_revision": expected_revision,
            "authorization_version": expected_authorization_version,
            "actions": [_public_record(row, binding) for row in records],
        }
    except Exception as exc:
        raise _error(exc) from exc


@router.get("/{flow_id}/mcp-actions/{action_id}")
async def get_flow_mcp_action(
    flow_id: str,
    action_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=5, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    _headers(response)
    binding = _binding(
        flow_id, expected_engagement_id, expected_revision, expected_authorization_version
    )
    service = _executor()
    try:
        await service._authority(binding, operator)
        record = await service.store.get(binding, operator["sub"], action_id)
        await service._authority(binding, operator)
        if record.get("action_id") != action_id:
            raise FlowMCPActionDenied(503, "MCP action identity changed")
        return _public_record(record, binding)
    except Exception as exc:
        raise _error(exc) from exc


@router.post("/{flow_id}/mcp-actions", status_code=201)
async def prepare_flow_mcp_action(
    flow_id: str,
    request: Request,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    _headers(response)
    body = await _parse(request, PrepareMCPAction)
    binding = _binding(
        flow_id,
        body.expected_engagement_id,
        body.expected_revision,
        body.expected_authorization_version,
    )
    try:
        record = await _executor().prepare(
            binding,
            operator,
            task_id=body.task_id,
            subtask_id=body.subtask_id,
            server_id=body.server_id,
            tool_name=body.tool_name,
            parameters=body.parameters,
        )
        return _public_record(record, binding)
    except Exception as exc:
        raise _error(exc) from exc


@router.post("/{flow_id}/mcp-actions/{action_id}/dispatch")
async def dispatch_flow_mcp_action(
    flow_id: str,
    action_id: str,
    request: Request,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    _headers(response)
    body = await _parse(request, DispatchMCPAction)
    binding = _binding(
        flow_id,
        body.expected_engagement_id,
        body.expected_revision,
        body.expected_authorization_version,
    )
    try:
        record = await _executor().dispatch(binding, operator, action_id)
        return _public_record(record, binding)
    except Exception as exc:
        raise _error(exc) from exc


@router.post("/{flow_id}/mcp-actions/{action_id}/reconcile")
async def reconcile_flow_mcp_action(
    flow_id: str,
    action_id: str,
    request: Request,
    response: Response,
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Submit separately signed provider status, never repeat the MCP action."""
    _headers(response)
    body = await _parse(request, ReconcileMCPAction)
    binding = _binding(
        flow_id,
        body.expected_engagement_id,
        body.expected_revision,
        body.expected_authorization_version,
    )
    try:
        record = await _executor().reconcile(
            binding,
            operator,
            action_id,
            body.provider_receipt,
        )
        return _public_record(record, binding)
    except Exception as exc:
        raise _error(exc) from exc


@router.get("/{flow_id}/mcp-actions/{action_id}/preflight")
async def preflight_flow_mcp_action(
    flow_id: str,
    action_id: str,
    response: Response,
    expected_engagement_id: str = Query(min_length=5, max_length=64),
    expected_revision: int = Query(ge=0),
    expected_authorization_version: int = Query(ge=1),
    task_id: str = Query(min_length=6, max_length=96),
    subtask_id: str = Query(min_length=9, max_length=96),
    server_id: str = Query(min_length=1, max_length=80),
    tool_name: str = Query(min_length=1, max_length=80),
    expected_parameters_sha256: str | None = Query(default=None, min_length=64, max_length=64),
    expected_manifest_sha256: str | None = Query(default=None, min_length=64, max_length=64),
    operator: Dict[str, Any] = Depends(_operator),
) -> Dict[str, Any]:
    """Current, non-reserving eligibility only; later dispatch rechecks everything."""
    _headers(response)
    binding = _binding(
        flow_id,
        expected_engagement_id,
        expected_revision,
        expected_authorization_version,
    )
    service = _executor()
    result = await FlowMCPActionApprovalPreflight(service, service.store).check(
        binding,
        operator,
        action_id=action_id,
        task_id=task_id,
        subtask_id=subtask_id,
        server_id=server_id,
        tool_name=tool_name,
        expected_parameters_sha256=expected_parameters_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    if result.get("allowed") is True:
        # A successful preflight still cannot survive an intervening signed
        # ROE/Flow revocation merely because an earlier DB snapshot passed.
        try:
            await service._authority(binding, operator)
        except Exception as exc:
            raise HTTPException(409, "MCP Action authority changed after preflight") from exc
    return result
