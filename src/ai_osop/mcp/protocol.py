"""
MCP Protocol Implementation
Standardized Model Context Protocol for tool integration.
Implements the core MCP spec with async support and structured I/O.
"""

import asyncio
import copy
import json
import math
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional
from unittest.mock import Mock

import aiohttp
import websockets
from pydantic import BaseModel, Field, PrivateAttr

from ai_osop.core.call_provenance import (
    BestEffortProvenance,
    ProvenanceCallback,
    action_provenance,
    safe_label,
)
from ai_osop.core.exceptions import MCPConnectionError, MCPException, MCPTimeoutError
from ai_osop.core.telemetry import RequestContext
from ai_osop.core.tracing import trace_span
from ai_osop.mcp.tool_budget import (
    BudgetCallback,
    check_cancellation_authorization,
    check_persisted_reconciliation_authorization,
    check_tool_authorization,
    check_tool_budget,
)
from ai_osop.mcp.receipt_attestation import provider_receipt_is_signed


# Called synchronously with dispatch and outcome transitions. Integrators
# should persist each event durably and deduplicate by request_id + kind.
ExecutionEventCallback = Callable[[str, str, str, Dict[str, Any]], Awaitable[Any]]
_EVENT_TIMEOUT_SECONDS = 2.0
_REMOTE_CANCEL_TIMEOUT_SECONDS = 4.0
# The tool endpoint is not a bulk artifact transport. Bound *decoded* response
# bytes before JSON parsing/validation or retaining original forensic bytes.
_MAX_EXECUTE_RESPONSE_BYTES = 2 * 1024 * 1024
_EXECUTE_RESPONSE_READ_CHUNK = 64 * 1024
_MAX_EXECUTE_JSON_DEPTH = 24
_MAX_EXECUTE_JSON_ITEMS = 4096
_MAX_EXECUTE_JSON_NODES = 65536


def _unique_execute_json_pairs(pairs: List[tuple[str, Any]]) -> Dict[str, Any]:
    """Reject ambiguous member names at every depth in provider JSON."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("MCP provider response contains duplicate JSON keys")
        result[key] = value
    return result


def _deny_execute_json_constant(value: str) -> Any:
    """Strict JSON disallows Python's NaN and Infinity extensions."""
    raise ValueError("MCP provider response contains non-finite JSON numbers")


def _validate_execute_json_shape(data: Any) -> None:
    """Reject deep/oversized JSON trees before Pydantic and recursive cleanup."""
    pending = [(data, 0)]
    nodes = 0
    seen = set()
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_EXECUTE_JSON_NODES or depth > _MAX_EXECUTE_JSON_DEPTH:
            raise ValueError("MCP provider response structure exceeds limits")
        if isinstance(node, dict):
            if id(node) in seen or len(node) > _MAX_EXECUTE_JSON_ITEMS:
                raise ValueError("MCP provider response collection exceeds limits")
            seen.add(id(node))
            if any(type(key) is not str for key in node):
                raise ValueError("MCP provider response has an invalid key")
            pending.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            if id(node) in seen or len(node) > _MAX_EXECUTE_JSON_ITEMS:
                raise ValueError("MCP provider response collection exceeds limits")
            seen.add(id(node))
            pending.extend((value, depth + 1) for value in node)
        elif node is not None and type(node) not in {str, bool, int, float}:
            raise ValueError("MCP provider response contains a non-JSON value")
        elif type(node) is float and not math.isfinite(node):
            # A syntactically valid exponent (1e9999) also overflows to Inf
            # under Python's default float parser; it must not reach consumers.
            raise ValueError("MCP provider response contains non-finite JSON numbers")


def _validate_fake_execute_json_size(data: Dict[str, Any]) -> None:
    """Bound the JSON-only test transport without assembling another full body."""
    encoded_length = 0
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False)
    for part in encoder.iterencode(data):
        # Skip UTF-8 encoding of oversized synthetic values entirely.
        encoded_length += len(part)
        if encoded_length > _MAX_EXECUTE_RESPONSE_BYTES:
            raise ValueError("MCP provider test response exceeds limits")


async def _bounded_execute_response_json(resp: Any) -> tuple[Dict[str, Any], Optional[bytes]]:
    """Read aiohttp streams incrementally; retain exact accepted HTTP bytes.

    Some in-process legacy test doubles expose only json(). Their decoded
    structure and reserialized size are checked before it can be copied or
    projected. Production ClientResponse always has a bounded content reader.
    """
    # A JSON-only in-process unittest transport has dynamically generated
    # attributes; those are not HTTP headers or streaming body readers.
    media_type = None if isinstance(resp, Mock) else getattr(resp, "content_type", None)
    if media_type is not None and (
        type(media_type) is not str
        or (media_type != "application/json" and not media_type.endswith("+json"))
    ):
        raise ValueError("MCP provider response has unsupported media type")
    content = getattr(resp, "content", None)
    if (
        content is not None
        and not isinstance(content, Mock)
        and callable(getattr(content, "read", None))
    ):
        content_length = getattr(resp, "content_length", None)
        if type(content_length) is int and content_length > _MAX_EXECUTE_RESPONSE_BYTES:
            raise ValueError("MCP provider response declared an oversized entity")
        body = bytearray()
        while True:
            part = await content.read(
                min(_EXECUTE_RESPONSE_READ_CHUNK, _MAX_EXECUTE_RESPONSE_BYTES + 1 - len(body))
            )
            if not isinstance(part, bytes) or len(part) > _EXECUTE_RESPONSE_READ_CHUNK:
                raise ValueError("MCP provider response returned invalid entity bytes")
            if not part:
                break
            body.extend(part)
            if len(body) > _MAX_EXECUTE_RESPONSE_BYTES:
                raise ValueError("MCP provider response entity exceeds limits")
        raw_body = bytes(body)
        data = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=_unique_execute_json_pairs,
            parse_constant=_deny_execute_json_constant,
        )
    else:
        # Compatibility for existing JSON-only in-process fake transports; no
        # unbounded network read() is permitted in the production path.
        data = await resp.json()
        raw_body = None
    if type(data) is not dict:
        raise ValueError("MCP provider returned a non-object envelope")
    _validate_execute_json_shape(data)
    if raw_body is None:
        _validate_fake_execute_json_size(data)
    return data, raw_body


# A provider HTTP 200 is data, never independent owner-of-record testimony.
# These reserved authority/release flags may only originate in separately
# governed and signed operator/reconciliation records, not a tool JSON body.
_UNTRUSTED_PROVIDER_AUTHORITY_FLAGS = frozenset(
    {
        # Unqualified generic affirmative labels are equally dangerous when
        # surfaced by UI/report collectors as an independent verdict. Keep
        # explicit False where useful, but never expose provider True as a
        # verified/certified/released authority field.
        "verified",
        "certified",
        "independently_verified",
        "owner_verified",
        "evidence_verified",
        "release_approved",
        "target_effect_verified",
        "independent_target_effect_verified",
        "owner_of_record_verified",
        "provider_side_signed_admission_verified",
        "provider_receipt_verified",
        "execution_authorized",
        "production_certified",
        "safe_to_automatically_retry",
        "reconciliation_result",
        "signed_provider_receipt",
        "provider_provenance",
    }
)


def _strip_untrusted_provider_authority_flags(value: Dict[str, Any]) -> Dict[str, Any]:
    """Remove reserved authority claims even when buried in provider tool data.

    Even a cryptographically valid provider receipt is *provider testimony*;
    it never upgrades arbitrary provider-authored fields into target effects.
    The original untrusted body is retained privately on the execution response;
    durable forensic retention belongs in a separately governed evidence store.
    """

    # Several consumers require an explicit negative assertion. Positive,
    # non-boolean and unknown values can never be independently verified by
    # the provider's own response, including inside findings/details arrays.
    def clean(node: Any) -> Any:
        if isinstance(node, dict):
            return {
                key: clean(item)
                for key, item in node.items()
                if key
                not in {"signed_provider_receipt", "reconciliation_result", "provider_provenance"}
                and (key not in _UNTRUSTED_PROVIDER_AUTHORITY_FLAGS or item is False)
            }
        if isinstance(node, list):
            return [clean(item) for item in node]
        return node

    return clean(value)


@dataclass
class _RemoteExecution:
    engagement_id: str
    task_id: str
    tool_name: str
    parameters: Dict[str, Any]
    requires_approval: bool = False
    active: bool = True
    outcome: str = "unknown"


def _cancel_receipt(status: str, server_id: str, request_id: str, **details: Any) -> Dict[str, Any]:
    """Safe receipt; status is verified independently of HTTP success."""
    return {"status": status, "server_id": server_id, "request_id": request_id, **details}


def _provider_receipt_record(
    data: Any,
    request_id: str,
    engagement_id: str,
    task_id: str,
    server_id: str = "",
    *,
    require_bound_identity: bool = False,
) -> Optional[Dict[str, Any]]:
    """Reject mismatched identities and failed tool envelopes before proof.

    Production signed dispatches require the provider to echo the complete
    original execution tuple, not merely a client-chosen request ID. A
    provider that cannot supply this attestation leaves the outcome UNKNOWN.
    """
    if not isinstance(data, dict):
        return None
    result = data.get("result")
    if isinstance(result, dict):
        # A tool invocation may use a separate envelope request ID. Its
        # status must nevertheless report successful processing before its
        # nested status is usable as remote-execution evidence.
        if data.get("status") != "success" or data.get("isError") is True or data.get("error"):
            return None
        record = result
    else:
        record = data
    if record.get("request_id") != request_id:
        return None
    if require_bound_identity:
        if not all(
            isinstance(expected, str) and expected and record.get(identity) == expected
            for identity, expected in (
                ("engagement_id", engagement_id),
                ("task_id", task_id),
                ("server_id", server_id),
            )
        ):
            return None
    for identity, expected in (
        ("engagement_id", engagement_id),
        ("task_id", task_id),
        ("server_id", server_id),
    ):
        if (identity in data and data[identity] != expected) or (
            identity in record and record[identity] != expected
        ):
            return None
    return record


def _verified_remote_cancel(
    data: Any,
    request_id: str,
    engagement_id: str = "",
    task_id: str = "",
    server_id: str = "",
    *,
    require_bound_identity: bool = False,
    require_signature: bool = False,
) -> str:
    """An accepted command alone never verifies termination on the provider."""
    explicit = _provider_receipt_record(
        data,
        request_id,
        engagement_id,
        task_id,
        server_id,
        require_bound_identity=require_bound_identity,
    )
    if explicit is None:
        return "unknown"
    if require_signature and not provider_receipt_is_signed(
        explicit,
        server_id,
        request_id,
        engagement_id,
        task_id,
    ):
        return "unknown"
    if (
        type(explicit.get("status")) is str
        and explicit["status"] in {"confirmed_stopped", "cancelled", "canceled"}
        and (explicit.get("verified") is True and explicit.get("stopped") is True)
    ):
        return "confirmed_stopped"
    return "unknown"


def _verified_remote_status(
    data: Any,
    request_id: str,
    engagement_id: str = "",
    task_id: str = "",
    server_id: str = "",
    *,
    require_bound_identity: bool = False,
    require_signature: bool = False,
) -> str:
    """Only an explicit matching, verified provider status is authoritative."""
    record = _provider_receipt_record(
        data,
        request_id,
        engagement_id,
        task_id,
        server_id,
        require_bound_identity=require_bound_identity,
    )
    if record is None or record.get("verified") is not True:
        return "unknown"
    if require_signature and not provider_receipt_is_signed(
        record,
        server_id,
        request_id,
        engagement_id,
        task_id,
    ):
        return "unknown"
    status = record.get("status")
    if not isinstance(status, str):
        return "unknown"
    if status in {"cancelled", "canceled", "confirmed_stopped"}:
        return "confirmed_stopped" if record.get("stopped") is True else "unknown"
    if status in {"finished", "completed", "succeeded", "failed"}:
        return "confirmed_finished"
    if status in {"running", "pending"}:
        return "running"
    return "unknown"


class SideEffectClass(str, Enum):
    READ_ONLY = "READ_ONLY"
    RECON_ACTIVE = "RECON_ACTIVE"
    INVASIVE_EXPLOIT = "INVASIVE_EXPLOIT"


class MCPAdapterManifest(BaseModel):
    tool_name: str
    version: str = "1.0.0"
    side_effect_class: SideEffectClass = SideEffectClass.READ_ONLY
    timeout_seconds: int = 30
    required_permissions: List[str] = Field(default_factory=list)
    description: str = ""


class MCPToolParameter(BaseModel):
    name: str
    type: str
    description: str
    required: bool = True
    default: Optional[Any] = None
    enum: Optional[List[Any]] = None


class MCPToolDefinition(BaseModel):
    name: str
    description: str
    parameters: List[MCPToolParameter]
    returns: Dict[str, Any]
    timeout_seconds: int = 30
    requires_approval: bool = False
    scope_check: bool = True
    side_effect_class: SideEffectClass = SideEffectClass.READ_ONLY
    version: str = "1.0.0"
    required_permissions: List[str] = Field(default_factory=list)


class MCPInitializeRequest(BaseModel):
    scope: Dict[str, Any]
    auth_credentials: Dict[str, Any] = Field(default_factory=dict)
    session_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MCPInitializeResponse(BaseModel):
    server_id: str
    # PATCH (REL-002, 2026-06-15): Defaulting `version` so that a partial MCP
    # response missing this field still parses. Real-time verification on
    # 2026-06-15 showed all current servers (recon/payload/shodan/threat-intel/
    # burp/browser/etc.) DO return a version, so this is defense-in-depth only.
    # The actual reason those four MCPs appear "uninitialized" in
    # /system/health/full is that no agent has invoked them yet — initialize
    # is called lazily by each adapter's .initialize() the first time it runs.
    version: str = "unknown"
    capabilities: List[str]
    tools: List[MCPToolDefinition]
    status: str = "ready"


class MCPExecuteRequest(BaseModel):
    tool_name: str
    parameters: Dict[str, Any]
    request_id: str = Field(default_factory=lambda: f"req-{uuid.uuid4().hex}")
    timeout_override: Optional[int] = None


class MCPProviderProvenance(BaseModel):
    """An HTTP result can report work, never certify a target-owned effect."""

    status_source: Literal["untrusted_provider"] = "untrusted_provider"
    target_effect_verified: Literal[False] = False
    verification_basis: Literal["no_independent_target_owner_evidence"] = (
        "no_independent_target_owner_evidence"
    )


class MCPExecuteResponse(BaseModel):
    request_id: str
    status: str  # success, error, timeout, cancelled
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time_ms: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    provider_provenance: Optional[MCPProviderProvenance] = None
    # Never serialize the full untrusted response (which can contain secrets or
    # deliberate authority-forgery attempts) into ordinary agent/UI readbacks.
    _untrusted_provider_body_bytes: Optional[bytes] = PrivateAttr(default=None)
    _untrusted_provider_payload: Optional[Dict[str, Any]] = PrivateAttr(default=None)


class MCPStateResponse(BaseModel):
    server_id: str
    status: str
    active_requests: int
    queued_requests: int
    uptime_seconds: int
    memory_usage_mb: float
    last_health_check: datetime


@dataclass
class MCPConnection:
    """Managed connection to an MCP server with circuit breaker v2 (half-open support)."""

    server_id: str
    host: str
    port: int
    auth_token: Optional[str] = None
    _session: Optional[aiohttp.ClientSession] = None
    _ws: Optional[websockets.WebSocketClientProtocol] = None
    _initialized: bool = False
    _capabilities: List[str] = field(default_factory=list)
    _tools: Dict[str, MCPToolDefinition] = field(default_factory=dict)
    # Circuit breaker state v2 (Sprint 7)
    _failure_count: int = field(default=0)
    _success_count: int = field(default=0)
    _circuit_open: bool = field(default=False)
    _circuit_opened_at: Optional[datetime] = field(default=None)
    _half_open: bool = field(default=False)
    _recovery_attempts: int = field(default=0)
    _last_success_at: Optional[datetime] = field(default=None)
    _last_failure_at: Optional[datetime] = field(default=None)
    _consecutive_successes: int = field(default=0)
    _provenance_recorder: BestEffortProvenance = field(
        default_factory=BestEffortProvenance, repr=False
    )
    _budget_callback: Optional[BudgetCallback] = field(default=None, repr=False)
    _execution_event_callback: Optional[ExecutionEventCallback] = field(default=None, repr=False)
    _executions: Dict[str, _RemoteExecution] = field(default_factory=dict, repr=False)
    _seen_request_ids: Dict[str, bool] = field(default_factory=dict, repr=False)
    _cancel_receipts: Dict[str, Dict[str, Any]] = field(default_factory=dict, repr=False)
    _signed_stop_receipts: Dict[str, Dict[str, Any]] = field(default_factory=dict, repr=False)
    _cancel_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    CIRCUIT_THRESHOLD: int = field(default=5)
    CIRCUIT_RECOVERY_SECONDS: int = field(default=30)
    CIRCUIT_HALF_OPEN_MAX_ATTEMPTS: int = field(default=3)
    CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED: int = field(default=2)

    def set_provenance_callback(self, callback: Optional[ProvenanceCallback]) -> None:
        """Bind an async, engagement-scoped action persistence callback."""
        self._provenance_recorder.set_callback(callback)

    def set_budget_callback(self, callback: Optional[BudgetCallback]) -> None:
        """Bind an optional atomic ROE quota callback, independent of provenance."""
        self._budget_callback = callback

    def set_execution_event_callback(self, callback: Optional[ExecutionEventCallback]) -> None:
        """Attach an async durable supervision event writer."""
        self._execution_event_callback = callback

    def _requires_bound_provider_receipt(self) -> bool:
        """Production verification must bind every remote result to signed ownership."""
        from ai_osop.memory.session_memory import SessionMemory

        return isinstance(getattr(self._budget_callback, "__self__", None), SessionMemory)

    def _requires_signed_provider_receipt(self) -> bool:
        """Production cannot promote a provider's self-asserted verified flag."""
        from ai_osop.core.config import settings

        return self._requires_bound_provider_receipt() and settings.environment.strip().lower() in {
            "production",
            "prod",
        }

    def _provider_control_parameters(
        self,
        request_id: str,
        engagement_id: str,
        task_id: str,
    ) -> Dict[str, str]:
        """Send extra context only to providers advertising the v1 bound extension.

        Older status/cancel tools often reject undeclared parameters. They
        remain callable for best-effort stopping, but their unbound responses
        cannot certify a production stop/completion.
        """
        result = {"request_id": request_id}
        if "mcp_bound_receipts_v1" in self._capabilities:
            result.update(
                {
                    "engagement_id": engagement_id,
                    "task_id": task_id,
                    "server_id": self.server_id,
                }
            )
        return result

    def _provider_execution_payload(
        self,
        request: MCPExecuteRequest,
        engagement_id: str,
        task_id: str,
    ) -> Dict[str, Any]:
        """Tell a capable provider the binding at dispatch, not only at lookup.

        A provider claiming bound receipts must retain this initial identity
        and later report its own stored tuple. An echo of status-query input
        alone is not independent evidence of which execution occurred.
        """
        payload = request.model_dump()
        if "mcp_bound_receipts_v1" in self._capabilities:
            payload["execution_binding"] = self._provider_control_parameters(
                request.request_id,
                engagement_id,
                task_id,
            )
        return payload

    async def _emit_execution_event(
        self,
        engagement_id: str,
        task_id: str,
        kind: str,
        metadata: Dict[str, Any],
    ) -> bool:
        if self._execution_event_callback is None or not engagement_id or not task_id:
            return self._execution_event_callback is None
        try:
            result = await asyncio.wait_for(
                self._execution_event_callback(engagement_id, task_id, kind, metadata),
                timeout=_EVENT_TIMEOUT_SECONDS,
            )
            return result is not False
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def request_cancellation(
        self,
        request_id: str,
        engagement_id: str,
        task_id: str,
    ) -> Dict[str, Any]:
        """Stop an attributable request only if the remote advertises support.

        A timeout/transport error can mean the provider acted without replying.
        Requests are idempotent per connection and remote execution identifier.
        """
        async with self._cancel_lock:
            if not all(
                isinstance(value, str) and 0 < len(value) <= 128
                for value in (
                    request_id,
                    engagement_id,
                    task_id,
                )
            ):
                return _cancel_receipt("denied", self.server_id, str(request_id or ""))
            execution = self._executions.get(request_id)
            if (
                execution is None
                or execution.engagement_id != engagement_id
                or execution.task_id != task_id
            ):
                return _cancel_receipt(
                    "denied" if request_id in self._cancel_receipts else "unknown",
                    self.server_id,
                    request_id,
                )
            # A cached provider receipt is evidence from an earlier policy
            # revision, not a grant to read it after revocation. Reauthorize
            # before returning cached results or issuing a provider command.
            denial = await check_cancellation_authorization(
                self._budget_callback,
                self.server_id,
                execution.tool_name,
                execution.parameters,
                engagement_id,
                task_id,
                requires_approval=execution.requires_approval,
            )
            if denial is not None:
                return _cancel_receipt("denied", self.server_id, request_id, reason=denial)
            from ai_osop.memory.session_memory import SessionMemory

            if (
                isinstance(getattr(self._budget_callback, "__self__", None), SessionMemory)
                and self._execution_event_callback is None
            ):
                return _cancel_receipt(
                    "unknown", self.server_id, request_id, reason="durable_writer_unavailable"
                )
            previous = self._cancel_receipts.get(request_id)
            if previous is not None:
                if (
                    previous.get("status") == "confirmed_stopped"
                    and self._requires_signed_provider_receipt()
                    and not provider_receipt_is_signed(
                        self._signed_stop_receipts.get(request_id),
                        self.server_id,
                        request_id,
                        engagement_id,
                        task_id,
                    )
                ):
                    # A removed signer or stale cached receipt is no longer
                    # current attestation, even if the local action was once
                    # reported stopped. No repeated cancellation side effect.
                    return _cancel_receipt(
                        "unknown",
                        self.server_id,
                        request_id,
                        reason="provider_receipt_no_longer_trusted",
                    )
                return dict(previous)

            if execution.outcome == "confirmed_finished":
                receipt = _cancel_receipt(
                    "unknown", self.server_id, request_id, reason="execution_already_finished"
                )
                self._cancel_receipts[request_id] = receipt
                return dict(receipt)

            has_endpoint = "mcp_cancel_request_v1" in self._capabilities
            has_tool = "cancel_request" in self._tools
            if not (has_endpoint or has_tool):
                receipt = _cancel_receipt("not_supported", self.server_id, request_id)
                self._cancel_receipts[request_id] = receipt
                return dict(receipt)
            metadata = {
                "server_id": self.server_id,
                "request_id": request_id,
                "tool_name": execution.tool_name,
            }
            if not await self._emit_execution_event(
                engagement_id, task_id, "cancellation_requested", metadata
            ):
                return _cancel_receipt(
                    "unknown", self.server_id, request_id, reason="audit_unavailable"
                )
            signed_stop = None
            try:
                if not self._session:
                    raise RuntimeError("MCP session unavailable")
                if has_endpoint:
                    url = f"http://{self.host}:{self.port}/mcp/cancel"
                    payload = self._provider_control_parameters(
                        request_id,
                        engagement_id,
                        task_id,
                    )
                else:
                    url = f"http://{self.host}:{self.port}/mcp/execute"
                    payload = MCPExecuteRequest(
                        tool_name="cancel_request",
                        parameters=self._provider_control_parameters(
                            request_id,
                            engagement_id,
                            task_id,
                        ),
                    ).model_dump()
                async with self._session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=_REMOTE_CANCEL_TIMEOUT_SECONDS),
                    allow_redirects=False,
                ) as response:
                    # A transport success only means the request reached the
                    # server. Verification requires explicit completion proof.
                    data = (
                        (await _bounded_execute_response_json(response))[0]
                        if response.status == 200
                        else None
                    )
                    status = _verified_remote_cancel(
                        data,
                        request_id,
                        engagement_id,
                        task_id,
                        self.server_id,
                        require_bound_identity=self._requires_bound_provider_receipt(),
                        require_signature=self._requires_signed_provider_receipt(),
                    )
                    signed_stop = (
                        _provider_receipt_record(
                            data,
                            request_id,
                            engagement_id,
                            task_id,
                            self.server_id,
                            require_bound_identity=True,
                        )
                        if status == "confirmed_stopped"
                        and self._requires_signed_provider_receipt()
                        else None
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                status = "unknown"
            recorded = await self._emit_execution_event(
                engagement_id,
                task_id,
                "cancellation_result",
                {
                    **metadata,
                    "status": status,
                    "attested_receipt": signed_stop if status == "confirmed_stopped" else None,
                },
            )
            if not recorded:
                # The provider may have stopped, but the durable cancellation
                # receipt was never committed. A replacement worker cannot
                # safely infer remote termination from an absent receipt.
                status = "unknown"
            receipt = _cancel_receipt(status, self.server_id, request_id)
            self._cancel_receipts[request_id] = receipt
            if status == "confirmed_stopped":
                execution.outcome = "confirmed_stopped"
                execution.active = False
                if signed_stop is not None:
                    self._signed_stop_receipts[request_id] = signed_stop
            if len(self._cancel_receipts) > 512:
                evicted = next(iter(self._cancel_receipts))
                self._cancel_receipts.pop(evicted)
                self._signed_stop_receipts.pop(evicted, None)
            return dict(receipt)

    async def reconcile_execution(
        self,
        request_id: str,
        engagement_id: str,
        task_id: str,
    ) -> Dict[str, Any]:
        """Query explicit remote execution-state capability using original ID.

        A local HTTP timeout or task cancellation says nothing about provider
        completion. With no advertised status capability, return not_supported.
        """
        async with self._cancel_lock:
            if not all(
                isinstance(value, str) and 0 < len(value) <= 128
                for value in (
                    request_id,
                    engagement_id,
                    task_id,
                )
            ):
                return _cancel_receipt("denied", self.server_id, str(request_id or ""))
            execution = self._executions.get(request_id)
            if (
                execution is None
                or execution.engagement_id != engagement_id
                or execution.task_id != task_id
            ):
                return _cancel_receipt("unknown", self.server_id, request_id)

            denial = await check_cancellation_authorization(
                self._budget_callback,
                self.server_id,
                execution.tool_name,
                execution.parameters,
                engagement_id,
                task_id,
                requires_approval=execution.requires_approval,
            )
            if denial is not None:
                return _cancel_receipt("denied", self.server_id, request_id, reason=denial)

            from ai_osop.memory.session_memory import SessionMemory

            if (
                isinstance(getattr(self._budget_callback, "__self__", None), SessionMemory)
                and self._execution_event_callback is None
            ):
                return _cancel_receipt(
                    "unknown", self.server_id, request_id, reason="durable_writer_unavailable"
                )

            endpoint = "mcp_request_status_v1" in self._capabilities
            tool = "get_request_status" in self._tools
            if not (endpoint or tool):
                return _cancel_receipt("not_supported", self.server_id, request_id)

            metadata = {
                "server_id": self.server_id,
                "request_id": request_id,
                "tool_name": execution.tool_name,
            }
            if not await self._emit_execution_event(
                engagement_id,
                task_id,
                "reconciliation_requested",
                metadata,
            ):
                return _cancel_receipt(
                    "unknown", self.server_id, request_id, reason="audit_unavailable"
                )
            signed_status = None
            try:
                if self._session is None:
                    raise RuntimeError("MCP session unavailable")
                if endpoint:
                    url = f"http://{self.host}:{self.port}/mcp/request/status"
                    payload = self._provider_control_parameters(
                        request_id,
                        engagement_id,
                        task_id,
                    )
                else:
                    url = f"http://{self.host}:{self.port}/mcp/execute"
                    payload = MCPExecuteRequest(
                        tool_name="get_request_status",
                        parameters=self._provider_control_parameters(
                            request_id,
                            engagement_id,
                            task_id,
                        ),
                    ).model_dump()
                async with self._session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=_REMOTE_CANCEL_TIMEOUT_SECONDS),
                    allow_redirects=False,
                ) as response:
                    data = (
                        (await _bounded_execute_response_json(response))[0]
                        if response.status == 200
                        else None
                    )
                    status = _verified_remote_status(
                        data,
                        request_id,
                        engagement_id,
                        task_id,
                        self.server_id,
                        require_bound_identity=self._requires_bound_provider_receipt(),
                        require_signature=self._requires_signed_provider_receipt(),
                    )
                    if (
                        status in {"confirmed_stopped", "confirmed_finished"}
                        and self._requires_signed_provider_receipt()
                    ):
                        signed_status = _provider_receipt_record(
                            data,
                            request_id,
                            engagement_id,
                            task_id,
                            self.server_id,
                            require_bound_identity=True,
                        )
            except asyncio.CancelledError:
                raise
            except Exception:
                status = "unknown"

            recorded = await self._emit_execution_event(
                engagement_id,
                task_id,
                "reconciliation_result",
                {**metadata, "status": status, "attested_receipt": signed_status},
            )
            if not recorded:
                # Do not promote a volatile receipt that was rejected by the
                # authoritative event writer. The provider's state may have
                # changed, but durable confirmation is still unknown.
                return _cancel_receipt(
                    "unknown", self.server_id, request_id, reason="audit_unavailable"
                )
            if status in {"confirmed_stopped", "confirmed_finished"}:
                execution.active = False
                execution.outcome = status
                if status == "confirmed_stopped":
                    self._cancel_receipts[request_id] = _cancel_receipt(
                        status,
                        self.server_id,
                        request_id,
                    )
            return _cancel_receipt(status, self.server_id, request_id)

    async def reconcile_persisted_status(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Read-only provider status after a worker restart, never replay tool.

        Caller must obtain claim from authoritative PostgreSQL for the exact
        engagement/task/server/request. No target parameters are resurrected
        and no attempt is made to cancel or execute the original tool.
        """
        if not isinstance(claim, dict):
            return _cancel_receipt("denied", self.server_id, "")
        request_id = claim.get("request_id")
        engagement_id = claim.get("engagement_id")
        task_id = claim.get("task_id")
        if (
            not isinstance(request_id, str)
            or not request_id
            or len(request_id) > 128
            or not isinstance(engagement_id, str)
            or not engagement_id
            or not isinstance(task_id, str)
            or not task_id
            or claim.get("server_id") != self.server_id
            or type(claim.get("authorization_version")) is not int
            or claim["authorization_version"] <= 0
            or claim.get("status")
            not in {
                "accepted_unconfirmed",
                "started_unknown",
                "outcome_unknown",
                "provider_returned",
                "cancel_requested",
                "provider_running",
                "confirmed_stopped",
                "confirmed_finished",
            }
        ):
            return _cancel_receipt("denied", self.server_id, str(request_id or ""))
        auth_denial = await check_persisted_reconciliation_authorization(
            self._budget_callback,
            claim,
        )
        if auth_denial is not None:
            return _cancel_receipt("denied", self.server_id, request_id, reason=auth_denial)
        if claim["status"] in {"confirmed_stopped", "confirmed_finished"}:
            # Already committed provider proof; do not issue another request.
            return _cancel_receipt(claim["status"], self.server_id, request_id)
        has_endpoint = "mcp_request_status_v1" in self._capabilities
        has_tool = "get_request_status" in self._tools
        if not (has_endpoint or has_tool):
            return _cancel_receipt("not_supported", self.server_id, request_id)
        if self._execution_event_callback is None:
            return _cancel_receipt(
                "unknown", self.server_id, request_id, reason="durable_writer_unavailable"
            )
        metadata = {
            "server_id": self.server_id,
            "request_id": request_id,
            "tool_name": claim.get("tool_name", ""),
        }
        # The writer must prove this exact original identity exists before
        # any remote observational HTTP request is made.
        if not await self._emit_execution_event(
            engagement_id,
            task_id,
            "reconciliation_requested",
            metadata,
        ):
            return _cancel_receipt(
                "unknown", self.server_id, request_id, reason="audit_unavailable"
            )
        signed_status = None
        try:
            if self._session is None:
                raise RuntimeError("Remote status transport unavailable")
            if has_endpoint:
                url = f"http://{self.host}:{self.port}/mcp/request/status"
                payload = self._provider_control_parameters(
                    request_id,
                    engagement_id,
                    task_id,
                )
            else:
                url = f"http://{self.host}:{self.port}/mcp/execute"
                payload = MCPExecuteRequest(
                    tool_name="get_request_status",
                    parameters=self._provider_control_parameters(
                        request_id,
                        engagement_id,
                        task_id,
                    ),
                ).model_dump()
            async with self._session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=_REMOTE_CANCEL_TIMEOUT_SECONDS),
                allow_redirects=False,
            ) as response:
                data = (
                    (await _bounded_execute_response_json(response))[0]
                    if response.status == 200
                    else None
                )
                status = _verified_remote_status(
                    data,
                    request_id,
                    engagement_id,
                    task_id,
                    self.server_id,
                    require_bound_identity=self._requires_bound_provider_receipt(),
                    require_signature=self._requires_signed_provider_receipt(),
                )
                if (
                    status in {"confirmed_stopped", "confirmed_finished"}
                    and self._requires_signed_provider_receipt()
                ):
                    signed_status = _provider_receipt_record(
                        data,
                        request_id,
                        engagement_id,
                        task_id,
                        self.server_id,
                        require_bound_identity=True,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            status = "unknown"
        if not await self._emit_execution_event(
            engagement_id,
            task_id,
            "reconciliation_result",
            {**metadata, "status": status, "attested_receipt": signed_status},
        ):
            # A receipt that was seen in memory but could not be committed
            # cannot be presented as verified to an operator.
            status = "unknown"
        return _cancel_receipt(status, self.server_id, request_id)

    async def cancel_persisted_execution(self, claim: Dict[str, Any]) -> Dict[str, Any]:
        """Single status-bound stop of a *durably admitted* remote execution.

        Caller must first commit a PostgreSQL cancellation intent via
        claim_mcp_cancellation_once. No remembered target arguments, original
        action, or queued retry are used. A provider receipt is accepted only
        when freshly signed by the original server's pinned Ed25519 key.
        Even this signature proves a provider assertion, not physical stop.
        """
        if not isinstance(claim, dict):
            return _cancel_receipt("denied", self.server_id, "")
        request_id = claim.get("request_id")
        engagement_id = claim.get("engagement_id")
        task_id = claim.get("task_id")
        if (
            not all(
                isinstance(value, str) and 0 < len(value) <= 128
                for value in (request_id, engagement_id, task_id)
            )
            or claim.get("server_id") != self.server_id
            or claim.get("status") != "cancel_requested"
            or type(claim.get("authorization_version")) is not int
            or claim["authorization_version"] < 1
        ):
            return _cancel_receipt("denied", self.server_id, str(request_id or ""))
        denied = await check_persisted_reconciliation_authorization(
            self._budget_callback,
            claim,
        )
        if denied is not None:
            return _cancel_receipt("denied", self.server_id, request_id)
        endpoint = "mcp_cancel_request_v1" in self._capabilities
        legacy_tool = "cancel_request" in self._tools
        if not endpoint and not legacy_tool:
            return _cancel_receipt("not_supported", self.server_id, request_id)
        if self._execution_event_callback is None:
            return _cancel_receipt(
                "unknown",
                self.server_id,
                request_id,
                reason="durable_stop_receipt_writer_unavailable",
            )
        status = "unknown"
        signed_receipt = None
        try:
            if self._session is None:
                raise RuntimeError("MCP stop transport unavailable")
            # A status/stop protocol is separate from re-executing the
            # original task; it must use the original committed tuple only.
            original = self._provider_control_parameters(
                request_id,
                engagement_id,
                task_id,
            )
            if endpoint:
                url = f"http://{self.host}:{self.port}/mcp/cancel"
                body = original
            else:
                url = f"http://{self.host}:{self.port}/mcp/execute"
                body = MCPExecuteRequest(
                    tool_name="cancel_request",
                    parameters=original,
                ).model_dump()
            async with self._session.post(
                url,
                json=body,
                timeout=aiohttp.ClientTimeout(total=_REMOTE_CANCEL_TIMEOUT_SECONDS),
                allow_redirects=False,
            ) as response:
                data = (
                    (await _bounded_execute_response_json(response))[0]
                    if response.status == 200
                    else None
                )
                status = _verified_remote_cancel(
                    data,
                    request_id,
                    engagement_id,
                    task_id,
                    self.server_id,
                    require_bound_identity=True,
                    require_signature=True,
                )
                if status == "confirmed_stopped":
                    signed_receipt = _provider_receipt_record(
                        data,
                        request_id,
                        engagement_id,
                        task_id,
                        self.server_id,
                        require_bound_identity=True,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            status = "unknown"
        recorded = await self._emit_execution_event(
            engagement_id,
            task_id,
            "cancellation_result",
            {
                "server_id": self.server_id,
                "request_id": request_id,
                "tool_name": claim.get("tool_name", ""),
                "status": status,
                "attested_receipt": signed_receipt,
            },
        )
        if not recorded:
            status = "unknown"
        return _cancel_receipt(status, self.server_id, request_id)

    def _circuit_breaker_check(self) -> None:
        """Check circuit state and transition OPEN -> HALF-OPEN if recovery time elapsed."""
        if not self._circuit_open and not self._half_open:
            return
        # If we're in half-open, let the next call through as a probe
        if self._half_open:
            return
        # OPEN state: check if recovery time has elapsed
        if self._circuit_opened_at is None:
            self._circuit_open = False
            return
        elapsed = (datetime.utcnow() - self._circuit_opened_at).total_seconds()
        if elapsed >= self.CIRCUIT_RECOVERY_SECONDS:
            # Transition to HALF-OPEN for probing
            self._circuit_open = False
            self._half_open = True
            self._recovery_attempts += 1
            self._consecutive_successes = 0

    def _record_success(self) -> None:
        """Record a successful call and update circuit state."""
        old_state = self.get_circuit_state()
        self._success_count += 1
        self._last_success_at = datetime.utcnow()
        if self._half_open:
            self._consecutive_successes += 1
            if self._consecutive_successes >= self.CIRCUIT_HALF_OPEN_SUCCESS_REQUIRED:
                # Transition back to CLOSED
                self._half_open = False
                self._failure_count = 0
                self._consecutive_successes = 0
                self._circuit_opened_at = None
        else:
            self._failure_count = 0
        new_state = self.get_circuit_state()
        if old_state != new_state:
            from ai_osop.core.observability import record_circuit_breaker_state

            record_circuit_breaker_state(self.server_id, is_open=(new_state == "open"))

    def _record_failure(self) -> None:
        """Record a failed call and update circuit state."""
        old_state = self.get_circuit_state()
        self._failure_count += 1
        self._last_failure_at = datetime.utcnow()
        if self._half_open:
            # Any failure in half-open goes back to OPEN
            self._half_open = False
            self._circuit_open = True
            self._circuit_opened_at = datetime.utcnow()
            self._consecutive_successes = 0
        elif self._failure_count >= self.CIRCUIT_THRESHOLD:
            self._circuit_open = True
            self._circuit_opened_at = datetime.utcnow()
        new_state = self.get_circuit_state()
        if old_state != new_state:
            from ai_osop.core.observability import record_circuit_breaker_state

            record_circuit_breaker_state(self.server_id, is_open=(new_state == "open"))

    def get_circuit_state(self) -> str:
        """Return current circuit state as a string: closed, open, or half_open."""
        if self._circuit_open:
            return "open"
        if self._half_open:
            return "half_open"
        return "closed"

    async def connect(self) -> None:
        """Establish HTTP and WebSocket connections."""
        # Do not retarget a connection while a signed original remote Action
        # may still be running. A disconnected client is never proof the
        # provider stopped, and reconnect must not cancel the live transport.
        if any(execution.active for execution in self._executions.values()):
            raise MCPConnectionError("In-flight MCP action prevents transport reconnection")
        # Reconnecting directly on a live MCPConnection must never retain a
        # negotiated manifest from a prior provider process. A new socket or
        # bearer is not authority to replay a previously UNKNOWN request.
        self._initialized = False
        self._tools = {}
        self._capabilities = []
        if self._session is not None:
            await self._session.close()
            self._session = None
        # Check direct MCPConnection use too, before creating a ClientSession
        # holding the SourceMap bearer. Registry checks alone do not fence
        # legacy direct adapter and test harness invocations.
        # A hostname (including "localhost") can be remapped by resolver or
        # hosts-file configuration. Never send the native bearer to DNS.
        if self.server_id == "source-map-mcp" and self.host != "127.0.0.1":
            raise MCPConnectionError("SourceMap native transport must use loopback")
        # All eleven adapters use plain HTTP on this transport. An operator
        # bearer/credential is confidential even when a different adapter
        # claims benign /health or initialization semantics. Before creating
        # any credential-bearing ClientSession, deny DNS, alternate loopback
        # names and remote hosts; independently pinned HTTPS support would
        # require an explicit separate transport implementation.
        if self.auth_token and self.host != "127.0.0.1":
            raise MCPConnectionError("Credential-bearing MCP transport requires numeric loopback")
        self._circuit_breaker_check()
        if self._circuit_open and not self._half_open:
            raise MCPConnectionError(f"MCP server {self.server_id} circuit breaker is open")
        try:
            self._session = aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}
            )
            async with self._session.get(
                f"http://{self.host}:{self.port}/health",
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False,
            ) as resp:
                if resp.status != 200:
                    self._record_failure()
                    raise MCPConnectionError(
                        f"MCP server {self.server_id} health check failed: {resp.status}"
                    )
            self._record_success()
        except asyncio.CancelledError:
            # /health has no approved Action or replay semantics. Cancellation
            # must still close its newly allocated bearer-holding session;
            # `asyncio.CancelledError` does not inherit from Exception in
            # Python 3.11, so the ordinary error branches cannot do this.
            try:
                await self.close()
            finally:
                raise
        except asyncio.TimeoutError:
            self._record_failure()
            await self.close()
            raise MCPTimeoutError(f"MCP server {self.server_id} connection timed out")
        except Exception:
            self._record_failure()
            await self.close()
            raise MCPConnectionError("MCP server connection failed") from None

    async def initialize(self, request: MCPInitializeRequest) -> MCPInitializeResponse:
        """Initialize server with scope and credentials."""
        # A failed renegotiation must revoke the previous manifest before
        # any await. In-flight operators may not continue to dispatch tools
        # from an obsolete definition after a failed server reinitialize.
        self._initialized = False
        self._tools = {}
        self._capabilities = []
        # A caller can supply credentials inside the initialization JSON even
        # if the connection itself has no bearer. Do not deliver those bytes
        # over remote plaintext HTTP (or DNS-overridable localhost). This is
        # separate from the Session's Authorization-header admission above.
        if request.auth_credentials and self.host != "127.0.0.1":
            raise MCPConnectionError("Credential-bearing MCP initialization requires numeric loopback")
        self._circuit_breaker_check()
        if self._circuit_open and not self._half_open:
            raise MCPConnectionError(f"MCP server {self.server_id} circuit breaker is open")
        if not self._session:
            await self.connect()

        try:
            async with self._session.post(
                f"http://{self.host}:{self.port}/mcp/initialize",
                json=request.model_dump(),
                allow_redirects=False,
            ) as resp:
                # Some gateways return syntactically valid MCP JSON alongside
                # an HTTP failure. Such an envelope cannot initialize an
                # executable registry entry.
                if resp.status != 200:
                    raise MCPConnectionError("MCP initialization HTTP status denied")
                data, _ = await _bounded_execute_response_json(resp)
                # Tool definitions originate at a different trust boundary.
                # The Pydantic compatibility defaults (READ_ONLY/approval
                # false) are NOT sufficient evidence for a remote scanner.
                # Require explicit side-effect and admission flags on the
                # original provider document before any defaulting occurs.
                if (
                    not isinstance(data, dict)
                    or not isinstance(data.get("tools"), list)
                    or len(data["tools"]) > 128
                    or any(
                        not isinstance(item, dict)
                        or item.get("side_effect_class")
                        not in {
                            SideEffectClass.READ_ONLY.value,
                            SideEffectClass.RECON_ACTIVE.value,
                            SideEffectClass.INVASIVE_EXPLOIT.value,
                        }
                        or type(item.get("requires_approval")) is not bool
                        or type(item.get("scope_check")) is not bool
                        or item["scope_check"] is not True
                        or (
                            item["side_effect_class"] != SideEffectClass.READ_ONLY.value
                            and item["requires_approval"] is not True
                        )
                        or not isinstance(item.get("parameters"), list)
                        or len(item["parameters"]) > 32
                        for item in data["tools"]
                    )
                ):
                    raise MCPConnectionError("Explicit remote MCP risk declaration required")
                response = MCPInitializeResponse(**data)
                if (
                    response.server_id != self.server_id
                    or response.status != "ready"
                    or len(response.tools) != len({tool.name for tool in response.tools})
                ):
                    raise MCPConnectionError("MCP initialization declaration mismatch")
                self._capabilities = response.capabilities
                self._tools = {t.name: t for t in response.tools}
                self._initialized = True
                self._record_success()
                return response
        except Exception:
            self._record_failure()
            raise MCPConnectionError("MCP server initialization failed") from None

    async def execute(
        self, request: MCPExecuteRequest, *, native_grant: Optional[str] = None
    ) -> MCPExecuteResponse:
        """Execute a tool with timeout, error handling, circuit breaker, and tracing."""
        # Only the internal signed 0027 Action dispatcher may pass a transient
        # one-shot native grant. Never take this header from user parameters,
        # a tool declaration, the global connection or a browser API request.
        if native_grant is not None and (
            request.tool_name != "authority_status"
            or type(native_grant) is not str
            or not 100 <= len(native_grant) <= 4096
            or re.fullmatch(r"[A-Za-z0-9_-]+", native_grant) is None
        ):
            raise MCPConnectionError("Native signed MCP grant is not valid for this operation")
        # Caller-owned Pydantic models contain mutable parameter dictionaries.
        # Freeze a private deep copy before ANY await so an unrelated callback
        # cannot retarget a signed, budgeted remote dispatch in flight.
        request = request.model_copy(deep=True)
        started = time.monotonic()
        outcome = "error"
        error_class: Optional[str] = None
        dispatch_metadata: Optional[Dict[str, Any]] = None
        terminal_event_recorded = False
        engagement_id = ""
        task_id = ""
        # Reserve the original remote request ID before any await: concurrent
        # retries cannot dispatch the same command twice in this process.
        if request.request_id in self._seen_request_ids:
            return MCPExecuteResponse(
                request_id=request.request_id,
                status="duplicate_request",
                error="MCP execution request ID already used",
            )
        self._seen_request_ids[request.request_id] = True
        try:
            self._circuit_breaker_check()
            if self._circuit_open and not self._half_open:
                outcome = "circuit_open"
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status="circuit_open",
                    error=f"MCP server {self.server_id} circuit breaker is open",
                )
            if not self._initialized:
                raise MCPException(f"MCP server {self.server_id} not initialized")

            tool = self._tools.get(request.tool_name)
            if not tool:
                raise MCPException(
                    f"Tool {request.tool_name} not available on server {self.server_id}"
                )

            # Request models/parameter dictionaries are mutable. A callback
            # (or another coroutine retaining the request) can replace a tool,
            # target, or timeout while the signed dispatch claim is awaited.
            # Fence exactly the envelope that the scope check will authorize.
            admitted_request = copy.deepcopy(request.model_dump())
            admitted_budget_callback = self._budget_callback
            admitted_event_callback = self._execution_event_callback

            # All call paths, including direct MCPConnection and broadcasts,
            # must pass target-specific ROE and persisted approval checks before
            # charging quota or executing a tool. Remote MCP tool metadata is
            # only one source of the required human approval policy.
            context = RequestContext.get()
            # Ad-hoc direct MCPConnection calls with real PostgreSQL-backed
            # engagement authority must not bypass the cross-replica durable
            # dispatch claim merely by omitting the registry's event writer.
            # Legacy inert mocks remain supported; bootstrap remains limited
            # to the earlier explicitly allowlisted health/discovery calls.
            from ai_osop.memory.session_memory import SessionMemory

            production_memory = getattr(self._budget_callback, "__self__", None)
            if (
                isinstance(production_memory, SessionMemory)
                and context.get("engagement_id") != "api-bootstrap"
                and self._execution_event_callback is None
            ):
                outcome = "audit_unavailable"
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status="audit_unavailable",
                    error="Durable MCP dispatch ownership is not configured",
                )
            safety_denial = await check_tool_authorization(
                self._budget_callback,
                self.server_id,
                request.tool_name,
                request.parameters,
                context,
                requires_approval=getattr(tool, "requires_approval", False) is True,
            )
            if safety_denial is not None:
                outcome = safety_denial
                error_class = "".join(part.capitalize() for part in safety_denial.split("_"))
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status=safety_denial,
                    error={
                        "scope_denied": "MCP destination is outside authorized scope",
                        "scope_context_missing": "MCP execution requires engagement context",
                        "scope_unavailable": "MCP scope authorization is unavailable",
                        "roe_denied": "MCP action is restricted by engagement rules",
                        "approval_required": (
                            "MCP action requires current persisted operator approval"
                        ),
                        "approval_unavailable": "MCP approval verification is unavailable",
                    }[safety_denial],
                )

            # Only authorized actions debit the shared engagement quota.
            denial = await check_tool_budget(
                self._budget_callback,
                self.server_id,
                request.tool_name,
                context,
                request_id=request.request_id,
            )
            if denial is not None:
                outcome = denial
                # The existing sanitized provenance record only permits the
                # standard outcome enum; preserve the exact quota denial in
                # its allowlisted error_class without modifying that schema.
                error_class = {
                    "quota_exceeded": "QuotaExceeded",
                    "quota_unavailable": "QuotaUnavailable",
                    "quota_context_missing": "QuotaContextMissing",
                }[denial]
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status=denial,
                    error={
                        "quota_exceeded": "Engagement MCP tool call budget exhausted",
                        "quota_unavailable": "MCP tool budget service unavailable",
                        "quota_context_missing": "MCP execution requires engagement context",
                    }[denial],
                )

            timeout = request.timeout_override or tool.timeout_seconds
            engagement_id = context.get("engagement_id", "")
            task_id = context.get("task_id", "")
            dispatch_metadata = {
                "server_id": self.server_id,
                "request_id": request.request_id,
                "tool_name": request.tool_name,
                "flow_id": context.get("flow_id", ""),
                "subtask_id": context.get("subtask_id", ""),
            }
            if self._execution_event_callback is not None and (
                not engagement_id
                or not task_id
                or not await self._emit_execution_event(
                    engagement_id,
                    task_id,
                    "dispatch_accepted",
                    dispatch_metadata,
                )
            ):
                outcome = "audit_unavailable"
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status="audit_unavailable",
                    error="MCP execution supervision is unavailable",
                )
            # Register before entering HTTP so supervisor controls can discover
            # an in-flight execution even while the request is sending.
            self._executions[request.request_id] = _RemoteExecution(
                engagement_id=engagement_id,
                task_id=task_id,
                tool_name=request.tool_name,
                parameters=request.parameters,
                requires_approval=getattr(tool, "requires_approval", False) is True,
            )
            if not await self._emit_execution_event(
                engagement_id,
                task_id,
                "execution_started",
                dispatch_metadata,
            ):
                self._executions.pop(request.request_id, None)
                outcome = "audit_unavailable"
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status="audit_unavailable",
                    error="MCP execution supervision is unavailable",
                )
            # There are two awaitable PostgreSQL event writes between the
            # first signed Task/ROE/approval check and the actual MCP HTTP
            # send. An operator can revoke the Task or its execution lease
            # during either callback. The durable dispatch claim is NOT
            # authority to start a now-revoked remote action. Check again
            # immediately before provider I/O, without charging quota twice.
            # The claim remains one-shot/UNKNOWN if authority changed: do not
            # reuse its request ID or automatically replay remote work.
            if (
                request.model_dump() != admitted_request
                or self._budget_callback is not admitted_budget_callback
                or self._execution_event_callback is not admitted_event_callback
                or any(
                    RequestContext.get().get(key) != context.get(key)
                    for key in ("engagement_id", "task_id", "flow_id", "subtask_id")
                )
            ):
                outcome = "unknown"
                error_class = "DispatchBindingChanged"
                return MCPExecuteResponse(
                    request_id=request.request_id,
                    status="unknown",
                    error="MCP dispatch binding changed before provider execution",
                )
            if isinstance(production_memory, SessionMemory) and engagement_id != "api-bootstrap":
                current_denial = await check_tool_authorization(
                    admitted_budget_callback,
                    self.server_id,
                    request.tool_name,
                    request.parameters,
                    context,
                    requires_approval=getattr(tool, "requires_approval", False) is True,
                )
                if current_denial is not None:
                    outcome = "unknown"
                    error_class = "DispatchAuthorityChanged"
                    return MCPExecuteResponse(
                        request_id=request.request_id,
                        status="unknown",
                        error="Current signed MCP dispatch authority unavailable",
                    )
            with trace_span(
                f"mcp.{safe_label(self.server_id)}.{safe_label(request.tool_name)}",
                attributes={
                    "ai_osop.mcp.server_id": safe_label(self.server_id),
                    "ai_osop.mcp.tool_name": safe_label(request.tool_name),
                    "ai_osop.mcp.port": self.port,
                },
            ):
                try:
                    async with self._session.post(
                        f"http://{self.host}:{self.port}/mcp/execute",
                        json=self._provider_execution_payload(
                            request,
                            engagement_id,
                            task_id,
                        ),
                        **(
                            {"headers": {"X-OSOP-Native-Grant": native_grant}}
                            if native_grant is not None
                            else {}
                        ),
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=False,
                    ) as resp:
                        # Transport-level failure is ambiguous after dispatch:
                        # a forged JSON success under HTTP 500 is never proof
                        # of execution, and the original request must not be
                        # replayed. Do not deserialize an untrusted error body.
                        if resp.status != 200:
                            outcome = "unknown"
                            error_class = "ProviderHTTPStatus"
                            self._record_failure()
                            return MCPExecuteResponse(
                                request_id=request.request_id,
                                status="unknown",
                                error="MCP tool outcome unknown after provider HTTP failure",
                            )
                        # Bound decoded HTTP bytes before JSON, Pydantic or
                        # retaining incident evidence. Status is still just
                        # provider testimony, never owner-of-record proof.
                        data, raw_body = await _bounded_execute_response_json(resp)
                        elapsed = int((time.monotonic() - started) * 1000)
                        # A provider-reported success with a conflicting MCP
                        # isError/error cannot establish a finished execution,
                        # even if the same envelope includes a valid signed
                        # status receipt. Check raw JSON before Pydantic could
                        # reject a malformed error object and lose the incident.
                        if data.get("status") == "success" and (
                            ("isError" in data and data["isError"] is not False)
                            or data.get("error") is not None
                        ):
                            outcome = "unknown"
                            error_class = "ContradictoryProviderOutcome"
                            self._record_failure()
                            untrusted = MCPExecuteResponse(
                                request_id=request.request_id,
                                status="unknown",
                                error="MCP provider reported conflicting execution outcomes",
                            )
                            untrusted._untrusted_provider_body_bytes = raw_body
                            untrusted._untrusted_provider_payload = copy.deepcopy(data)
                            return untrusted
                        # The provider cannot supply the locally constructed
                        # provenance field, even through extra JSON fields.
                        response = MCPExecuteResponse(
                            **{
                                key: value
                                for key, value in data.items()
                                if key != "provider_provenance"
                            },
                            provider_provenance=MCPProviderProvenance(),
                        )
                        response._untrusted_provider_body_bytes = raw_body
                        response._untrusted_provider_payload = copy.deepcopy(data)
                        # Untrusted provider metadata must never supply the
                        # settlement credential consumed by the original 0027
                        # Action executor. Only a separately verified and
                        # durably recorded provider-origin signature below
                        # may populate this field. A successful HTTP envelope
                        # by itself is not settlement evidence.
                        response.metadata = _strip_untrusted_provider_authority_flags(
                            response.metadata
                        )
                        if response.result is not None:
                            response.result = _strip_untrusted_provider_authority_flags(
                                response.result
                            )
                        if (
                            response.request_id != request.request_id
                            and self._requires_bound_provider_receipt()
                        ):
                            # A remote server must never relabel another
                            # previously accepted one-shot request as this
                            # execution. The network outcome remains UNKNOWN.
                            outcome = "unknown"
                            return MCPExecuteResponse(
                                request_id=request.request_id,
                                status="unknown",
                                error="MCP provider returned a mismatched request identity",
                            )
                        response.execution_time_ms = elapsed
                        outcome = response.status
                        # Remote servers and HTTP response parsers can include
                        # credentials or sensitive URLs in error messages.
                        if response.error is not None:
                            response.error = "MCP tool execution failed"
                        terminal_kind = (
                            "execution_finished"
                            if outcome == "success"
                            else (
                                "execution_unknown"
                                if outcome in {"cancelled", "canceled", "unknown"}
                                else "execution_failed"
                            )
                        )
                        if self._execution_event_callback is not None:
                            terminal_event_recorded = await self._emit_execution_event(
                                engagement_id,
                                task_id,
                                terminal_kind,
                                {**dispatch_metadata, "status": outcome},
                            )
                            if not terminal_event_recorded:
                                # An HTTP response is not a durable receipt if
                                # the storage callback could not persist it.
                                outcome = "unknown"
                                response.status = "unknown"
                                response.result = None
                                response.metadata = {}
                                response.error = "MCP execution outcome could not be persisted"
                                return response
                            # A successful HTTP/tool envelope is not a signed
                            # provider receipt. Only an Ed25519 assertion over
                            # the original request/tenant/Task identity may
                            # create a durable confirmed_finished observation.
                            # Missing or invalid proof remains unconfirmed and
                            # cannot certify target-side effects.
                            native = (
                                data.get("provider_receipt") if isinstance(data, dict) else None
                            )
                            if (
                                outcome == "success"
                                and isinstance(native, dict)
                                and native.get("verified") is True
                                and native.get("status") == "succeeded"
                                and provider_receipt_is_signed(
                                    native,
                                    self.server_id,
                                    request.request_id,
                                    engagement_id,
                                    task_id,
                                )
                            ):
                                if not await self._emit_execution_event(
                                    engagement_id,
                                    task_id,
                                    "reconciliation_result",
                                    {
                                        **dispatch_metadata,
                                        "status": "confirmed_finished",
                                        "attested_receipt": native,
                                    },
                                ):
                                    outcome = "unknown"
                                    response.status = "unknown"
                                    response.result = None
                                    response.metadata = {}
                                    response.error = (
                                        "Signed provider outcome could not be committed"
                                    )
                                    return response
                                # Bridge the *verified* signed native receipt
                                # to FlowMCPActionExecutor.dispatch. Preserve
                                # its independent store-side signature/current
                                # Task/Flow/reviewer/lease check; never treat
                                # it as a verified target-side effect.
                                response.metadata["signed_provider_receipt"] = native
                        if outcome == "success":
                            self._record_success()
                        else:
                            self._record_failure()
                        return response
                except asyncio.TimeoutError:
                    outcome = "unknown"
                    error_class = "TimeoutError"
                    self._record_failure()
                    return MCPExecuteResponse(
                        request_id=request.request_id,
                        status="unknown",
                        error="MCP tool outcome unknown after timeout",
                    )
                except asyncio.CancelledError:
                    outcome = "unknown"
                    error_class = "CancelledError"
                    self._record_failure()
                    raise
                except Exception as e:
                    outcome = "unknown"
                    error_class = type(e).__name__
                    self._record_failure()
                    return MCPExecuteResponse(
                        request_id=request.request_id,
                        status="unknown",
                        error="MCP tool outcome unknown after transport failure",
                    )
        finally:
            self._seen_request_ids[request.request_id] = False
            if len(self._seen_request_ids) > 1024:
                for old_id, active in list(self._seen_request_ids.items()):
                    if not active and old_id != request.request_id:
                        del self._seen_request_ids[old_id]
                    if len(self._seen_request_ids) <= 1024:
                        break
            if dispatch_metadata is not None and request.request_id in self._executions:
                execution = self._executions[request.request_id]
                execution.active = False
                # Verified remote cancellation/status can race with a weaker
                # execution HTTP response. Never discard stronger provider
                # evidence by overwriting it with an unverified outcome.
                if execution.outcome in {"confirmed_stopped", "confirmed_finished"}:
                    outcome = execution.outcome
                else:
                    execution.outcome = outcome
                event_kind = (
                    "execution_finished"
                    if outcome in {"success", "confirmed_stopped", "confirmed_finished"}
                    else (
                        "execution_unknown"
                        if outcome in {"unknown", "timeout", "cancelled"}
                        else "execution_failed"
                    )
                )
                if not terminal_event_recorded:
                    await self._emit_execution_event(
                        engagement_id,
                        task_id,
                        event_kind,
                        {**dispatch_metadata, "status": outcome},
                    )
                # Remote jobs may outlive an HTTP response; retain a bounded
                # set of request identifiers for subsequent cancellation.
                if len(self._executions) > 512:
                    for old_id, execution in list(self._executions.items()):
                        if not execution.active and old_id != request.request_id:
                            del self._executions[old_id]
                        if len(self._executions) <= 512:
                            break
            elapsed_seconds = max(0.0, time.monotonic() - started)
            try:
                from ai_osop.core.observability import record_mcp_call

                record_mcp_call(
                    safe_label(self.server_id),
                    safe_label(request.tool_name),
                    elapsed_seconds,
                    success=(outcome == "success"),
                )
            except Exception:
                # Metrics failures must never change an MCP tool outcome.
                pass
            try:
                self._provenance_recorder.submit(
                    action_provenance(
                        f"mcp.{safe_label(self.server_id)}.{safe_label(request.tool_name)}",
                        outcome,
                        int(elapsed_seconds * 1000),
                        safe_metadata={
                            "server_id": self.server_id,
                            "request_id": request.request_id,
                            "error_class": error_class,
                        },
                    )
                )
            except Exception:
                # Sanitization/persistence must never replace the tool outcome.
                pass

    async def get_state(self) -> MCPStateResponse:
        """Get current server state."""
        async with self._session.get(
            f"http://{self.host}:{self.port}/mcp/state", allow_redirects=False
        ) as resp:
            if resp.status != 200:
                raise MCPConnectionError("MCP state HTTP status denied")
            data, _ = await _bounded_execute_response_json(resp)
            return MCPStateResponse(**data)

    async def list_tools(self) -> List[MCPToolDefinition]:
        """List available tools."""
        return list(self._tools.values())

    def reset_circuit(self) -> None:
        """Manually reset the circuit breaker back to CLOSED state."""
        old_state = self.get_circuit_state()
        self._circuit_open = False
        self._half_open = False
        self._failure_count = 0
        self._consecutive_successes = 0
        self._circuit_opened_at = None
        new_state = self.get_circuit_state()
        if old_state != new_state:
            from ai_osop.core.observability import record_circuit_breaker_state

            record_circuit_breaker_state(self.server_id, is_open=False)

    async def ping(self) -> Dict[str, Any]:
        """Probe configured local HTTP only; never treat a probe as authority.

        An operator ping is not a signed process, Action, or target witness.
        In particular, never create a bearer-holding session for DNS names or
        remote cleartext HTTP endpoints, even for a registered server.
        """
        started = time.monotonic()
        if self.host != "127.0.0.1" or type(self.port) is not int or not (1 <= self.port <= 65535):
            return {
                "server_id": self.server_id,
                "status": "unverified_nonlocal_transport",
                "latency_ms": 0,
                "circuit_state": self.get_circuit_state(),
                "runtime_health_verified": False,
                "current_authorized_operation_verified": False,
                "independent_target_effect_verified": False,
                "timestamp": datetime.utcnow().isoformat(),
            }
        try:
            # Keep the diagnostic transport independent from any active Action
            # and do not alter a real MCP session/circuit/replay journal.
            async with aiohttp.ClientSession(
                headers={"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {},
                trust_env=False,
            ) as probe:
                async with probe.get(
                    f"http://127.0.0.1:{self.port}/health",
                    timeout=aiohttp.ClientTimeout(total=5),
                    allow_redirects=False,
                ) as resp:
                    latency_ms = int((time.monotonic() - started) * 1000)
                    return {
                        "server_id": self.server_id,
                        "status": "healthy" if resp.status == 200 else "unhealthy",
                        "latency_ms": latency_ms,
                        "status_code": resp.status,
                        "circuit_state": self.get_circuit_state(),
                        "runtime_health_verified": False,
                        "current_authorized_operation_verified": False,
                        "independent_target_effect_verified": False,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
        except asyncio.CancelledError:
            raise
        except Exception:
            latency_ms = int((time.monotonic() - started) * 1000)
            return {
                "server_id": self.server_id,
                "status": "unreachable",
                "latency_ms": latency_ms,
                "error": "MCP local diagnostic transport unavailable",
                "circuit_state": self.get_circuit_state(),
                "runtime_health_verified": False,
                "current_authorized_operation_verified": False,
                "independent_target_effect_verified": False,
                "timestamp": datetime.utcnow().isoformat(),
            }

    def get_manifests(self) -> List[MCPAdapterManifest]:
        """Return standardized manifests for all tools hosted by this adapter."""
        manifests = []
        for tool in self._tools.values():
            manifests.append(
                MCPAdapterManifest(
                    tool_name=tool.name,
                    version=tool.version,
                    side_effect_class=tool.side_effect_class,
                    timeout_seconds=tool.timeout_seconds,
                    required_permissions=tool.required_permissions,
                    description=tool.description,
                )
            )
        return manifests

    async def close(self) -> None:
        """Clean up connections."""
        # Closing a transport is also a hard capability revocation. Retain
        # one-shot request IDs: they cannot become safe to replay on restart.
        self._initialized = False
        self._tools = {}
        self._capabilities = []
        await self._provenance_recorder.drain()
        if self._session:
            await self._session.close()
            self._session = None
        if self._ws:
            await self._ws.close()
            self._ws = None


class MCPRegistry:
    """Central registry for all MCP server connections."""

    def __init__(self) -> None:
        self._servers: Dict[str, MCPConnection] = {}
        self._event_handlers: Dict[str, List[Callable]] = {}
        self.call_counts: Dict[str, int] = {}
        self._provenance_recorder = BestEffortProvenance()
        self._budget_callback: Optional[BudgetCallback] = None
        self._execution_event_callback: Optional[ExecutionEventCallback] = None
        self._task_cancel_receipts: Dict[tuple[str, str, str], Dict[str, Any]] = {}
        self._task_cancel_lock = asyncio.Lock()
        # Serializes the registered identity across awaits, preventing two
        # concurrent transports under one server_id from replacing each other
        # and clearing the prior connection's in-memory replay fences.
        self._register_lock = asyncio.Lock()

    def set_provenance_callback(self, callback: Optional[ProvenanceCallback]) -> None:
        """Attach a durable action-writer callback to all current/future servers."""
        self._provenance_recorder.set_callback(callback)
        for connection in self._servers.values():
            connection._provenance_recorder = self._provenance_recorder

    def set_budget_callback(self, callback: Optional[BudgetCallback]) -> None:
        """Bind atomic per-engagement quota accounting to every MCP connection."""
        self._budget_callback = callback
        for connection in self._servers.values():
            connection.set_budget_callback(callback)

    def set_execution_event_callback(self, callback: Optional[ExecutionEventCallback]) -> None:
        """Bind durable supervision events to existing and future MCP servers."""
        self._execution_event_callback = callback
        for connection in self._servers.values():
            connection.set_execution_event_callback(callback)

    async def register_server(
        self, server_id: str, host: str, port: int, auth_token: Optional[str] = None
    ) -> MCPConnection:
        """Register and connect to a new MCP server."""
        # This MCP transport is plain HTTP. The SourceMap native client
        # bearer must never traverse a configured remote host until there is
        # a separately authenticated, pinned-TLS native transport. The
        # independently signed central source-authority hop already uses
        # HTTPS; it does not secure the registry-to-native hop.
        if server_id == "source-map-mcp" and host != "127.0.0.1":
            raise MCPConnectionError("SourceMap native transport must use loopback")
        if auth_token and host != "127.0.0.1":
            raise MCPConnectionError("Credential-bearing MCP transport requires numeric loopback")
        async with self._register_lock:
            if server_id in self._servers:
                # A replacement after ambiguous ACK requires durable original
                # Action reconciliation, not a silent new MCPConnection with
                # an empty _seen_request_ids set. This registry deliberately
                # offers NO unsafe hot-replace operation.
                raise MCPConnectionError("MCP server identity already registered")
            conn = MCPConnection(server_id=server_id, host=host, port=port, auth_token=auth_token)
            conn._provenance_recorder = self._provenance_recorder
            conn.set_budget_callback(self._budget_callback)
            conn.set_execution_event_callback(self._execution_event_callback)
            await conn.connect()
            self._servers[server_id] = conn
            return conn

    async def initialize_server(
        self, server_id: str, scope: Dict[str, Any], credentials: Dict[str, Any], session_id: str
    ) -> MCPInitializeResponse:
        """Initialize a registered server."""
        conn = self._servers.get(server_id)
        if not conn:
            raise MCPConnectionError(f"Server {server_id} not registered")

        request = MCPInitializeRequest(
            scope=scope, auth_credentials=credentials, session_id=session_id
        )
        return await conn.initialize(request)

    async def execute_tool(
        self,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        timeout_override: Optional[int] = None,
        request_id: Optional[str] = None,
        native_grant: Optional[str] = None,
    ) -> MCPExecuteResponse:
        """Execute a tool on a specific server with tracing."""
        with trace_span(
            "mcp_registry.execute_tool",
            attributes={
                "ai_osop.mcp.server_id": safe_label(server_id),
                "ai_osop.mcp.tool_name": safe_label(tool_name),
            },
        ):
            conn = self._servers.get(server_id)
            if not conn:
                raise MCPConnectionError(f"Server {server_id} not registered")
            conn._provenance_recorder = self._provenance_recorder
            conn.set_budget_callback(self._budget_callback)
            conn.set_execution_event_callback(self._execution_event_callback)

            self.call_counts[server_id] = self.call_counts.get(server_id, 0) + 1
            request = MCPExecuteRequest(
                tool_name=tool_name,
                parameters=parameters,
                timeout_override=timeout_override,
                **({"request_id": request_id} if request_id else {}),
            )
            return (
                await conn.execute(request, native_grant=native_grant)
                if native_grant
                else await conn.execute(request)
            )

    async def request_cancellation(
        self,
        server_id: str,
        request_id: str,
        engagement_id: str,
        task_id: str,
    ) -> Dict[str, Any]:
        """Ask an MCP provider to cancel a known remote execution."""
        connection = self._servers.get(server_id)
        if connection is None:
            return _cancel_receipt("unknown", server_id, request_id)
        connection.set_budget_callback(self._budget_callback)
        connection.set_execution_event_callback(self._execution_event_callback)
        return await connection.request_cancellation(request_id, engagement_id, task_id)

    async def reconcile_execution(
        self,
        server_id: str,
        request_id: str,
        engagement_id: str,
        task_id: str,
    ) -> Dict[str, Any]:
        """Reconcile one attributable MCP request via advertised remote status."""
        conn = self._servers.get(server_id)
        if conn is None:
            return _cancel_receipt("unknown", server_id, request_id)
        conn.set_budget_callback(self._budget_callback)
        conn.set_execution_event_callback(self._execution_event_callback)
        return await conn.reconcile_execution(request_id, engagement_id, task_id)

    async def reconcile_task_execution(
        self,
        task_id: str,
        engagement_id: str,
        request_id: str,
    ) -> Dict[str, Any]:
        """Reconcile known provider jobs without guessing untracked executions."""
        if not all(
            isinstance(value, str) and 0 < len(value) <= 128
            for value in (
                task_id,
                engagement_id,
                request_id,
            )
        ):
            return {"status": "denied", "request_id": request_id}
        matches = [
            (server_id, remote_id)
            for server_id, connection in self._servers.items()
            for remote_id, execution in list(connection._executions.items())
            if execution.engagement_id == engagement_id and execution.task_id == task_id
        ]
        if not matches:
            return {
                "status": "unknown",
                "request_id": request_id,
                "reason": "remote_execution_not_identified",
                "executions": [],
            }
        receipts = [
            await self.reconcile_execution(server_id, remote_id, engagement_id, task_id)
            for server_id, remote_id in matches
        ]
        statuses = {receipt["status"] for receipt in receipts}
        status = (
            "denied"
            if "denied" in statuses
            else (
                "confirmed_stopped"
                if statuses == {"confirmed_stopped"}
                else (
                    "confirmed_finished"
                    if statuses == {"confirmed_finished"}
                    else (
                        "not_supported"
                        if statuses == {"not_supported"}
                        else "running" if statuses == {"running"} else "unknown"
                    )
                )
            )
        )
        return {"status": status, "request_id": request_id, "executions": receipts}

    async def cancel_task_execution(
        self,
        task_id: str,
        engagement_id: str,
        request_id: str,
    ) -> Dict[str, Any]:
        """Cancel matching MCP calls for a task, with an idempotent control ID.

        No registered in-flight request means we cannot infer remote shutdown.
        Records survive HTTP return locally to allow cancellation of providers
        that launch an asynchronous job, but process restarts require storage
        recovery before such requests can be targeted again.
        """
        if not all(
            isinstance(value, str) and 0 < len(value) <= 128
            for value in (
                task_id,
                engagement_id,
                request_id,
            )
        ):
            return {"status": "denied", "request_id": request_id}
        key = (engagement_id, task_id, request_id)
        async with self._task_cancel_lock:
            matches = [
                (server_id, remote_id)
                for server_id, connection in self._servers.items()
                for remote_id, execution in list(connection._executions.items())
                if execution.engagement_id == engagement_id and execution.task_id == task_id
            ]
            if key in self._task_cancel_receipts:
                # A control ID must not bypass freshly revoked task approval
                # or signed ROE merely because this process cached its result.
                if not matches:
                    return {
                        "status": "unknown",
                        "request_id": request_id,
                        "reason": "remote_execution_not_identified",
                        "executions": [],
                    }
                for server_id, remote_id in matches:
                    connection = self._servers[server_id]
                    execution = connection._executions[remote_id]
                    denial = await check_cancellation_authorization(
                        self._budget_callback,
                        server_id,
                        execution.tool_name,
                        execution.parameters,
                        engagement_id,
                        task_id,
                        requires_approval=execution.requires_approval,
                    )
                    if denial is not None:
                        return {"status": "denied", "request_id": request_id}
                return copy.deepcopy(self._task_cancel_receipts[key])
            if not matches:
                receipt = {
                    "status": "unknown",
                    "request_id": request_id,
                    "reason": "remote_execution_not_identified",
                    "executions": [],
                }
                self._task_cancel_receipts[key] = receipt
                return copy.deepcopy(receipt)
            executions = [
                await self.request_cancellation(server_id, remote_id, engagement_id, task_id)
                for server_id, remote_id in matches
            ]
            statuses = {receipt["status"] for receipt in executions}
            status = (
                "denied"
                if "denied" in statuses
                else (
                    "confirmed_stopped"
                    if statuses == {"confirmed_stopped"}
                    else "not_supported" if statuses == {"not_supported"} else "unknown"
                )
            )
            receipt = {"status": status, "request_id": request_id, "executions": executions}
            self._task_cancel_receipts[key] = receipt
            if len(self._task_cancel_receipts) > 512:
                self._task_cancel_receipts.pop(next(iter(self._task_cancel_receipts)))
            return copy.deepcopy(receipt)

    async def broadcast_execute(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        server_filter: Optional[Callable[[MCPConnection], bool]] = None,
    ) -> Dict[str, MCPExecuteResponse]:
        """Execute a tool across multiple servers with tracing."""
        with trace_span(
            "mcp_registry.broadcast_execute",
            attributes={
                "ai_osop.mcp.tool_name": safe_label(tool_name),
            },
        ):
            results = {}
            tasks = []

            for server_id, conn in self._servers.items():
                if server_filter and not server_filter(conn):
                    continue
                if tool_name in conn._tools:
                    conn._provenance_recorder = self._provenance_recorder
                    conn.set_budget_callback(self._budget_callback)
                    conn.set_execution_event_callback(self._execution_event_callback)
                    task = conn.execute(
                        MCPExecuteRequest(tool_name=tool_name, parameters=parameters)
                    )
                    tasks.append((server_id, task))

            for server_id, task in tasks:
                try:
                    results[server_id] = await task
                except Exception:
                    results[server_id] = MCPExecuteResponse(
                        request_id="broadcast",
                        status="error",
                        error="MCP broadcast execution failed",
                    )

            return results

    def get_server(self, server_id: str) -> Optional[MCPConnection]:
        return self._servers.get(server_id)

    def reset_circuit(self, server_id: str) -> bool:
        """Reset the circuit breaker for a registered server."""
        conn = self._servers.get(server_id)
        if not conn:
            return False
        conn.reset_circuit()
        return True

    async def ping_server(self, server_id: str) -> Dict[str, Any]:
        """Ping a registered server and return health/latency metadata."""
        conn = self._servers.get(server_id)
        if not conn:
            return {
                "server_id": server_id,
                "status": "not_registered",
                "circuit_state": "unknown",
                "latency_ms": 0,
            }
        return await conn.ping()

    def get_server_manifests(self, server_id: str) -> List[MCPAdapterManifest]:
        """Return manifests for all tools on the specified server."""
        conn = self._servers.get(server_id)
        if not conn:
            return []
        return conn.get_manifests()

    def get_all_manifests(self) -> Dict[str, List[MCPAdapterManifest]]:
        """Return all manifests grouped by server ID."""
        return {server_id: conn.get_manifests() for server_id, conn in self._servers.items()}

    def get_server_circuit_status(self, server_id: str) -> Optional[Dict[str, Any]]:
        """Return current circuit breaker metrics for a server."""
        conn = self._servers.get(server_id)
        if not conn:
            return None
        return {
            "server_id": conn.server_id,
            "circuit_state": conn.get_circuit_state(),
            "failure_count": conn._failure_count,
            "success_count": conn._success_count,
            "circuit_open": conn._circuit_open,
            "half_open": conn._half_open,
            "circuit_opened_at": (
                conn._circuit_opened_at.isoformat() if conn._circuit_opened_at else None
            ),
            "last_failure_at": (
                conn._last_failure_at.isoformat() if conn._last_failure_at else None
            ),
            "last_success_at": (
                conn._last_success_at.isoformat() if conn._last_success_at else None
            ),
        }

    async def health_check_all(self) -> Dict[str, bool]:
        """Check health of all registered servers."""
        results = {}
        for server_id, conn in self._servers.items():
            try:
                state = await conn.get_state()
                results[server_id] = state.status == "ready"
            except Exception:
                results[server_id] = False
        return results

    async def close_all(self) -> None:
        """Close all connections."""
        await asyncio.gather(
            *[conn.close() for conn in self._servers.values()], return_exceptions=True
        )
        await self._provenance_recorder.drain()
        self._servers.clear()
