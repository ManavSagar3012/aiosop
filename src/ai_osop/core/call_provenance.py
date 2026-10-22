"""Sanitized, asynchronous provenance records for MCP and model calls.

This module never stores call arguments, prompts, results, credentials or raw
exception messages. A caller may attach an async action-record persistence
callback (for example, SessionMemory.record_action via a small adapter).
"""

import asyncio
import inspect
import logging
import math
import re
import uuid
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Optional, Set

from ai_osop.core.telemetry import RequestContext

ProvenanceCallback = Callable[[Dict[str, Any]], Awaitable[None]]
_logger = logging.getLogger("ai_osop.provenance")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:/-]{1,90}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")


def safe_label(value: Any) -> str:
    """Allow compact, low-cardinality names; never emit arbitrary strings."""
    if not isinstance(value, str) or not _SAFE_LABEL.fullmatch(value):
        return "unknown"
    return value


def _safe_id(value: Any, prefix: str) -> Optional[str]:
    if isinstance(value, str) and value.startswith(prefix) and _SAFE_ID.fullmatch(value):
        return value
    return None


def _safe_trace_id(value: Any) -> Optional[str]:
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return value.lower()
    return None


def _nonnegative_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0 or int(value) != value:
        return None
    return int(value)


def _nonnegative_amount(value: Any) -> Optional[float]:
    """Use an explicit provider billed amount; never estimate from price lists."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return float(value)


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else getattr(value, key, None)


def provider_usage(response: Any) -> Dict[str, Any]:
    """Capture only explicit usage and billed cost fields from a provider response.

    Hidden LiteLLM response_cost is deliberately ignored: it can be calculated
    from a pricing table and is not evidence of the provider's actual bill.
    """
    usage = _field(response, "usage")
    input_tokens = _nonnegative_int(_field(usage, "prompt_tokens"))
    if input_tokens is None:
        input_tokens = _nonnegative_int(_field(usage, "input_tokens"))
    output_tokens = _nonnegative_int(_field(usage, "completion_tokens"))
    if output_tokens is None:
        output_tokens = _nonnegative_int(_field(usage, "output_tokens"))

    cost = None
    for source, key in (
        (usage, "billed_cost_usd"),
        (usage, "total_cost_usd"),
        (usage, "cost_usd"),
        (response, "provider_billed_cost_usd"),
        (response, "billed_cost_usd"),
    ):
        cost = _nonnegative_amount(_field(source, key))
        if cost is not None:
            break
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "billed_cost_usd": cost,
        "cost_source": "provider_reported" if cost is not None else "unavailable",
    }


def action_provenance(
    tool_name: str,
    outcome: str,
    duration_ms: int,
    *,
    safe_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Produce fields compatible with the ExecutionActionRecord write callback."""
    context = RequestContext.get()
    metadata = safe_metadata or {}
    # Use a fixed allowlist so credentials/arguments cannot be smuggled via
    # untrusted callback metadata.
    approved: Dict[str, Any] = {}
    for key in ("server_id", "provider", "model", "cost_source"):
        if key in metadata:
            approved[key] = safe_label(metadata[key])
    error_class = metadata.get("error_class")
    if isinstance(error_class, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", error_class):
        approved["error_class"] = error_class
    for key in ("input_tokens", "output_tokens"):
        numeric = _nonnegative_int(metadata.get(key))
        if numeric is not None:
            approved[key] = numeric
    billed = _nonnegative_amount(metadata.get("billed_cost_usd"))
    if billed is not None and approved.get("cost_source") == "provider_reported":
        approved["cost_usd"] = billed
    attempt = _nonnegative_int(metadata.get("attempt"))
    if attempt is not None and attempt > 0:
        approved["retry_count"] = attempt - 1
    request_id = _safe_id(metadata.get("request_id"), "req-")
    if request_id is not None:
        approved["correlation_id"] = request_id
    parent_request_id = _safe_id(context.get("request_id"), "req-")
    if parent_request_id is not None:
        approved["request_id"] = parent_request_id
    trace_id = _safe_trace_id(context.get("trace_id"))
    if trace_id is not None:
        approved["trace_id"] = trace_id

    return {
        "id": f"act-{uuid.uuid4().hex}",
        "engagement_id": (
            _safe_id(context.get("engagement_id"), "")
            if context.get("engagement_id") != "api-bootstrap"
            else None
        ),
        "flow_id": _safe_id(context.get("flow_id"), "flow-"),
        "task_id": _safe_id(context.get("task_id"), "task-"),
        "subtask_id": _safe_id(context.get("subtask_id"), "subtask-"),
        "tool_name": safe_label(tool_name),
        "outcome": (
            outcome
            if outcome in {"success", "error", "timeout", "unknown", "cancelled", "circuit_open"}
            else "error"
        ),
        "duration_ms": max(0, int(duration_ms)),
        "created_at": datetime.utcnow().isoformat(),
        "safe_metadata": approved,
    }


class BestEffortProvenance:
    """Fire-and-track callback dispatcher; failures never affect the caller."""

    def __init__(self, callback: Optional[ProvenanceCallback] = None, max_pending: int = 256):
        self.callback = callback
        self.max_pending = max_pending
        self._pending: Set[asyncio.Task[None]] = set()

    def set_callback(self, callback: Optional[ProvenanceCallback]) -> None:
        self.callback = callback

    def submit(self, record: Dict[str, Any]) -> None:
        if self.callback is None or record.get("engagement_id") is None:
            return
        if len(self._pending) >= self.max_pending:
            _logger.warning("provenance_queue_full")
            return

        callback = self.callback

        async def _deliver() -> None:
            try:
                outcome = callback(record)
                if inspect.isawaitable(outcome):
                    await outcome
            except Exception:
                # Exceptions can contain upstream credentials or request bodies.
                _logger.warning("provenance_write_failed")

        try:
            task = asyncio.create_task(_deliver())
        except RuntimeError:
            return
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def drain(self, timeout: float = 2.0) -> None:
        """Finish outstanding callbacks on orderly shutdown, up to timeout."""
        if self._pending:
            done, _ = await asyncio.wait(tuple(self._pending), timeout=timeout)
            for task in done:
                if not task.cancelled():
                    task.exception()
