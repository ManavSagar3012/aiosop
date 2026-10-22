"""Authenticated operator view and durable supervision commands for task agents."""

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from starlette.responses import StreamingResponse

from ai_osop.api.deps import assert_engagement_access, require_role, state, verify_token
from ai_osop.memory.supervision_store import SupervisionConflict, SupervisionStore
from ai_osop.memory.model_usage import ModelUsageLedger

router = APIRouter(prefix="/supervision", tags=["supervision"])
_MAX_SUPERVISION_SEQUENCE = 9223372036854775807  # PostgreSQL BIGINT / Identity
_MAX_SUPERVISION_SSE_ROW_BYTES = 8192


@router.get("/engagements/{engagement_id}/model-usage")
async def get_model_usage(
    engagement_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator)
    return {"usage": await ModelUsageLedger(store.session_memory).summary(engagement_id)}


@router.get("/engagements/{engagement_id}/model-usage/unreconciled")
async def get_unreconciled_model_calls(
    engagement_id: str,
    limit: int = Query(100, ge=1, le=200),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Show unresolved provider-call identities without authorizing retries."""
    store = await _access(engagement_id, operator)
    return {
        "calls": await ModelUsageLedger(store.session_memory).list_unreconciled(
            engagement_id,
            limit=limit,
        ),
        "invoice_reconciled": False,
        "safe_to_retry": False,
    }


@router.get("/engagements/{engagement_id}/mcp-dispatches")
async def get_mcp_dispatches(
    engagement_id: str,
    task_id: Optional[str] = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=200),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Read actual cross-replica remote dispatch outcomes, not inferred stops."""
    store = await _access(engagement_id, operator, task_id)
    return {"dispatches": await store.list_mcp_dispatches(engagement_id, task_id, limit)}


class HumanInputRequest(BaseModel):
    task_id: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=1, max_length=4096)
    request_id: str = Field(min_length=1, max_length=128)


class ControlRequest(BaseModel):
    action: str = Field(pattern=r"^(cancel|stop|pause|resume|reconcile)$")
    reason: str = Field(min_length=1, max_length=1024)
    request_id: str = Field(min_length=1, max_length=128)


class MCPReconciliationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    server_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")


class MCPPendingObservationRequest(BaseModel):
    """A bounded observational sweep; never a remote tool retry."""

    model_config = ConfigDict(extra="forbid", strict=True)
    limit: StrictInt = Field(default=6, ge=1, le=8)


class MCPPersistedStopRequest(MCPReconciliationRequest):
    expected_authorization_version: StrictInt = Field(ge=1)
    reason: str = Field(min_length=10, max_length=500)


class TemporalExistenceReconciliationRequest(BaseModel):
    expected_authorization_version: int = Field(ge=1)


@router.post("/engagements/{engagement_id}/tasks/{task_id}/temporal/observe")
async def observe_temporal_request(
    engagement_id: str,
    task_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Read an existing Temporal workflow without issuing a new start.

    A workflow's presence, failure or cancellation says nothing conclusive
    about any external MCP effect. The operator must own the persisted Task;
    no user-supplied status or receipt is accepted as execution authority.
    """
    await _access(engagement_id, operator, task_id)
    unavailable = {
        "task_id": task_id,
        "observation": "unknown",
        "provider_status": "unknown",
        "verified": False,
        "durable_status_changed": False,
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }
    orch = state.get("orchestrator")
    scheduler = getattr(orch, "task_scheduler", None)
    observe = getattr(scheduler, "reconcile_temporal_dispatch", None)
    if not callable(observe):
        return unavailable
    try:
        receipt = await asyncio.wait_for(
            observe(task_id, engagement_id),
            timeout=8.0,
        )
    except Exception:
        return unavailable
    if (
        not isinstance(receipt, dict)
        or receipt.get("task_id") != task_id
        or receipt.get("engagement_id") != engagement_id
        or receipt.get("observation")
        not in {
            "found",
            "not_found",
            "unknown",
            "not_applicable",
        }
        or receipt.get("provider_status")
        not in {
            "running",
            "completed",
            "failed",
            "canceled",
            "terminated",
            "continued_as_new",
            "timed_out",
            "unknown",
        }
    ):
        return unavailable
    # Never copy raw provider data/errors or client-invented success fields
    # into the authenticated UI. Even a verified completed Temporal workflow
    # does not establish any external tool terminated or achieved its effect.
    return {
        "task_id": task_id,
        "observation": receipt["observation"],
        "provider_status": receipt["provider_status"],
        "verified": receipt.get("verified") is True,
        "durable_status_changed": False,
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }


@router.post("/engagements/{engagement_id}/tasks/{task_id}/temporal/reconcile-existence")
async def reconcile_temporal_existence(
    engagement_id: str,
    task_id: str,
    request: TemporalExistenceReconciliationRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Senior-confirmed PG CAS for *workflow existence only*, never effects.

    Only a verified exact Temporal describe receipt supplies run ID/status.
    Missing/ambiguous provider observation is not permission to resubmit.
    External execution/cancel outcomes stay UNKNOWN despite a reconciled
    durable workflow-start receipt.
    """
    await _access(engagement_id, operator, task_id)
    orch = state.get("orchestrator")
    memory = getattr(orch, "session_memory", None)
    scheduler = getattr(orch, "task_scheduler", None)
    if not callable(getattr(scheduler, "reconcile_temporal_dispatch", None)) or not callable(
        getattr(memory, "reconcile_temporal_dispatch_observation", None)
    ):
        raise HTTPException(status_code=503, detail="Durable Temporal reconciliation unavailable")
    task = await memory.load_task_authoritative(task_id)
    if task is None or task.engagement_id != engagement_id or not isinstance(task.payload, dict):
        raise HTTPException(status_code=404, detail="Owned execution Task unavailable")
    if (
        type(task.payload.get("_authorization_version")) is not int
        or task.payload["_authorization_version"] != request.expected_authorization_version
    ):
        raise HTTPException(status_code=409, detail="Signed authorization revision changed")
    if (
        task.status != "dispatch_unknown"
        or not isinstance(task.result, dict)
        or (task.result.get("reason") != "temporal_start_unverified")
    ):
        raise HTTPException(
            status_code=409, detail="Task is not awaiting workflow-start reconciliation"
        )
    try:
        receipt = await asyncio.wait_for(
            scheduler.reconcile_temporal_dispatch(task_id, engagement_id), timeout=8.0
        )
    except Exception:
        return {
            "task_id": task_id,
            "reconciled_workflow_existence": False,
            "provider_observation": "unknown",
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }
    if (
        not isinstance(receipt, dict)
        or receipt.get("task_id") != task_id
        or receipt.get("engagement_id") != engagement_id
        or receipt.get("verified") is not True
        or receipt.get("observation") != "found"
        or receipt.get("workflow_id") != "ai-osop-" + task_id
        or not isinstance(receipt.get("run_id"), str)
        or not receipt["run_id"]
        or receipt.get("provider_status")
        not in {
            "running",
            "completed",
            "failed",
            "canceled",
            "terminated",
            "continued_as_new",
            "timed_out",
        }
    ):
        return {
            "task_id": task_id,
            "reconciled_workflow_existence": False,
            "provider_observation": "unknown",
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }
    try:
        updated = await memory.reconcile_temporal_dispatch_observation(
            task_id,
            engagement_id,
            receipt["workflow_id"],
            provider_run_id=receipt["run_id"],
            provider_status=receipt["provider_status"].upper(),
        )
    except (PermissionError, ValueError) as exc:
        raise HTTPException(
            status_code=409,
            detail="Signed authorization or workflow reconciliation changed",
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Durable Temporal receipt unavailable") from exc
    return {
        "task_id": task_id,
        "reconciled_workflow_existence": updated is True,
        "provider_observation": "found",
        "durable_task_status": "scheduled" if updated else "unchanged",
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }


@router.post("/engagements/{engagement_id}/tasks/{task_id}/mcp/reconcile")
async def reconcile_mcp_request(
    engagement_id: str,
    task_id: str,
    request: MCPReconciliationRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Check an existing remote request; never rerun its original tool."""
    store = await _access(engagement_id, operator, task_id)
    if (
        await store.get_mcp_dispatch(engagement_id, task_id, request.server_id, request.request_id)
        is None
    ):
        raise HTTPException(status_code=404, detail="Persisted remote request not found")
    orch = state.get("orchestrator")
    if not callable(getattr(orch, "reconcile_mcp_dispatch", None)):
        return {"status": "unknown", "reason": "worker_unavailable"}
    try:
        outcome = await asyncio.wait_for(
            orch.reconcile_mcp_dispatch(
                engagement_id, task_id, request.server_id, request.request_id
            ),
            timeout=10.0,
        )
    except Exception:
        return {"status": "unknown", "reason": "reconciliation_unavailable"}
    if not isinstance(outcome, dict) or outcome.get("status") not in {
        "unknown",
        "running",
        "confirmed_stopped",
        "confirmed_finished",
        "not_supported",
        "denied",
    }:
        return {"status": "unknown", "reason": "unverified_provider_receipt"}
    return {
        "status": outcome["status"],
        "persisted_status": outcome.get("persisted_status", "outcome_unknown"),
        "request_id": request.request_id,
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }


@router.post("/engagements/{engagement_id}/tasks/{task_id}/mcp/reconcile-pending")
async def reconcile_pending_mcp_requests(
    engagement_id: str,
    task_id: str,
    request: MCPPendingObservationRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Observe a bounded set of durable UNKNOWN dispatches without replay.

    Original PostgreSQL dispatch identity is the only input to the underlying
    provider status query. No request parameters or consequential tools can
    be reconstructed from this endpoint. One account's Task cannot sweep
    another owner's records. Provider status is never proof of physical effect.
    """
    store = await _access(engagement_id, operator, task_id)
    rows = await store.list_mcp_dispatches(engagement_id, task_id, 100)
    if not isinstance(rows, list):
        raise HTTPException(status_code=503, detail="Durable remote inventory unavailable")
    unknown = {
        "accepted_unconfirmed",
        "started_unknown",
        "outcome_unknown",
        "provider_returned",
        "cancel_requested",
        "provider_running",
    }
    candidates = []
    identities = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("status") not in unknown:
            continue
        if row.get("task_id") != task_id:
            raise HTTPException(status_code=503, detail="Durable remote identity mismatch")
        key = (row.get("server_id"), row.get("request_id"))
        if (
            not all(isinstance(value, str) and 0 < len(value) <= 128 for value in key)
            or key in identities
        ):
            raise HTTPException(status_code=503, detail="Durable remote identity ambiguous")
        identities.add(key)
        candidates.append(key)
    orch = state.get("orchestrator")
    observe = getattr(orch, "reconcile_mcp_dispatch", None)
    if not callable(observe):
        return {
            "observed": [],
            "unavailable": True,
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }
    observed = []
    for server_id, request_id in candidates[: request.limit]:
        # Recheck current ownership on every network-bound operation, not just
        # once before a potentially slow sweep. The MCP connection also
        # revalidates the signed version on its own admission boundary.
        await _access(engagement_id, operator, task_id)
        try:
            outcome = await asyncio.wait_for(
                observe(engagement_id, task_id, server_id, request_id),
                timeout=6.0,
            )
        except Exception:
            outcome = None
        status = "unknown"
        persisted = "outcome_unknown"
        if (
            isinstance(outcome, dict)
            and outcome.get("request_id") == request_id
            and outcome.get("status")
            in {
                "unknown",
                "running",
                "confirmed_stopped",
                "confirmed_finished",
                "not_supported",
                "denied",
            }
            and outcome.get("persisted_status")
            in {
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
            status, persisted = outcome["status"], outcome["persisted_status"]
            if (status == "running" and persisted != "provider_running") or (
                status in {"confirmed_stopped", "confirmed_finished"} and persisted != status
            ):
                status = "unknown"
        observed.append(
            {
                "server_id": server_id,
                "request_id": request_id,
                "status": status,
                "persisted_status": persisted,
                "safe_to_retry": False,
                "external_effect_status": "unknown",
            }
        )
    return {
        "observed": observed,
        "remaining_unobserved": max(0, len(candidates) - len(observed)),
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }


@router.post("/engagements/{engagement_id}/tasks/{task_id}/mcp/cancel-persisted")
async def stop_persisted_remote_request(
    engagement_id: str,
    task_id: str,
    request: MCPPersistedStopRequest,
    operator: Dict[str, Any] = Depends(require_role("senior_operator")),
) -> Dict[str, Any]:
    """Senior-only durable one-shot stop of a previously admitted remote job.

    The scheduler never repeats a failed/UNKNOWN stop. This action does not
    invoke the original tool, and an accepted cancellation or provider-signed
    stop remains distinct from independent physical target-side termination.
    """
    store = await _access(engagement_id, operator, task_id)
    original = await store.get_mcp_dispatch(
        engagement_id,
        task_id,
        request.server_id,
        request.request_id,
    )
    if original is None:
        raise HTTPException(status_code=404, detail="Original remote dispatch not found")
    if original.get("authorization_version") != request.expected_authorization_version:
        raise HTTPException(status_code=409, detail="Remote dispatch signed version changed")
    orch = state.get("orchestrator")
    stop = getattr(orch, "cancel_persisted_mcp_dispatch", None)
    if not callable(stop):
        return {
            "status": "unknown",
            "persisted_status": original["status"],
            "provider_reported_stop": False,
            "remote_stopped": False,
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }
    # No HTTP retry after this invocation: the PG one-shot claim fences any
    # crash or timeout before an independently signed status reconciliation.
    try:
        outcome = await asyncio.wait_for(
            stop(
                engagement_id,
                task_id,
                request.server_id,
                request.request_id,
                actor_id=str(operator["sub"]),
                reason=request.reason.strip(),
                expected_authorization_version=request.expected_authorization_version,
            ),
            timeout=9.0,
        )
    except Exception:
        outcome = None
    verified = (
        isinstance(outcome, dict)
        and outcome.get("status") == "confirmed_stopped"
        and outcome.get("provider_reported_stop") is True
        and outcome.get("persisted_status") == "confirmed_stopped"
    )
    return {
        "status": "confirmed_stopped" if verified else "unknown",
        "persisted_status": (
            outcome.get("persisted_status", "unknown") if isinstance(outcome, dict) else "unknown"
        ),
        "provider_reported_stop": verified,
        "remote_stopped": False,
        "safe_to_retry": False,
        "external_effect_status": "unknown",
    }


def _supervision() -> SupervisionStore:
    orch = state.get("orchestrator")
    if orch is None or getattr(orch, "session_memory", None) is None:
        raise HTTPException(status_code=503, detail="Supervision storage unavailable")
    store = getattr(orch, "supervision_store", None)
    if isinstance(store, SupervisionStore):
        return store
    # Read-only API deployment with an older orchestrator retains durable DB access.
    return SupervisionStore(orch.session_memory)


async def _access(
    engagement_id: str,
    operator: Dict[str, Any],
    task_id: Optional[str] = None,
) -> SupervisionStore:
    await assert_engagement_access(operator, engagement_id)
    store = _supervision()
    try:
        await store.assert_access(
            engagement_id, str(operator["sub"]), str(operator["role"]), task_id
        )
    except SupervisionConflict as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return store


def _control_error(exc: SupervisionConflict) -> HTTPException:
    return HTTPException(status_code=409, detail=str(exc))


@router.get("/engagements/{engagement_id}/events")
async def list_events(
    engagement_id: str,
    task_id: Optional[str] = Query(None, max_length=64),
    limit: int = Query(100, ge=1, le=200),
    after_sequence: Optional[int] = Query(None, ge=0, le=_MAX_SUPERVISION_SEQUENCE),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator, task_id)
    if after_sequence is not None:
        return {
            "events": await store.list_events_after(engagement_id, after_sequence, task_id, limit)
        }
    return {"events": await store.list_events(engagement_id, task_id, limit)}


async def _stream_revalidate(
    request: Request,
    operator: Dict[str, Any],
    engagement_id: str,
    task_id: Optional[str],
) -> SupervisionStore:
    """Re-check credentials and durable ownership on every SSE poll."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer ") or not header[7:].strip():
        raise HTTPException(status_code=401, detail="SSE requires a bearer header")
    current = await verify_token(
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=header[7:].strip()),
        token=None,
    )
    if (current.get("sub"), current.get("role")) != (operator.get("sub"), operator.get("role")):
        raise HTTPException(status_code=403, detail="SSE operator identity changed")
    return await _access(engagement_id, current, task_id)


def _sse_resume_cursor(after_sequence: int, last_event_id: Optional[str]) -> int:
    """Parse a bounded durable cursor without int-conversion DoS or overflow.

    An explicit query cursor wins over EventSource's implicit resume header;
    neither can exceed the underlying PostgreSQL signed BIGINT sequence.
    """
    if type(after_sequence) is not int or not 0 <= after_sequence <= _MAX_SUPERVISION_SEQUENCE:
        raise HTTPException(status_code=422, detail="Invalid supervision event cursor")
    if after_sequence != 0 or not last_event_id:
        return after_sequence
    if (
        type(last_event_id) is not str
        or len(last_event_id) > 19
        or not last_event_id.isascii()
        or not last_event_id.isdecimal()
    ):
        raise HTTPException(status_code=422, detail="Invalid supervision event cursor")
    cursor = int(last_event_id)
    if cursor > _MAX_SUPERVISION_SEQUENCE:
        raise HTTPException(status_code=422, detail="Invalid supervision event cursor")
    return cursor


def _sse_committed_event(
    event: Any, *, engagement_id: str, task_id: Optional[str], after_sequence: int
) -> Optional[tuple[int, str]]:
    """Accept only a bounded committed row for the currently authorized tenant.

    The SQL store ordinarily supplies these identities. Checking them again at
    the streaming boundary prevents a faulty cache/fake/replica adapter from
    turning a cross-tenant result into an SSE publication. A reused cursor is
    ignored; an invalid sequence must never turn into a resumable event ID.
    """
    if not isinstance(event, dict):
        raise ValueError("Invalid committed supervision event")
    sequence = event.get("sequence")
    if (
        type(sequence) is not int
        or not 1 <= sequence <= _MAX_SUPERVISION_SEQUENCE
        or event.get("engagement_id") != engagement_id
        or (task_id is not None and event.get("task_id") != task_id)
        or not isinstance(event.get("payload"), dict)
    ):
        raise ValueError("Committed supervision event identity unavailable")
    if sequence <= after_sequence:
        return None
    payload = json.dumps(
        event,
        default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    if len(payload.encode("utf-8")) > _MAX_SUPERVISION_SSE_ROW_BYTES:
        raise ValueError("Committed supervision event is too large")
    return sequence, payload


@router.get("/engagements/{engagement_id}/events/stream")
async def stream_events(
    engagement_id: str,
    request: Request,
    after_sequence: int = Query(0, ge=0, le=_MAX_SUPERVISION_SEQUENCE),
    task_id: Optional[str] = Query(None, max_length=64),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> StreamingResponse:
    await _stream_revalidate(request, operator, engagement_id, task_id)
    cursor = _sse_resume_cursor(after_sequence, request.headers.get("last-event-id"))

    async def generate():
        nonlocal cursor
        last_heartbeat = asyncio.get_running_loop().time()
        # Capped streams reconnect with Last-Event-ID; continually revalidate
        # token expiry and durable engagement ownership while connected.
        for _ in range(300):
            if await request.is_disconnected():
                break
            try:
                store = await _stream_revalidate(request, operator, engagement_id, task_id)
                events = await store.list_events_after(engagement_id, cursor, task_id, 100)
            except (HTTPException, SupervisionConflict):
                yield "event: auth_required\ndata: {}\n\n"
                break
            except Exception:
                yield "event: unavailable\ndata: {}\n\n"
                break
            for event in events:
                try:
                    # Revocation can commit between the batch SELECT and the
                    # next item. Never publish an additional row using only
                    # the authorization checked before that earlier SELECT.
                    await _stream_revalidate(request, operator, engagement_id, task_id)
                except (HTTPException, SupervisionConflict):
                    yield "event: auth_required\ndata: {}\n\n"
                    return
                except Exception:
                    yield "event: unavailable\ndata: {}\n\n"
                    return
                try:
                    checked = _sse_committed_event(
                        event, engagement_id=engagement_id, task_id=task_id, after_sequence=cursor
                    )
                except (ValueError, TypeError):
                    yield "event: unavailable\ndata: {}\n\n"
                    return
                if checked is None:
                    continue
                sequence, payload = checked
                # JSON serialization and any async pause can outlive the last
                # authorization read. Revalidate immediately before handing a
                # complete frame to ASGI, and never yield after disconnect.
                # This narrows (but cannot eliminate) revocation that races
                # with ASGI transport publication; no automatic ACK is sent.
                try:
                    if await request.is_disconnected():
                        return
                    await _stream_revalidate(request, operator, engagement_id, task_id)
                except (HTTPException, SupervisionConflict):
                    yield "event: auth_required\ndata: {}\n\n"
                    return
                except Exception:
                    yield "event: unavailable\ndata: {}\n\n"
                    return
                yield f"id: {sequence}\nevent: supervision\ndata: {payload}\n\n"
                cursor = sequence
            if asyncio.get_running_loop().time() - last_heartbeat >= 15:
                yield ": heartbeat\n\n"
                last_heartbeat = asyncio.get_running_loop().time()
            await asyncio.sleep(1)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/engagements/{engagement_id}/tasks/{task_id}/attempts")
async def list_attempts(
    engagement_id: str,
    task_id: str,
    limit: int = Query(100, ge=1, le=200),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator, task_id)
    return {"attempts": await store.list_attempts(engagement_id, task_id, limit)}


@router.get("/engagements/{engagement_id}/tasks/{task_id}/terminal-callbacks")
async def list_terminal_callbacks(
    engagement_id: str,
    task_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    """Show authoritative completion/callback state across worker replicas.

    'unknown' is intentionally not a success or a retry authorization.
    Reconciliation requires the provider/worker's independently verified
    execution and callback receipts, not a client-provided boolean.
    """
    await _access(engagement_id, operator, task_id)
    from ai_osop.memory.terminal_lifecycle import TerminalLifecycleStore

    return {
        "callbacks": await TerminalLifecycleStore(_supervision().session_memory).list_callbacks(
            engagement_id, task_id, 100
        )
    }


@router.get("/engagements/{engagement_id}/tasks")
async def list_persisted_tasks(
    engagement_id: str,
    limit: int = Query(100, ge=1, le=200),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator)
    return {"tasks": await store.list_tasks(engagement_id, limit)}


@router.get("/engagements/{engagement_id}/tasks/{task_id}/control")
async def get_control(
    engagement_id: str,
    task_id: str,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator, task_id)
    return {"control": await store.get_control(task_id, engagement_id)}


@router.get("/engagements/{engagement_id}/tasks/{task_id}/controls")
async def list_controls(
    engagement_id: str,
    task_id: str,
    limit: int = Query(100, ge=1, le=200),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator, task_id)
    return {"controls": await store.list_controls(engagement_id, task_id, limit)}


@router.post("/engagements/{engagement_id}/tasks/{task_id}/controls", status_code=202)
async def request_control(
    engagement_id: str,
    task_id: str,
    request: ControlRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator, task_id)
    action = "cancel" if request.action == "stop" else request.action
    try:
        control = await store.request_control(
            engagement_id=engagement_id,
            task_id=task_id,
            action=action,
            actor_id=str(operator["sub"]),
            actor_role=str(operator["role"]),
            reason=request.reason,
            request_id=request.request_id,
        )
    except SupervisionConflict as exc:
        raise _control_error(exc) from exc

    # Persist before attempting runtime dispatch. A durable "pending" request
    # is not evidence that Temporal/MCP/worker execution actually stopped.
    if action == "reconcile":
        # Reconciliation requires an authoritative remote receipt. Leave unknown
        # while the worker has not supplied one.
        if control["status"] == "pending":
            await store.resolve_control(
                request.request_id,
                "unknown",
                {"source": "api", "error_code": "receipt_not_available"},
            )
    else:
        orch = state.get("orchestrator")
        if not callable(getattr(orch, "request_task_control", None)):
            if control["status"] == "pending":
                await store.resolve_control(
                    request.request_id,
                    "unknown",
                    {"source": "api", "error_code": "orchestrator_unavailable"},
                )
        elif control["status"] == "pending":
            try:
                # Runtime method owns remote cancellation and authoritative
                # receipt recording. Never infer it from returning without error.
                await orch.request_task_control(
                    engagement_id=engagement_id,
                    task_id=task_id,
                    action=action,
                    request_id=request.request_id,
                )
            except Exception:
                await store.resolve_control(
                    request.request_id,
                    "unknown",
                    {"source": "api", "error_code": "dispatch_uncertain"},
                )
    persisted = await store.load_control(request.request_id)
    if (
        persisted is None
        or persisted["engagement_id"] != engagement_id
        or persisted["task_id"] != task_id
    ):
        raise HTTPException(status_code=503, detail="Committed control state unavailable")
    return {"control": persisted, "execution_stopped": False}


@router.get("/engagements/{engagement_id}/sessions/{session_id}/messages")
async def list_messages(
    engagement_id: str,
    session_id: str,
    limit: int = Query(100, ge=1, le=200),
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator)
    return {"messages": await store.list_messages(engagement_id, session_id, limit)}


@router.post("/engagements/{engagement_id}/sessions/{session_id}/messages", status_code=202)
async def append_human_input(
    engagement_id: str,
    session_id: str,
    request: HumanInputRequest,
    operator: Dict[str, Any] = Depends(require_role("operator", "senior_operator")),
) -> Dict[str, Any]:
    store = await _access(engagement_id, operator, request.task_id)
    try:
        message = await store.append_message(
            engagement_id=engagement_id,
            session_id=session_id,
            task_id=request.task_id,
            role="operator",
            actor_id=str(operator["sub"]),
            actor_role=str(operator["role"]),
            content=request.content,
            idempotency_key=request.request_id,
        )
    except SupervisionConflict as exc:
        raise _control_error(exc) from exc
    # An intervention is durable and can be picked up from the outbox. No
    # existing runtime method guarantees injection into a running agent.
    return {"message": message, "delivery_status": "pending"}
