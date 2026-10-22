"""
Temporal Worker
Durable task execution using Temporal.io workflows.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta
from typing import Any, Dict, Optional

try:
    from temporalio import workflow
    from temporalio import activity as temporal_activity
    from temporalio.client import Client
    from temporalio.common import RetryPolicy, WorkflowIDReusePolicy
    from temporalio.exceptions import WorkflowAlreadyStartedError
    from temporalio.service import RPCError, RPCStatusCode
    from temporalio.worker import Worker
except ModuleNotFoundError:  # pragma: no cover - exercised through availability checks
    workflow = None
    temporal_activity = None
    Client = None
    Worker = None
    RetryPolicy = None
    WorkflowIDReusePolicy = None
    RPCError = None
    RPCStatusCode = None

    class WorkflowAlreadyStartedError(Exception):
        """Fallback type for deterministic scheduler tests without Temporal."""


from ai_osop.core.config import settings


_LEASE_TTL_SECONDS = 30
_HEARTBEAT_INTERVAL_SECONDS = 5.0
_CONTROL_CHECK_SECONDS = 3.0


def _heartbeat_checkpoint(stage: str, task_id: str) -> None:
    """Heartbeat only inside a real Temporal activity, never from test calls.

    The heartbeat is an activity *liveness* signal, not proof that an MCP
    provider terminated. A heartbeat timeout must not authorize a retry.
    """
    if temporal_activity is None:
        return
    try:
        temporal_activity.info()
    except (RuntimeError, LookupError):
        return
    temporal_activity.heartbeat({"stage": stage, "task_id": task_id})


async def _renew_execution_owner(memory: Any, key: str, owner: str) -> None:
    """Compare-and-renew Redis execution ownership, failing closed on loss."""
    renew = getattr(memory, "renew_lock", None)
    try:
        if callable(renew):
            valid = await asyncio.wait_for(
                renew(key, owner, ttl_seconds=_LEASE_TTL_SECONDS),
                timeout=_CONTROL_CHECK_SECONDS,
            )
        else:
            get_redis = getattr(memory, "_ensure_redis", None)
            if not callable(get_redis):
                raise RuntimeError("Atomic Redis lease renewal unavailable")
            redis = await asyncio.wait_for(get_redis(), timeout=_CONTROL_CHECK_SECONDS)
            valid = await asyncio.wait_for(
                redis.eval(
                    'if redis.call("get", KEYS[1]) == ARGV[1] then '
                    'return redis.call("expire", KEYS[1], ARGV[2]) else return 0 end',
                    1, key, owner, _LEASE_TTL_SECONDS,
                ), timeout=_CONTROL_CHECK_SECONDS,
            )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        raise RuntimeError("Execution ownership lease cannot be verified") from exc
    if valid is not True and valid != 1:
        raise RuntimeError("Execution ownership lease expired or changed")


async def _refresh_postgres_lease(
    supervision: Any, engagement_id: str, task_id: str,
    owner_id: str, lease_id: Optional[str],
) -> None:
    """Renew and verify durable ownership before further agent progress."""
    if lease_id is None:
        return
    renew = getattr(supervision, "renew_execution_lease", None)
    check = getattr(supervision, "check_execution_lease", None)
    if not callable(renew) or not callable(check):
        raise RuntimeError("PostgreSQL execution ownership contract unavailable")
    try:
        refreshed = await asyncio.wait_for(
            renew(engagement_id, task_id, owner_id, lease_id,
                  ttl_seconds=_LEASE_TTL_SECONDS),
            timeout=_CONTROL_CHECK_SECONDS,
        )
        if not isinstance(refreshed, dict):
            raise RuntimeError("Durable lease renewal denied")
        still_owned = await asyncio.wait_for(
            check(engagement_id, task_id, owner_id, lease_id),
            timeout=_CONTROL_CHECK_SECONDS,
        )
        if still_owned is not True:
            raise RuntimeError("Durable lease ownership changed")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        raise RuntimeError("PostgreSQL execution ownership lost") from exc


async def _assert_temporal_checkpoint(
    memory: Any, task: Any, *, check_controls: Optional[Any] = None,
    allow_terminal_result: bool = False,
) -> None:
    """Revalidate authoritative task, ROE and controls between side effects."""
    from ai_osop.safety.scope import (
        ScopeEnforcer, action_requires_approval, validate_payload_targets,
    )

    try:
        from ai_osop.memory.session_memory import SessionMemory

        durable_task_reader = (
            getattr(memory, "load_task_authoritative", None)
            if isinstance(memory, SessionMemory) else None
        )
        task_reader = (
            durable_task_reader
            if callable(durable_task_reader)
            else memory.load_task
        )
        persisted_task, engagement = await asyncio.wait_for(
            asyncio.gather(
                task_reader(task.id), memory.load_session_state(task.engagement_id),
            ), timeout=_CONTROL_CHECK_SECONDS,
        )
        if (
            persisted_task is None or engagement is None
            or persisted_task.engagement_id != task.engagement_id
            or (not allow_terminal_result and persisted_task.status not in {
                "scheduled", "running",
            })
            or persisted_task.status in ({
                "cancelled", "halted", "dispatch_unknown",
                "pause_requested", "cancel_requested", "paused",
            } if allow_terminal_result else {
                "cancelled", "halted", "dispatch_unknown", "failed", "completed",
                "pause_requested", "cancel_requested", "paused",
            })
            or engagement.phase in {"halted", "completed"}
            or not engagement.scope.authorization_ref
            or not (engagement.scope.domains or engagement.scope.ips)
        ):
            raise RuntimeError("Temporal task or engagement no longer authorized")
        if isinstance(memory, SessionMemory):
            signed_version = persisted_task.payload.get("_authorization_version")
            if type(signed_version) is not int or signed_version < 1:
                raise RuntimeError("Temporal task missing authorization revision")
            await asyncio.wait_for(
                memory.assert_signed_authorization(
                    task.engagement_id, expected_version=signed_version
                ),
                timeout=_CONTROL_CHECK_SECONDS,
            )
        enforcer = ScopeEnforcer(engagement.scope)
        enforcer.validate_time_window()
        validate_payload_targets(enforcer, persisted_task.payload)
        if persisted_task.approval_required or action_requires_approval(
            persisted_task.type, engagement.scope,
        ):
            approval_id = persisted_task.payload.get("approval_id")
            if not isinstance(approval_id, str) or not approval_id or not await asyncio.wait_for(
                memory.is_task_approved(task.id, task.engagement_id, approval_id),
                timeout=_CONTROL_CHECK_SECONDS,
            ):
                raise RuntimeError("Task approval revoked during Temporal execution")
        if check_controls is not None:
            controls = await asyncio.wait_for(
                check_controls(task.engagement_id, task.id, limit=10),
                timeout=_CONTROL_CHECK_SECONDS,
            )
            if any(
                control.get("action") in {"cancel", "stop", "pause"}
                and control.get("status") in {"pending", "acknowledged"}
                for control in controls
            ):
                raise RuntimeError("Temporal control requires activity stop")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        raise RuntimeError("Temporal execution checkpoint unavailable or denied") from exc


class TemporalUnavailableError(RuntimeError):
    """Raised when Temporal is enabled but the SDK is unavailable."""


def temporal_available() -> bool:
    """Return whether the Temporal Python SDK can be used."""
    return workflow is not None and Client is not None and Worker is not None


def _sandboxed_workflow_runner() -> Any:
    """Keep workflow replay deterministic despite import-time app side effects.

    TaskWorkflow only coordinates execute_activity and contains no direct app
    execution. The ai_osop package is imported as trusted pass-through because
    its package initializer eagerly loads orchestration/logging modules that
    invoke randomness during import, which Temporal's sandbox must reject.
    All non-application workflow imports remain sandboxed.
    """
    if not temporal_available():
        raise TemporalUnavailableError("temporalio is not installed")
    from temporalio.worker.workflow_sandbox import (
        SandboxedWorkflowRunner,
        SandboxRestrictions,
    )

    return SandboxedWorkflowRunner(
        restrictions=SandboxRestrictions.default.with_passthrough_modules("ai_osop")
    )


# Activities
if workflow is not None:

    @workflow.defn
    class TaskWorkflow:
        @workflow.run
        async def run(self, task_data: dict) -> dict:
            execution_timeout = max(1, int(task_data.get("timeout_seconds", 600)))
            result = await workflow.execute_activity(
                "execute_task_activity",
                task_data,
                start_to_close_timeout=timedelta(seconds=execution_timeout),
                heartbeat_timeout=timedelta(seconds=min(15, execution_timeout)),
                # External security scans can have side effects; replaying one
                # automatically could repeat an intrusive request.
                retry_policy=RetryPolicy(maximum_attempts=1),
                # Do not acknowledge workflow cancellation as completed before
                # the activity gets to persist its unknown-outcome quarantine.
                # Temporal cancellation alone never proves remote termination.
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
            )
            return result

    @temporal_activity.defn
    async def execute_task_activity(task_data: dict) -> dict:
        raise RuntimeError(
            "Unbound Temporal activity: start the worker with "
            "TaskActivities(orchestrator).execute_task_activity"
        )

else:

    class TaskWorkflow:  # type: ignore[no-redef]
        """Placeholder used when temporalio is not installed."""

    async def execute_task_activity(task_data: dict) -> dict:
        raise TemporalUnavailableError("temporalio is not installed")


class TemporalTaskScheduler:
    """Small adapter around Temporal workflow startup."""

    def __init__(
        self,
        client: Optional[Any] = None,
        *,
        address: Optional[str] = None,
        namespace: Optional[str] = None,
        task_queue: Optional[str] = None,
    ):
        self.client = client
        self.address = address or settings.temporal_address
        self.namespace = namespace or settings.temporal_namespace
        self.task_queue = task_queue or settings.temporal_task_queue

    async def connect(self) -> None:
        """Connect to Temporal if no client was injected."""
        if self.client is not None:
            return
        if Client is None:
            raise TemporalUnavailableError("temporalio is not installed")

        self.client = await Client.connect(self.address, namespace=self.namespace)

    async def start_task_workflow(self, task_data: Dict[str, Any]) -> str:
        """Start a durable workflow without reusing a previously completed ID.

        Stable IDs plus REJECT_DUPLICATE prevent a lost startup acknowledgement
        or worker restart from replaying an external side-effecting job, even
        if the first workflow has already reached a terminal state.
        """
        await self.connect()
        workflow_id = f"ai-osop-{task_data['id']}"
        workflow_entrypoint = getattr(TaskWorkflow, "run", "TaskWorkflow")
        try:
            options = {"id": workflow_id, "task_queue": self.task_queue}
            if WorkflowIDReusePolicy is not None:
                options["id_reuse_policy"] = WorkflowIDReusePolicy.REJECT_DUPLICATE
            await self.client.start_workflow(
                workflow_entrypoint, task_data, **options,
            )
        except WorkflowAlreadyStartedError:
            # Temporal workflow IDs are stable across reconnects/recovery. If a
            # process died after start_workflow committed but before the local
            # task status was stored, treating AlreadyStarted as success avoids
            # resetting the task or spawning an additional workflow.
            pass
        return workflow_id

    async def observe_task_workflow(self, task_id: str) -> Dict[str, Any]:
        """Read Temporal history for an uncertain launch, without starting work.

        A DescribeWorkflowExecution response establishes only that a matching
        workflow exists and what *Temporal* reports about that workflow. It
        cannot establish completion, cancellation or safety to retry an agent,
        MCP call or other external side effect. A NOT_FOUND response may mean
        history retention expired; it cannot authorize a new start either.
        """
        if not isinstance(task_id, str) or not 0 < len(task_id) <= 64 or any(
            not (char.isascii() and (char.isalnum() or char in "-_"))
            for char in task_id
        ):
            raise ValueError("Invalid Temporal task identity")

        workflow_id = f"ai-osop-{task_id}"
        receipt: Dict[str, Any] = {
            "workflow_id": workflow_id,
            "observation": "unknown",
            "provider_status": "unknown",
            "verified": False,
            "safe_to_retry": False,
            "external_effect_status": "unknown",
        }
        try:
            await asyncio.wait_for(self.connect(), timeout=2.0)
            handle = self.client.get_workflow_handle(workflow_id)
            description = await asyncio.wait_for(handle.describe(), timeout=2.0)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A verified Temporal NOT_FOUND still does not prove that a
            # workflow never ran: history can expire after retention.
            if RPCError is not None and isinstance(exc, RPCError) and (
                exc.status == RPCStatusCode.NOT_FOUND
            ):
                receipt["observation"] = "not_found"
            return receipt

        status_name = getattr(getattr(description, "status", None), "name", "")
        if isinstance(status_name, str):
            status_name = status_name.removeprefix("WORKFLOW_EXECUTION_STATUS_")
        statuses = {
            "RUNNING": "running",
            "COMPLETED": "completed",
            "FAILED": "failed",
            "CANCELED": "canceled",
            "TERMINATED": "terminated",
            "CONTINUED_AS_NEW": "continued_as_new",
            "TIMED_OUT": "timed_out",
        }
        run_id = getattr(description, "run_id", None)
        if (
            getattr(description, "id", None) != workflow_id
            or getattr(description, "namespace", None) != self.namespace
            or getattr(description, "task_queue", None) != self.task_queue
            or getattr(description, "workflow_type", None) != "TaskWorkflow"
            or not isinstance(run_id, str) or not run_id
            or not isinstance(status_name, str) or status_name not in statuses
        ):
            # A mismatched/malformed provider response is never a receipt.
            return receipt

        receipt.update({
            "observation": "found",
            "provider_status": statuses[status_name],
            "verified": True,
            "run_id": run_id,
        })
        return receipt

    async def cancel_task_workflow(self, task_id: str) -> Dict[str, Any]:
        """Return a receipt distinguishing cancel acceptance from termination.

        Temporal's cancel() acknowledges a cancellation *request*. Only a
        verified CANCELED workflow status can establish that it stopped.
        Cancellation of an activity is not proof that an external MCP tool or
        remote process stopped; those have their own cancellation receipts.
        """
        workflow_id = f"ai-osop-{task_id}"
        receipt: Dict[str, Any] = {
            "workflow_id": workflow_id,
            "status": "unknown",
            "accepted": False,
            "verified": False,
        }
        try:
            await asyncio.wait_for(self.connect(), timeout=2.0)
            handle = self.client.get_workflow_handle(workflow_id)
            await asyncio.wait_for(handle.cancel(), timeout=2.0)
            receipt["accepted"] = True
        except asyncio.CancelledError:
            raise
        except Exception:
            # A lost acknowledgement leaves the remote outcome unknown.
            return receipt

        receipt["status"] = "cancellation_requested"
        try:
            description = await asyncio.wait_for(handle.describe(), timeout=1.0)
            status = getattr(description, "status", None)
            status_name = getattr(status, "name", "")
            if status_name in {"WORKFLOW_EXECUTION_STATUS_CANCELED", "CANCELED"}:
                receipt["status"] = "confirmed_stopped"
                receipt["verified"] = True
        except asyncio.CancelledError:
            raise
        except Exception:
            # The cancellation RPC was acknowledged, but verification failed.
            pass
        return receipt


class TaskActivities:
    """Class wrapper for Temporal activities using orchestrator context."""

    def __init__(self, orchestrator: Any):
        self.orchestrator = orchestrator

    async def execute_task_activity(self, task_data: dict) -> dict:
        """Execute a persisted, authorized task with current approval evidence.

        Temporal input is not trusted to carry approval or scope. Always reload
        the task and engagement from the database before dispatching an agent.
        """
        from ai_osop.core.models import Task
        from ai_osop.safety.scope import (
            ScopeEnforcer,
            action_requires_approval,
            validate_payload_targets,
        )

        supplied = Task(**task_data)
        memory = self.orchestrator.session_memory
        # Real workers must not trust a stale Redis task cache after a remote
        # operator stopped the engagement or committed terminal completion.
        durable_task_reader = getattr(memory, "load_task_authoritative", None)
        if callable(durable_task_reader):
            task = await durable_task_reader(supplied.id)
        else:
            task = await memory.load_task(supplied.id)
        if task is None or task.engagement_id != supplied.engagement_id:
            raise RuntimeError("Temporal task has no matching persisted record")
        if task.status in {"completed", "failed", "cancelled"}:
            return {"status": task.status, "task_id": task.id, "already_finalized": True}
        # A worker must never fall back to its process-local engagement when
        # PostgreSQL cannot prove current authorization. The cached copy may
        # predate an operator's halt or scope revocation.
        engagement = await memory.load_session_state(task.engagement_id)
        if engagement is None or engagement.phase in {"halted", "completed"}:
            raise RuntimeError("Persisted engagement is missing or no longer active")
        scope = engagement.scope
        if not scope.authorization_ref or not (scope.domains or scope.ips):
            raise RuntimeError("Explicit authorization and target scope are required")
        enforcer = ScopeEnforcer(scope)
        enforcer.validate_time_window()
        validate_payload_targets(enforcer, task.payload)

        if task.approval_required or action_requires_approval(task.type, scope):
            approval_id = task.payload.get("approval_id")
            approved = isinstance(approval_id, str) and await memory.is_task_approved(
                task.id, task.engagement_id, approval_id
            )
            if not approved:
                raise RuntimeError("No current persisted approval for consequential task")

        # Redis is a short-lived ownership fence, while start_attempt's
        # PostgreSQL uniqueness prevents replay across Redis failovers. Both
        # must succeed before invoking a consequential agent.
        lease_key = f"temporal:execute:{task.engagement_id}:{task.id}"
        lease_owner = f"temporal-{uuid.uuid4().hex}"
        acquire = getattr(memory, "acquire_lock", None)
        if not callable(acquire) or await asyncio.wait_for(
            acquire(lease_key, lease_owner, ttl_seconds=_LEASE_TTL_SECONDS),
            timeout=_CONTROL_CHECK_SECONDS,
        ) is not True:
            raise RuntimeError("Temporal task execution ownership unavailable")
        supervision = self.orchestrator.supervision_store
        pg_lease_id: Optional[str] = None
        try:
            pg_claim = getattr(supervision, "claim_execution_lease", None)
            if not callable(pg_claim) and getattr(
                self.orchestrator, "_supervision_active", False
            ):
                raise RuntimeError("PostgreSQL execution lease backend unavailable")
            if callable(pg_claim):
                lease = await asyncio.wait_for(
                    pg_claim(task.engagement_id, task.id, lease_owner,
                             ttl_seconds=_LEASE_TTL_SECONDS),
                    timeout=_CONTROL_CHECK_SECONDS,
                )
                if (
                    not isinstance(lease, dict)
                    or lease.get("acquired") is not True
                    or not isinstance(lease.get("lease_id"), str)
                    or not lease["lease_id"]
                ):
                    raise RuntimeError("PostgreSQL execution lease denied")
                pg_lease_id = lease["lease_id"]
                await _refresh_postgres_lease(
                    supervision, task.engagement_id, task.id, lease_owner, pg_lease_id,
                )
            attempt_number = max(1, task.retry_count + 1)
            prior = await supervision.list_attempts(task.engagement_id, task.id)
            if any(
                record.get("attempt", 0) >= attempt_number or
                record.get("status") in {"running", "queued", "unknown"}
                for record in prior
            ):
                return {"status": "execution_unknown", "reason": "unresolved_previous_attempt"}
            attempt = await supervision.start_attempt(
                task.engagement_id, task.id, attempt_number,
                status="running", external_id=f"ai-osop-{task.id}",
            )
            if attempt.get("created") is not True:
                # A retry or another worker may own this immutable attempt.
                return {"status": "execution_unknown", "reason": "duplicate_or_unreconciled_attempt"}
            attempt_id = attempt["id"]
            attempt_revision = attempt["revision"]

            monitor_error: Optional[Exception] = None
            monitor_task: Optional[asyncio.Task[Any]] = None
            remote_task: Optional[asyncio.Task[Any]] = None
            try:
                await _renew_execution_owner(memory, lease_key, lease_owner)
                await _refresh_postgres_lease(
                    supervision, task.engagement_id, task.id, lease_owner, pg_lease_id,
                )
                check_controls = getattr(supervision, "list_controls", None)
                await _assert_temporal_checkpoint(
                    memory, task, check_controls=check_controls if callable(check_controls) else None,
                )
                if pg_lease_id is not None:
                    mark_dispatched = getattr(supervision, "mark_execution_dispatched", None)
                    if not callable(mark_dispatched) or await asyncio.wait_for(
                        mark_dispatched(
                            task.engagement_id, task.id, lease_owner, pg_lease_id,
                        ), timeout=_CONTROL_CHECK_SECONDS,
                    ) is not True:
                        raise RuntimeError("Durable dispatch lease transition denied")
                _heartbeat_checkpoint("authorized", task.id)

                if getattr(self.orchestrator, "_supervision_active", False):
                    # The Temporal activity owns the PG attempt. Do not
                    # persist TaskORM terminal status in the agent coroutine:
                    # the terminal + callback intent must commit atomically.
                    remote_task = asyncio.create_task(
                        self.orchestrator._execute_task_durable(
                            task, persist_terminal=False
                        )
                    )
                else:
                    remote_task = asyncio.create_task(
                        self.orchestrator._execute_task_durable(task)
                    )

                async def heartbeat_and_check() -> None:
                    nonlocal monitor_error
                    while True:
                        await asyncio.sleep(_HEARTBEAT_INTERVAL_SECONDS)
                        try:
                            await _renew_execution_owner(memory, lease_key, lease_owner)
                            await _refresh_postgres_lease(
                                supervision, task.engagement_id, task.id,
                                lease_owner, pg_lease_id,
                            )
                            await _assert_temporal_checkpoint(
                                memory, task,
                                check_controls=check_controls if callable(check_controls) else None,
                            )
                            _heartbeat_checkpoint("running", task.id)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            monitor_error = exc
                            remote_task.cancel()
                            return

                monitor_task = asyncio.create_task(heartbeat_and_check())
                done, _ = await asyncio.wait(
                    {remote_task, monitor_task}, return_when=asyncio.FIRST_COMPLETED,
                )
                if monitor_task in done:
                    # The monitor must run until the remote task completes. A
                    # clean return, cancellation or unexpected exception with
                    # monitor_error still None is equally unsafe: no worker
                    # may continue dispatching without a live ownership check.
                    # Do not await an agent that may ignore cancellation.
                    remote_task.cancel()
                    remote_task.add_done_callback(
                        lambda future: future.exception() if not future.cancelled() else None
                    )
                    raise RuntimeError(
                        "Temporal execution lost checkpoint ownership: "
                        "heartbeat monitor terminated before verified completion"
                    ) from (
                        monitor_error if monitor_error is not None
                        else None if monitor_task.cancelled()
                        else monitor_task.exception()
                    )
                result = await remote_task
                if monitor_task.done():
                    raise RuntimeError(
                        "Temporal heartbeat monitor terminated before final checkpoint"
                    )
                await _renew_execution_owner(memory, lease_key, lease_owner)
                await _refresh_postgres_lease(
                    supervision, task.engagement_id, task.id, lease_owner, pg_lease_id,
                )
                await _assert_temporal_checkpoint(
                    memory, task, check_controls=check_controls if callable(check_controls) else None,
                    allow_terminal_result=True,
                )
                if monitor_task.done():
                    raise RuntimeError(
                        "Temporal heartbeat monitor terminated during final checkpoint"
                    )
                _heartbeat_checkpoint("result_received", task.id)
                if not isinstance(result, dict):
                    raise RuntimeError("Temporal agent returned an invalid result")
            except (Exception, asyncio.CancelledError):
                # A disconnected client, cancelled activity or ownership loss
                # cannot establish whether a remote MCP command stopped.
                try:
                    await asyncio.wait_for(
                        supervision.update_attempt(
                            attempt_id, attempt_revision, "unknown",
                            receipt={"outcome": "worker_interrupted"},
                        ),
                        timeout=_CONTROL_CHECK_SECONDS,
                    )
                finally:
                    # Even a stalled persistence backend must not turn lost
                    # monitor ownership into an unbounded activity wait.
                    await asyncio.wait_for(
                        self.orchestrator._quarantine_unknown_execution(task),
                        timeout=_CONTROL_CHECK_SECONDS,
                    )
                raise
            finally:
                if monitor_task is not None:
                    monitor_task.cancel()
                    # A checkpoint dependency may suppress task cancellation.
                    # Cleanup must never trap the Temporal activity indefinitely.
                    await asyncio.wait({monitor_task}, timeout=1.0)
                    monitor_task.add_done_callback(
                        lambda future: future.exception() if not future.cancelled() else None
                    )
            outcome = result.get("status")
            ambiguous = outcome in {"unknown", "execution_unknown", "timeout", "error", "cancelled"}
            final_status = (
                "unknown" if ambiguous else "failed" if outcome == "failed" else "succeeded"
            )
            if getattr(self.orchestrator, "_supervision_active", False):
                # The only path permitted to write authoritative terminal
                # task status. A callback intent and outbox event are committed
                # in the same PostgreSQL transaction as the attempt receipt.
                # No pre-commit task.completed callback is fired here.
                trusted_outcome = "succeeded" if final_status == "succeeded" else "unknown"
                committed = await self.orchestrator.terminal_store.commit_terminal(
                    task.engagement_id,
                    task.id,
                    attempt_id,
                    attempt_revision,
                    trusted_outcome,
                    owner_id=lease_owner,
                    lease_id=pg_lease_id,
                    receipt_code=(
                        "temporal_agent_completed"
                        if trusted_outcome == "succeeded"
                        else "remote_outcome_unverified"
                    ),
                    continuation=result if trusted_outcome == "succeeded" else None,
                )
                if committed is None:
                    raise RuntimeError("Temporal terminal receipt transaction was rejected")
                if trusted_outcome == "unknown":
                    return {
                        "status": "execution_unknown",
                        "task_id": task.id,
                        "reason": "remote_outcome_unverified",
                    }
                return result
            saved = await supervision.update_attempt(
                attempt_id, attempt_revision, final_status,
                receipt={"outcome": str(outcome)[:128]},
            )
            if saved is None:
                raise RuntimeError("Temporal supervision attempt changed during execution")
            if ambiguous:
                await self.orchestrator._quarantine_unknown_execution(task)
                return {"status": "execution_unknown", "task_id": task.id,
                        "reason": "remote_outcome_unverified"}
            if final_status == "succeeded":
                await self.orchestrator._on_task_success(task, result)
            else:
                await self.orchestrator._on_task_failure(task, result)
            return result
        finally:
            if pg_lease_id is not None:
                release_pg = getattr(supervision, "release_execution_lease", None)
                if callable(release_pg):
                    try:
                        await asyncio.wait_for(
                            release_pg(task.engagement_id, task.id, lease_owner, pg_lease_id),
                            timeout=_CONTROL_CHECK_SECONDS,
                        )
                    except Exception:
                        # A stale owner is incapable of releasing a newer lease.
                        pass
            release = getattr(memory, "release_lock", None)
            if callable(release):
                try:
                    await asyncio.wait_for(
                        release(lease_key, lease_owner), timeout=_CONTROL_CHECK_SECONDS,
                    )
                except Exception:
                    # Failure to release expires safely via Redis TTL.
                    pass


if workflow is not None:
    # Decorate TaskActivities.execute_task_activity as a Temporal activity
    TaskActivities.execute_task_activity = temporal_activity.defn(name="execute_task_activity")(
        TaskActivities.execute_task_activity
    )


async def run_worker(activities: Optional[list[Any]] = None) -> None:
    """Run a Temporal worker for AI-OSOP task workflows."""
    if Worker is None:
        raise TemporalUnavailableError("temporalio is not installed")
    if not activities:
        raise ValueError(
            "Temporal worker requires bound activities, such as "
            "TaskActivities(orchestrator).execute_task_activity"
        )

    scheduler = TemporalTaskScheduler()
    await scheduler.connect()
    worker = Worker(
        scheduler.client,
        task_queue=scheduler.task_queue,
        workflows=[TaskWorkflow],
        activities=activities,
        workflow_runner=_sandboxed_workflow_runner(),
    )
    await worker.run()


def build_bound_worker(orchestrator: Any) -> Any:
    """Construct the actual Temporal worker wired to the initialized agent fleet."""
    if Worker is None:
        raise TemporalUnavailableError("temporalio is not installed")
    scheduler = orchestrator.temporal_scheduler
    if scheduler is None or scheduler.client is None:
        raise TemporalUnavailableError("Temporal scheduler must connect before worker startup")
    return Worker(
        scheduler.client,
        task_queue=scheduler.task_queue,
        workflows=[TaskWorkflow],
        activities=[TaskActivities(orchestrator).execute_task_activity],
        workflow_runner=_sandboxed_workflow_runner(),
    )
