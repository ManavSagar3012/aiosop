"""Durable, non-replaying lifecycle callback consumer.

Every task completion has a persisted callback intent. We claim it across
replicas, execute follow-up projection only after current authorization, and
record the final acknowledgement. An expired claimed callback is marked
unknown rather than replaying an arbitrary external side effect twice.
"""

import asyncio
import uuid
from typing import Any, Awaitable, Callable, Dict, Optional

import structlog

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.memory.session_memory import ExecutionFlowORM, TaskORM
from ai_osop.core.models import ScopeDefinition
from ai_osop.safety.scope import ScopeEnforcer, validate_payload_targets
from sqlalchemy import select

logger = structlog.get_logger("ai_osop.orchestrator.terminal_dispatcher")


class TerminalCallbackDispatcher:
    def __init__(self, orchestrator: Any, interval: float = 2.0) -> None:
        self.orch = orchestrator
        self.store = orchestrator.terminal_store
        self.interval = max(0.1, interval)
        self.worker_id = "callbacks-" + uuid.uuid4().hex
        self._task: Optional[asyncio.Task] = None
        self._comparison_cursor: Optional[str] = None

    async def _load_authorized_task(self, engagement_id: str, task_id: str) -> Task:
        """Read the database, not a potentially stale Redis task cache."""
        async with self.store._sessions() as db:
            engagement, task = await self.store._guard(
                db, engagement_id, task_id, require_window=True
            )
            validate_payload_targets(
                ScopeEnforcer(ScopeDefinition(**engagement.scope)),
                task.payload or {},
            )
            if task.status not in {"completed", "failed"}:
                raise RuntimeError("Terminal callback lost authoritative task status")
            if task.flow_id:
                flow = (
                    await db.execute(
                        select(ExecutionFlowORM).where(
                            ExecutionFlowORM.id == task.flow_id,
                            ExecutionFlowORM.engagement_id == engagement_id,
                        )
                    )
                ).scalar_one_or_none()
                if flow is None or flow.status not in {"pending", "running"}:
                    raise RuntimeError("Flow was paused or closed before callback")
            controls = await self.store.list_controls(engagement_id, task_id, 1)
            if controls and controls[0]["action"] in {"pause", "cancel", "stop"}:
                raise RuntimeError("Operator control blocks callback")
            return Task(
                id=task.id,
                type=task.type,
                priority=task.priority,
                agent_type=AgentType(task.agent_type),
                payload=task.payload or {},
                dependencies=task.dependencies or [],
                max_retries=task.max_retries,
                timeout_seconds=task.timeout_seconds,
                scope_check=task.scope_check,
                approval_required=task.approval_required,
                status=task.status,
                result=task.result or {"status": task.status},
                retry_count=task.retry_count,
                created_at=task.created_at,
                started_at=task.started_at,
                completed_at=task.completed_at,
                engagement_id=task.engagement_id,
                assigned_agent_id=task.assigned_agent_id,
                flow_id=task.flow_id,
                subtask_id=task.subtask_id,
                parent_task_id=task.parent_task_id,
            )

    async def _project(self, item: Dict[str, Any]) -> None:
        await self._check_callback_owner(item)
        task = await self._load_authorized_task(item["engagement_id"], item["task_id"])
        self.orch._tasks[task.id] = task
        safe = task.result or {"status": task.status}
        effects = ["sync_subtask", "graph_upsert"]
        # An opted-in signed graph research index must be projected only from
        # durable attested MCP receipts, never from ordinary graph upsert or
        # agent-authored success prose. Its callback effect is fenced/persisted.
        from ai_osop.memory.graph_research_context import research_enabled

        signed_replay_observation = (
            task.status == "completed"
            and getattr(task, "type", None) == "navigate"
            and bool(task.flow_id)
            and isinstance(getattr(task, "payload", None), dict)
            and type(task.payload.get("_authorization_version")) is int
            and isinstance(task.result, dict)
            and task.result.get("verification_status") == "provider_testimony_only"
            and task.result.get("authorization_violation_verified") is False
        )
        if (
            task.status == "completed"
            and getattr(task, "flow_id", None)
            and (research_enabled() or signed_replay_observation)
        ):
            # Replay receipts must be projected into the existing signed
            # ToolAction provenance graph even when model retrieval from that
            # index is disabled. The projection itself verifies the original
            # PostgreSQL Task and signed provider event independently; graph
            # writing is not evidence of a real authorization flaw.
            effects.append("signed_graph_research")
        if signed_replay_observation and task.payload.get("_comparison_role") in {
            "source",
            "target",
        }:
            effects.append("signed_diff_comparison")
        if task.status == "completed":
            effects.extend(["flow_refinement", "downstream_schedule", "surface_continuation"])
            if getattr(self.orch, "adaptive_planner", None) is not None:
                effects.append("adaptive_planner")
        saved_plan = item.get("effect_steps")
        if saved_plan is not None:
            # On replacement the callback must use the exact committed plan.
            # An optional feature toggle or different agent registry after a
            # restart must not invalidate an already acknowledged checkpoint.
            # Preserve each done prefix: start_callback_effect skips it.
            saved = saved_plan.get("order") if isinstance(saved_plan, dict) else None
            required = {"sync_subtask", "graph_upsert"}
            if task.status == "completed":
                required.update({"flow_refinement", "downstream_schedule", "surface_continuation"})
            if signed_replay_observation:
                required.add("signed_graph_research")
                if task.payload.get("_comparison_role") in {"source", "target"}:
                    required.add("signed_diff_comparison")
            if (
                not isinstance(saved, list)
                or len(saved) != len(set(saved))
                or saved[:2] != ["sync_subtask", "graph_upsert"]
                or not required.issubset(set(saved))
                or set(saved) - set(effects) - {"signed_graph_research", "adaptive_planner"}
                or (task.status != "completed" and set(saved) - required)
            ):
                raise RuntimeError("Stored callback manifest no longer matches signed task")
            effects = list(saved)
        # Commit the whole expected plan before invoking even the first
        # potentially consequential downstream action. A missing plan is
        # NEVER evidence that no callback work remained.
        if not await self.store.plan_callback_effects(
            item["id"], item["lease_id"], self.worker_id, effects
        ):
            raise RuntimeError("Unable to persist callback effect plan")
        await self._apply_effect(
            item,
            "sync_subtask",
            lambda: self.orch._sync_subtask_result(task, task.status, safe),
        )
        await self._apply_effect(
            item,
            "graph_upsert",
            lambda: self.orch.graph_memory.upsert_task(
                task, result_summary={"status": task.status}
            ),
        )
        if "signed_graph_research" in effects:
            from ai_osop.memory.graph_research_projection import (
                project_verified_mcp_action,
            )

            await self._apply_effect(
                item,
                "signed_graph_research",
                lambda: project_verified_mcp_action(
                    memory=self.orch.session_memory,
                    supervision=self.orch.supervision_store,
                    graph=self.orch.graph_memory,
                    engagement_id=task.engagement_id,
                    task_id=task.id,
                ),
            )
        if "signed_diff_comparison" in effects:
            from ai_osop.core.signed_replay_comparison import (
                persist_verified_replay_comparison,
            )

            await self._apply_effect(
                item,
                "signed_diff_comparison",
                lambda: persist_verified_replay_comparison(
                    memory=self.orch.session_memory,
                    supervision=self.orch.supervision_store,
                    graph=self.orch.graph_memory,
                    engagement_id=task.engagement_id,
                    terminal_task_id=task.id,
                ),
            )
        if task.status == "completed":
            await self._apply_effect(
                item,
                "flow_refinement",
                lambda: self.orch._refine_completed_flow_subtask(task, safe),
            )
            await self._apply_effect(
                item,
                "downstream_schedule",
                lambda: self.orch._trigger_downstream_tasks(task),
            )
            await self._apply_effect(
                item,
                "surface_continuation",
                lambda: self.orch._chain_authenticated_surface(task, safe),
            )
            if "adaptive_planner" in effects:
                await self._apply_effect(
                    item,
                    "adaptive_planner",
                    lambda: self.orch.adaptive_planner.on_task_completed(task),
                )

    async def _apply_effect(
        self, item: Dict[str, Any], step: str, action: Callable[[], Awaitable[Any]]
    ) -> None:
        # A previously returned step is never invoked twice; a previously
        # started step with an unverified return is quarantined by the store.
        await self._check_callback_owner(item)
        await self._load_authorized_task(item["engagement_id"], item["task_id"])
        should_execute = await self.store.start_callback_effect(
            item["id"], item["lease_id"], self.worker_id, step
        )
        if not should_execute:
            return
        # Fencing is checked again *after* the write-ahead intent commit.
        # A lost lease between planning and admission must not start a tool.
        await self._check_callback_owner(item)
        # The durable write-ahead admission itself awaited PostgreSQL. During
        # that window signed ROE, Flow state or the terminal Task may have
        # been revoked/rebound. Lease renewal alone does not check authority.
        # Re-read the *same* completed source before any callback side effect;
        # a failed check leaves the started effect UNKNOWN, never replayed.
        current = await self._load_authorized_task(item["engagement_id"], item["task_id"])
        if current.id != item["task_id"] or current.engagement_id != item["engagement_id"]:
            raise RuntimeError("Callback source identity changed after admission")
        await self._check_callback_owner(item)
        await action()
        if not await self.store.confirm_callback_effect(
            item["id"], item["lease_id"], self.worker_id, step
        ):
            raise RuntimeError("Callback ownership lost before effect receipt")

    async def _check_callback_owner(self, item: Dict[str, Any]) -> None:
        renewed = await self.store.renew_callback_lease(
            item["id"], item["lease_id"], self.worker_id, lease_seconds=30
        )
        if renewed is not True:
            raise RuntimeError("Terminal callback ownership expired or changed")

    async def flush_once(self) -> int:
        claimed = await self.store.claim_callbacks(self.worker_id, limit=10)
        completed = 0
        for item in claimed:
            projection_returned = False
            try:
                await self._project_with_owner_monitor(item)
                projection_returned = True
                await self._check_callback_owner(item)
                if await self.store.finish_callback(item["id"], item["lease_id"]):
                    completed += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if projection_returned:
                    # All effects returned and committed their own receipts.
                    # A failed *final ACK* must not turn an otherwise complete
                    # callback UNKNOWN: leave the lease to expire so the
                    # PostgreSQL reaper can independently inspect every done
                    # checkpoint and finish its outbox notification safely.
                    logger.warning(
                        "terminal_callback_ack_unconfirmed",
                        task_id=item["task_id"],
                        error_class=type(exc).__name__,
                    )
                    continue
                # The projection may have performed side effects before its
                # exception. Never resubmit it without a reconciliation plan.
                try:
                    await self.store.finish_callback(item["id"], item["lease_id"], status="unknown")
                except Exception:
                    pass
                logger.warning(
                    "terminal_callback_unknown",
                    task_id=item["task_id"],
                    error_class=type(exc).__name__,
                )
        # A signed source callback may have returned BEFORE the target
        # completed. If the target's callback is lost, no callback is left to
        # record the pair. Inspect committed PG terminal receipts independently
        # of callback ACKs. This is only a local read/compare/action append.
        await self._reconcile_completed_pairs()
        return completed

    async def _reconcile_completed_pairs(self) -> int:
        listing = getattr(self.store, "list_completed_comparison_pairs", None)
        claiming = getattr(self.store, "claim_completed_comparison_pair", None)
        if not callable(listing) or not callable(claiming):
            return 0
        batch_size = 12
        try:
            candidates = await listing(
                limit=batch_size, after=getattr(self, "_comparison_cursor", None)
            )
        except Exception as exc:
            logger.warning(
                "signed_comparison_recovery_scan_failed",
                error_class=type(exc).__name__,
            )
            return 0
        if not isinstance(candidates, list):
            return 0
        # Keyset pagination prevents one permanently invalid signed candidate
        # from starving every later pair across repeated polling cycles.
        self._comparison_cursor = (
            candidates[-1]["terminal_task_id"] if len(candidates) == batch_size else None
        )
        reconciled = 0
        from ai_osop.core.signed_replay_comparison import persist_verified_replay_comparison

        for item in candidates:
            try:
                engagement_id = item["engagement_id"]
                terminal_task_id = item["terminal_task_id"]
                async with claiming(engagement_id, terminal_task_id) as held:
                    if held is not True:
                        continue
                    # The verifier loads the ORIGINAL source, both actual
                    # PostgreSQL children and independent signed MCP events.
                    # SessionMemory.record_action rechecks ROE/Flow and inserts
                    # an immutable idempotent provider-only comparison action.
                    recorded = await persist_verified_replay_comparison(
                        memory=self.orch.session_memory,
                        supervision=self.orch.supervision_store,
                        graph=self.orch.graph_memory,
                        engagement_id=engagement_id,
                        terminal_task_id=terminal_task_id,
                    )
                    if recorded is True:
                        reconciled += 1
            except asyncio.CancelledError:
                raise
            except PermissionError:
                # Revoked/rotated ROE stays unrecorded, even for two completed
                # browser calls; no replay and no automatic approval.
                continue
            except Exception as exc:
                logger.warning(
                    "signed_comparison_recovery_unknown",
                    error_class=type(exc).__name__,
                )
        return reconciled

    async def _project_with_owner_monitor(self, item: Dict[str, Any]) -> None:
        """Cancel a long-running callback promptly when PostgreSQL ownership is lost.

        Checkpoint guards protect boundaries *between* effects. This monitor
        also protects a callback blocked inside a downstream await. It does
        not claim to undo an external operation that was already accepted.
        """
        await self._check_callback_owner(item)
        projection = asyncio.create_task(self._project(item))

        async def heartbeat() -> None:
            while True:
                await asyncio.sleep(5)
                await self._check_callback_owner(item)

        monitor = asyncio.create_task(heartbeat())
        try:
            finished, _ = await asyncio.wait(
                {projection, monitor}, return_when=asyncio.FIRST_COMPLETED
            )
            if monitor in finished:
                # Even a clean monitor exit is unsafe; no reliable owner
                # heartbeat remains to fence the pending downstream effect.
                if monitor.cancelled():
                    error = RuntimeError("Callback ownership monitor cancelled")
                else:
                    error = monitor.exception() or RuntimeError(
                        "Callback ownership monitor exited unexpectedly"
                    )
                raise RuntimeError("Callback execution lost PostgreSQL ownership") from error
            await projection
            await self._check_callback_owner(item)
        finally:
            for running in (projection, monitor):
                if not running.done():
                    running.cancel()
            # Do not wait indefinitely for a model/tool adapter that refuses
            # coroutine cancellation. Its external outcome remains unknown.
            try:
                await asyncio.wait_for(
                    asyncio.gather(projection, monitor, return_exceptions=True),
                    timeout=1,
                )
            except asyncio.TimeoutError:
                for running in (projection, monitor):
                    if not running.done():
                        running.add_done_callback(
                            lambda future: future.exception() if not future.cancelled() else None
                        )

    async def run(self) -> None:
        while True:
            try:
                await self.flush_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("terminal_callback_poll_failed", error_class=type(exc).__name__)
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
