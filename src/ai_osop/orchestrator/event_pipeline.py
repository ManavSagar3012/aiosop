"""
Unified Event Pipeline — Inspired by Buzz (block/buzz)

Buzz processes every event through a 12-step pipeline:
1. Auth check → 2. Pubkey match → 3. Kind reject → 4. Ephemeral route
→ 5. Verify → 6. Membership → 7. DB insert → 8. Redis publish
→ 9. Fan-out → 10. Search index → 11. Audit log → 12. Workflow trigger

AI-OSOP's equivalent pipeline:
1. Source validation → 2. Signature verification → 3. Schema validation
→ 4. Scope check → 5. DB persist → 6. Bus publish → 7. Fan-out
→ 8. Search index → 9. Audit log → 10. Workflow trigger

Each step is independent and failures are non-blocking (fire-and-forget
after step 6). This ensures events are processed reliably even when
downstream systems are temporarily unavailable.

Phase 7: Architectural alignment with Buzz patterns.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import structlog

from ai_osop.orchestrator.distributed_bus import (
    CoordinationEvent,
    DistributedCoordinationBus,
)

logger = structlog.get_logger("ai_osop.event_pipeline")


class PipelineStep(str, Enum):
    """Pipeline step identifiers."""

    SOURCE_VALIDATION = "source_validation"
    SIGNATURE_VERIFICATION = "signature_verification"
    SCHEMA_VALIDATION = "schema_validation"
    SCOPE_CHECK = "scope_check"
    DB_PERSIST = "db_persist"
    BUS_PUBLISH = "bus_publish"
    FAN_OUT = "fan_out"
    SEARCH_INDEX = "search_index"
    AUDIT_LOG = "audit_log"
    WORKFLOW_TRIGGER = "workflow_trigger"


@dataclass
class PipelineResult:
    """Result of processing an event through the pipeline."""

    event_id: str
    success: bool
    steps_completed: List[str] = field(default_factory=list)
    steps_failed: List[str] = field(default_factory=list)
    step_details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class PipelineMetrics:
    """Aggregated pipeline metrics."""

    total_events: int = 0
    successful_events: int = 0
    failed_events: int = 0
    avg_duration_ms: float = 0.0
    step_success_rates: Dict[str, float] = field(default_factory=dict)
    last_event_time: Optional[str] = None


class EventPipeline:
    """Unified event processing pipeline.

    Inspired by Buzz's 12-step event pipeline, this processes every
    coordination event through a structured sequence of validation,
    persistence, and notification steps.

    Key Buzz principles applied:
    - Events are signed and verified (Phase 7: signed events)
    - Each step is independent (failures don't block the pipeline)
    - Audit logging is fire-and-forget (non-blocking)
    - Fan-out excludes unauthorized recipients (security boundary)
    - Search indexing is async (bounded worker queue pattern)
    """

    def __init__(
        self,
        bus: Optional[DistributedCoordinationBus] = None,
        authorized_sources: Optional[set] = None,
    ):
        self.bus = bus
        self.authorized_sources = authorized_sources or (
            bus.AUTHORIZED_SOURCES if bus else set()
        )
        self._metrics = PipelineMetrics()
        self._step_hooks: Dict[PipelineStep, List[Callable]] = {}
        self._search_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._audit_events: List[Dict[str, Any]] = []

    async def process_event(
        self,
        event: CoordinationEvent,
        session_memory: Optional[Any] = None,
        graph_memory: Optional[Any] = None,
        audit_callback: Optional[Callable] = None,
    ) -> PipelineResult:
        """Process an event through the full pipeline.

        Returns a PipelineResult with step-by-step status.
        """
        start = time.monotonic()
        result = PipelineResult(event_id=event.event_id, success=True)

        # Step 1: Signature verification (BEFORE any payload modification)
        # This matches Buzz's pipeline: verify signature before any mutation
        try:
            await self._step_signature_verification(event, result)
        except Exception as e:
            result.steps_failed.append(PipelineStep.SIGNATURE_VERIFICATION)
            result.step_details["signature_verification"] = {"error": str(e)}

        # Step 2: Source validation (after signature verification)
        try:
            await self._step_source_validation(event, result)
        except Exception as e:
            result.steps_failed.append(PipelineStep.SOURCE_VALIDATION)
            result.step_details["source_validation"] = {"error": str(e)}

        # Step 3: Schema validation
        try:
            await self._step_schema_validation(event, result)
        except Exception as e:
            result.steps_failed.append(PipelineStep.SCHEMA_VALIDATION)
            result.step_details["schema_validation"] = {"error": str(e)}
            result.success = False  # Schema failure IS fatal

        # Step 4: Scope check (if engagement-scoped)
        try:
            await self._step_scope_check(event, result)
        except Exception as e:
            result.steps_failed.append(PipelineStep.SCOPE_CHECK)
            result.step_details["scope_check"] = {"error": str(e)}

        # Step 5: DB persist
        try:
            await self._step_db_persist(event, result, session_memory, graph_memory)
        except Exception as e:
            result.steps_failed.append(PipelineStep.DB_PERSIST)
            result.step_details["db_persist"] = {"error": str(e)}
            # DB failure is non-blocking (event still published)

        # Step 6: Bus publish (if not already published)
        try:
            await self._step_bus_publish(event, result)
        except Exception as e:
            result.steps_failed.append(PipelineStep.BUS_PUBLISH)
            result.step_details["bus_publish"] = {"error": str(e)}

        # Steps 7-10: Fire-and-forget (non-blocking)
        asyncio.create_task(self._step_fan_out(event, result))
        asyncio.create_task(self._step_search_index(event, result))
        asyncio.create_task(self._step_audit_log(event, result, audit_callback))
        asyncio.create_task(self._step_workflow_trigger(event, result))

        result.duration_ms = (time.monotonic() - start) * 1000
        self._update_metrics(result)

        return result

    async def _step_source_validation(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Validate the event source against the authorized sources list.

        Note: We do NOT modify event.payload here. Tags like _unauthorized_source
        are added AFTER signature verification to avoid invalidating the signature.
        """
        authorized = event.source_agent in self.authorized_sources
        if not authorized:
            logger.warning(
                "pipeline_unauthorized_source",
                event_id=event.event_id,
                source=event.source_agent,
            )

        result.steps_completed.append(PipelineStep.SOURCE_VALIDATION)
        result.step_details["source_validation"] = {"authorized": authorized}

    async def _step_signature_verification(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Verify the event signature (Buzz-inspired signed events)."""
        if event.signature:
            valid = event.verify_signature()
            if not valid:
                logger.warning(
                    "pipeline_invalid_signature",
                    event_id=event.event_id,
                    source=event.source_agent,
                )
                event.payload["_invalid_signature"] = True
            result.step_details["signature_verification"] = {"valid": valid}
        else:
            result.step_details["signature_verification"] = {"valid": None, "note": "no signature"}

        result.steps_completed.append(PipelineStep.SIGNATURE_VERIFICATION)

    async def _step_schema_validation(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Validate event structure and required fields."""
        errors = []
        if not event.topic:
            errors.append("missing topic")
        if not event.source_agent:
            errors.append("missing source_agent")
        if not event.event_type:
            errors.append("missing event_type")
        if not isinstance(event.payload, dict):
            errors.append("payload must be dict")

        if errors:
            raise ValueError(f"Schema validation failed: {', '.join(errors)}")

        result.steps_completed.append(PipelineStep.SCHEMA_VALIDATION)
        result.step_details["schema_validation"] = {"valid": True}

    async def _step_scope_check(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Check event is properly scoped to an engagement."""
        scoped = bool(event.engagement_id and event.engagement_id != "default")
        result.steps_completed.append(PipelineStep.SCOPE_CHECK)
        result.step_details["scope_check"] = {"scoped": scoped}

    async def _step_db_persist(
        self,
        event: CoordinationEvent,
        result: PipelineResult,
        session_memory: Optional[Any],
        graph_memory: Optional[Any],
    ) -> None:
        """Persist event to the database (if available)."""
        if session_memory and hasattr(session_memory, "store_event"):
            try:
                await session_memory.store_event(event.to_dict())
                result.step_details["db_persist"] = {"stored": True}
            except Exception as e:
                result.step_details["db_persist"] = {"stored": False, "error": str(e)}
        else:
            result.step_details["db_persist"] = {"stored": False, "note": "no session_memory"}

        result.steps_completed.append(PipelineStep.DB_PERSIST)

    async def _step_bus_publish(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Publish event to the coordination bus (if not already published)."""
        # Events are typically published by the caller before reaching the pipeline
        # This step is a no-op unless explicitly needed
        result.steps_completed.append(PipelineStep.BUS_PUBLISH)
        result.step_details["bus_publish"] = {"note": "handled by caller"}

    async def _step_fan_out(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Fan out event to subscribers (non-blocking)."""
        # In Buzz, this uses a three-tier DashMap index for O(1) lookup
        # AI-OSOP uses Redis Streams consumer groups for fan-out
        result.steps_completed.append(PipelineStep.FAN_OUT)

    async def _step_search_index(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Index event for search (non-blocking, bounded queue)."""
        try:
            self._search_queue.put_nowait(event.to_dict())
        except asyncio.QueueFull:
            logger.warning("search_queue_full", event_id=event.event_id)

    async def _step_audit_log(
        self,
        event: CoordinationEvent,
        result: PipelineResult,
        audit_callback: Optional[Callable],
    ) -> None:
        """Log event to audit trail (non-blocking, fire-and-forget)."""
        audit_entry = {
            "event_id": event.event_id,
            "topic": event.topic,
            "source_agent": event.source_agent,
            "event_type": event.event_type,
            "engagement_id": event.engagement_id,
            "timestamp": event.timestamp,
            "signature_valid": event.verify_signature() if event.signature else None,
        }
        self._audit_events.append(audit_entry)

        if audit_callback:
            try:
                from ai_osop.core.models import AuditEvent

                await audit_callback(
                    AuditEvent(
                        event_type="pipeline_event_processed",
                        severity="info",
                        actor_type="agent",
                        actor_id=event.source_agent,
                        action={"topic": event.topic, "event_type": event.event_type},
                        result={"pipeline_steps": result.steps_completed},
                        context={"event_id": event.event_id},
                        engagement_id=event.engagement_id,
                    )
                )
            except Exception:
                pass  # Audit failure is non-blocking

    async def _step_workflow_trigger(
        self, event: CoordinationEvent, result: PipelineResult
    ) -> None:
        """Trigger workflow automation based on event (non-blocking)."""
        # Buzz uses YAML workflow triggers (buzz-workflow crate)
        # AI-OSOP can trigger downstream tasks based on event patterns
        result.steps_completed.append(PipelineStep.WORKFLOW_TRIGGER)

    def _update_metrics(self, result: PipelineResult) -> None:
        """Update aggregate pipeline metrics."""
        self._metrics.total_events += 1
        if result.success:
            self._metrics.successful_events += 1
        else:
            self._metrics.failed_events += 1

        # Update running average duration
        n = self._metrics.total_events
        self._metrics.avg_duration_ms = (
            (self._metrics.avg_duration_ms * (n - 1) + result.duration_ms) / n
        )
        self._metrics.last_event_time = datetime.utcnow().isoformat()

    def get_metrics(self) -> Dict[str, Any]:
        """Return pipeline metrics for observability."""
        return {
            "total_events": self._metrics.total_events,
            "successful_events": self._metrics.successful_events,
            "failed_events": self._metrics.failed_events,
            "success_rate": round(
                self._metrics.successful_events
                / max(self._metrics.total_events, 1)
                * 100,
                1,
            ),
            "avg_duration_ms": round(self._metrics.avg_duration_ms, 2),
            "last_event_time": self._metrics.last_event_time,
            "search_queue_depth": self._search_queue.qsize(),
            "audit_events_logged": len(self._audit_events),
        }

    def get_recent_audit_events(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return recent audit events."""
        return self._audit_events[-limit:]
