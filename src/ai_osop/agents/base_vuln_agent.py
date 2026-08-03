from abc import abstractmethod
from typing import Any, Dict, List, Optional

from ai_osop.agents.base import BaseAgent
from ai_osop.core.models import Task, Vulnerability
from ai_osop.core.validation_ledger import ValidatedFindingEvent, ValidationLedger

# Max chars of an HTTP response body persisted as finding evidence. Bounds graph
# storage and avoids dumping unbounded/PII-heavy bodies while keeping enough of
# the response to demonstrate the vulnerability.
_EVIDENCE_BODY_SNIPPET = 2048


class BaseVulnerabilityAgent(BaseAgent):
    """
    Standardized vulnerability scanner, providing finding persistence and the
    audit-coupled validation ledger write so every finding is tracked.
    """

    async def _create_ledger(self) -> ValidationLedger:
        ledger = ValidationLedger(self.ctx.session_memory)
        await ledger.initialize()
        return ledger

    async def persist_finding(self, vuln: Vulnerability) -> None:
        """Persist a vuln to graph + audit ledger. Idempotent against duplicate IDs.

        AIOSOP-CALIBRATION-CLOSED (2026-08-03): the calibration engine RECORDED
        real validation outcomes (``graph_memory.validate_vulnerability`` ->
        ``record_outcome``, corpus keyed on ``vuln_type``) but the confidence
        emitted here was never derived from them — the loop was open. Every
        standalone scanner and the vuln agent routes through this single method,
        so calibrate HERE using the count-aware Beta-Binomial path: a class with
        decided outcomes is pulled toward its observed accept-rate, while a cold
        class (no outcomes) is returned untouched — nothing is fabricated. The
        raw (pre-calibration) confidence is preserved in ``yield_metadata`` so
        the audit trail stays honest about what the model originally believed.
        """
        original_confidence = vuln.confidence
        try:
            from ai_osop.core.calibration_engine import ConfidenceCalibrationEngine

            engine = ConfidenceCalibrationEngine(self.ctx.session_memory)
            intent = None
            _task = getattr(self.ctx, "current_task", None)
            if _task is not None:
                intent = getattr(_task, "type", None) or None
            calibrated = await engine.calibrate_for_class(
                vuln.confidence, vuln.vuln_type.value, intent
            )
            if calibrated != vuln.confidence:
                meta = dict(vuln.yield_metadata or {})
                meta["raw_confidence"] = round(original_confidence, 4)
                meta["calibration"] = "empirical"
                vuln.yield_metadata = meta
                vuln.confidence = calibrated
        except Exception as e:  # noqa: BLE001 - calibration is advisory, never blocks persistence
            log = getattr(self, "logger", None)
            if log is not None and hasattr(log, "warning"):
                log.warning(
                    "confidence_calibration_skipped",
                    vuln_id=vuln.id,
                    error=str(e)[:200],
                )
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            self.logger.error(f"Failed to add vulnerability {vuln.id} to graph: {e}")

        state = "manual_review" if vuln.confidence < 0.7 else "validated"
        event = ValidatedFindingEvent(
            id=finding_event_id(vuln),
            vuln_id=vuln.id,
            endpoint_id=vuln.endpoint_id or "",
            state=state,
            evidence_summary=vuln.evidence[0].get("proof", "") if vuln.evidence else "",
            trust_score=vuln.confidence,
        )
        try:
            ledger = await self._create_ledger()
            await ledger.record(event)
        except Exception as e:
            # Never let ledger noise kill the pipeline; log only when logger is real.
            log = getattr(self, "logger", None)
            if log is not None and hasattr(log, "warning"):
                log.warning("validation_ledger_record_failed", vuln_id=vuln.id, error=str(e))

    def _build_evidence(
        self,
        *,
        evidence_type: str,
        url: str,
        provenance: str = "http",
        request_details: Optional[Dict[str, Any]] = None,
        response_details: Optional[Dict[str, Any]] = None,
        payload: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Build a standardised evidence list that the scorer can recognise.

        The returned list has a primary entry with ``type`` set to the scanner-
        specific value (e.g. ``mass_assignment``, ``csrf``) AND nested
        ``request`` / ``response`` / ``payload`` sub-dicts so the scorer's
        evidence-kind detection finds them via the ``_EVIDENCE_ALIASES`` table.

        AIOSOP-DEADCODE (2026-08-03): this method was previously nested inside
        ``finding_event_id`` after its early ``return`` — unreachable dead code
        that referenced ``self`` from a module-level function. Hoisted to a real
        method so scanners can emit the standardised evidence shape.

        Args:
            evidence_type: Scanner-specific type (e.g. ``csrf``, ``sqlmap_injection``).
            url: The target URL.
            provenance: Source of the evidence (``http``, ``browser``, ``sqlmap``).
            request_details: Dict with keys ``method``, ``url``, ``headers``, ``body``.
            response_details: Dict with keys ``status``, ``headers``, ``body_snippet``.
            payload: The injected payload string.
            extra: Any additional evidence dict keys.

        Returns:
            A list containing one evidence dict with the standardised shape.
        """
        evidence: Dict[str, Any] = {
            "type": evidence_type,
            "provenance": provenance,
            "url": url,
        }

        # Nest request/response/payload at the top level so the scorer's
        # _evidence_kinds function finds them via key iteration.
        if request_details:
            evidence["request"] = {
                "method": request_details.get("method", "GET"),
                "url": request_details.get("url", url),
                "headers": request_details.get("headers", {}),
                "body": request_details.get("body", ""),
            }
        if response_details:
            body = response_details.get("body_snippet") or response_details.get("body") or ""
            evidence["response"] = {
                "status": response_details.get("status", 0),
                "headers": response_details.get("headers", {}),
                "body_snippet": (body if isinstance(body, str) else str(body))[
                    :_EVIDENCE_BODY_SNIPPET
                ],
            }
        if payload:
            evidence["payload"] = payload

        # Merge extra fields (token, diff, evidence-specific fields)
        if extra:
            evidence.update(extra)

        return [evidence]


def finding_event_id(vuln: Vulnerability) -> str:
    """Stable ID used by the ledger for later state transitions and audits."""
    return f"ledger-{vuln.id}"

    def _build_evidence(
        self,
        *,
        evidence_type: str,
        url: str,
        provenance: str = "http",
        request_details: Optional[Dict[str, Any]] = None,
        response_details: Optional[Dict[str, Any]] = None,
        payload: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Build a standardised evidence list that the scorer can recognise.

        The returned list has a primary entry with ``type`` set to the scanner-
        specific value (e.g. ``mass_assignment``, ``csrf``) AND nested
        ``request`` / ``response`` / ``payload`` sub-dicts so the scorer's
        evidence-kind detection finds them via the ``_EVIDENCE_ALIASES`` table.

        Args:
            evidence_type: Scanner-specific type (e.g. ``csrf``, ``sqlmap_injection``).
            url: The target URL.
            provenance: Source of the evidence (``http``, ``browser``, ``sqlmap``).
            request_details: Dict with keys ``method``, ``url``, ``headers``, ``body``.
            response_details: Dict with keys ``status``, ``headers``, ``body_snippet``.
            payload: The injected payload string.
            extra: Any additional evidence dict keys.

        Returns:
            A list containing one evidence dict with the standardised shape.
        """
        evidence: Dict[str, Any] = {
            "type": evidence_type,
            "provenance": provenance,
            "url": url,
        }

        # Nest request/response/payload at the top level so the scorer's
        # _evidence_kinds function finds them via key iteration.
        if request_details:
            evidence["request"] = {
                "method": request_details.get("method", "GET"),
                "url": request_details.get("url", url),
                "headers": request_details.get("headers", {}),
                "body": request_details.get("body", ""),
            }
        if response_details:
            body = response_details.get("body_snippet") or response_details.get("body") or ""
            evidence["response"] = {
                "status": response_details.get("status", 0),
                "headers": response_details.get("headers", {}),
                "body_snippet": (body if isinstance(body, str) else str(body))[
                    :_EVIDENCE_BODY_SNIPPET
                ],
            }
        if payload:
            evidence["payload"] = payload

        # Merge extra fields (token, diff, evidence-specific fields)
        if extra:
            evidence.update(extra)

        return [evidence]

    @abstractmethod
    async def _execute(self, task: Task) -> Dict[str, Any]:
        """Specific scanner logic."""
        pass

    async def _setup_resources(self) -> None:
        """Initialize scanner resources."""
        pass

    async def _cleanup_resources(self) -> None:
        """Cleanup scanner resources."""
        pass
