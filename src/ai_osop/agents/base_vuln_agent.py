from abc import abstractmethod
from typing import Any, Dict, List, Optional

from ai_osop.agents.base import BaseAgent
from ai_osop.core.models import Task, Vulnerability


# Max chars of an HTTP response body persisted as finding evidence. Bounds graph
# storage and avoids dumping unbounded/PII-heavy bodies while keeping enough of
# the response to demonstrate the vulnerability.
_EVIDENCE_BODY_SNIPPET = 2048


class BaseVulnerabilityAgent(BaseAgent):
    """
    Base class for all vulnerability scanner agents, providing
    standardized finding persistence and error handling.
    """

    async def persist_finding(self, vuln: Vulnerability) -> None:
        """Persist a vulnerability finding to the Graph Memory."""
        try:
            await self.ctx.graph_memory.add_vulnerability(vuln)
            self.findings[vuln.id] = vuln
        except Exception as e:
            self.logger.error(f"Failed to add vulnerability {vuln.id} to graph: {e}")

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
                "body_snippet": (body if isinstance(body, str) else str(body))[:_EVIDENCE_BODY_SNIPPET],
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
