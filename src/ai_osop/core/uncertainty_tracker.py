"""Uncertainty-Aware Planner — track what we DON'T know and actively seek it.

The assessment's next maturity level asks: 'Does it know what it doesn't
know and gather evidence accordingly?' A human researcher maintains a
mental list of uncertainties: 'I don't know if this endpoint is
authenticated', 'I don't know if the backend is MySQL or PostgreSQL',
'I don't know if the WAF blocks angle brackets'.

This module tracks uncertainties per engagement and generates
'information-seeking' hypotheses that reduce them. Instead of only
testing for vulnerabilities, the system now also tests to RESOLVE
uncertainty — exactly what a human does when they probe an endpoint
just to understand how it behaves before attacking it.

Uncertainty types tracked:
  - technology: 'I don't know what framework this runs'
  - authentication: 'I don't know if this endpoint requires auth'
  - parameter_behavior: 'I don't know if this param is reflected/executed'
  - waf_filtering: 'I don't know which chars are WAF-filtered'
  - data_format: 'I don't know if the backend accepts XML'
  - session_state: 'I don't know if the session is stateful'
  - business_logic: 'I don't know the checkout workflow steps'
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Uncertainty:
    """A single uncertainty the system should resolve."""
    id: str
    category: str  # technology, authentication, parameter_behavior, etc.
    description: str  # 'I don't know if /api/users requires authentication'
    target: str  # endpoint URL or asset
    resolution_action: str  # what to do to resolve it
    resolution_task_type: str = ""  # task type to dispatch
    priority: float = 0.5  # 0-1, higher = more important to resolve
    resolved: bool = False
    resolution_result: str = ""
    generated_hypotheses: List[str] = field(default_factory=list)


# Predefined uncertainty templates — triggered when the system observes
# certain conditions but doesn't yet know the answer.
_UNCERTAINTY_TEMPLATES = [
    {
        "category": "authentication",
        "trigger": "endpoint_returns_401_or_403",
        "description": "Endpoint {url} returns {status} — is it auth-gated or just broken?",
        "resolution_action": "Test with and without auth tokens to confirm the endpoint is auth-gated",
        "resolution_task_type": "capture_authenticated_surface",
        "priority": 0.8,
    },
    {
        "category": "technology",
        "trigger": "no_framework_detected",
        "description": "No framework detected on {url} — what stack does it run?",
        "resolution_action": "Run technology_fingerprint + provoke error states to identify the framework",
        "resolution_task_type": "technology_fingerprint",
        "priority": 0.6,
    },
    {
        "category": "parameter_behavior",
        "trigger": "param_reflected_not_executed",
        "description": "Parameter {param} at {url} is reflected but may not be executed — is it in a dangerous context?",
        "resolution_action": "Send a canary payload to determine if the reflection is in an executable context",
        "resolution_task_type": "xss_scan",
        "priority": 0.7,
    },
    {
        "category": "waf_filtering",
        "trigger": "waf_detected",
        "description": "WAF ({waf}) detected on {url} — which characters/patterns are filtered?",
        "resolution_action": "Run WAF character probing to map the filter",
        "resolution_task_type": "waf_detection",
        "priority": 0.9,
    },
    {
        "category": "data_format",
        "trigger": "json_endpoint",
        "description": "Endpoint {url} accepts JSON — does it also accept XML (XXE surface)?",
        "resolution_action": "Send an XML body to the JSON endpoint and check if it's parsed",
        "resolution_task_type": "request_smuggling_scan",
        "priority": 0.5,
    },
    {
        "category": "session_state",
        "trigger": "session_cookie_present",
        "description": "Session cookie detected — is the session stateful or stateless (JWT)?",
        "resolution_action": "Decode the session token to determine if it's a JWT or opaque session",
        "resolution_task_type": "jwt_scan",
        "priority": 0.6,
    },
    {
        "category": "business_logic",
        "trigger": "multi_step_workflow_detected",
        "description": "Multi-step workflow detected at {url} — what are the valid state transitions?",
        "resolution_action": "Map the workflow steps and test out-of-order execution",
        "resolution_task_type": "map_business_process",
        "priority": 0.8,
    },
]


class UncertaintyTracker:
    """Tracks uncertainties per engagement and generates resolution hypotheses.

    The system maintains a list of 'things it doesn't know' and actively
    generates hypotheses to resolve them. This is the 'information-seeking'
    behavior the assessment says is missing — instead of only testing for
    vulnerabilities, the system also tests to REDUCE UNCERTAINTY.
    """

    def __init__(self):
        self._uncertainties: Dict[str, List[Uncertainty]] = {}  # engagement_id -> list

    def detect_uncertainties(
        self,
        engagement_id: str,
        endpoints: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        technologies: List[str] = None,
    ) -> List[Uncertainty]:
        """Scan the current graph state for unresolved uncertainties.

        For each endpoint + finding, check if there's an uncertainty
        template that applies (e.g. endpoint returns 401 → 'is it auth-gated?').
        Returns new uncertainties that haven't been resolved yet.
        """
        uncertainties: List[Uncertainty] = []
        existing = {u.description for u in self._uncertainties.get(engagement_id, [])}

        for ep in endpoints:
            url = ep.get("url", "")
            status = ep.get("status_code")
            auth_required = ep.get("auth_required")
            technologies = ep.get("technologies") or []

            # Authentication uncertainty: endpoint returns 401/403
            if status in (401, 403) or auth_required:
                desc = f"Endpoint {url} returns {status} — is it auth-gated or just broken?"
                if desc not in existing:
                    uncertainties.append(Uncertainty(
                        id=f"unc-auth-{url[:30]}",
                        category="authentication",
                        description=desc,
                        target=url,
                        resolution_action="Test with and without auth tokens",
                        resolution_task_type="capture_authenticated_surface",
                        priority=0.8,
                    ))

            # Technology uncertainty: no framework detected
            if not technologies:
                desc = f"No framework detected on {url} — what stack does it run?"
                if desc not in existing:
                    uncertainties.append(Uncertainty(
                        id=f"unc-tech-{url[:30]}",
                        category="technology",
                        description=desc,
                        target=url,
                        resolution_action="Run technology_fingerprint + provoke error states",
                        resolution_task_type="technology_fingerprint",
                        priority=0.6,
                    ))

        # Check for WAF uncertainty from findings
        for f in findings:
            if f.get("vuln_type") == "ssrf" or "waf" in str(f.get("evidence", "")).lower():
                desc = "WAF may be present — which characters/patterns are filtered?"
                if desc not in existing:
                    uncertainties.append(Uncertainty(
                        id="unc-waf",
                        category="waf_filtering",
                        description=desc,
                        target="",
                        resolution_action="Run WAF character probing",
                        resolution_task_type="waf_detection",
                        priority=0.9,
                    ))

        # Store new uncertainties
        self._uncertainties.setdefault(engagement_id, []).extend(uncertainties)
        return uncertainties

    def resolve(self, engagement_id: str, uncertainty_id: str, result: str) -> None:
        """Mark an uncertainty as resolved."""
        for u in self._uncertainties.get(engagement_id, []):
            if u.id == uncertainty_id:
                u.resolved = True
                u.resolution_result = result
                break

    def _all_for(self, engagement_id: str, *aliases: str) -> List[Uncertainty]:
        """Collect uncertainties stored under any of the given id forms.

        Same split-brain fix as GraphMemory.get_vulnerabilities_by_engagement
        (AIOSOP-FINDINGS-KEY) — uncertainties get recorded under whichever id
        the reasoning loop was passed, not necessarily what the API caller
        queries with.
        """
        out: List[Uncertainty] = []
        for eid in dict.fromkeys(i for i in (engagement_id, *aliases) if i):
            out.extend(self._uncertainties.get(eid, []))
        return out

    def get_open_uncertainties(self, engagement_id: str, *aliases: str) -> List[Uncertainty]:
        """Get unresolved uncertainties for an engagement."""
        return [u for u in self._all_for(engagement_id, *aliases) if not u.resolved]

    def get_uncertainty_hypotheses(self, engagement_id: str) -> List[Dict[str, Any]]:
        """Generate hypotheses from open uncertainties.

        Each open uncertainty becomes a hypothesis the reasoning loop
        can dispatch — this is the 'active information-seeking' behavior.
        """
        hypotheses = []
        for u in self.get_open_uncertainties(engagement_id):
            hypotheses.append({
                "title": f"Resolve uncertainty: {u.description[:60]}",
                "description": u.resolution_action,
                "category": f"uncertainty_{u.category}",
                "target_id": u.target,
                "confidence": u.priority,
                "recommended_tests": [u.resolution_action],
                "recommended_skills": [u.resolution_task_type] if u.resolution_task_type else [],
                "status": "open",
                "engagement_id": engagement_id,
            })
        return hypotheses

    def get_summary(self, engagement_id: str, *aliases: str) -> Dict[str, Any]:
        """Get uncertainty summary for an engagement."""
        all_u = self._all_for(engagement_id, *aliases)
        return {
            "total": len(all_u),
            "resolved": len([u for u in all_u if u.resolved]),
            "open": len([u for u in all_u if not u.resolved]),
            "by_category": {
                cat: len([u for u in all_u if u.category == cat])
                for cat in set(u.category for u in all_u)
            },
        }
