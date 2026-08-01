"""Pivoting Broker — strategic pivoting when active scanning is blocked.

The assessment identifies "Strategic Pivoting" as a cognitive capability
AI-OSOP lacks: if active scanning is blocked by a strict WAF, a human
researcher stops active attacks and switches to passive OSINT, JS
analysis, or credential harvesting to find alternative entry points.

This module monitors WAF block signals (403/406/429 responses, challenge
pages) and, when a threshold is exceeded, raises the priority of passive
recon tasks and deprioritizes active scanning against the blocked host.

It's wired into the reasoning loop's _evaluate_result method: if a
hypothesis test gets blocked by the WAF, the broker generates a pivot
hypothesis ("switch to passive recon for this target") instead of
continuing to hammer the WAF.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# WAF block signals in HTTP responses
_WAF_BLOCK_STATUSES = {403, 406, 429, 503}
_WAF_CHALLENGE_PATTERNS = [
    "just a moment",
    "cf-browser-verification",
    "access denied",
    "request blocked",
    "security check",
    "captcha",
    "ray id",
    "attention required",
    "cloudflare",
    "akamai",
]

# Threshold: after this many consecutive WAF blocks, pivot to passive.
_WAF_BLOCK_THRESHOLD = 3


@dataclass
class PivotDecision:
    """Result of a pivoting evaluation."""

    should_pivot: bool
    reason: str = ""
    pivot_strategy: str = ""
    blocked_host: str = ""


class PivotingBroker:
    """Monitors WAF block signals and recommends strategic pivots.

    Tracks consecutive WAF blocks per host. When the threshold is exceeded,
    recommends pivoting from active scanning to passive recon/OSINT.
    """

    def __init__(self):
        self._block_counts: Dict[str, int] = {}

    def record_response(self, host: str, status_code: int, body: str = "") -> bool:
        """Record a response and check if it's a WAF block.

        Returns True if this response was a WAF block, False otherwise.
        Resets the counter on a non-block response (the WAF is letting us through).
        """
        is_block = False

        if status_code in _WAF_BLOCK_STATUSES:
            is_block = True
        elif body:
            body_lower = body[:2000].lower()
            if any(p in body_lower for p in _WAF_CHALLENGE_PATTERNS):
                is_block = True

        if is_block:
            self._block_counts[host] = self._block_counts.get(host, 0) + 1
        else:
            # Non-block response resets the counter
            self._block_counts.pop(host, None)

        return is_block

    def should_pivot(self, host: str) -> PivotDecision:
        """Check if the system should pivot away from active scanning for a host.

        After _WAF_BLOCK_THRESHOLD consecutive blocks, recommends pivoting
        to passive recon (crt.sh, Wayback, JS analysis) instead of
        continuing to hammer the WAF.
        """
        count = self._block_counts.get(host, 0)
        if count < _WAF_BLOCK_THRESHOLD:
            return PivotDecision(should_pivot=False)

        return PivotDecision(
            should_pivot=True,
            reason=f"WAF blocked {count} consecutive requests to {host}",
            pivot_strategy=(
                "pivot to passive recon: run cert_transparency, wayback_discovery, "
                "and JS bundle analysis on this host. Deprioritize active injection "
                "scans until WAF bypass payloads are generated."
            ),
            blocked_host=host,
        )

    def get_pivot_hypothesis(self, host: str) -> Optional[Dict[str, Any]]:
        """Generate a pivot hypothesis for the reasoning loop.

        When the broker detects repeated WAF blocks, it returns a hypothesis
        dict that the reasoning loop can dispatch — a passive recon task
        instead of another active scan that the WAF will block.
        """
        decision = self.should_pivot(host)
        if not decision.should_pivot:
            return None

        return {
            "title": f"Pivot to passive recon — WAF blocking active scans on {host}",
            "description": decision.pivot_strategy,
            "category": "passive_recon",
            "target_id": host,
            "confidence": 0.7,
            "recommended_tests": [
                "Run cert_transparency to find subdomains that may bypass the WAF",
                "Run wayback_discovery to find historical endpoints",
                "Analyze JS bundles for API endpoints not behind the WAF",
            ],
            "recommended_skills": [
                "cert_transparency",
                "wayback_discovery",
                "content_discovery",
            ],
            "status": "open",
            "engagement_id": "",
        }

    def reset(self, host: str = "") -> None:
        """Reset block counters for a host (or all hosts if empty)."""
        if host:
            self._block_counts.pop(host, None)
        else:
            self._block_counts.clear()
