"""
Scope Signature Enforcement — Assignment-Time Verification

Ensures that every task assigned to an agent carries a valid scope
signature. Prevents agents from operating on out-of-scope targets
even if the scope check is bypassed in the agent layer.

Phase 6: Enterprise Hardening
"""

import hashlib
import hmac
import re
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse

import structlog

from ai_osop.core.config import scope_signing_key

logger = structlog.get_logger("ai_osop.scope_enforcement")


class ScopeEnforcementError(Exception):
    """Raised when scope enforcement fails."""

    pass


class ScopeSignatureVerifier:
    """Verifies scope signatures at task assignment time.

    Defense-in-depth: this runs BEFORE the task reaches an agent,
    providing a second layer of scope enforcement beyond the agent's
    own scope check.
    """

    def __init__(self, secret_key: Optional[bytes] = None):
        self._secret_key = secret_key or scope_signing_key()

    def verify_scope_signature(
        self, engagement_id: str, domains: list, ips: list, signature: str
    ) -> bool:
        """Verify that the scope signature is valid."""
        if not signature:
            logger.warning("scope_missing_signature", engagement_id=engagement_id)
            return False

        # Reconstruct the signing payload
        payload = f"{engagement_id}:{','.join(domains)}:{','.join(ips)}"
        expected = hmac.new(
            self._secret_key, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    def validate_task_scope(
        self,
        task_payload: Dict[str, Any],
        session_scope: Any,
    ) -> Dict[str, Any]:
        """Validate that a task's target is within the engagement scope.

        Returns:
            - allowed: bool
            - target: str
            - reason: str
        """
        target = (
            task_payload.get("target")
            or task_payload.get("url")
            or task_payload.get("domain")
            or ""
        )

        if not target:
            return {
                "allowed": True,
                "target": "",
                "reason": "no_target_specified",
            }

        # Extract hostname from URL
        hostname = self._extract_hostname(target)
        if not hostname:
            return {
                "allowed": False,
                "target": target,
                "reason": "could_not_extract_hostname",
            }

        # Check exclusions first
        exclusions = getattr(session_scope, "exclusions", []) or []
        for exclusion in exclusions:
            if self._hostname_matches(hostname, exclusion):
                logger.warning(
                    "scope_exclusion_hit",
                    target=target,
                    hostname=hostname,
                    exclusion=exclusion,
                )
                return {
                    "allowed": False,
                    "target": target,
                    "reason": f"target matches exclusion: {exclusion}",
                }

        # Check allowed domains
        domains = getattr(session_scope, "domains", []) or []
        for domain in domains:
            if self._hostname_matches(hostname, domain):
                return {
                    "allowed": True,
                    "target": target,
                    "reason": f"matches domain: {domain}",
                }

        # Check allowed IPs
        ips = getattr(session_scope, "ips", []) or []
        for ip_range in ips:
            if self._ip_in_range(hostname, ip_range):
                return {
                    "allowed": True,
                    "target": target,
                    "reason": f"matches IP range: {ip_range}",
                }

        logger.warning(
            "scope_violation_at_assignment",
            target=target,
            hostname=hostname,
            allowed_domains=domains,
        )
        return {
            "allowed": False,
            "target": target,
            "reason": f"hostname '{hostname}' not in scope domains: {domains}",
        }

    @staticmethod
    def _extract_hostname(target: str) -> str:
        """Extract hostname from a target string (URL or plain hostname)."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or ""
        # Plain hostname — take the first part before any path/port
        return target.split("/")[0].split(":")[0]

    @staticmethod
    def _hostname_matches(hostname: str, pattern: str) -> bool:
        """Check if a hostname matches a domain pattern (supports wildcards)."""
        hostname = hostname.lower()
        pattern = pattern.lower()

        # Exact match
        if hostname == pattern:
            return True

        # Wildcard match: *.example.com matches sub.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            return hostname == base or hostname.endswith("." + base)

        # Subdomain match: example.com matches sub.example.com
        return hostname.endswith("." + pattern)

    @staticmethod
    def _ip_in_range(hostname: str, ip_range: str) -> bool:
        """Check if a hostname (which might be an IP) falls within a CIDR range."""
        try:
            import ipaddress

            # If hostname is actually an IP
            ip = ipaddress.ip_address(hostname)
            network = ipaddress.ip_network(ip_range, strict=False)
            return ip in network
        except (ValueError, TypeError):
            return False
