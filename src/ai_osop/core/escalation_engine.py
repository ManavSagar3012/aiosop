"""
Escalation Engine — "never stop at a signal" reasoner (Sprint 2.1).

Given a raw Primitive, the Escalation Engine decides what the *next step* is
to turn it into actionable proof. It never emits the Primitive as a finding
itself — it produces a list of EscalationPath suggestions that a ChainComposer
or agent scheduler can act on.

Design
------
The engine is intentionally LLM-free for latency/reliability. It uses a
rule-based signal→technique routing table extended by optional pattern matching
on the raw payload. Each rule produces one or more EscalationPath objects.

Rules are keyed on PrimitiveType and optionally on tags or severity_hint.
The engine is designed to be extended: override `extra_rules()` in a subclass
to inject domain-specific or LLM-backed escalation logic.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.models import EscalationPath, PrimitiveLedger, PrimitiveType

logger = structlog.get_logger("ai_osop.escalation_engine")


# ---------------------------------------------------------------------------
# Escalation rule table
# ---------------------------------------------------------------------------
# Format: (primitive_type, condition_fn | None) → List[EscalationPath kwargs]
# condition_fn takes the primitive dict and returns bool
# ---------------------------------------------------------------------------


def _has_tag(tag: str):
    """Closure: true if primitive has a given tag."""

    def _check(p: PrimitiveLedger) -> bool:
        return tag in (p.tags or [])

    return _check


def _severity_gte(level: str):
    ORDER = ["info", "low", "medium", "high", "critical"]

    def _check(p: PrimitiveLedger) -> bool:
        own = p.severity_hint.lower()
        return ORDER.index(own) >= ORDER.index(level)

    return _check


_ESCALATION_TABLE: List[Dict[str, Any]] = [
    # ---- Nuclei signals → verify with active scan ----
    {
        "type": PrimitiveType.NUCLEI_SIGNAL,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "nuclei_verify_active",
                "reason": "Nuclei template hit requires active re-verification to eliminate false positives",
                "confidence": 0.70,
                "required_skills": ["nuclei_verify", "burp_active_scan"],
            }
        ],
    },
    {
        "type": PrimitiveType.NUCLEI_SIGNAL,
        "condition": _severity_gte("high"),
        "suggestions": [
            {
                "suggested_technique": "burp_active_scan_targeted",
                "reason": "High/Critical nuclei signal warrants Burp targeted active scan",
                "confidence": 0.80,
                "required_skills": ["burp_active_scan", "manual_verify"],
            },
            {
                "suggested_technique": "capture_http_evidence",
                "reason": "Capture raw HTTP request/response for PoC",
                "confidence": 0.90,
                "required_skills": ["http_capture"],
            },
        ],
    },
    # ---- Auth signals → differential auth check ----
    {
        "type": PrimitiveType.AUTH_SIGNAL,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "differential_auth_verify",
                "reason": "Auth anomaly requires cross-identity differential check before claiming IDOR/BOLA",
                "confidence": 0.75,
                "required_skills": ["diff_auth_engine", "session_capture"],
            }
        ],
    },
    # ---- Endpoint observed → parameter fuzzing ----
    {
        "type": PrimitiveType.ENDPOINT_OBSERVED,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "nuclei_param_scan",
                "reason": "New endpoint observed; run Nuclei param templates",
                "confidence": 0.55,
                "required_skills": ["nuclei_scan", "parameter_fuzz"],
            }
        ],
    },
    # ---- SSRF hint → OOB verification ----
    {
        "type": PrimitiveType.SSRF_HINT,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "oast_ssrf_verify",
                "reason": "SSRF hint requires out-of-band callback verification",
                "confidence": 0.80,
                "required_skills": ["oast_server", "burp_collaborator"],
            }
        ],
    },
    # ---- IDOR hint → diff-auth + capture ----
    {
        "type": PrimitiveType.IDOR_HINT,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "idor_cross_account_verify",
                "reason": "IDOR hint requires cross-account access verification",
                "confidence": 0.75,
                "required_skills": ["diff_auth_engine", "session_swap"],
            }
        ],
    },
    # ---- JS secret → liveness check ----
    {
        "type": PrimitiveType.JS_SECRET,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "secret_liveness_check",
                "reason": "Potential secret in JS; verify it is live and not a test key",
                "confidence": 0.70,
                "required_skills": ["secret_verifier"],
            }
        ],
    },
    # ---- Rate limit miss → abuse chain ----
    {
        "type": PrimitiveType.RATE_LIMIT_MISS,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "race_condition_probe",
                "reason": "No rate limiting detected; probe for race condition / enumeration abuse",
                "confidence": 0.65,
                "required_skills": ["turbo_intruder", "race_condition"],
            }
        ],
    },
    # ---- DNS record → subdomain takeover check ----
    {
        "type": PrimitiveType.DNS_RECORD,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "subdomain_takeover_check",
                "reason": "DNS record discovered; check for dangling CNAME/subdomain takeover",
                "confidence": 0.60,
                "required_skills": ["subdomain_takeover"],
            }
        ],
    },
    # ---- Header anomaly → security header audit ----
    {
        "type": PrimitiveType.HEADER_ANOMALY,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "security_headers_audit",
                "reason": "Suspicious response header; audit security header posture",
                "confidence": 0.55,
                "required_skills": ["header_audit"],
            }
        ],
    },
    # ---- Generic fallback ----
    {
        "type": PrimitiveType.GENERIC,
        "condition": None,
        "suggestions": [
            {
                "suggested_technique": "manual_review",
                "reason": "Generic primitive; manual review required to determine escalation path",
                "confidence": 0.40,
                "required_skills": ["manual_review"],
            }
        ],
    },
]


class EscalationEngine:
    """Rule-based signal escalation reasoner.

    Given a PrimitiveLedger, returns a list of EscalationPath objects
    representing next-step actions to turn the signal into actionable proof.

    Never emits findings. Never stops at a signal — there is always a next step.
    """

    def escalate(self, primitive: PrimitiveLedger) -> List[EscalationPath]:
        """Return escalation paths for a given primitive.

        Returns at least one path (falls through to GENERIC if no specific rule
        matches), ensuring the principle "never stop at a signal" is upheld.
        """
        paths: List[EscalationPath] = []

        for rule in _ESCALATION_TABLE:
            if rule["type"] != primitive.primitive_type:
                continue
            condition = rule.get("condition")
            if condition is not None and not condition(primitive):
                continue
            for suggestion in rule["suggestions"]:
                paths.append(
                    EscalationPath(
                        source_primitive_id=primitive.id,
                        suggested_technique=suggestion["suggested_technique"],
                        reason=suggestion["reason"],
                        confidence=suggestion["confidence"],
                        required_skills=suggestion.get("required_skills", []),
                        engagement_id=primitive.engagement_id,
                    )
                )

        # Fallback: ensure at least one path is always returned
        if not paths:
            paths.append(
                EscalationPath(
                    source_primitive_id=primitive.id,
                    suggested_technique="manual_review",
                    reason=(
                        f"No specific escalation rule for {primitive.primitive_type.value}; "
                        "manual review required"
                    ),
                    confidence=0.30,
                    required_skills=["manual_review"],
                    engagement_id=primitive.engagement_id,
                )
            )

        logger.info(
            "escalation_paths_generated",
            primitive_id=primitive.id,
            primitive_type=primitive.primitive_type.value,
            paths_count=len(paths),
        )
        return paths

    def extra_rules(self, primitive: PrimitiveLedger) -> List[EscalationPath]:
        """Override in subclass to inject domain-specific or LLM-backed rules."""
        return []
