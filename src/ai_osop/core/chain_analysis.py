"""Chain analysis — the consume side of the primitive→escalation→chain loop.

The PrimitiveLedger (persistence), EscalationEngine (signal→next-step routing), and
ChainComposer (primitives→AttackChain+PoC) each existed but were never tied together.
This module is the glue that makes the loop actually run:

    vuln_to_primitive()   maps a confirmed Vulnerability into a typed primitive so
                          detectors feed the ledger (the feed side), and
    analyze_primitives()  groups primitives by target, escalates each (never stops
                          at a signal), and composes a proof-carrying AttackChain per
                          target that has enough co-located signal (the consume side).

Composition is deliberately conservative: a chain is only built when ≥2 primitives
share a target (a single signal is a lead, not a chain), and PoC generation defers to
ChainComposer which refuses to fabricate — chains without a deterministic PoC stay
PENDING_POC for the triage gate rather than being emitted as findings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.chain_composer import ChainComposer
from ai_osop.core.escalation_engine import EscalationEngine
from ai_osop.core.models import PrimitiveLedger, PrimitiveType, Vulnerability

logger = structlog.get_logger("ai_osop.chain_analysis")


# Confirmed-vulnerability class (VulnClass.value) -> the escalatable primitive type.
# Only classes that unlock a downstream escalation/chain are mapped to a hint type;
# the rest become GENERIC (still recorded, still chainable by co-location, but they
# carry no bespoke escalation rule).
_VULN_TO_PRIMITIVE_TYPE = {
    # access-control family -> idor_hint (escalates to cross-account verify -> ATO)
    "idor": PrimitiveType.IDOR_HINT,
    "bola": PrimitiveType.IDOR_HINT,
    "bfla": PrimitiveType.IDOR_HINT,
    "broken_access_control": PrimitiveType.IDOR_HINT,
    "privilege_escalation": PrimitiveType.IDOR_HINT,
    "mass_assignment": PrimitiveType.IDOR_HINT,
    # ssrf -> ssrf_hint (escalates to OAST verification)
    "ssrf": PrimitiveType.SSRF_HINT,
    # secrets -> js_secret (escalates to liveness check)
    "exposed_secret": PrimitiveType.JS_SECRET,
    "osint_leak": PrimitiveType.JS_SECRET,
    # auth/token -> auth_signal (escalates to differential-auth verify)
    "jwt_abuse": PrimitiveType.AUTH_SIGNAL,
    "oauth2": PrimitiveType.AUTH_SIGNAL,
    "authentication_weakness": PrimitiveType.AUTH_SIGNAL,
    # takeover -> dns_record (escalates to subdomain-takeover check)
    "subdomain_takeover": PrimitiveType.DNS_RECORD,
}


def _vuln_type_value(vuln: Vulnerability) -> str:
    vt = vuln.vuln_type
    return getattr(vt, "value", str(vt)).lower()


def _target_of(vuln: Vulnerability) -> str:
    """Best-effort stable target key for grouping/dedup."""
    return str(vuln.endpoint_id or vuln.asset_id or vuln.entry_point or "unknown")


def vuln_to_primitive(vuln: Vulnerability) -> PrimitiveLedger:
    """Map a confirmed Vulnerability into a typed primitive for the ledger.

    Unmapped classes become GENERIC (still recorded and chainable by co-location).
    The dedup_key ties the primitive back to a stable (type, target) identity so
    idempotent replays MERGE onto the same node.
    """
    vt = _vuln_type_value(vuln)
    ptype = _VULN_TO_PRIMITIVE_TYPE.get(vt, PrimitiveType.GENERIC)
    target = _target_of(vuln)
    severity = vuln.severity
    severity_hint = getattr(severity, "value", str(severity)) if severity is not None else "medium"
    return PrimitiveLedger(
        primitive_type=ptype,
        engagement_id=vuln.engagement_id,
        source=f"vuln:{vuln.tool_source or 'unknown'}",
        dedup_key=f"{vt}:{target}",
        target=target,
        raw={"vuln_id": vuln.id, "vuln_type": vt, "title": vuln.title},
        confidence=float(vuln.confidence or 0.0),
        severity_hint=severity_hint,
        tags=[vt],
        promoted_to_finding=True,   # it already IS a confirmed finding
        finding_id=vuln.id,
    )


def analyze_primitives(
    primitives: List[PrimitiveLedger],
    *,
    escalation_engine: Optional[EscalationEngine] = None,
    composer: Optional[ChainComposer] = None,
    min_chain_size: int = 2,
) -> Dict[str, Any]:
    """Run the consume side of the loop over a set of primitives.

    For every primitive, collect escalation suggestions (the "never stop at a signal"
    step). For every target with ≥ ``min_chain_size`` co-located primitives, compose a
    proof-carrying AttackChain. Pure and deterministic — no DB, no network — so it is
    fully unit-testable and safe to call from an orchestrator pass.

    Returns ``{"chains": [...], "escalations": [...]}``.
    """
    engine = escalation_engine or EscalationEngine()
    comp = composer or ChainComposer()

    escalations: List[Any] = []
    for p in primitives:
        try:
            escalations.extend(engine.escalate(p))
        except Exception as e:  # noqa: BLE001 - advisory, never fatal
            logger.warning("escalation_failed", primitive_id=getattr(p, "id", "?"), error=str(e))

    # Group by target; a chain needs multiple co-located signals.
    by_target: Dict[str, List[PrimitiveLedger]] = {}
    for p in primitives:
        by_target.setdefault(p.target or "unknown", []).append(p)

    chains: List[Any] = []
    for target, group in by_target.items():
        if len(group) < min_chain_size:
            continue
        # Order by severity so the strongest primitive roots the chain/PoC.
        ordered = sorted(group, key=lambda x: _SEVERITY_RANK.get((x.severity_hint or "").lower(), 0), reverse=True)
        try:
            chain = comp.compose(ordered)
            chain = comp.generate_poc(chain, ordered)
            chains.append(chain)
        except Exception as e:  # noqa: BLE001 - one bad group must not abort the rest
            logger.warning("chain_compose_failed", target=target, error=str(e))

    logger.info(
        "chain_analysis_complete",
        primitives=len(primitives),
        chains=len(chains),
        escalations=len(escalations),
    )
    return {"chains": chains, "escalations": escalations}


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
