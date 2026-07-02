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

import hashlib
import json
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.chain_composer import ChainComposer
from ai_osop.core.escalation_engine import EscalationEngine
from ai_osop.core.models import (
    AttackChain,
    ChainStatus,
    EvidencePackage,
    PrimitiveLedger,
    PrimitiveType,
    TriageReport,
    TriageVerdict,
    Vulnerability,
)
from ai_osop.core.triager_gate import TriagerGate

logger = structlog.get_logger("ai_osop.chain_analysis")

# TriageVerdict -> the honest ChainStatus it maps to. EMIT means the gate would
# submit it (VALIDATED, report-ready — actual external submission stays a separate,
# deliberately gated action). Anything short of EMIT is not report-ready.
_VERDICT_TO_STATUS = {
    TriageVerdict.EMIT: ChainStatus.VALIDATED,
    TriageVerdict.NEEDS_POC: ChainStatus.PENDING_POC,
    TriageVerdict.ESCALATE: ChainStatus.PENDING_POC,
    TriageVerdict.DROP: ChainStatus.DROPPED,
}


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
        # Carry the confirmed finding's captured evidence into the ledger so the
        # Triager Gate downstream can see it (a chain without captured evidence can
        # never be EMIT-ready, by design).
        raw={
            "vuln_id": vuln.id,
            "vuln_type": vt,
            "title": vuln.title,
            "evidence": list(vuln.evidence or []),
        },
        confidence=float(vuln.confidence or 0.0),
        severity_hint=severity_hint,
        tags=[vt],
        promoted_to_finding=True,   # it already IS a confirmed finding
        finding_id=vuln.id,
    )


def _deterministic_chain_id(engagement_id: str, group: List[PrimitiveLedger]) -> str:
    """Stable chain id derived from the engagement + its constituent primitives.

    ChainComposer mints a random uuid per call, which would create a *new* Chain node
    every consume cycle (duplicate churn, and the triage gate could never dedup across
    passes). Pinning the id to the sorted dedup-key set makes ``upsert_chain`` MERGE
    idempotently and lets the gate recognise a chain it has already judged.
    """
    keys = "|".join(sorted((p.dedup_key or p.target or p.id) for p in group))
    digest = hashlib.sha256(f"{engagement_id}::{keys}".encode()).hexdigest()[:16]
    return f"chain-{digest}"


def analyze_primitives(
    primitives: List[PrimitiveLedger],
    *,
    escalation_engine: Optional[EscalationEngine] = None,
    composer: Optional[ChainComposer] = None,
    min_chain_size: int = 2,
    gate: Optional[TriagerGate] = None,
    evidence_by_primitive: Optional[Dict[str, EvidencePackage]] = None,
) -> Dict[str, Any]:
    """Run the consume side of the loop over a set of primitives.

    For every primitive, collect escalation suggestions (the "never stop at a signal"
    step). For every target with ≥ ``min_chain_size`` co-located primitives, compose a
    proof-carrying AttackChain. Pure and deterministic — no DB, no network — so it is
    fully unit-testable and safe to call from an orchestrator pass.

    When a ``gate`` (TriagerGate) is supplied, every composed chain is additionally run
    through the adversarial reproducibility gate: the chain's status is set from the
    verdict (EMIT→VALIDATED, NEEDS_POC/ESCALATE→PENDING_POC, DROP→DROPPED) and its
    ``triage_report_id`` is stamped, so only gate-passed chains are ever report-ready.
    ``evidence_by_primitive`` maps a root primitive id to its captured EvidencePackage
    (the gate needs captured evidence to allow emission).

    Returns ``{"chains": [...], "escalations": [...]}`` — plus ``"reports": [...]`` when
    a gate ran.
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

    chains: List[AttackChain] = []
    roots: Dict[str, PrimitiveLedger] = {}  # chain.id -> root (strongest) primitive
    for target, group in by_target.items():
        if len(group) < min_chain_size:
            continue
        # Order by severity so the strongest primitive roots the chain/PoC.
        ordered = sorted(group, key=lambda x: _SEVERITY_RANK.get((x.severity_hint or "").lower(), 0), reverse=True)
        try:
            chain = comp.compose(ordered)
            chain = comp.generate_poc(chain, ordered)
            chain.id = _deterministic_chain_id(chain.engagement_id or ordered[0].engagement_id, ordered)
            chains.append(chain)
            roots[chain.id] = ordered[0]
        except Exception as e:  # noqa: BLE001 - one bad group must not abort the rest
            logger.warning("chain_compose_failed", target=target, error=str(e))

    result: Dict[str, Any] = {"chains": chains, "escalations": escalations}

    if gate is not None:
        reports = gate_chains(
            chains, roots, gate=gate, evidence_by_primitive=evidence_by_primitive
        )
        result["reports"] = reports

    logger.info(
        "chain_analysis_complete",
        primitives=len(primitives),
        chains=len(chains),
        escalations=len(escalations),
        gated=gate is not None,
    )
    return result


def gate_chains(
    chains: List[AttackChain],
    roots: Dict[str, PrimitiveLedger],
    *,
    gate: TriagerGate,
    evidence_by_primitive: Optional[Dict[str, EvidencePackage]] = None,
) -> List[TriageReport]:
    """Run the Triager Gate over composed chains, mutating status in place.

    For each chain, evaluate its root primitive + the chain + any captured evidence.
    The chain's ``status`` is set from the verdict and ``triage_report_id`` is stamped.
    Returns the list of TriageReports (one per chain). Pure/deterministic — no DB.
    """
    evidence_by_primitive = evidence_by_primitive or {}
    reports: List[TriageReport] = []
    for chain in chains:
        root = roots.get(chain.id)
        if root is None:
            continue
        evidence = evidence_by_primitive.get(root.id)
        try:
            report = gate.evaluate(root, chain=chain, evidence=evidence)
        except Exception as e:  # noqa: BLE001 - gate failure must not drop the chain silently
            logger.warning("triage_gate_failed", chain_id=chain.id, error=str(e))
            continue
        chain.triage_report_id = report.id
        chain.status = _VERDICT_TO_STATUS.get(report.verdict, ChainStatus.PENDING_POC)
        reports.append(report)
    return reports


def evidence_from_primitive(primitive: PrimitiveLedger) -> Optional[EvidencePackage]:
    """Build an EvidencePackage from a primitive's carried captured evidence, if any.

    A confirmed Vulnerability's ``evidence`` (captured request/response dicts) rides in
    ``primitive.raw["evidence"]`` (see ``vuln_to_primitive``). Returns None when there is
    no captured evidence, so the gate correctly withholds EMIT for unproven chains.
    """
    raw = primitive.raw or {}
    captured = raw.get("evidence") or []
    if not captured:
        return None
    return EvidencePackage(
        finding_id=primitive.finding_id or primitive.id,
        engagement_id=primitive.engagement_id,
        raw_responses=list(captured),
    )


def primitive_from_node(node: Dict[str, Any]) -> PrimitiveLedger:
    """Reconstruct a PrimitiveLedger from a raw Neo4j :Primitive node dict.

    Mirrors ``PrimitiveLedgerStore.upsert_primitive`` serialisation (``raw`` is a JSON
    string, empty-string sentinels for optional refs). Used by the orchestrator consume
    pass to turn persisted primitives back into models the analyzer can chain.
    """
    raw_field = node.get("raw")
    try:
        raw = json.loads(raw_field) if isinstance(raw_field, str) else (raw_field or {})
    except (ValueError, TypeError):
        raw = {}
    return PrimitiveLedger(
        id=node.get("id") or PrimitiveLedger.model_fields["id"].default_factory(),
        primitive_type=PrimitiveType(node.get("primitive_type", PrimitiveType.GENERIC.value)),
        engagement_id=node.get("engagement_id", ""),
        source=node.get("source", "ledger"),
        dedup_key=node.get("dedup_key", ""),
        target=node.get("target", ""),
        raw=raw,
        confidence=float(node.get("confidence") or 0.0),
        severity_hint=node.get("severity_hint", "medium"),
        tags=list(node.get("tags") or []),
        escalated_from=node.get("escalated_from") or None,
        chain_id=node.get("chain_id") or None,
        promoted_to_finding=bool(node.get("promoted", False)),
        finding_id=node.get("finding_id") or None,
    )


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}
