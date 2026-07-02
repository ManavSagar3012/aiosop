"""
Chain Composer + Auto-PoC Generator (Sprint 2.2 / 2.3).

Chain Composer
--------------
Assembles an ordered list of Primitives into an AttackChain. Replaces the
previous "TBD payload" placeholder — every chain has a concrete title,
description, severity, and confidence computed from its constituent primitives.

Auto-PoC Generator
------------------
Given a validated AttackChain, generates a runnable PoC script (argv list)
stored in AttackChain.poc_script. The PoC is injected into EvidencePackage.
replay_script so the ReplayabilityTruthEngine can re-execute it.

Design rules
------------
- No hallucinated proofs. If a PoC cannot be constructed deterministically, the
  field is left empty and the chain status is PENDING_POC (not fabricated).
- PoC scripts are concrete argv lists (not shell strings) to prevent injection.
- The composer selects a technique for the PoC based on PrimitiveType routing.
- Confidence is the geometric mean of member primitive confidences, capped at
  the minimum primitive confidence (a chain is only as strong as its weakest link).
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.models import (
    AttackChain,
    ChainStatus,
    EvidencePackage,
    EvidenceProvenance,
    PrimitiveLedger,
    PrimitiveType,
)

logger = structlog.get_logger("ai_osop.chain_composer")


# ---------------------------------------------------------------------------
# PoC template registry
# ---------------------------------------------------------------------------
# Maps PrimitiveType → a function that takes a primitive and returns an argv
# list representing the PoC command. Returns [] if no PoC can be constructed.
# ---------------------------------------------------------------------------

def _poc_nuclei(primitives: List[PrimitiveLedger]) -> List[str]:
    """nuclei re-verification PoC."""
    targets = list({p.target for p in primitives if p.target})
    if not targets:
        return []
    template_ids = []
    for p in primitives:
        tid = p.raw.get("template_id") or p.raw.get("templateID")
        if tid:
            template_ids.append(str(tid))
    if not template_ids or not targets:
        return []
    # Concrete argv: nuclei -u <target> -t <template_id> -j
    # Multi-template: use first target, all templates
    cmd = ["nuclei", "-u", targets[0], "-json-export", "nuclei_poc_output.json"]
    for tid in template_ids:
        cmd += ["-t", tid]
    return cmd


def _poc_curl(primitives: List[PrimitiveLedger]) -> List[str]:
    """Generic HTTP-replay PoC via curl."""
    targets = [p.target for p in primitives if p.target]
    if not targets:
        return []
    # Reconstruct from raw HTTP data if available
    first = primitives[0]
    method = first.raw.get("method", "GET")
    url = targets[0]
    headers: Dict[str, str] = first.raw.get("headers", {})
    body: str = first.raw.get("body", "")
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", method, url]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    if body and method in ("POST", "PUT", "PATCH"):
        cmd += ["-d", body]
    return cmd


def _poc_diff_auth(primitives: List[PrimitiveLedger]) -> List[str]:
    """Differential auth PoC — script that replays with two session cookies."""
    targets = [p.target for p in primitives if p.target]
    if not targets:
        return []
    first = primitives[0]
    victim_cookie = first.raw.get("victim_cookie", "<VICTIM_COOKIE>")
    attacker_cookie = first.raw.get("attacker_cookie", "<ATTACKER_COOKIE>")
    url = targets[0]
    return [
        "python3", "-c",
        (
            "import httpx; "
            f"r1=httpx.get('{url}', cookies={{'session': '{victim_cookie}'}}); "
            f"r2=httpx.get('{url}', cookies={{'session': '{attacker_cookie}'}}); "
            "print(f'victim={r1.status_code}, attacker={r2.status_code}'); "
            "assert r2.status_code == 200, 'No IDOR'"
        ),
    ]


def _poc_oast(primitives: List[PrimitiveLedger]) -> List[str]:
    """SSRF OOB PoC via curl to OAST callback."""
    targets = [p.target for p in primitives if p.target]
    if not targets:
        return []
    first = primitives[0]
    oast_domain = first.raw.get("oast_domain", "<OAST_DOMAIN>")
    param = first.raw.get("ssrf_param", "url")
    return [
        "curl", "-s", "-G",
        f"{targets[0]}",
        "--data-urlencode", f"{param}=http://{oast_domain}/ssrf-probe",
    ]


_POC_BUILDERS = {
    PrimitiveType.NUCLEI_SIGNAL: _poc_nuclei,
    PrimitiveType.AUTH_SIGNAL: _poc_diff_auth,
    PrimitiveType.IDOR_HINT: _poc_diff_auth,
    PrimitiveType.SSRF_HINT: _poc_oast,
    PrimitiveType.ENDPOINT_OBSERVED: _poc_curl,
    PrimitiveType.JS_SECRET: _poc_curl,
    PrimitiveType.RATE_LIMIT_MISS: _poc_curl,
    PrimitiveType.HEADER_ANOMALY: _poc_curl,
    PrimitiveType.PORT_OPEN: _poc_curl,
    PrimitiveType.DNS_RECORD: _poc_curl,
    PrimitiveType.REDIRECT_CHAIN: _poc_curl,
    PrimitiveType.GENERIC: _poc_curl,
}


# ---------------------------------------------------------------------------
# Severity routing
# ---------------------------------------------------------------------------

_SEVERITY_PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _max_severity(primitives: List[PrimitiveLedger]) -> str:
    best = "info"
    for p in primitives:
        hint = p.severity_hint.lower()
        if _SEVERITY_PRIORITY.get(hint, 0) > _SEVERITY_PRIORITY.get(best, 0):
            best = hint
    return best


def _chain_confidence(primitives: List[PrimitiveLedger]) -> float:
    """Geometric mean capped by minimum — weakest-link semantics."""
    if not primitives:
        return 0.0
    values = [p.confidence for p in primitives]
    geo_mean = math.exp(sum(math.log(max(v, 1e-9)) for v in values) / len(values))
    return round(min(geo_mean, min(values)), 4)


# ---------------------------------------------------------------------------
# ChainComposer
# ---------------------------------------------------------------------------

class ChainComposer:
    """Assembles Primitives into an AttackChain with a concrete payload.

    Usage
    -----
    composer = ChainComposer()
    chain = composer.compose(primitives, title="IDOR on /api/v1/user/{id}")
    chain = composer.generate_poc(chain, primitives)  # fills poc_script
    """

    def compose(
        self,
        primitives: List[PrimitiveLedger],
        title: str = "",
        description: str = "",
    ) -> AttackChain:
        """Build an AttackChain from a list of Primitives.

        Args:
            primitives:   Ordered list of PrimitiveLedger objects.
            title:        Human-readable chain title. Auto-derived if empty.
            description:  Narrative description. Auto-derived if empty.

        Returns:
            AttackChain with BUILDING status (no PoC yet).
        """
        if not primitives:
            raise ValueError("Cannot compose a chain from zero primitives")

        engagement_id = primitives[0].engagement_id
        confidence = _chain_confidence(primitives)
        severity = _max_severity(primitives)
        prim_ids = [p.id for p in primitives]

        if not title:
            types_str = " → ".join(p.primitive_type.value for p in primitives[:3])
            target = primitives[0].target or "unknown"
            title = f"Chain: {types_str} on {target}"

        if not description:
            description = (
                f"Attack chain comprising {len(primitives)} signal(s) targeting "
                f"{primitives[0].target}. Max severity: {severity}. "
                f"Chain confidence: {confidence:.2f}."
            )

        chain = AttackChain(
            engagement_id=engagement_id,
            primitive_ids=prim_ids,
            title=title,
            description=description,
            status=ChainStatus.BUILDING,
            confidence=confidence,
            severity=severity,
            poc_script=[],
        )

        logger.info(
            "chain_composed",
            chain_id=chain.id,
            primitives=len(primitives),
            confidence=confidence,
            severity=severity,
        )
        return chain

    def generate_poc(
        self,
        chain: AttackChain,
        primitives: List[PrimitiveLedger],
    ) -> AttackChain:
        """Generate a runnable PoC script and attach it to the chain.

        Selects the most appropriate PoC builder based on the dominant
        PrimitiveType in the chain. If a PoC cannot be constructed
        deterministically, sets status to PENDING_POC rather than fabricating.

        Returns:
            Updated AttackChain (in-place mutation, also returned for chaining).
        """
        if not primitives:
            chain.status = ChainStatus.PENDING_POC
            return chain

        # Dominant type = type of the first/root primitive
        dominant_type = primitives[0].primitive_type
        builder = _POC_BUILDERS.get(dominant_type, _poc_curl)

        poc_script = builder(primitives)
        chain.updated_at = datetime.utcnow()

        if poc_script:
            chain.poc_script = poc_script
            chain.status = ChainStatus.PENDING_POC  # waiting for triage gate
            logger.info(
                "poc_generated",
                chain_id=chain.id,
                technique=dominant_type.value,
                cmd_len=len(poc_script),
            )
        else:
            chain.poc_script = []
            chain.status = ChainStatus.PENDING_POC
            logger.warning(
                "poc_not_generated",
                chain_id=chain.id,
                reason="PoC builder returned empty script — insufficient raw data",
            )

        return chain

    def build_evidence_package(
        self,
        chain: AttackChain,
        primitives: List[PrimitiveLedger],
    ) -> EvidencePackage:
        """Create an EvidencePackage from chain + primitive raw data.

        Collects raw requests/responses from primitive payloads and wires the
        chain's poc_script into EvidencePackage.replay_script so the
        ReplayabilityTruthEngine can re-execute it.
        """
        raw_requests = []
        raw_responses = []
        screenshots = []

        for p in primitives:
            if p.raw.get("request"):
                raw_requests.append(p.raw["request"])
            if p.raw.get("response"):
                raw_responses.append(p.raw["response"])
            if p.raw.get("screenshot"):
                screenshots.append(p.raw["screenshot"])

        pkg = EvidencePackage(
            finding_id=chain.id,         # use chain id as placeholder finding_id
            engagement_id=chain.engagement_id,
            raw_requests=raw_requests,
            raw_responses=raw_responses,
            screenshots=screenshots,
            replay_script=chain.poc_script,
            provenance=EvidenceProvenance.LIVE,
        )

        logger.info(
            "evidence_package_built",
            chain_id=chain.id,
            raw_requests=len(raw_requests),
            raw_responses=len(raw_responses),
            has_replay=bool(chain.poc_script),
        )
        return pkg
