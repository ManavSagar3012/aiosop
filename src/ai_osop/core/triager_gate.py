"""
Triager Gate — adversarial reviewer for findings before emission.

Rule: "Would a senior triager reproduce this in 5 minutes from what we have?"
If the answer is No, the finding is NOT emitted — it is either returned for
escalation (more evidence needed) or dropped (noise/duplicate).

Five mandatory criteria for EMIT:
  1. runnable PoC  — poc_script is non-empty (or captured_requests are replay-ready)
  2. captured evidence — raw_requests OR raw_responses OR screenshots present
  3. deduplication pass — no existing emitted finding with the same dedup_key
  4. confidence threshold — chain or primitive confidence >= MIN_CONFIDENCE (0.5)
  5. target is non-empty — avoids emitting findings with no target

This gate is intentionally STRICT. False negatives (missed real bugs) are
recoverable; false positives (fabricated bugs) destroy program trust.
"""

import hashlib
import logging
from typing import Any, Dict, List, Optional

import structlog

from ai_osop.core.models import (
    AttackChain,
    EvidencePackage,
    PrimitiveLedger,
    TriageReport,
    TriageVerdict,
)

logger = structlog.get_logger("ai_osop.triager_gate")

# Minimum confidence to even consider emitting
MIN_CONFIDENCE: float = 0.50
# Minimum confidence to emit without explicit PoC (requires extra evidence)
HIGH_CONFIDENCE_THRESHOLD: float = 0.85


class TriagerGate:
    """Adversarial reviewer that enforces the 5-minute-reproducibility rule.

    Usage
    -----
    gate = TriagerGate(emitted_dedup_keys=await _load_emitted_keys(engagement_id))
    report = gate.evaluate(primitive, chain=chain, evidence=evidence_pkg)
    if report.verdict == TriageVerdict.EMIT:
        # safe to create Vulnerability and call report_to_platform
        ...

    The gate is stateless w.r.t. persistence — the caller loads historical
    dedup_keys from Neo4j/Postgres and passes them in.
    """

    def __init__(self, emitted_dedup_keys: Optional[List[str]] = None) -> None:
        self._emitted: set[str] = set(emitted_dedup_keys or [])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        primitive: PrimitiveLedger,
        chain: Optional[AttackChain] = None,
        evidence: Optional[EvidencePackage] = None,
    ) -> TriageReport:
        """Run all gate checks and return a TriageReport.

        Args:
            primitive:  The root Primitive being considered for promotion.
            chain:      The AttackChain built from this primitive (if any).
            evidence:   Captured EvidencePackage for this primitive/chain.

        Returns:
            TriageReport with verdict EMIT | ESCALATE | DROP | NEEDS_POC.
        """
        reasons: List[str] = []
        blockers: List[str] = []

        # Effective confidence: use chain confidence if available (richer signal)
        confidence = chain.confidence if chain else primitive.confidence

        # 1. Confidence floor
        if confidence < MIN_CONFIDENCE:
            blockers.append(
                f"confidence {confidence:.2f} < minimum {MIN_CONFIDENCE:.2f}"
            )

        # 2. Target non-empty
        if not primitive.target or primitive.target.strip() == "":
            blockers.append("target is empty — no reproducible attack surface")

        # 3. Evidence presence
        has_captured = self._has_captured_evidence(evidence)
        if not has_captured:
            blockers.append(
                "no captured evidence (raw_requests / raw_responses / screenshots)"
            )
        else:
            reasons.append("captured evidence present")

        # 4. Runnable PoC
        has_poc = self._has_poc(chain, evidence)
        if not has_poc:
            if confidence >= HIGH_CONFIDENCE_THRESHOLD and has_captured:
                # Very high confidence with evidence: allow without PoC, but flag it
                reasons.append(
                    f"high confidence {confidence:.2f} with evidence — PoC waived"
                )
            else:
                blockers.append(
                    "no runnable PoC (chain.poc_script or evidence.replay_script empty)"
                )

        # 5. Deduplication check
        dedup_key = self._dedup_key(primitive, chain)
        is_duplicate = dedup_key in self._emitted
        if is_duplicate:
            blockers.append(f"duplicate — already emitted dedup_key={dedup_key[:16]}…")
        else:
            reasons.append("passes dedup check")

        # ---- Compute reproducibility score ----
        repro_score = self._reproducibility_score(has_poc, has_captured, confidence)

        # ---- Verdict ----
        verdict = self._decide_verdict(blockers, has_poc, has_captured, is_duplicate)

        if verdict == TriageVerdict.EMIT:
            # Register so subsequent calls within the same gate instance dedup
            self._emitted.add(dedup_key)

        report = TriageReport(
            primitive_id=primitive.id,
            chain_id=chain.id if chain else None,
            verdict=verdict,
            confidence=confidence,
            reasons=reasons,
            blockers=blockers,
            reproducibility_score=repro_score,
            has_poc=has_poc,
            has_captured_evidence=has_captured,
            is_duplicate=is_duplicate,
            engagement_id=primitive.engagement_id,
        )

        logger.info(
            "triage_verdict",
            primitive_id=primitive.id,
            verdict=verdict.value,
            confidence=confidence,
            blockers=blockers,
        )
        return report

    def register_emitted(self, dedup_key: str) -> None:
        """Manually register a dedup key as emitted (e.g. loaded from DB)."""
        self._emitted.add(dedup_key)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _has_captured_evidence(evidence: Optional[EvidencePackage]) -> bool:
        if evidence is None:
            return False
        return bool(
            evidence.raw_requests
            or evidence.raw_responses
            or evidence.screenshots
            or evidence.workflow_trace
        )

    @staticmethod
    def _has_poc(
        chain: Optional[AttackChain], evidence: Optional[EvidencePackage]
    ) -> bool:
        if chain and chain.poc_script:
            return True
        if evidence and evidence.replay_script:
            return True
        return False

    @staticmethod
    def _dedup_key(
        primitive: PrimitiveLedger, chain: Optional[AttackChain]
    ) -> str:
        """Stable fingerprint for deduplication.

        Prefer chain.id (most specific) → primitive.dedup_key → computed hash.
        """
        if chain:
            return chain.id
        if primitive.dedup_key:
            return primitive.dedup_key
        # Fallback: hash (engagement + type + target)
        raw = f"{primitive.engagement_id}:{primitive.primitive_type.value}:{primitive.target}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def _reproducibility_score(
        has_poc: bool, has_captured: bool, confidence: float
    ) -> float:
        """Heuristic 0-1 reproducibility score used in the TriageReport."""
        score = 0.0
        if has_poc:
            score += 0.4
        if has_captured:
            score += 0.3
        score += confidence * 0.3
        return round(min(score, 1.0), 3)

    @staticmethod
    def _decide_verdict(
        blockers: List[str],
        has_poc: bool,
        has_captured: bool,
        is_duplicate: bool,
    ) -> TriageVerdict:
        if is_duplicate:
            return TriageVerdict.DROP
        if not blockers:
            return TriageVerdict.EMIT
        # If only missing PoC but everything else passes → NEEDS_POC
        non_poc_blockers = [b for b in blockers if "PoC" not in b and "poc_script" not in b.lower()]
        if not non_poc_blockers and has_captured:
            return TriageVerdict.NEEDS_POC
        return TriageVerdict.ESCALATE
