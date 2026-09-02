"""Deterministic Confidence Engine (charter section 17) + validation lifecycle.

Scores are AUDITABLE: every component derives from recorded signals, no LLM in
the loop. The Validation Engine (P2) is the only component permitted to move
`validation_state` to VALIDATED/REJECTED; until then findings are UNTESTED.

    confidence              overall belief the condition is real & exploitable
    evidence_score          quality/quantity of captured artifacts
    applicability_score     does this detector's precondition fit this target
    false_positive_probability  1 - calibrated confidence floor

Signals consumed (all already produced by the platform):
    finding_class        observation|weakness|vulnerability   (FIT layer)
    detection_level      detected|candidate                    (service probes)
    fp flags             catch_all / fp_prone_template         (nuclei runner)
    evidence count       len(evidence)
"""

import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

# Lifecycle states (persisted on Vulnerability.validation_state).
UNTESTED = "UNTESTED"
APPLICABLE = "APPLICABLE"
INCONCLUSIVE = "INCONCLUSIVE"
VALIDATED = "VALIDATED"
REJECTED = "REJECTED"

_VALID_TRANSITIONS = {
    UNTESTED: {APPLICABLE, INCONCLUSIVE, VALIDATED, REJECTED},
    APPLICABLE: {INCONCLUSIVE, VALIDATED, REJECTED},
    INCONCLUSIVE: {VALIDATED, REJECTED, APPLICABLE},
    VALIDATED: set(),  # terminal — only retest flow may reopen via new finding
    REJECTED: {UNTESTED},  # a NEW independent observation may revive for review
}


def can_transition(current: str, target: str) -> bool:
    return target in _VALID_TRANSITIONS.get(current, set())


def assert_transition(current: str, target: str,
                      finding_id: Optional[str] = None,
                      actor: Optional[str] = None,
                      explanation: Optional[str] = None) -> str:
    """Guard a lifecycle transition; optionally record WHO moved WHAT and WHY.

    FIX (transition-audit-2026-08-25): the ValidationEngine call site passes
    full provenance (finding_id, actor, explanation) for the charter-16 audit
    trail. Signature extended compatibly; returns target_state so callers may
    assign the result directly.
    """
    if not can_transition(current, target):
        raise ValueError(f"Illegal validation_state transition {current} -> {target}")
    if finding_id or actor:
        logging.getLogger(__name__).info(
            f"validation_state_transition finding={finding_id} "
            f"{current}->{target} actor={actor or 'unknown'} "
            f"reason={explanation or ''}"
        )
    return target


@dataclass
class ConfidenceScore:
    confidence: float
    evidence_score: float
    applicability_score: float
    false_positive_probability: float
    validation_state: str
    drivers: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def score_finding(
    finding_class: str,
    evidence_count: int = 0,
    fp_flags: int = 0,
    detection_level: str = "detected",
    validated: bool = False,
    rejected: bool = False,
    applicable: bool = False,
) -> ConfidenceScore:
    """Deterministic, auditable scoring. No hidden state."""
    drivers: Dict[str, Any] = {}

    # Evidence: saturating at 5 artifacts.
    ev = min(1.0, evidence_count / 5.0)

    # Applicability from class + level + flags.
    base = {"observation": 0.20, "weakness": 0.55, "vulnerability": 0.70}.get(finding_class, 0.40)
    if detection_level == "candidate":
        base += 0.10
    if fp_flags:
        base -= 0.25 * min(fp_flags, 2)
    applicability = max(0.05, min(1.0, base))
    drivers["applicability_inputs"] = {
        "class": finding_class,
        "level": detection_level,
        "fp_flags": fp_flags,
    }

    # Validation dominates when present.
    state = UNTESTED
    if rejected:
        state = REJECTED
    elif validated:
        state = VALIDATED
    elif applicable:
        state = APPLICABLE

    if state == VALIDATED:
        confidence = 0.90 + 0.09 * ev
    elif state == REJECTED:
        confidence = 0.05
    else:
        # Unvalidated ceiling: even perfect evidence cannot claim near-certainty.
        confidence = min(0.75, (0.35 * applicability + 0.45 * ev + 0.10))

    fp_probability = round(max(0.02, 1.0 - confidence), 3)
    return ConfidenceScore(
        confidence=round(confidence, 3),
        evidence_score=round(ev, 3),
        applicability_score=round(applicability, 3),
        false_positive_probability=fp_probability,
        validation_state=state,
        drivers=drivers,
    )
