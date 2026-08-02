"""Auditable confidence scoring for security findings.

The score is deliberately a transparent evidence rubric, not a replacement for
the finding's model confidence.  A caller must explicitly attest replay,
ground-truth, and attack-path signals; storing a payload alone never implies
that it was independently reproduced.
"""

from typing import Any, Dict, List, Mapping

SIGNAL_WEIGHTS: Dict[str, int] = {
    "tool_validation": 20,
    "payload_reproduced": 20,
    "evidence_stored": 15,
    "ground_truth_match": 15,
    "manual_replay_succeeds": 15,
    "attack_path_confirmed": 15,
}


def score_signals(signals: Mapping[str, bool]) -> Dict[str, Any]:
    """Calculate a 0--100 confidence score from independently attested signals.

    Raises:
        ValueError: If a caller supplies a signal outside the stable rubric.
    """
    unknown = set(signals) - set(SIGNAL_WEIGHTS)
    if unknown:
        raise ValueError(f"Unknown confidence signal(s): {', '.join(sorted(unknown))}")

    verified: List[str] = []
    missing: List[str] = []
    score = 0
    for signal, weight in SIGNAL_WEIGHTS.items():
        if signals.get(signal, False):
            score += weight
            verified.append(signal)
        else:
            missing.append(signal)

    return {
        "score": score,
        "confidence": score / 100,
        "verified_signals": verified,
        "missing_signals": missing,
        "weights": SIGNAL_WEIGHTS.copy(),
    }


def score_finding(finding: Mapping[str, Any], attestations: Mapping[str, bool]) -> Dict[str, Any]:
    """Score a finding using persisted facts plus explicit independent attestations.

    ``tool_validation`` and ``evidence_stored`` are derived from the persisted
    finding. All other signals must be supplied by the caller so this function
    cannot inflate confidence from correlated evidence.
    """
    evidence = finding.get("evidence")
    signals = {
        "tool_validation": bool(finding.get("validated") and finding.get("tool_source")),
        "payload_reproduced": False,
        "evidence_stored": bool(evidence),
        "ground_truth_match": False,
        "manual_replay_succeeds": False,
        "attack_path_confirmed": False,
    }
    signals.update(attestations)
    return score_signals(signals)
