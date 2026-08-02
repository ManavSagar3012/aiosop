"""Build training rows from raw ActionTrace JSONL files.

Input: per-engagement ``<engagement_id>.jsonl`` files written by TraceRecorder.
Output: ``TrainingRow`` objects — one per trace — with evidence hashed so
prompts/responses don't ship raw in the training corpus (they'd be giant +
contain user-supplied data that needs minimization anyway).

feedback_score is a 0–1 proxy signal: ``ok`` steps score highest, ``failed``
next, ``rejected`` lowest. Later replaced by proper labels.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from ai_osop.core.trace_capture import ActionTrace


@dataclass
class TrainingRow:
    """One line of (state, action, outcome) the learner will see."""

    trace_id: str
    engagement_id: str
    step_idx: int
    vuln_class: str
    action_name: str
    action_params_hash: str
    evidence_hash: str
    observation_status: str
    feedback_score: float
    target: str
    caller_model: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "engagement_id": self.engagement_id,
            "step_idx": self.step_idx,
            "vuln_class": self.vuln_class,
            "action_name": self.action_name,
            "action_params_hash": self.action_params_hash,
            "evidence_hash": self.evidence_hash,
            "observation_status": self.observation_status,
            "feedback_score": self.feedback_score,
            "target": self.target,
            "caller_model": self.caller_model,
            "timestamp": self.timestamp,
        }


def feedback_score(trace: ActionTrace) -> float:
    """Convert observation status + evidence density into a 0–1 quality signal."""
    if trace.observation_status == "ok":
        base = 1.0
    elif trace.observation_status == "failed":
        base = 0.4
    elif trace.observation_status == "rejected":
        base = 0.1
    else:
        base = 0.2

    # Slight discount for empty evidence (a "ok" with nothing learned is suspicious).
    if not trace.observation_summary.strip():
        return base * 0.5
    return base


def build_row(trace: ActionTrace) -> TrainingRow:
    """Convert one trace into a training row."""
    return TrainingRow(
        trace_id=trace.trace_id,
        engagement_id=trace.engagement_id,
        step_idx=trace.step_idx,
        vuln_class=trace.vuln_class,
        action_name=trace.action_name,
        action_params_hash=hashlib.sha256(
            json.dumps(trace.action_params, sort_keys=True, default=str).encode()
        ).hexdigest(),
        evidence_hash=hashlib.sha256(trace.observation_summary.encode()).hexdigest(),
        observation_status=trace.observation_status,
        feedback_score=feedback_score(trace),
        target=trace.target,
        caller_model=trace.caller_model,
        timestamp=trace.timestamp,
    )


def build_rows_from_traces(base_dir: Any) -> Iterator[TrainingRow]:
    """Yield one TrainingRow per valid JSONL line across all files in ``base_dir``.

    Malformed lines are skipped (logged by callers that care). Files are matched
    per engagement: ``<engagement_id>.jsonl``.
    """
    base = Path(base_dir)
    for path in sorted(base.glob("*.jsonl")):
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    trace = ActionTrace(**json.loads(raw))
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                yield build_row(trace)
