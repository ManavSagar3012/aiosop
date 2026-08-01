"""Step D trace capture: snapshot of a single ActionLoop iteration for later
model training.

A trace pairs each (state, action) decision with its observation, so weeks of
running the platform against real targets produce the labeled dataset a LoRA
fine-tune actually needs. Writes are opt-in via OSOP_TRACE_OUT_DIR; no tracing
by default so dev boxes stay clean.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ActionTrace:
    """One step the loop took: prompt context, chosen action, observed result."""

    trace_id: str
    engagement_id: str
    goal: str
    vuln_class: str
    step_idx: int
    thought: str
    action_name: str
    action_params: Dict[str, Any]
    observation_status: str  # "ok" | "failed" | "rejected"
    observation_summary: str
    target: str
    caller_model: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "engagement_id": self.engagement_id,
            "goal": self.goal,
            "vuln_class": self.vuln_class,
            "step_idx": self.step_idx,
            "thought": self.thought,
            "action_name": self.action_name,
            "action_params": self.action_params,
            "observation_status": self.observation_status,
            "observation_summary": self.observation_summary,
            "target": self.target,
            "caller_model": self.caller_model,
            "timestamp": self.timestamp,
        }


class TraceRecorder:
    """Persists traces as JSONL files (one per engagement)."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.environ.get("OSOP_TRACE_OUT_DIR")
        self.enabled = bool(self.base_dir)
        if self.enabled:
            os.makedirs(self.base_dir, exist_ok=True)

    def _path_for(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.jsonl")

    def record(self, trace: ActionTrace) -> Optional[str]:
        if not self.enabled:
            return None
        line = json.dumps(trace.to_dict(), sort_keys=True, default=str)
        path = self._path_for(trace.engagement_id)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return path


def hash_dedupe(trace: ActionTrace) -> str:
    """Stable-content hash used downstream to dedupe identical steps."""
    key = "|".join(
        [
            trace.vuln_class,
            trace.action_name,
            json.dumps(trace.action_params, sort_keys=True, default=str),
            trace.observation_status,
            trace.observation_summary[:200],
        ]
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]
