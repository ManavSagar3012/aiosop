"""Held-out evaluator for Step D candidacy.

Splits TrainingRows into train/holdout deterministically (seed), runs an
AnchoredReasoner against the holdout with the LLM supplied, and returns the
action-classification accuracy so any "distillation beats baseline" claim has
a concrete number to clear.
"""

from __future__ import annotations

import json
import random
from typing import Any, Dict, List, Optional, Tuple

from ai_osop.core.action_loop_anchored import AnchoredReasoner
from ai_osop.training.dataset_builder import TrainingRow


def split_corpus(
    rows: List[TrainingRow], holdout_frac: float = 0.2, seed: int = 42
) -> Tuple[List[TrainingRow], List[TrainingRow]]:
    """Deterministically split into (train, holdout) by trace_id."""
    if not rows:
        return [], []
    rng = random.Random(seed)
    rows_order = sorted(rows, key=lambda r: r.trace_id)
    shuffled = list(rows_order)
    rng.shuffle(shuffled)
    holdout_n = max(1, int(round(len(shuffled) * holdout_frac)))
    holdout = shuffled[:holdout_n]
    train = shuffled[holdout_n:]
    return train, holdout


def _parse_action(llm_raw: Any) -> Optional[str]:
    """Extract action.name from the AnchoredReasoner's raw output."""
    if isinstance(llm_raw, dict):
        return llm_raw.get("action", {}).get("name")
    if isinstance(llm_raw, str):
        try:
            obj = json.loads(llm_raw)
            return (obj.get("action") or {}).get("name")
        except (json.JSONDecodeError, AttributeError):
            return None
    return None


class HeldoutEvaluator:
    """Evaluates the reasoner against a holdout: % where predicted action matches."""

    def __init__(self, llm: Any, holdout_frac: float = 0.2, seed: int = 42):
        self.llm = llm
        self.holdout_frac = holdout_frac
        self.seed = seed

    async def evaluate(
        self, rows: List[TrainingRow], train_frac: Optional[float] = None
    ) -> Dict[str, Any]:
        """Score the reasoner on the holdout. Returns a metrics dict."""
        frac = self.holdout_frac if train_frac is None else train_frac
        rows = list(rows)
        if not rows:
            return {
                "holdout_size": 0,
                "evaluated": 0,
                "action_accuracy": 0.0,
                "correct": 0,
                "wrong": 0,
                "per_class": {},
            }

        train, holdout = split_corpus(rows, holdout_frac=frac, seed=self.seed)
        reasoner = AnchoredReasoner(self.llm, max_window=8)

        correct = wrong = 0
        per_class: Dict[str, Dict[str, int]] = {}
        for row in holdout:
            prompt_state = {
                "goal": f"on {row.target}",
                "observations": [],
                "allowed_actions_hint": [row.action_name],
            }
            out = await reasoner.reason_step(prompt_state)
            predicted = out.action.get("name") if isinstance(out.action, dict) else None
            predicted = predicted or _parse_action(out.action)

            bucket = per_class.setdefault(row.vuln_class, {"correct": 0, "wrong": 0})
            if predicted == row.action_name:
                correct += 1
                bucket["correct"] += 1
            else:
                wrong += 1
                bucket["wrong"] += 1

        evaluated = correct + wrong
        return {
            "holdout_size": len(holdout),
            "evaluated": evaluated,
            "action_accuracy": correct / evaluated if evaluated else 0.0,
            "correct": correct,
            "wrong": wrong,
            "per_class": per_class,
        }
