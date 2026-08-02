"""D-2: held-out evaluator — splits the corpus into train/holdout, uses the same
AnchoredReasoner to score against a stub LLM and reports step-classification
accuracy. Baseline for any future 'now it learns' claim."""

import json
from pathlib import Path

import pytest

from ai_osop.training.evaluator import HeldoutEvaluator, split_corpus
from ai_osop.training.dataset_builder import TrainingRow


def _mk_row(i: int = 0, pattern: str = "sqli") -> TrainingRow:
    return TrainingRow(
        trace_id=f"t-{i}",
        engagement_id="eng-eval",
        step_idx=i,
        vuln_class=pattern,
        action_name="sqli_oracle" if pattern == "sqli" else "idor_read",
        action_params_hash="x" * 64,
        evidence_hash="y" * 64,
        observation_status="ok",
        feedback_score=1.0,
        target="http://t",
        caller_model="gpt-4o",
        timestamp="2026-08-02T00:00:00Z",
    )


def test_split_corpus_deterministic_and_disjoint():
    rows = [_mk_row(i) for i in range(100)]
    train, holdout = split_corpus(rows, holdout_frac=0.2, seed=7)
    assert len(holdout) == 20
    assert len(train) == 80
    assert set(r.trace_id for r in train) & set(r.trace_id for r in holdout) == set()
    # Deterministic across runs
    train2, holdout2 = split_corpus(rows, holdout_frac=0.2, seed=7)
    assert [r.trace_id for r in holdout] == [r.trace_id for r in holdout2]


def test_evaluator_scores_action_classification():
    class _StubLLM:
        async def complete(self, messages):
            # returns sqli_oracle to match 'sqli' rows
            return json.dumps({"think": "", "action": {"name": "sqli_oracle", "params": {}}})

    rows = [_mk_row(i) for i in range(10)]
    ev = HeldoutEvaluator(llm=_StubLLM())
    import asyncio

    rep = asyncio.run(ev.evaluate(rows, train_frac=0.2))
    assert rep["evaluated"] == 2
    # Stub always returns sqli_oracle matching the rows, so action accuracy = 1.0 on holdout
    assert rep["action_accuracy"] == 1.0
    assert rep["holdout_size"] >= 1


def test_evaluator_handles_empty_corpus():
    class _StubLLM:
        async def complete(self, messages):
            return json.dumps({"think": "", "action": {"name": "noop"}})

    ev = HeldoutEvaluator(llm=_StubLLM())
    import asyncio

    rep = asyncio.run(ev.evaluate([], train_frac=0.2))
    assert rep["evaluated"] == 0
    assert rep["action_accuracy"] == 0.0
