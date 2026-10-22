"""Fail-closed checkpoint proposal integrity tests (no providers or database)."""

import pytest

from ai_osop.memory.model_usage import ModelOutcomeUncertain
from ai_osop.orchestrator.research_checkpoint import ResearchCheckpointStore


def test_restart_digest_stable_across_json_key_order():
    first = [{"type": "inspect", "description": "read-only", "target": "x"}]
    second = [{"target": "x", "description": "read-only", "type": "inspect"}]
    assert ResearchCheckpointStore._proposal_digest(first, "llm", "a" * 64) == (
        ResearchCheckpointStore._proposal_digest(second, "llm", "a" * 64)
    )


@pytest.mark.parametrize(
    "modified",
    [
        ([{"type": "inspect", "description": "changed"}], "llm", "a" * 64),
        ([{"type": "inspect", "description": "read-only"}], "deterministic", "a" * 64),
        ([{"type": "inspect", "description": "read-only"}], "llm", "b" * 64),
    ],
)
def test_mutated_proposal_provenance_or_research_changes_digest(modified):
    reference = ResearchCheckpointStore._proposal_digest(
        [{"type": "inspect", "description": "read-only"}], "llm", "a" * 64
    )
    assert ResearchCheckpointStore._proposal_digest(*modified) != reference


@pytest.mark.parametrize(
    "invalid",
    [
        [{"score": float("nan")}],
        [{"unsafe": object()}],
        [{}] * 16,
        [{"large": "X" * 19001}],
    ],
)
def test_corrupt_or_unbounded_checkpoint_never_recoverable(invalid):
    with pytest.raises(ModelOutcomeUncertain, match="no replay"):
        ResearchCheckpointStore._proposal_digest(invalid, "llm", "a" * 64)
