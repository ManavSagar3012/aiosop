"""Step D-1: dataset builder converts ActionTrace JSONL into training rows."""

import json

import pytest

from ai_osop.core.trace_capture import ActionTrace
from ai_osop.training.dataset_builder import (
    TrainingRow,
    build_row,
    build_rows_from_traces,
    feedback_score,
)


def _mk_trace(**over):
    base = dict(
        trace_id="t-1",
        engagement_id="eng-x",
        goal="confirm sqli on /login",
        vuln_class="sqli",
        step_idx=0,
        thought="first probe the form",
        action_name="sqli_oracle",
        action_params={"url": "http://t/login", "param": "user"},
        observation_status="ok",
        observation_summary="500 + sql syntax error collapsed",
        target="http://t",
        caller_model="gpt-4o",
        timestamp="2026-08-02T00:00:00Z",
    )
    base.update(over)
    return ActionTrace(**base)


def test_feedback_score_rewards_validated_steps():
    ok = _mk_trace(observation_status="ok", observation_summary="evidence great")
    failed = _mk_trace(observation_status="failed", observation_summary="WAF blocked")
    rejected = _mk_trace(observation_status="rejected", observation_summary="policy: out of scope")
    assert feedback_score(ok) > feedback_score(failed) > feedback_score(rejected)


def test_build_row_attaches_hashes_and_keeps_trace_fields():
    row = build_row(_mk_trace())
    assert isinstance(row, TrainingRow)
    assert row.trace_id == "t-1"
    assert row.vuln_class == "sqli"
    assert row.action_name == "sqli_oracle"
    assert row.feedback_score > 0
    # evidence surface: observation_summary is hashed, not surfaced in raw form
    assert row.evidence_hash != ""
    assert "sql syntax error collapsed" not in json.dumps(row.to_dict())


def test_build_rows_from_traces_groups_by_engagement(tmp_path):
    f = tmp_path / "eng-x.jsonl"
    f.write_text("\n".join([json.dumps(_mk_trace(step_idx=i).to_dict()) for i in range(3)]))
    rows = list(build_rows_from_traces(tmp_path))
    assert len(rows) == 3
    assert all(r.engagement_id == "eng-x" for r in rows)


def test_build_rows_skips_malformed_lines(tmp_path):
    f = tmp_path / "eng-x.jsonl"
    f.write_text(
        json.dumps(_mk_trace().to_dict())
        + "\nnot-json\n"
        + json.dumps(_mk_trace(step_idx=1).to_dict())
    )
    rows = list(build_rows_from_traces(tmp_path))
    assert len(rows) == 2  # malformed line skipped
