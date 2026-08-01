"""TraceCapture: ActionLoop emits a JSONL trace per engagement."""

import json
import os

import pytest

from ai_osop.core.trace_capture import ActionTrace, TraceRecorder, hash_dedupe


def _mk_trace(step_idx: int = 0, engagement_id: str = "eng-x") -> ActionTrace:
    return ActionTrace(
        trace_id="t-1",
        engagement_id=engagement_id,
        goal="confirm sqli on /login",
        vuln_class="sqli",
        step_idx=step_idx,
        thought="first probe the form",
        action_name="sqli_oracle",
        action_params={"url": "http://t/login", "param": "user"},
        observation_status="ok",
        observation_summary="500 + sql syntax error collapsed",
        target="http://t",
        caller_model="gpt-4o",
        timestamp="2026-08-02T00:00:00Z",
    )


def test_hash_dedupe_stable_for_same_step():
    a = _mk_trace()
    b = _mk_trace()
    assert hash_dedupe(a) == hash_dedupe(b)


def test_hash_dedupe_differs_on_outcome():
    a = _mk_trace()
    b = _mk_trace()
    b.observation_status = "failed"
    assert hash_dedupe(a) != hash_dedupe(b)


def test_recorder_writes_jsonl_per_engagement(tmp_path, monkeypatch):
    monkeypatch.setenv("OSOP_TRACE_OUT_DIR", str(tmp_path))
    rec = TraceRecorder()
    assert rec.enabled
    rec.record(_mk_trace(step_idx=0))
    rec.record(_mk_trace(step_idx=1))
    written = (tmp_path / "eng-x.jsonl").read_text().splitlines()
    assert len(written) == 2
    parsed = [json.loads(w) for w in written]
    assert parsed[0]["step_idx"] == 0
    assert parsed[1]["step_idx"] == 1


def test_recorder_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("OSOP_TRACE_OUT_DIR", raising=False)
    rec = TraceRecorder()
    assert not rec.enabled
    assert rec.record(_mk_trace()) is None
    assert not os.listdir(tmp_path)
