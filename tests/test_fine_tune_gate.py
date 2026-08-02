"""Step D-3 launcher: refuses to fine-tune on synthetic-only / low-score inputs."""

import json
import subprocess
import sys

import pytest


@pytest.fixture()
def synthetic_only_traces(tmp_path):
    from ai_osop.core.trace_capture import ActionTrace

    rows = []
    for i in range(600):
        t = ActionTrace(
            trace_id=f"t-{i}",
            engagement_id="eng-syn",
            goal="g",
            vuln_class="sqli",
            step_idx=0,
            thought="ok",
            action_name="noop",
            action_params={},
            observation_status="ok",
            observation_summary="everything works",
            target="http://t",
            caller_model="m",
            timestamp="2026-08-02T00:00:00Z",
        )
        rows.append(t.to_dict())
    f = tmp_path / "eng-syn.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in rows))
    return tmp_path


@pytest.fixture()
def real_mixed_traces(tmp_path):
    from ai_osop.core.trace_capture import ActionTrace

    rows = []
    for i in range(600):
        status = "ok" if i % 2 == 0 else "failed"
        t = ActionTrace(
            trace_id=f"t-{i}",
            engagement_id="eng-mixed",
            goal="g",
            vuln_class="idor",
            step_idx=0,
            thought="...",
            action_name="idor_probe",
            action_params={},
            observation_status=status,
            observation_summary="real results vary",
            target="http://t",
            caller_model="m",
            timestamp="2026-08-02T00:00:00Z",
        )
        rows.append(t.to_dict())
    f = tmp_path / "eng-mixed.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in rows))
    return tmp_path


def test_refuses_synthetic_only(synthetic_only_traces, tmp_path):
    eval_report = tmp_path / "eval.json"
    eval_report.write_text(json.dumps({"action_accuracy": 0.99}))
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/training/fine_tune_lora.py",
            "--traces-dir",
            str(synthetic_only_traces),
            "--eval-report",
            str(eval_report),
            "--out-model",
            "m",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        cwd="C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop",
    )
    assert proc.returncode != 0
    assert "synthetic" in proc.stderr.lower() or "flat" in proc.stderr.lower()


def test_refuses_low_accuracy_floor(real_mixed_traces, tmp_path):
    eval_report = tmp_path / "eval.json"
    eval_report.write_text(json.dumps({"action_accuracy": 0.30}))
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/training/fine_tune_lora.py",
            "--traces-dir",
            str(real_mixed_traces),
            "--eval-report",
            str(eval_report),
            "--out-model",
            "m",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        cwd="C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop",
    )
    assert proc.returncode != 0
    assert "below floor" in proc.stderr


def test_plan_succeeds_with_real_corpus_and_floor_met(real_mixed_traces, tmp_path):
    eval_report = tmp_path / "eval.json"
    eval_report.write_text(json.dumps({"action_accuracy": 0.80}))
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/training/fine_tune_lora.py",
            "--traces-dir",
            str(real_mixed_traces),
            "--eval-report",
            str(eval_report),
            "--out-model",
            "m",
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        cwd="C:/Users/HP/OneDrive/Desktop/burp_mcp/ai-osop",
    )
    assert proc.returncode == 0
    assert "eval gate passed" in proc.stdout
