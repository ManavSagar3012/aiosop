"""No report task can publish a release-shaped receipt without bounded hashes."""

from datetime import datetime

import pytest

from ai_osop.memory.session_memory import TaskORM
from ai_osop.memory.supervision_store import SupervisionConflict
from ai_osop.memory.terminal_lifecycle import _signed_report_terminal_receipt


def _task():
    return TaskORM(
        id="task-report-fixture", engagement_id="eng-report-fixture",
        type="generate_report", agent_type="reporting", approval_required=True,
        started_at=datetime.utcnow(),
        payload={
            "version": "v1", "require_attestation": True,
            "signer_key_id": "trusted-kid", "_authorization_version": 2,
        },
    )


def _result():
    return {
        "status": "success", "signature_status": "ed25519_signed",
        "report_id": "report-eng-report-fixture-v1", "requires_approval": True,
        "report_paths": {"json": "C:/private/password=secret"},
        "artifact_sha256": {
            name: format(index + 1, "064x")
            for index, name in enumerate(
                ("md", "html", "graph.html", "json", "attestation", "manifest")
            )
        },
    }


def test_exact_report_receipt_persists_hashes_without_paths_or_raw_evidence():
    expected = _result()
    receipt = _signed_report_terminal_receipt(_task(), expected)
    assert receipt["artifact_sha256"] == expected["artifact_sha256"]
    assert receipt["status"] == "success"
    assert "report_paths" not in receipt
    assert "secret" not in str(receipt)


@pytest.mark.parametrize("tamper", [
    lambda task, result: result["artifact_sha256"].pop("manifest"),
    lambda task, result: result["artifact_sha256"].update({"json": "x" * 64}),
    lambda task, result: result.update({"report_id": "report-other-v1"}),
    lambda task, result: result.update({"signature_status": "not_signed"}),
    lambda task, result: result.update({"requires_approval": False}),
    lambda task, result: result.update({"status": "execution_unknown"}),
    lambda task, result: setattr(task, "approval_required", False),
    lambda task, result: setattr(task, "started_at", None),
    lambda task, result: task.payload.update({"_authorization_version": "2"}),
    lambda task, result: task.payload.pop("signer_key_id"),
])
def test_unverified_report_terminal_receipts_fail_closed(tamper):
    task, result = _task(), _result()
    tamper(task, result)
    with pytest.raises(SupervisionConflict):
        _signed_report_terminal_receipt(task, result)


def test_unsigned_or_nonreport_task_retains_draft_only_generic_lifecycle():
    task = _task()
    task.payload["require_attestation"] = False
    assert _signed_report_terminal_receipt(task, _result()) is None
    task = _task()
    task.type = "summarize_context"
    assert _signed_report_terminal_receipt(task, _result()) is None
