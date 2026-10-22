"""Compare only durable, doubly approved provider testimony; no target requests."""

from copy import deepcopy

import pytest

from ai_osop.core.config import AgentType
from ai_osop.core.models import Task
from ai_osop.core.signed_replay_comparison import (
    classify_signed_observation_pair,
    observation_subtask_id,
    observation_task_id,
)


SID, PARENT, FLOW, WID, STEP = (
    "eng-owned",
    "task-parent",
    "flow-owned",
    "wf-owned",
    "step-owned",
)
SHA = "a" * 64


def pair(source_status=200, target_status=200, *, same_body=True):
    tasks = []
    for role, label, status, digest in (
        ("source", "alice", source_status, SHA),
        ("target", "bob", target_status, SHA if same_body else "b" * 64),
    ):
        tasks.append(
            Task(
                id=observation_task_id(SID, PARENT, FLOW, WID, STEP, label, 7),
                engagement_id=SID,
                flow_id=FLOW,
                parent_task_id=PARENT,
                dependencies=[PARENT],
                type="navigate",
                agent_type=AgentType.WORKFLOW,
                status="completed",
                approval_required=True,
                max_retries=0,
                payload={
                    "url": "https://authorized.test/account",
                    "method": "GET",
                    "user_label": label,
                    "source_user_label": "alice",
                    "target_user_label": "bob",
                    "_comparison_role": role,
                    "_authorization_version": 7,
                    "_flow_revision": 3,
                    "step_id": STEP,
                    "workflow_id": WID,
                    "operator_approved": True,
                    "approval_id": "apr-" + role,
                },
                result={
                    "status": "success",
                    "verification_status": "provider_testimony_only",
                    "authorization_violation_verified": False,
                    "remote_effect_verified": False,
                    "source_task_id": "task-original",
                    "replay_parent_task_id": PARENT,
                    "comparison_role": role,
                    "redirected": False,
                    "http_status_code": status,
                    "response_body_sha256": digest,
                    "provider_evidence": {
                        "provider_event_id": "evt-" + role,
                        "provider_receipt_sha256": SHA,
                        "source_authenticity_verified": False,
                        "target_effect_verified": False,
                        "finding_verified": False,
                    },
                },
            )
        )
    return tasks


def verdict(source, target):
    return classify_signed_observation_pair(
        source,
        target,
        engagement_id=SID,
        parent_id=PARENT,
        flow_id=FLOW,
        workflow_id=WID,
        step_id=STEP,
        source_identity="alice",
        target_identity="bob",
        version=7,
        flow_revision=3,
        original_source_task_id="task-original",
    )


@pytest.mark.parametrize(
    "status_a,status_b,match,expected",
    [
        (200, 200, True, "candidate_needs_independent_review"),
        (200, 200, False, "inconclusive"),
        (200, 403, True, "expected_denial_observed"),
        (200, 302, True, "inconclusive"),
        (401, 200, True, "inconclusive"),
    ],
)
def test_never_promotes_success_or_matching_body_to_vulnerability(
    status_a,
    status_b,
    match,
    expected,
):
    source, target = pair(status_a, status_b, same_body=match)
    decision = verdict(source, target)
    assert decision["status"] == expected
    assert decision["source_observed"] and decision["target_observed"]
    assert decision["findings_count"] == 0
    assert decision["authorization_violation_verified"] is False
    assert decision["target_effect_verified"] is False
    assert decision["source_authenticity_verified"] is False
    assert len(decision["comparison_sha256"]) == 64
    assert "alice" not in str(decision) and "bob" not in str(decision)
    assert "authorized.test" not in str(decision)
    assert SHA not in str(decision)


@pytest.mark.parametrize(
    "tamper",
    [
        "foreign_tenant",
        "source_missing",
        "same_identity",
        "stale_authorization",
        "approval_revoked",
        "unsigned_provider",
        "unknown_remote",
        "source_task_forged",
        "step_mismatch",
        "target_switched",
        "missing_digest",
        "redirected",
        "wrong_source_role",
    ],
)
def test_ambiguous_or_spoofed_pair_fails_closed(tamper):
    source, target = pair()
    if tamper == "foreign_tenant":
        target.engagement_id = "eng-foreign"
    elif tamper == "source_missing":
        source = None
    elif tamper == "same_identity":
        target.payload["user_label"] = "alice"
    elif tamper == "stale_authorization":
        target.payload["_authorization_version"] = 6
    elif tamper == "approval_revoked":
        target.payload.pop("operator_approved")
    elif tamper == "unsigned_provider":
        target.result["provider_evidence"]["provider_receipt_sha256"] = "forged"
    elif tamper == "unknown_remote":
        target.status = "dispatch_unknown"
    elif tamper == "source_task_forged":
        target.result["source_task_id"] = "task-foreign"
    elif tamper == "step_mismatch":
        target.payload["step_id"] = "step-other"
    elif tamper == "target_switched":
        target.payload["url"] = "https://foreign.test/"
    elif tamper == "missing_digest":
        target.result["response_body_sha256"] = None
        assert verdict(source, target)["status"] == "inconclusive"
        return
    elif tamper == "redirected":
        target.result["redirected"] = True
        assert verdict(source, target)["status"] == "inconclusive"
        return
    elif tamper == "wrong_source_role":
        source.result["comparison_role"] = "target"
    decision = verdict(source, target)
    assert decision["status"] == "inconclusive"
    assert decision["findings_count"] == 0


def test_task_identity_role_is_stable_and_readonly():
    source, target = pair()
    assert source.id != target.id
    assert observation_task_id(SID, PARENT, FLOW, WID, STEP, "alice", 7) == source.id
    assert observation_subtask_id(source.id) != observation_subtask_id(target.id)
    assert observation_subtask_id(source.id) == observation_subtask_id(source.id)
    with pytest.raises(ValueError):
        observation_task_id("../tenant", PARENT, FLOW, WID, STEP, "alice", 7)
    with pytest.raises(ValueError):
        observation_subtask_id("task-../foreign")


def test_new_signed_subtask_lineage_is_immutable_and_provider_only():
    source, target = pair()
    source.subtask_id = observation_subtask_id(source.id)
    target.subtask_id = observation_subtask_id(target.id)
    assert verdict(source, target)["status"] == "candidate_needs_independent_review"
    assert verdict(source, target)["authorization_violation_verified"] is False
    target.subtask_id = observation_subtask_id(source.id)
    assert verdict(source, target)["status"] == "inconclusive"
    target.subtask_id = None
    assert verdict(source, target)["status"] == "inconclusive"
