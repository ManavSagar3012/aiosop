"""Unit tests for ApprovalCoordinator.

Focuses on the static and pure methods that don't require mock orchestrators:
- ``_canonical_decision``: maps operator synonyms to canonical status
- ``is_task_approved``: authority check from approval request records
- ``has_pending_approval``: dedupe check for pending approvals
- ``_strip_stale_approval``: sanitises persistent grants
"""

from __future__ import annotations

from unittest.mock import MagicMock

from ai_osop.core.models import ApprovalRequest, Task
from ai_osop.orchestrator.approval_coordinator import ApprovalCoordinator


# ── _canonical_decision ───────────────────────────────────────────────────────


class TestCanonicalDecision:
    """Tests for the _canonical_decision static method."""

    # Approved synonyms

    def test_approve(self):
        assert ApprovalCoordinator._canonical_decision("approve") == "approved"

    def test_approved(self):
        assert ApprovalCoordinator._canonical_decision("approved") == "approved"

    def test_accept(self):
        assert ApprovalCoordinator._canonical_decision("accept") == "approved"

    def test_accepted(self):
        assert ApprovalCoordinator._canonical_decision("accepted") == "approved"

    def test_allow(self):
        assert ApprovalCoordinator._canonical_decision("allow") == "approved"

    def test_allowed(self):
        assert ApprovalCoordinator._canonical_decision("allowed") == "approved"

    def test_grant(self):
        assert ApprovalCoordinator._canonical_decision("grant") == "approved"

    def test_granted(self):
        assert ApprovalCoordinator._canonical_decision("granted") == "approved"

    def test_approve_case_insensitive(self):
        assert ApprovalCoordinator._canonical_decision("APPROVED") == "approved"

    def test_approve_mixed_case(self):
        assert ApprovalCoordinator._canonical_decision("Accept") == "approved"

    # Rejected synonyms

    def test_reject(self):
        assert ApprovalCoordinator._canonical_decision("reject") == "rejected"

    def test_rejected(self):
        assert ApprovalCoordinator._canonical_decision("rejected") == "rejected"

    def test_denied(self):
        """The most common mistake — "denied" must map to "rejected"."""
        assert ApprovalCoordinator._canonical_decision("denied") == "rejected"

    def test_deny(self):
        assert ApprovalCoordinator._canonical_decision("deny") == "rejected"

    def test_decline(self):
        assert ApprovalCoordinator._canonical_decision("decline") == "rejected"

    def test_declined(self):
        assert ApprovalCoordinator._canonical_decision("declined") == "rejected"

    def test_refused(self):
        assert ApprovalCoordinator._canonical_decision("refused") == "rejected"

    def test_refuse(self):
        assert ApprovalCoordinator._canonical_decision("refuse") == "rejected"

    # Modified synonyms

    def test_modify(self):
        assert ApprovalCoordinator._canonical_decision("modify") == "modified"

    def test_modified(self):
        assert ApprovalCoordinator._canonical_decision("modified") == "modified"

    def test_amend(self):
        assert ApprovalCoordinator._canonical_decision("amend") == "modified"

    def test_amended(self):
        assert ApprovalCoordinator._canonical_decision("amended") == "modified"

    def test_changed(self):
        assert ApprovalCoordinator._canonical_decision("changed") == "modified"

    # Unknown → passthrough

    def test_unknown_passthrough(self):
        """An unrecognised decision passes through as-is."""
        assert ApprovalCoordinator._canonical_decision("unknown") == "unknown"

    def test_empty_string(self):
        """Empty string returns empty string."""
        assert ApprovalCoordinator._canonical_decision("") == ""

    def test_none_becomes_empty_string(self):
        """None becomes empty string because 'decision or ""' evaluates to ""."""
        result = ApprovalCoordinator._canonical_decision(None)  # type: ignore[arg-type]
        assert result == ""  # None or "" = ""

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace is stripped before matching."""
        assert ApprovalCoordinator._canonical_decision("  approved  ") == "approved"


# ── is_task_approved / has_pending_approval ───────────────────────────────────


def _make_orch(requests: dict) -> MagicMock:
    """Build a mock orchestrator with _approval_requests populated."""
    orch = MagicMock()
    orch._approval_requests = requests
    return orch


class TestApprovalGate:
    """Tests for the approval authority methods."""

    def test_is_task_approved_yes(self):
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="approved",
                    operator_id="ops-1",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.is_task_approved("task-1") is True

    def test_is_task_approved_no_when_pending(self):
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="pending",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.is_task_approved("task-1") is False

    def test_is_task_approved_no_when_missing(self):
        orch = _make_orch({})
        coord = ApprovalCoordinator(orch)
        assert coord.is_task_approved("task-nonexistent") is False

    def test_is_task_approved_no_when_rejected(self):
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="rejected",
                    operator_id="ops-1",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.is_task_approved("task-1") is False

    def test_is_task_approved_requires_operator_id(self):
        """An approved request WITHOUT an operator_id does NOT count as approved."""
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="approved",
                    operator_id="",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.is_task_approved("task-1") is False

    def test_has_pending_approval_yes(self):
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="pending",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.has_pending_approval("task-1") is True

    def test_has_pending_approval_no_when_resolved(self):
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="approved",
                    operator_id="ops-1",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.has_pending_approval("task-1") is False

    def test_has_pending_approval_no_when_missing(self):
        orch = _make_orch({})
        coord = ApprovalCoordinator(orch)
        assert coord.has_pending_approval("task-42") is False

    def test_multi_task_distinct_approvals(self):
        """Different tasks have independent approval states."""
        orch = _make_orch(
            {
                "apr-1": ApprovalRequest(
                    task_id="task-1",
                    agent_id="",
                    action_type="test",
                    target="x",
                    payload_summary="x",
                    status="approved",
                    operator_id="ops-1",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
                "apr-2": ApprovalRequest(
                    task_id="task-2",
                    agent_id="",
                    action_type="test",
                    target="y",
                    payload_summary="y",
                    status="pending",
                    risk_assessment="medium",
                    engagement_id="eng-1",
                ),
            }
        )
        coord = ApprovalCoordinator(orch)
        assert coord.is_task_approved("task-1") is True
        assert coord.is_task_approved("task-2") is False
        assert coord.has_pending_approval("task-1") is False
        assert coord.has_pending_approval("task-2") is True


class TestApprovedRequestId:
    """Tests for the approved_request_id method."""

    def test_returns_id_when_approved(self):
        apr = ApprovalRequest(
            id="apr-1",
            task_id="task-1",
            agent_id="",
            action_type="test",
            target="x",
            payload_summary="x",
            status="approved",
            operator_id="ops-1",
            risk_assessment="medium",
            engagement_id="eng-1",
        )
        orch = _make_orch({"apr-1": apr})
        coord = ApprovalCoordinator(orch)
        assert coord.approved_request_id("task-1") == "apr-1"

    def test_returns_none_when_pending(self):
        apr = ApprovalRequest(
            id="apr-1",
            task_id="task-1",
            agent_id="",
            action_type="test",
            target="x",
            payload_summary="x",
            status="pending",
            risk_assessment="medium",
            engagement_id="eng-1",
        )
        orch = _make_orch({"apr-1": apr})
        coord = ApprovalCoordinator(orch)
        assert coord.approved_request_id("task-1") is None

    def test_returns_none_when_missing(self):
        orch = _make_orch({})
        coord = ApprovalCoordinator(orch)
        assert coord.approved_request_id("nonexistent") is None

    def test_returns_none_when_no_operator(self):
        """An approved request without an operator_id returns None (safety)."""
        apr = ApprovalRequest(
            id="apr-1",
            task_id="task-1",
            agent_id="",
            action_type="test",
            target="x",
            payload_summary="x",
            status="approved",
            operator_id="",
            risk_assessment="medium",
            engagement_id="eng-1",
        )
        orch = _make_orch({"apr-1": apr})
        coord = ApprovalCoordinator(orch)
        assert coord.approved_request_id("task-1") is None


class TestStripStaleApproval:
    """Tests for the _strip_stale_approval static method."""

    def test_strips_both_fields_from_approved_task(self):
        task = Task(
            type="exploit_validation",
            agent_type="exploit_validation",
            priority=9,
            engagement_id="eng-1",
            approval_required=True,
            payload={"operator_approved": True, "approval_id": "apr-1", "url": "http://x"},
        )
        ApprovalCoordinator._strip_stale_approval(task)
        assert "operator_approved" not in task.payload
        assert "approval_id" not in task.payload
        assert task.payload.get("url") == "http://x"

    def test_skips_non_dict_payload(self):
        task = Task(
            type="scan",
            agent_type="recon",
            priority=5,
            engagement_id="eng-1",
            payload={"key": "value"},
        )
        ApprovalCoordinator._strip_stale_approval(task)

    def test_skips_non_approval_tasks(self):
        task = Task(
            type="normal_scan",
            agent_type="recon",
            priority=5,
            engagement_id="eng-1",
            approval_required=False,
            payload={"operator_approved": True, "url": "http://x"},
        )
        ApprovalCoordinator._strip_stale_approval(task)
        assert "operator_approved" in task.payload  # not stripped when approval_required=False
