"""No hidden nested options may change after an operator reviews a task."""

import pytest

from ai_osop.safety.approval_binding import (
    matches_pinned_payload, pinned_evidence, task_payload_sha256,
)


def test_nested_payload_fingerprint_is_stable_across_key_order_only():
    first = {"target": "https://example.com", "options": {"ports": [443, 8443], "rate": 2}}
    second = {"options": {"rate": 2, "ports": [443, 8443]}, "target": "https://example.com"}
    evidence = pinned_evidence([], first)
    assert matches_pinned_payload(evidence, second)
    assert len(evidence[0]["sha256"]) == 64
    assert "example.com" not in str(evidence)


@pytest.mark.parametrize("modified", [
    {"target": "https://example.com", "options": {"ports": [443, 8080], "rate": 2}},
    {"target": "https://example.com", "options": {"ports": [443, 8443], "rate": 3}},
    {"target": "https://example.com", "options": {"ports": [443, 8443], "rate": 2}, "headers": {"Host": "other.example"}},
])
def test_changed_nested_payload_cannot_reuse_previous_approval(modified):
    initial = {"target": "https://example.com", "options": {"ports": [443, 8443], "rate": 2}}
    assert not matches_pinned_payload(pinned_evidence([], initial), modified)


def test_grant_metadata_does_not_change_approved_payload_fingerprint():
    original = {"target": "https://example.com", "options": {"port": 443}}
    approved = {**original, "approval_id": "apr-one", "operator_approved": True}
    assert matches_pinned_payload(pinned_evidence([], original), approved)


def test_unbound_legacy_approval_and_forged_digest_fail_closed():
    payload = {"target": "https://example.com"}
    assert not matches_pinned_payload([], payload)
    assert not matches_pinned_payload([{"kind": "task_payload_sha256_v1", "sha256": "0" * 64}], payload)
    assert not matches_pinned_payload([{"kind": "task_payload_sha256_v1", "sha256": task_payload_sha256(payload)}] * 2, payload)
    received = [{"kind": "task_payload_sha256_v1", "sha256": "0" * 64}]
    assert matches_pinned_payload(pinned_evidence(received, payload), payload)


@pytest.mark.parametrize("payload", [
    [], None, {"non_finite": float("nan")}, {"unserializable": object()},
    {"huge": "x" * 270000},
])
def test_noncanonical_or_oversize_request_cannot_be_bound(payload):
    with pytest.raises(ValueError):
        task_payload_sha256(payload)
