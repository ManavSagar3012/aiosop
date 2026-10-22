"""Approved browser replay identity provenance is non-reversible and revocable."""

import hashlib
import json
from datetime import datetime, timezone

import pytest

from ai_osop.auth.session_store import UserSession
from ai_osop.core.authority_session_binding import (
    AuthoritySessionBindingUnavailable,
    bound_replay_fingerprints,
    reverify_replay_fingerprints,
)


def _session(label="alpha"):
    return UserSession(
        engagement_id="eng-provenance",
        user_label=label,
        cookies=[{"name": "session", "value": "private-cookie-123", "domain": "lab.example.test"}],
        bearer_token="private-bearer-abc",
        captured_at=datetime(2026, 10, 16, tzinfo=timezone.utc),
    )


def _values(label="alpha"):
    return dict(
        engagement_id="eng-provenance",
        user_label=label,
        method="GET",
        url="https://lab.example.test/private/asset",
        task_id="task-observation",
        parent_task_id="task-approved-parent",
    )


def test_default_disabled_preserves_existing_approved_manual_replay(monkeypatch):
    monkeypatch.delenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", raising=False)
    assert bound_replay_fingerprints(_session(), **_values()) == {}
    reverify_replay_fingerprints({}, _session(), **_values())


def test_approved_session_and_request_are_keyed_never_raw(monkeypatch):
    monkeypatch.setenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", "A" * 48)
    witness = bound_replay_fingerprints(_session(), **_values())
    assert set(witness) == {"_authority_request_sha256", "_authority_session_sha256"}
    assert all(
        len(value) == 64 and value != hashlib.sha256(b"private-cookie-123").hexdigest()
        for value in witness.values()
    )
    assert "private-cookie" not in json.dumps(witness)
    assert "private-bearer" not in json.dumps(witness)
    reverify_replay_fingerprints(witness, _session(), **_values())


def test_rotated_session_or_changed_request_denied_before_dispatch(monkeypatch):
    monkeypatch.setenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", "A" * 48)
    witness = bound_replay_fingerprints(_session(), **_values())
    changed = _session()
    changed.cookies[0]["value"] = "rotated-cookie"
    with pytest.raises(AuthoritySessionBindingUnavailable, match="rotated"):
        reverify_replay_fingerprints(witness, changed, **_values())
    with pytest.raises(AuthoritySessionBindingUnavailable, match="rotated"):
        reverify_replay_fingerprints(
            witness, _session(), **{**_values(), "url": "https://lab.example.test/other"}
        )


@pytest.mark.parametrize("key", ["x", " " * 60, "A" * 257])
def test_bad_provenance_secret_fails_closed(monkeypatch, key):
    monkeypatch.setenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", key)
    with pytest.raises(AuthoritySessionBindingUnavailable):
        bound_replay_fingerprints(_session(), **_values())


def test_secret_removed_after_admission_prevents_oracle_promotability(monkeypatch):
    monkeypatch.setenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", "A" * 48)
    witness = bound_replay_fingerprints(_session(), **_values())
    monkeypatch.delenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY")
    with pytest.raises(AuthoritySessionBindingUnavailable):
        reverify_replay_fingerprints(witness, _session(), **_values())


def test_source_and_target_sessions_are_distinct(monkeypatch):
    monkeypatch.setenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", "A" * 48)
    source = bound_replay_fingerprints(_session("alpha"), **_values("alpha"))
    target = bound_replay_fingerprints(_session("bravo"), **_values("bravo"))
    assert source["_authority_session_sha256"] != target["_authority_session_sha256"]


def test_partial_or_unrecognized_authority_witness_denied(monkeypatch):
    monkeypatch.setenv("OSOP_TARGET_AUTHORITY_PROVENANCE_KEY", "A" * 48)
    witness = bound_replay_fingerprints(_session(), **_values())
    bad_bindings = [
        {"_authority_request_sha256": witness["_authority_request_sha256"]},
        {"_authority_session_sha256": witness["_authority_session_sha256"]},
        {**witness, "_authority_forged": "trusted"},
        {"_authority_unknown": "trusted"},
        {1: "invalid"},
        None,
    ]
    for binding in bad_bindings:
        with pytest.raises(AuthoritySessionBindingUnavailable):
            reverify_replay_fingerprints(binding, _session(), **_values())
