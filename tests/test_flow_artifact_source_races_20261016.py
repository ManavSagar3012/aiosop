"""Deterministic senior source-read TOCTOU and revocation regressions.

This exercises the real review store and router using an inert SQL transaction
double. No application PostgreSQL, remote target, provider or host files.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import httpx
import pytest
from fastapi import FastAPI
from jose import jwt

from ai_osop.api import deps
from ai_osop.api.deps import state
from ai_osop.api.routers.flow_artifact_reviews import router
from ai_osop.core.config import settings
from ai_osop.memory.flow_artifact_reviews import ArtifactReviewDenied
from tests.test_flow_artifact_review_receipts_20261016 import (
    ARTIFACT_ID,
    AUTH_ID,
    AUTH_SHA,
    FLOW_ID,
    OWNER,
    REVIEWER,
    SHA,
    SID,
    Rows,
    Transaction,
    harness,
)

_TOKEN = hashlib.sha256(b"verified-senior-bearer").hexdigest()


def _fenced(harness: Any, *, content: bool = False) -> Dict[str, Any]:
    params = {
        "flow_id": FLOW_ID,
        "engagement_id": SID,
        "revision": 7,
        "version": 3,
        "authorization_id": AUTH_ID,
        "authorization_sha256": AUTH_SHA,
        "reviewer_sub": REVIEWER,
        "reviewer_role": "senior_operator",
        "reviewer_token_sha256": _TOKEN,
        "reviewer_expires_at": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
    }
    if content:
        params.update(artifact_id=ARTIFACT_ID, sha256=SHA)
    return params


def _revocation_adapter(monkeypatch: pytest.MonkeyPatch, state: Dict[str, Any]) -> None:
    """Intercept only the added durable revocation SQL using the existing fake DB."""
    original = Transaction.execute

    async def execute(self: Transaction, statement: Any, args: Any = None) -> Rows:
        sql = str(statement)
        if "FROM operator_token_revocations" in sql:
            assert args["digest"] == state.get("expected_digest", _TOKEN)
            state["checks"] = state.get("checks", 0) + 1
            return Rows(args["digest"] if state.get("revoked") else None)
        if "FROM operator_subject_controls" in sql:
            assert args["actor"] == REVIEWER
            return Rows(state.get("disabled"))
        if state.get("revoke_during_content") and "FROM flow_artifacts WHERE" in sql:
            state["revoked"] = True
        if state.get("disable_during_inventory") and "LEFT JOIN flow_artifact_reviews" in sql:
            state["disabled"] = True
        if state.get("revoke_during_event") and "INSERT INTO supervision_outbox" in sql:
            state["revoked"] = True
        return await original(self, statement, args)

    monkeypatch.setattr(Transaction, "execute", execute)


@pytest.mark.asyncio
async def test_revoked_after_signed_header_but_before_source_read_is_denied(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    race = {"revoke_during_content": True}
    _revocation_adapter(monkeypatch, race)
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.read_review_source(**_fenced(harness, content=True))
    assert err.value.status == 401
    assert race["checks"] >= 1
    assert harness.db.review is None


@pytest.mark.asyncio
async def test_disabled_during_inventory_fetch_cannot_expose_candidates(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    race = {"disable_during_inventory": True}
    _revocation_adapter(monkeypatch, race)
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.list_review_candidates(**_fenced(harness))
    assert err.value.status == 401
    assert race["checks"] >= 2


@pytest.mark.asyncio
async def test_revocation_before_receipt_commit_rolls_back_event_and_outbox(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    race = {"revoke_during_event": True}
    _revocation_adapter(monkeypatch, race)
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.decide(
            **harness.kwargs,
            reviewer_sub=REVIEWER,
            reviewer_role="senior_operator",
            reviewer_token_sha256=_TOKEN,
            reviewer_expires_at=_fenced(harness)["reviewer_expires_at"],
            decision="approve",
            reason="Reviewed original bytes",
        )
    assert err.value.status == 401
    assert harness.db.review is None
    assert harness.db.events == []
    assert harness.db.outbox == []


@pytest.mark.asyncio
@pytest.mark.parametrize("token", [None, "", "bad", "f" * 63])
async def test_revocation_enabled_requires_real_sha256_bearer_proof(
    harness: Any, monkeypatch: pytest.MonkeyPatch, token: Any
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    args = _fenced(harness, content=True)
    args["reviewer_token_sha256"] = token
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.read_review_source(**args)
    assert err.value.status == 403


@pytest.mark.asyncio
async def test_expired_reviewer_denied_even_if_feature_toggle_is_off(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", False)
    args = _fenced(harness, content=True)
    args["reviewer_expires_at"] = 1
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.read_review_source(**args)
    assert err.value.status == 401


@pytest.mark.asyncio
async def test_db_revocation_failure_denies_source_without_partial_response(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    original = Transaction.execute

    async def broken(self: Transaction, sql: Any, args: Any = None) -> Rows:
        if "FROM operator_token_revocations" in str(sql):
            raise OSError("unavailable revocation database")
        return await original(self, sql, args)

    monkeypatch.setattr(Transaction, "execute", broken)
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.read_review_source(**_fenced(harness, content=True))
    assert err.value.status == 503


@pytest.mark.asyncio
async def test_original_bytea_is_not_windows_file_path_or_symlink(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stored filename/path cannot become a Windows filesystem read primitive."""
    original = Transaction.execute
    paths = []

    async def malicious_name(self: Transaction, sql: Any, args: Any = None) -> Rows:
        result = await original(self, sql, args)
        if "FROM flow_artifacts WHERE" in str(sql) and result.value is not None:
            result.value["name"] = r"C:\Users\Public\reparse\..\secret.txt"
        return result

    def denied_open(*args: Any, **kwargs: Any) -> Any:
        paths.append(args)
        raise AssertionError("Review API must never open host files")

    monkeypatch.setattr(Transaction, "execute", malicious_name)
    monkeypatch.setattr(Path, "open", denied_open)
    monkeypatch.setattr(os, "open", denied_open)
    info, blob = await harness.store.read_review_source(
        **{
            key: value
            for key, value in _fenced(harness, content=True).items()
            if key not in {"reviewer_token_sha256", "reviewer_expires_at"}
        }
    )
    assert blob == b"Reviewed inert notes"
    assert hashlib.sha256(blob).hexdigest() == info["sha256"]
    assert paths == []


@pytest.mark.asyncio
async def test_content_mutated_before_snapshot_rejected_without_leaking_bytes(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Transaction.execute

    async def tamper(self: Transaction, statement: Any, args: Any = None) -> Rows:
        if "FROM flow_artifacts WHERE" in str(statement):
            harness.db.blob = b"tampered after signed ROE but before BYTEA read"
        return await original(self, statement, args)

    monkeypatch.setattr(Transaction, "execute", tamper)
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.read_review_source(**_fenced(harness, content=True))
    assert err.value.status == 503


@pytest.mark.asyncio
async def test_reviewed_source_replaced_with_new_consistent_hash_cannot_retain_decision(
    harness: Any,
) -> None:
    await harness.store.decide(
        **harness.kwargs,
        reviewer_sub=REVIEWER,
        reviewer_role="senior_operator",
        decision="approve",
        reason="Approval for original immutable bytes only",
    )
    # Simulate a privileged storage corruption that changes both BYTEA and
    # its upload SHA. The current bytes are self-consistent, but the separately
    # persisted immutable senior review is for DIFFERENT original content.
    harness.db.blob = b"other bytes with a matching forged upload digest"
    harness.db.sha = hashlib.sha256(harness.db.blob).hexdigest()
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.list_review_candidates(
            **{
                k: v
                for k, v in _fenced(harness).items()
                if k not in {"reviewer_token_sha256", "reviewer_expires_at"}
            }
        )
    assert err.value.status == 409
    assert len(harness.db.events) == len(harness.db.outbox) == 1


@pytest.mark.asyncio
async def test_flow_revision_advanced_after_initial_lookup_before_lock_denies_read(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = Transaction.execute

    async def advance(self: Transaction, statement: Any, args: Any = None) -> Rows:
        if "SELECT created_by,phase FROM session_states" in str(statement):
            harness.db.revision = 8
        return await original(self, statement, args)

    monkeypatch.setattr(Transaction, "execute", advance)
    with pytest.raises(ArtifactReviewDenied) as err:
        await harness.store.read_review_source(**_fenced(harness, content=True))
    assert err.value.status == 409


@pytest.mark.asyncio
async def test_http_bearer_revoked_between_verify_and_binary_delivery(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "operator_revocation_required", True)
    monkeypatch.setattr(settings, "jwt_secret", "review-race-test-secret")
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "jwt_audience", None)
    monkeypatch.setattr(settings, "jwt_issuer", None)
    monkeypatch.setitem(
        state,
        "orchestrator",
        SimpleNamespace(session_memory=SimpleNamespace(_async_session=harness.db)),
    )

    # Simulate a bearer verified by the existing authentication dependency,
    # then revoked while the source operation is acquiring its PG snapshot.
    async def header_verification_succeeded(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr(deps, "_assert_operator_not_revoked", header_verification_succeeded)
    race = {"revoke_during_content": True}
    _revocation_adapter(monkeypatch, race)
    token = jwt.encode(
        {
            "sub": REVIEWER,
            "role": "senior_operator",
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    headers = {"Authorization": "Bearer " + token}
    race["expected_digest"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
    params = {
        "expected_engagement_id": SID,
        "expected_sha256": SHA,
        "expected_revision": 7,
        "expected_authorization_version": 3,
        "expected_authorization_id": AUTH_ID,
        "expected_authorization_sha256": AUTH_SHA,
    }
    app = FastAPI()
    app.include_router(router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://review-race.invalid"
    ) as client:
        response = await client.get(
            f"/flows/{FLOW_ID}/artifact-reviews/{ARTIFACT_ID}/content",
            headers=headers,
            params=params,
        )
    assert response.status_code == 401, response.text
    assert response.headers.get("x-artifact-sha256") is None
    assert response.content != b"Reviewed inert notes"
    assert race["checks"] >= 1
