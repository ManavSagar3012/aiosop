"""Join actual controlled ASGI observations, three Ed25519 proofs and nonce admission.

The always-running tests execute the REAL target authority verifier,
target-owned oracle, independent audit corroborator and
TargetAuthorityReplayGuard against a deterministic SQL transaction *fixture*.
This fixture is not PostgreSQL and does not prove durability or PG row locks.

The separate optional PG test only opens an explicitly provided PostgreSQL URL
on 127.0.0.1:65492, user postgres, database postgres. It never uses the app DB.
The ASGI target uses HTTPX's in-process transport, never an external socket.
Even corroborated receipts stay candidate_only; there is no finding/report
promotion or remote exploitation.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
from dataclasses import replace
from types import SimpleNamespace
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
import pytest
from fastapi import Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from ai_osop.core import target_authority_corroboration as audit
from ai_osop.core import target_authority_proof as authority
from ai_osop.core.controlled_target_audit_oracle import (
    ControlledOracleDenied,
    ControlledTargetAuditOracle,
    TargetSession,
    _session_digest,
)
from ai_osop.memory.target_authority_receipts import TargetAuthorityReplayGuard
from tests.qualification.test_instrumented_target_audit_oracle_20261016 import (
    _configure,
    _http,
    _signed_proof,
)
from tests.test_target_authority_proof_20261016 import proof_case  # noqa: F401


class DeterministicSqlReceipts:
    """Transaction-aware SQL substitute, exercising production Guard's INSERT.

    This is deliberately named a fixture rather than an actual PostgreSQL
    implementation. SQL shape, nonce scope and commit/rollback are inspected,
    while concurrency, persistence across processes and PG locks are untested.
    """

    def __init__(self) -> None:
        self.committed: dict[str, Dict[str, str]] = {}
        self.pending: dict[str, Dict[str, str]] = {}
        self.insert_attempts = 0

    async def execute(self, statement: Any, params: Dict[str, str]) -> Any:
        command = str(statement)
        assert "INSERT INTO target_authority_nonce_receipts" in command
        assert "ON CONFLICT DO NOTHING RETURNING id" in command
        assert set(params) == {
            "id",
            "engagement_id",
            "flow_id",
            "key_id",
            "nonce_sha256",
            "proof_sha256",
        }
        assert "signature" not in params
        assert "raw_body" not in params
        assert all(type(v) is str for v in params.values())
        self.insert_attempts += 1
        row_id = params["id"]
        if row_id in self.pending or row_id in self.committed:
            return SimpleNamespace(scalar_one_or_none=lambda: None)
        self.pending[row_id] = dict(params)
        return SimpleNamespace(scalar_one_or_none=lambda: row_id)

    def commit(self) -> None:
        self.committed.update(self.pending)
        self.pending.clear()

    def rollback(self) -> None:
        self.pending.clear()


def _current_lab_authority(
    case: Any, oracle: ControlledTargetAuditOracle, store: Dict[str, TargetSession]
):
    """Recheck target sessions and source Task/Flow/ROE (test stand-in for PG locks)."""
    canonical = lambda obj: json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    pinned = tuple(
        hashlib.sha256(canonical(task.model_dump(mode="json"))).digest()
        for task in (case.original, case.source, case.target)
    )
    flow_snapshot = (case.flow.id, case.flow.revision, case.flow.status)
    signed_snapshot = (case.signed.authorization_id, case.signed.version, case.signed.policy_sha256)

    async def current() -> bool:
        if (
            tuple(
                hashlib.sha256(canonical(task.model_dump(mode="json"))).digest()
                for task in (case.original, case.source, case.target)
            )
            != pinned
        ):
            return False
        if (case.flow.id, case.flow.revision, case.flow.status) != flow_snapshot:
            return False
        if (
            case.signed.authorization_id,
            case.signed.version,
            case.signed.policy_sha256,
        ) != signed_snapshot:
            return False
        for role in ("source", "target"):
            observed = oracle.observations[role]
            fresh = store.get(observed.session_handle or "")
            if (
                not isinstance(fresh, TargetSession)
                or fresh.identity != observed.identity
                or fresh.handle != observed.session_handle
                or _session_digest(oracle._binding, fresh) != observed.session_sha256
            ):
                return False
        return True

    return current


async def _observed_case(case: Any, monkeypatch: Any, *, bug: bool = True, public: bool = False):
    oracle, app, store, ownership, keys, binding = _configure(
        case, monkeypatch, bug=bug, public=public
    )
    # Three independently authenticated actual HTTP ASGI responses.
    replies = await _http(oracle, case.key_row["origin"])
    return oracle, app, store, ownership, binding, replies


async def _verify_joined(
    case: Any, oracle: ControlledTargetAuditOracle, store: Dict[str, TargetSession], db: Any
):
    proof, signature, proof_sha = _signed_proof(case, oracle)
    context = {
        **case.context,
        "replay_guard": TargetAuthorityReplayGuard(db),
        "current_authority_check": _current_lab_authority(case, oracle, store),
    }
    target_verdict = await authority.verify_target_authority_proof(
        claims_json=proof, signature_b64url=signature, **context
    )
    assert target_verdict.proof_sha256 == proof_sha
    assert target_verdict.independent_target_authority_verified is True
    assert target_verdict.authorization_violation_verified is False
    assert target_verdict.finding_verified is False
    assert target_verdict.report_release_approved is False
    signed_audits = await oracle.attest(
        target_claims_json=proof,
        target_signature_b64url=signature,
        verified_target_proof_sha256=target_verdict.proof_sha256,
    )
    assert signed_audits.validation_state == "candidate_only"
    assert signed_audits.finding_verified is False
    assert signed_audits.report_release_approved is False
    corroborated = audit.corroborate_target_audits(
        target_claims_json=proof,
        target_proof_sha256=target_verdict.proof_sha256,
        ownership_json=signed_audits.ownership_json,
        ownership_signature=signed_audits.ownership_signature,
        access_json=signed_audits.access_json,
        access_signature=signed_audits.access_signature,
    )
    assert corroborated.source_records_correlated is True
    assert corroborated.target_audit_signatures_verified is True
    assert corroborated.proof_sha256 == target_verdict.proof_sha256
    assert corroborated.finding_verified is False
    assert corroborated.report_release_approved is False
    assert json.loads(signed_audits.ownership_json)["resource_owner_identity"] == "account_a"
    assert (
        json.loads(signed_audits.access_json)["target_response_sha256"]
        == oracle.observations["target"].response_sha256
    )
    for receipt in (signed_audits.ownership_json, signed_audits.access_json):
        assert b"source-test-session" not in receipt
        assert b"target-test-session" not in receipt
        assert b"controlled-object-123" not in receipt
    return proof, signature, context, target_verdict


@pytest.mark.asyncio
async def test_joined_actual_asgi_target_and_signed_oracles_with_sql_fixture_one_time(
    proof_case: Any, monkeypatch: Any
) -> None:
    case = proof_case
    # Use a fresh valid nonce so the same fixture cannot pass on a reused proof.
    case.claims["nonce"] = secrets.token_hex(16)
    oracle, _app, store, ownership, binding, replies = await _observed_case(case, monkeypatch)
    assert [replies[role].status_code for role in ("source", "target", "anonymous")] == [
        200,
        200,
        403,
    ]
    assert ownership["123"].resource_id == binding.resource_id
    assert (
        oracle.observations["source"].request_sha256 != oracle.observations["target"].request_sha256
    )
    assert (
        oracle.observations["source"].session_sha256 != oracle.observations["target"].session_sha256
    )
    assert (
        oracle.observations["source"].response_sha256
        == oracle.observations["target"].response_sha256
    )
    db = DeterministicSqlReceipts()
    proof, signature, context, verdict = await _verify_joined(case, oracle, store, db)
    assert len(db.pending) == 1
    assert db.insert_attempts == 1
    committed_row = next(iter(db.pending.values()))
    assert committed_row["proof_sha256"] == verdict.proof_sha256
    assert (
        committed_row["nonce_sha256"] == hashlib.sha256(case.claims["nonce"].encode()).hexdigest()
    )
    db.commit()
    assert len(db.committed) == 1

    with pytest.raises(authority.TargetAuthorityDenied, match="replayed"):
        await authority.verify_target_authority_proof(
            claims_json=proof, signature_b64url=signature, **context
        )
    assert db.insert_attempts == 2
    assert len(db.committed) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["public", "denied", "redirect", "unknown_session"])
async def test_negative_actual_asgi_evidence_cannot_reach_receipt_admission(
    proof_case: Any, monkeypatch: Any, scenario: str
) -> None:
    case = proof_case
    if scenario in {"public", "denied"}:
        oracle, app, store, _ownership, _binding, observed_replies = await _observed_case(
            case, monkeypatch, bug=scenario != "denied", public=scenario == "public"
        )
    else:
        oracle, app, store, _ownership, _keys, _binding = _configure(case, monkeypatch)
        observed_replies = {}
    db = DeterministicSqlReceipts()
    if scenario == "redirect":

        @app.middleware("http")
        async def redirect_target(request: Request, call_next: Any) -> Any:
            if request.headers.get("authorization") == "Bearer target-test-session":
                return RedirectResponse("/redirected", status_code=302)
            return await call_next(request)

        replies = await _http(oracle, case.key_row["origin"])
        assert replies["target"].status_code == 302
    elif scenario == "unknown_session":
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=oracle), base_url=case.key_row["origin"]
        ) as client:
            assert (
                await client.get(
                    "/api/record/123", headers={"Authorization": "Bearer source-test-session"}
                )
            ).status_code == 200
            assert (
                await client.get(
                    "/api/record/123", headers={"Authorization": "Bearer not-a-real-session"}
                )
            ).status_code == 403
            assert (await client.get("/api/record/123")).status_code == 403
        assert "target" not in oracle.observations
    else:
        assert (
            observed_replies["anonymous"].status_code
            if scenario == "public"
            else observed_replies["target"].status_code
        ) == (200 if scenario == "public" else 403)

    if scenario in {"public", "denied"}:
        with pytest.raises(authority.TargetAuthorityDenied):
            await _verify_joined(case, oracle, store, db)
    else:
        with pytest.raises(ControlledOracleDenied):
            await oracle.attest(
                target_claims_json=b"{}",
                target_signature_b64url="invalid",
                verified_target_proof_sha256="0" * 64,
            )
    assert db.insert_attempts == 0
    assert db.committed == {}


@pytest.mark.asyncio
async def test_sql_fixture_rollback_discards_unfinished_target_attestation(
    proof_case: Any, monkeypatch: Any
) -> None:
    case = proof_case
    case.claims["nonce"] = secrets.token_hex(16)
    oracle, _app, store, _ownership, _binding, replies = await _observed_case(case, monkeypatch)
    assert replies["anonymous"].status_code == 403
    proof, signature, _expected_sha = _signed_proof(case, oracle)
    db = DeterministicSqlReceipts()
    ctx = {
        **case.context,
        "replay_guard": TargetAuthorityReplayGuard(db),
        "current_authority_check": _current_lab_authority(case, oracle, store),
    }
    verdict = await authority.verify_target_authority_proof(
        claims_json=proof, signature_b64url=signature, **ctx
    )
    assert len(db.pending) == 1
    original = store["b"]
    store["b"] = replace(original, secret_version=b"rotated-after-proof")
    with pytest.raises(ControlledOracleDenied, match="rotated"):
        await oracle.attest(
            target_claims_json=proof,
            target_signature_b64url=signature,
            verified_target_proof_sha256=verdict.proof_sha256,
        )
    db.rollback()
    assert db.pending == db.committed == {}
    store["b"] = original
    replayable_after_rollback = await authority.verify_target_authority_proof(
        claims_json=proof, signature_b64url=signature, **ctx
    )
    assert replayable_after_rollback.proof_sha256 == verdict.proof_sha256
    db.commit()
    assert len(db.committed) == 1


@pytest.mark.asyncio
async def test_target_session_rotation_before_signed_authority_admission_is_denied(
    proof_case: Any, monkeypatch: Any
) -> None:
    case = proof_case
    oracle, _app, store, _ownership, _binding, replies = await _observed_case(case, monkeypatch)
    assert replies["target"].status_code == 200
    proof, signature, _digest = _signed_proof(case, oracle)
    check = _current_lab_authority(case, oracle, store)
    db = DeterministicSqlReceipts()
    store["b"] = replace(store["b"], secret_version=b"rotated-after-http")
    with pytest.raises(authority.TargetAuthorityDenied, match="verification unavailable"):
        await authority.verify_target_authority_proof(
            claims_json=proof,
            signature_b64url=signature,
            **{
                **case.context,
                "current_authority_check": check,
                "replay_guard": TargetAuthorityReplayGuard(db),
            },
        )
    assert db.insert_attempts == 0


def _approved_disposable_pg_url() -> Optional[str]:
    raw = os.environ.get("OSOP_DISPOSABLE_JOINED_TARGET_AUDIT_DB", "")
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
        if (
            parsed.scheme != "postgresql+asyncpg"
            or parsed.hostname != "127.0.0.1"
            or parsed.port != 65492
            or parsed.path != "/postgres"
            or parsed.username != "postgres"
            or parsed.query
            or parsed.fragment
            or parsed.netloc.rsplit("@", 1)[-1] != "127.0.0.1:65492"
        ):
            raise ValueError("Unexpected disposable database address")
    except ValueError as exc:
        pytest.fail("Refusing any PostgreSQL URL outside 127.0.0.1:65492/postgres")
    return raw


@pytest.mark.parametrize(
    "invalid_url",
    [
        "postgresql+asyncpg://postgres@127.0.0.1:5432/postgres",
        "postgresql+asyncpg://postgres@localhost:65492/postgres",
        "postgresql+asyncpg://postgres@127.0.0.1:65492/ai_osop",
        "postgresql+asyncpg://postgres@10.0.0.1:65492/postgres",
        "postgresql+asyncpg://operator@127.0.0.1:65492/postgres",
        "postgresql://postgres@127.0.0.1:65492/postgres",
        "postgresql+asyncpg://postgres@127.0.0.1:65492/postgres?sslmode=disable",
    ],
)
def test_disposable_pg_gate_rejects_any_other_database_without_connection(
    monkeypatch: Any, invalid_url: str
) -> None:
    monkeypatch.setenv("OSOP_DISPOSABLE_JOINED_TARGET_AUDIT_DB", invalid_url)
    with pytest.raises(pytest.fail.Exception, match="Refusing any PostgreSQL URL"):
        _approved_disposable_pg_url()


def test_disposable_pg_gate_accepts_only_exact_loopback_database(monkeypatch: Any) -> None:
    allowed = "postgresql+asyncpg://postgres@127.0.0.1:65492/postgres"
    monkeypatch.setenv("OSOP_DISPOSABLE_JOINED_TARGET_AUDIT_DB", allowed)
    assert _approved_disposable_pg_url() == allowed


@pytest.mark.asyncio
async def test_optional_real_postgres_joined_candidate_and_one_time_admission(
    proof_case: Any, monkeypatch: Any
) -> None:
    url = _approved_disposable_pg_url()
    if url is None:
        pytest.skip("No explicit OSOP_DISPOSABLE_JOINED_TARGET_AUDIT_DB; no database contacted")
    # Defensively check the dedicated loopback socket before constructing an
    # asyncpg engine. A refusal is environmental unavailability, never success.
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", 65492), timeout=1.5
        )
    except (OSError, TimeoutError, asyncio.TimeoutError):
        pytest.skip("Disposable PostgreSQL on 127.0.0.1:65492 is unavailable")
    writer.close()
    await writer.wait_closed()
    engine = create_async_engine(url, pool_size=2, max_overflow=0, connect_args={"timeout": 2})
    try:
        async with engine.begin() as db:
            await db.execute(
                text(
                    "CREATE TABLE IF NOT EXISTS target_authority_nonce_receipts ("
                    "id varchar(64) PRIMARY KEY,"
                    "engagement_id varchar(64) NOT NULL,"
                    "flow_id varchar(64) NOT NULL,"
                    "key_id varchar(64) NOT NULL,"
                    "nonce_sha256 varchar(64) NOT NULL,"
                    "proof_sha256 varchar(64) NOT NULL,"
                    "UNIQUE (engagement_id, flow_id, key_id, nonce_sha256))"
                )
            )
        proof_case.claims["nonce"] = secrets.token_hex(16)
        oracle, _app, store, _owner, _binding, replies = await _observed_case(
            proof_case, monkeypatch
        )
        assert [replies[role].status_code for role in ("source", "target", "anonymous")] == [
            200,
            200,
            403,
        ]
        async with engine.begin() as db:
            proof, signature, context, verdict = await _verify_joined(proof_case, oracle, store, db)
        # Different transaction checks the committed PostgreSQL unique index.
        async with engine.begin() as db:
            with pytest.raises(authority.TargetAuthorityDenied, match="replayed"):
                await authority.verify_target_authority_proof(
                    claims_json=proof,
                    signature_b64url=signature,
                    **{**context, "replay_guard": TargetAuthorityReplayGuard(db)},
                )
        assert verdict.finding_verified is False
        assert verdict.report_release_approved is False
    finally:
        await engine.dispose()
