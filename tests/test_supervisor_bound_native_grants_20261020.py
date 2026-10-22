"""0029 -> 0033 staged-native redemption is separately supervisor-bound.

These tests deliberately use only the real signed Flow Action/0029 in-memory
SQL fixture with a simulated *durable* 0033 snapshot. No application database,
Docker, target, provider or Go server is contacted. The mounted API may forward
worker_proof but an absent/copied-only proof MUST deny staged grants.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import inspect
import json
from typing import Any, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.api.routers import native_mcp_redemption
from ai_osop.memory.flow_mcp_action_dispatch import MCPActionDenied
from ai_osop.memory.flow_resource_exports import make_manifest
from ai_osop.memory.native_mcp_execution_grants import (
    NativeMCPGrantDenied,
    SUPERVISOR_REDEEM_DOMAIN,
    _SUPERVISOR_REDEEM_FIELDS,
    _b64url,
    _canonical,
)
from tests.test_native_mcp_execution_grants_20261020 import (
    ACTION,
    REQ,
    SECRET,
    SHA,
    Result,
    binding,
    harness,
)

_SUPERVISOR = "supervisor-isolated-unit"
_KID = "supervisor-test-key"
_WORKER = "worker-isolated-unit"
_CONTAINER = "e" * 64


def _configure_resource(db: Any) -> str:
    """Use immutable artifact SHA, original Task pin, and distinct human review."""
    original = b"// reviewed source bytes for inert native staging"
    artifact = {
        "id": "artifact-" + "3" * 32,
        "flow_id": "flow-current",
        "name": "reviewed-source.txt",
        "size_bytes": len(original),
        "sha256": hashlib.sha256(original).hexdigest(),
        "flow_revision": 6,
        "authorization_version": 3,
        "authorization_sha256": SHA,
        "content": original,
    }
    db.artifacts = [artifact]
    digest = make_manifest("flow-current", 6, 3, [(artifact, original)])["manifest_sha256"]
    db.pinned_resource = digest
    db.review = {
        "uploader_sub": "owner-current",
        "reviewer_sub": "distinct-reviewed-operator",
        "reviewer_role": "senior_operator",
        "decision": "approve",
        "artifact_sha256": artifact["sha256"],
        "flow_revision": 6,
        "authorization_id": "signed-3",
        "authorization_version": 3,
        "authorization_sha256": SHA,
    }
    return digest


def _durable_worker(grant: dict[str, Any]) -> dict[str, Any]:
    return {
        **grant,
        "grant_claims_sha256": grant["claims_sha256"],
        "state": "provisioned",
        "epoch": 777,
        "revision": 1,
        "worker_id": _WORKER,
        "supervisor_id": _SUPERVISOR,
        "supervisor_kid": _KID,
        "container_id": _CONTAINER,
    }


def _install_0033(db: Any) -> dict[str, Any]:
    """Simulate only parameterized 0033 row/event selectors in existing fake DB."""
    assert len(db.grants) == 1
    worker = _durable_worker(next(iter(db.grants.values())))
    db.worker = worker
    db.worker_event = True
    original_execute = db.execute

    async def execute(sql: Any, params: Optional[dict[str, Any]] = None) -> Result:
        statement = str(sql)
        if statement.startswith("SELECT * FROM native_mcp_worker_supervisions"):
            assert params == {"grant": worker["grant_id"]}
            return Result(dict(db.worker) if db.worker is not None else None)
        if statement.startswith("SELECT 1 FROM native_mcp_worker_supervision_events"):
            assert "state='provisioned'" in statement
            assert params["grant"] == worker["grant_id"]
            assert params["epoch"] == worker["epoch"]
            assert params["revision"] == worker["revision"]
            assert params["supervisor"] == worker["supervisor_id"]
            assert params["kid"] == worker["supervisor_kid"]
            return Result(1 if db.worker_event else None)
        return await original_execute(sql, params)

    db.execute = execute
    return worker


def _trusted_supervisor(monkeypatch: Any) -> Ed25519PrivateKey:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON",
        json.dumps(
            {
                _SUPERVISOR: {
                    "kid": _KID,
                    "public_key": _b64url(public),
                    "secret_sha256": hashlib.sha256(b"separate-supervisor-passphrase").hexdigest(),
                }
            }
        ),
    )
    return key


def _proof(
    db: Any, worker: dict[str, Any], signer: Ed25519PrivateKey, **changes: Any
) -> dict[str, Any]:
    grant = next(iter(db.grants.values()))
    claims = {
        "version": 1,
        "grant_id": grant["grant_id"],
        "request_id": grant["request_id"],
        "engagement_id": grant["engagement_id"],
        "flow_id": grant["flow_id"],
        "task_id": grant["task_id"],
        "subtask_id": grant["subtask_id"],
        "action_id": grant["action_id"],
        "owner_id": grant["owner_id"],
        "server_id": grant["server_id"],
        "worker_id": worker["worker_id"],
        "container_id": _CONTAINER,
        "supervisor_id": worker["supervisor_id"],
        "epoch": worker["epoch"],
        "revision": worker["revision"],
        "approval_id": grant["approval_id"],
        "lease_id": grant["lease_id"],
        "authorization_sha256": grant["authorization_sha256"],
        "claims_sha256": grant["claims_sha256"],
        "resource_sha256": grant["resource_sha256"],
        "nonce": "1" * 32,
        "issued_at": db.clock,
        "expires_at": min(db.clock + 5, grant["expires_at"]),
    }
    claims.update(changes)
    return {
        "claims": claims,
        "kid": _KID,
        "signature": _b64url(signer.sign(SUPERVISOR_REDEEM_DOMAIN + _canonical(claims))),
    }


async def _issued(monkeypatch: Any) -> tuple[Any, Any, dict[str, Any], dict[str, Any]]:
    store, db, controls = harness(monkeypatch)
    digest = _configure_resource(db)
    issued = await store.issue(binding(), "owner-current", ACTION, REQ, resource_sha256=digest)
    assert issued["token"]["claims"]["resource_sha256"] == digest
    assert issued["revision"] == 1
    return store, db, controls, issued


@pytest.mark.asyncio
async def test_no_copied_service_bearer_or_legacy_transport_bypasses_staged_worker_gate(
    monkeypatch: Any,
) -> None:
    store, db, _, issued = await _issued(monkeypatch)
    # A real 0033 provision alone is not proof the HTTP peer belongs to that
    # worker. This is the original copied-secret attack.
    _install_0033(db)
    _trusted_supervisor(monkeypatch)
    with pytest.raises(NativeMCPGrantDenied, match="worker proof"):
        await store.redeem(issued["token"], server_id="recon-mcp", server_secret=SECRET)
    assert db.grants[issued["grant_id"]]["status"] == "issued"
    assert not any(e["kind"] == "redeemed" for e in db.events)
    # Go/API are owned by prime: the optional argument must stay fail-closed
    # when absent, so copying only the per-service bearer cannot suffice.
    assert (
        inspect.signature(native_mcp_redemption._redeem_trusted).parameters["worker_proof"].default
        is None
    )
    assert set(issued["token"]) == {"claims", "kid", "signature"}
    assert set(issued["token"]["claims"]) != _SUPERVISOR_REDEEM_FIELDS


@pytest.mark.asyncio
async def test_exact_current_0033_and_separate_signer_allow_one_direct_staged_redeem(
    monkeypatch: Any,
) -> None:
    store, db, _, issued = await _issued(monkeypatch)
    worker = _install_0033(db)
    signer = _trusted_supervisor(monkeypatch)
    signed = _proof(db, worker, signer)
    assert set(signed["claims"]) == _SUPERVISOR_REDEEM_FIELDS
    answer = await store.redeem(
        issued["token"],
        server_id="recon-mcp",
        server_secret=SECRET,
        worker_proof=signed,
    )
    assert answer["durably_redeemed"] is True
    assert answer["grant_id"] == issued["grant_id"]
    assert db.grants[issued["grant_id"]]["status"] == "redeemed"
    assert [event["kind"] for event in db.events] == ["issued", "redeemed"]
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(
            issued["token"],
            server_id="recon-mcp",
            server_secret=SECRET,
            worker_proof=signed,
        )
    assert [event["kind"] for event in db.events] == ["issued", "redeemed"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    (
        "missing_worker",
        "missing_event",
        "wrong_tenant",
        "wrong_flow",
        "wrong_task",
        "wrong_request",
        "wrong_approval",
        "wrong_lease",
        "wrong_resource",
        "wrong_claim_sha",
        "stale_epoch",
        "stale_revision",
        "running_state",
        "revoked_state",
        "orphan_container",
        "wrong_signer",
        "tampered_signature",
        "wrong_container",
        "wrong_valid_container",
        "wrong_nonce",
        "expired_proof",
        "future_proof",
        "wrong_source_revision",
        "wrong_source_epoch",
        "wrong_worker",
        "rotated_supervisor_kid",
        "missing_supervisor_root",
    ),
)
async def test_staged_supervisor_proof_fails_closed_without_grant_consumption(
    monkeypatch: Any, mutation: str
) -> None:
    store, db, _, issued = await _issued(monkeypatch)
    worker = _install_0033(db)
    signer = _trusted_supervisor(monkeypatch)
    proof = _proof(db, worker, signer)
    changed = {
        "wrong_tenant": ("engagement_id", "eng-foreign"),
        "wrong_flow": ("flow_id", "flow-foreign"),
        "wrong_task": ("task_id", "task-foreign"),
        "wrong_request": ("request_id", "req-" + "f" * 48),
        "wrong_approval": ("approval_id", "apr-foreign"),
        "wrong_lease": ("lease_id", "lease-foreign"),
        "wrong_resource": ("resource_sha256", "f" * 64),
        "wrong_claim_sha": ("grant_claims_sha256", "f" * 64),
        "stale_epoch": ("epoch", worker["epoch"] + 1),
        "stale_revision": ("revision", 2),
        "running_state": ("state", "running"),
        "revoked_state": ("state", "unknown"),
        "orphan_container": ("container_id", None),
        "rotated_supervisor_kid": ("supervisor_kid", "revoked-supervisor"),
    }
    if mutation == "missing_worker":
        db.worker = None
    elif mutation == "missing_event":
        db.worker_event = False
    elif mutation in changed:
        name, value = changed[mutation]
        worker[name] = value
    elif mutation == "wrong_signer":
        proof = _proof(db, worker, Ed25519PrivateKey.generate())
    elif mutation == "tampered_signature":
        proof["claims"]["task_id"] = "task-foreign"
    elif mutation == "wrong_container":
        proof = _proof(db, worker, signer, container_id="not-a-real-container")
    elif mutation == "wrong_valid_container":
        # A correctly signed, syntactically valid independent proof for a
        # DIFFERENT Docker process must not reuse this grant's durable 0033
        # pre-redemption container observation.
        proof = _proof(db, worker, signer, container_id="f" * 64)
    elif mutation == "wrong_nonce":
        proof = _proof(db, worker, signer, nonce="X" * 32)
    elif mutation == "expired_proof":
        proof = _proof(db, worker, signer, issued_at=db.clock - 10, expires_at=db.clock - 1)
    elif mutation == "future_proof":
        proof = _proof(db, worker, signer, issued_at=db.clock + 5, expires_at=db.clock + 6)
    elif mutation == "wrong_source_revision":
        proof = _proof(db, worker, signer, revision=99)
    elif mutation == "wrong_source_epoch":
        proof = _proof(db, worker, signer, epoch=99)
    elif mutation == "wrong_worker":
        proof = _proof(db, worker, signer, worker_id="worker-foreign")
    elif mutation == "missing_supervisor_root":
        monkeypatch.delenv("OSOP_NATIVE_WORKER_SUPERVISOR_TRUST_JSON")
    with pytest.raises(MCPActionDenied):
        await store.redeem(
            issued["token"],
            server_id="recon-mcp",
            server_secret=SECRET,
            worker_proof=proof,
        )
    assert db.grants[issued["grant_id"]]["status"] == "issued"
    assert all(event["kind"] != "redeemed" for event in db.events)


@pytest.mark.asyncio
@pytest.mark.parametrize("revoked", ["authority", "approval", "lease", "review"])
async def test_source_revocation_outranks_valid_supervisor_proof(
    monkeypatch: Any, revoked: str
) -> None:
    store, db, controls, issued = await _issued(monkeypatch)
    worker = _install_0033(db)
    proof = _proof(db, worker, _trusted_supervisor(monkeypatch))
    if revoked == "review":
        db.reviewer_disabled = True
    else:
        controls[revoked] = False
    with pytest.raises(MCPActionDenied):
        await store.redeem(
            issued["token"],
            server_id="recon-mcp",
            server_secret=SECRET,
            worker_proof=proof,
        )
    assert db.grants[issued["grant_id"]]["status"] == "issued"


@pytest.mark.asyncio
async def test_legacy_inert_no_resource_preserves_previous_single_use_semantics(
    monkeypatch: Any,
) -> None:
    (
        store,
        db,
        _,
    ) = harness(monkeypatch)
    issued = await store.issue(binding(), "owner-current", ACTION, REQ)
    assert issued["token"]["claims"]["resource_sha256"] is None
    result = await store.redeem(issued["token"], server_id="recon-mcp", server_secret=SECRET)
    assert result["durably_redeemed"] is True
    assert not any("native_mcp_worker_supervisions" in query for query in db.calls)
    with pytest.raises(NativeMCPGrantDenied):
        await store.redeem(issued["token"], server_id="recon-mcp", server_secret=SECRET)


@pytest.mark.asyncio
async def test_latest_durable_supervisor_state_and_grant_cas_are_not_replayable(
    monkeypatch: Any,
) -> None:
    store, db, _, issued = await _issued(monkeypatch)
    worker = _install_0033(db)
    signer = _trusted_supervisor(monkeypatch)
    signed = _proof(db, worker, signer)

    async def call() -> bool:
        try:
            await store.redeem(
                issued["token"],
                server_id="recon-mcp",
                server_secret=SECRET,
                worker_proof=signed,
            )
            return True
        except NativeMCPGrantDenied:
            return False

    outcomes = await asyncio.gather(call(), call())
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
    assert len([event for event in db.events if event["kind"] == "redeemed"]) == 1
