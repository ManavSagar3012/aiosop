"""SourceMap cross-binding denial tests; no grants or provider effects produced.

Rows below are inert dicts, NEVER registered in PostgreSQL or signed into
native grant tokens. The production native verifier rejects SourceMap today.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import time
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ai_osop.memory import native_mcp_execution_grants as native
from ai_osop.memory.sourcemap_native_grant_binding import (
    SourceMapNativeGrantBindingDenied,
    SourceMapNativeGrantBindingStore,
    _join_snapshot,
)
from ai_osop.memory.sourcemap_source_authority import canonical


S = "a" * 64
M = "b" * 64
D = "c" * 64
P = "d" * 64
A = "artifact-" + "1" * 32
N = "ngr-" + "2" * 32
PF = "nsp-" + "3" * 32
ACT = "action-" + "4" * 32
REQ = "req-" + "5" * 48


def _rows() -> dict[str, Any]:
    """Inert comparison vectors, not fake authority issuance or DB fixtures."""
    now = int(time.time())
    original = {
        "action_id": ACT,
        "request_id": REQ,
        "engagement_id": "eng-origin",
        "flow_id": "flow-origin",
        "task_id": "task-origin",
        "subtask_id": "subtask-origin",
        "owner_id": "owner-origin",
        "approval_id": "approve-origin",
        "lease_id": "lease-origin",
        "lease_owner_id": "leaseowner-origin",
        "flow_revision": 2,
        "authorization_id": "auth-origin",
        "authorization_version": 3,
        "authorization_sha256": S,
        "server_id": "source-map-mcp",
        "tool_name": "inspect_local_original_sourcemap",
        "side_effect_class": "READ_ONLY",
        "parameters_sha256": P,
        "declaration_sha256": D,
        "intent_sha256": "f" * 64,
        "status": "unknown",
        "cancel_requested": False,
        "receipt_sha256": None,
    }
    fields = (
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "owner_id",
        "approval_id",
        "lease_id",
        "authorization_version",
        "authorization_sha256",
        "server_id",
        "tool_name",
    )
    source_claims = {key: original[key] for key in fields}
    source_claims.update(
        version=1,
        preflight_id=PF,
        artifact_sha256=S,
        manifest_sha256=M,
        issued_at=now - 1,
        expires_at=now + 8,
    )
    source_digest = hashlib.sha256(canonical(source_claims)).hexdigest()
    preflight = {
        **source_claims,
        "kid": "kid-original",
        "claims_sha256": source_digest,
        "signature_sha256": "e" * 64,
        "committed_at": object(),
    }
    grant = {**original}
    grant.update(
        grant_id=N,
        status="issued",
        revision=1,
        kid="kid-native",
        issued_at=now - 1,
        expires_at=now + 20,
        manifest_sha256=D,
        resource_sha256=M,
        claims_sha256="7" * 64,
        signature_sha256="8" * 64,
    )
    claims_fields = (
        "request_id",
        "engagement_id",
        "flow_id",
        "task_id",
        "subtask_id",
        "action_id",
        "server_id",
        "tool_name",
        "authorization_version",
        "authorization_sha256",
        "lease_id",
        "parameters_sha256",
        "side_effect_class",
    )
    native_claims = {key: original[key] for key in claims_fields}
    native_claims.update(
        version=1,
        grant_id=N,
        manifest_sha256=D,
        resource_sha256=M,
        issued_at=now - 1,
        expires_at=now + 20,
    )
    task_payload = {
        "resource_artifact_id": A,
        "resource_artifact_sha256": S,
        "resource_authorization_sha256": S,
        "resource_command_sha256": P,
        "resource_manifest_sha256": M,
    }
    reviewer = {
        "artifact_id": A,
        "artifact_sha256": S,
        "reviewer_sub": "reviewer-distinct",
        "reviewer_role": "senior_operator",
        "decision": "approve",
        "uploader_sub": "owner-origin",
        **{
            key: original[key]
            for key in (
                "engagement_id",
                "flow_id",
                "flow_revision",
                "authorization_id",
                "authorization_version",
                "authorization_sha256",
            )
        },
    }
    return {
        "original": original,
        "preflight": preflight,
        "grant": grant,
        "source_claims": source_claims,
        "native_claims": native_claims,
        "task_payload": task_payload,
        "review": reviewer,
        "artifact_sha256": S,
        "manifest_sha256": M,
        "source_kid": "kid-original",
        "native_kid": "kid-native",
        "source_signature_sha256": "e" * 64,
        "native_signature_sha256": "8" * 64,
        "native_claims_sha256": "7" * 64,
        "now": now,
    }


@pytest.mark.parametrize(
    ("location", "key", "tamper"),
    [
        ("original", "status", "prepared"),
        ("original", "cancel_requested", True),
        ("original", "receipt_sha256", S),
        ("original", "side_effect_class", "ACTIVE"),
        ("original", "request_id", "req-" + "1" * 48),
        ("preflight", "action_id", "action-" + "9" * 32),
        ("preflight", "manifest_sha256", P),
        ("preflight", "expires_at", 1),
        ("preflight", "kid", "wrong-issuer"),
        ("preflight", "signature_sha256", P),
        ("source_claims", "artifact_sha256", M),
        ("grant", "status", "redeemed"),
        ("grant", "revision", 2),
        ("grant", "resource_sha256", None),
        ("grant", "resource_sha256", S),
        ("grant", "manifest_sha256", M),
        ("grant", "authorization_sha256", M),
        ("grant", "action_id", "action-" + "0" * 32),
        ("native_claims", "server_id", "other-mcp"),
        ("native_claims", "tool_name", "authority_status"),
        ("native_claims", "expires_at", 1),
        ("task_payload", "resource_artifact_id", "artifact-" + "6" * 32),
        ("task_payload", "resource_command_sha256", M),
        ("task_payload", "resource_manifest_sha256", P),
        ("review", "decision", "reject"),
        ("review", "reviewer_sub", "owner-origin"),
        ("review", "reviewer_role", "worker"),
        ("review", "authorization_sha256", P),
    ],
)
def test_untrusted_or_stale_cross_table_source_denied(location: str, key: str, tamper: Any) -> None:
    params = deepcopy(_rows())
    params[location][key] = tamper
    with pytest.raises(SourceMapNativeGrantBindingDenied):
        _join_snapshot(**params)


@pytest.mark.parametrize(
    ("key", "tamper"),
    [
        ("artifact_sha256", M),
        ("manifest_sha256", S),
        ("source_signature_sha256", M),
        ("native_signature_sha256", M),
        ("native_claims_sha256", M),
        ("native_kid", "forged-native"),
        ("source_kid", "forged-source"),
        ("now", 1),
    ],
)
def test_external_join_claim_mismatch_rejected(key: str, tamper: Any) -> None:
    params = deepcopy(_rows())
    params[key] = tamper
    with pytest.raises(SourceMapNativeGrantBindingDenied):
        _join_snapshot(**params)


@pytest.mark.asyncio
async def test_production_native_verifier_denies_before_any_db_or_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Independently enrolled source proof verifier must fail before database
    # access when source signing roots are absent or proof is forged.
    from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore

    fake = object.__new__(FlowMCPActionStore)

    def db_called() -> Any:
        raise AssertionError("No DB, token issuance, 0035 commit or dispatch allowed")

    monkeypatch.setattr(fake, "_sessions", db_called)
    monkeypatch.delenv("OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON", raising=False)
    store = SourceMapNativeGrantBindingStore(fake)
    with pytest.raises(SourceMapNativeGrantBindingDenied):
        await store.bind_existing(source_proof={}, native_grant_token={})


@pytest.mark.asyncio
async def test_genuinely_signed_preflight_does_not_bypass_native_grant_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real Ed25519 source proof alone cannot mint a cross-binding or grant."""
    from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore
    from ai_osop.memory.sourcemap_source_authority import DOMAIN

    signer = Ed25519PrivateKey.generate()
    public = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv(
        "OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
        json.dumps({"kid-independent": base64.b64encode(public).decode("ascii")}),
    )
    claims = _rows()["source_claims"]
    raw = signer.sign(DOMAIN + canonical(claims))
    envelope = {
        "claims": claims,
        "kid": "kid-independent",
        "signature": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
    }
    fake = object.__new__(FlowMCPActionStore)

    def deny_db() -> Any:
        raise AssertionError("Signed 0035 source alone must never open a DB transaction")

    monkeypatch.setattr(fake, "_sessions", deny_db)
    store = SourceMapNativeGrantBindingStore(fake)
    with pytest.raises(SourceMapNativeGrantBindingDenied):
        await store.bind_existing(source_proof=envelope, native_grant_token={})


def test_store_unmounted_is_a_join_not_an_execution_authority() -> None:
    import ai_osop.memory.sourcemap_native_grant_binding as module

    source = inspect.getsource(module.SourceMapNativeGrantBindingStore.bind_existing)
    assert "_verify_native(" in source and "native_grant_token" in source
    assert "self.sources._source(db, request)" in source
    assert "SourceMapStatusAuthorityStore._verify_issued(" in source
    assert "ON CONFLICT DO NOTHING RETURNING binding_id" in source
    assert '"native_mcp_resource_offers", "native_mcp_worker_supervisions"' in source
    assert '"authorizes_execution": False' in source
    assert '"authorizes_staging": False' in source
    assert "await self.sources.admit(" not in source
    assert "self.grants.issue(" not in source
    assert "self.grants.redeem(" not in source
    assert "dispatch(" not in source
    assert "mark_dispatched(" not in source
    assert "_join_snapshot" in source
    assert "_verify_native(" in source
    assert '"OSOP_SOURCEMAP_SOURCE_TRUSTED_PUBLIC_KEYS_JSON"' in source
    assert "_signed_claims(" in source
    assert "self.sources._source(db, request)" in source
    assert "SELECT * FROM flow_artifact_reviews" in source
    assert "FOR SHARE" in source
    # Resource offering, running supervisor and host staging are deliberately
    # not authorized by an immutable bound-only audit row.
    assert '"status": "bound_only"' in source
    # Today even a syntactically valid SourceMap native grant claim is denied
    # before native Ed25519 key resolution by the existing operational guard.
    with pytest.raises(native.NativeMCPGrantDenied):
        native._require_operational_pair(
            "source-map-mcp", "inspect_local_original_sourcemap", "READ_ONLY"
        )
