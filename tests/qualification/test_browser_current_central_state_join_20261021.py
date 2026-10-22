"""Offline original 0027 + committed 0034 + current signed central Browser join.

REAL: source/provider/current Ed25519 signatures and production readback SQL
and signed ROE verifier. SIMULATED: an isolated in-memory SELECT-only FakePG
transaction; no application database, browser, network, Docker or navigation.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ai_osop.memory.browser_source_authority import DOMAIN as SOURCE_DOMAIN, _canonical
from ai_osop.memory.flow_mcp_action_dispatch import FlowMCPActionStore, _DIGEST_DOMAIN, _digest
from ai_osop.mcp.protocol import SideEffectClass
from ai_osop.orchestrator.browser_current_authority_readback import (
    BrowserCurrentAuthorityDenied,
    BrowserCurrentAuthorityReadback,
    CURRENT_DOMAIN,
    EVIDENCE_DOMAIN,
    verify_current_browser_authority,
)
from ai_osop.safety.approval_binding import pinned_evidence
from tests.test_authorization_store import make_signed_session


def _public(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )).decode("ascii")


def _proof(key: Ed25519PrivateKey, kid: str, domain: bytes,
           claims: dict[str, Any]) -> dict[str, Any]:
    sig = key.sign(domain + _canonical(claims))
    return {
        "claims": claims,
        "kid": kid,
        "signature": base64.urlsafe_b64encode(sig).decode("ascii").rstrip("="),
    }


class QueryRows:
    def __init__(self, row: Any = None) -> None:
        self.row = copy.deepcopy(row)

    def mappings(self) -> "QueryRows":
        return self

    def one_or_none(self) -> Any:
        return self.row


class FakeReadOnlyPG:
    def __init__(self, rows: dict[str, Any]) -> None:
        self.rows = rows
        self.statements: list[str] = []

    async def __aenter__(self) -> "FakeReadOnlyPG":
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    def begin(self) -> "FakeReadOnlyPG":
        return self

    async def execute(self, statement: Any, params: Any = None) -> QueryRows:
        sql = str(statement)
        self.statements.append(sql)
        if len(self.statements) == 1:
            if sql != "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY":
                raise AssertionError("Missing read-only central transaction")
            return QueryRows()
        if not sql.startswith("SELECT ") or "FOR UPDATE" in sql or "FOR SHARE" in sql:
            raise AssertionError("Effectful current authority SQL: " + sql)
        mapping = {
            "FROM flow_mcp_action_dispatches": "action",
            "FROM flow_mcp_action_dispatch_events": "event",
            "FROM native_browser_source_preflights": "source",
            "FROM session_states": "session",
            "FROM signed_authorizations": "authorization",
            "FROM execution_flows": "flow",
            "FROM tasks": "task",
            "FROM execution_subtasks": "subtask",
            "FROM approval_requests": "approval",
            "FROM operator_subject_controls": "owner_control",
            "FROM supervision_execution_leases": "lease",
        }
        for snippet, name in mapping.items():
            if snippet in sql:
                if name == "owner_control" and (params or {}).get("actor") == self.rows["reviewer"]:
                    return QueryRows(self.rows.get("reviewer_control"))
                return QueryRows(self.rows.get(name))
        raise AssertionError("Unexpected query: " + sql)


@pytest.fixture
def current_case(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    owner, reviewer = "operator-browser-owner", "operator-browser-reviewer"
    roe_signer = Ed25519PrivateKey.generate()
    session, verified, roe_envelope, _ = make_signed_session(
        monkeypatch,
        session_id="eng-browser-current-readback",
        owner=owner,
        authorization_id="auth-browser-current-readback",
        private_key=roe_signer,
        roe_override={"allow_active_scanning": True},
    )
    session.scope.allowed_techniques = ["execute"]
    # Re-sign the modified policy with the original trusted ROE key.
    roe_envelope["policy"]["allowed_techniques"] = ["execute"]
    from ai_osop.safety.signed_roe import canonical_json_bytes, verify_signed_roe

    roe_envelope["signature"] = base64.urlsafe_b64encode(
        roe_signer.sign(canonical_json_bytes(roe_envelope["policy"]))
    ).decode("ascii").rstrip("=")
    verified = verify_signed_roe(
        roe_envelope, expected_engagement_id=session.session_id,
        expected_owner=owner, expected_scope=session.scope,
        expected_roe=session.roe, now=datetime.now(timezone.utc),
    )
    target = "https://authorized.example/capture"
    parameters = {
        "url": target, "action": "navigate", "user_label": "local-reviewer",
        "evidence_mode": "screenshot_dom_har",
    }
    action: dict[str, Any] = {
        "request_id": "", "action_id": "action-" + "a" * 32,
        "engagement_id": session.session_id, "flow_id": "flow-browser-current",
        "task_id": "task-browser-current", "subtask_id": "subtask-browser-current",
        "owner_id": owner, "flow_revision": 0,
        "authorization_id": roe_envelope["policy"]["authorization_id"],
        "authorization_version": 1, "authorization_sha256": verified.policy_digest,
        "approval_id": "apr-browser-current", "lease_id": "lease-browser-current",
        "lease_owner_id": "worker-browser-current", "server_id": "browser-mcp",
        "tool_name": "execute", "side_effect_class": "RECON_ACTIVE",
        "declaration_sha256": "d" * 64,
        "parameters_sha256": FlowMCPActionStore.parameters_sha256(parameters),
        "safe_parameters": parameters, "status": "unknown", "cancel_requested": False,
        "receipt_sha256": None,
    }
    identity = {
        "engagement_id": action["engagement_id"], "flow_id": action["flow_id"],
        "revision": action["flow_revision"], "version": 1,
        "authorization_id": action["authorization_id"],
        "authorization_sha256": action["authorization_sha256"],
    }
    intent = {**identity, **{
        name: action[name] for name in (
            "task_id", "subtask_id", "action_id", "owner_id", "approval_id",
            "lease_id", "lease_owner_id", "server_id", "tool_name",
            "side_effect_class", "declaration_sha256", "parameters_sha256",
        )
    }}
    action["intent_sha256"] = _digest(_DIGEST_DOMAIN, intent, 4096)
    action["request_id"] = "req-" + action["intent_sha256"][:48]
    now = int(time.time())
    source_key = Ed25519PrivateKey.generate()
    native_key = Ed25519PrivateKey.generate()
    central_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("OSOP_BROWSER_SOURCE_TRUSTED_PUBLIC_KEYS_JSON",
                       json.dumps({"centralSource": _public(source_key)}))
    monkeypatch.setenv("OSOP_MCP_RECEIPT_TRUSTED_KEYS_JSON",
                       json.dumps({"browser-mcp": {"nativeBrowser": _public(native_key)}}))
    monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_TRUSTED_PUBLIC_KEYS_JSON",
                       json.dumps({"centralReadback": _public(central_key)}))
    monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_SIGNING_KID", "centralReadback")
    monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_PRIVATE_KEY_B64",
                       base64.b64encode(central_key.private_bytes_raw()).decode("ascii"))
    source_claims = {
        "version": 1, "preflight_id": "nbp-" + "b" * 32,
        **{name: action[name] for name in (
            "request_id", "engagement_id", "flow_id", "task_id", "subtask_id",
            "action_id", "owner_id", "server_id", "tool_name", "authorization_version",
            "authorization_sha256", "approval_id", "lease_id")},
        "action": "navigate", "url_sha256": hashlib.sha256(target.encode()).hexdigest(),
        "origin": "https://authorized.example:443", "user_label": "local-reviewer",
        "evidence_mode": "screenshot_dom_har", "issued_at": now - 7, "expires_at": now + 3,
    }
    source_proof = _proof(source_key, "centralSource", SOURCE_DOMAIN, source_claims)
    evidence_claims = {
        "version": 1,
        **{name: action[name] for name in (
            "request_id", "engagement_id", "task_id", "server_id", "action_id",
            "authorization_sha256")},
        "source_preflight_id": source_claims["preflight_id"],
        "evidence_mode": "screenshot_dom_har",
        "artifacts": {kind: {
            "path": f"captures/{str(i) * 32}.{ext}",
            "sha256": str(i) * 64,
            "size_bytes": 48,
        } for i, (kind, ext) in enumerate((
            ("screenshot", "png"), ("dom", "html"), ("har", "har")), 1)},
        "issued_at": now,
    }
    evidence_proof = _proof(native_key, "nativeBrowser", EVIDENCE_DOMAIN, evidence_claims)
    task_payload = {
        "mcp_action_id": action["action_id"], "mcp_flow_revision": 0,
        "_authorization_version": 1,
        "mcp_server_id": "browser-mcp", "mcp_tool_name": "execute",
        "mcp_parameters_sha256": action["parameters_sha256"],
        "mcp_declaration_sha256": action["declaration_sha256"],
        "operator_approved": True, "approval_id": action["approval_id"],
        "url": target,
    }
    rows = {
        "action": action,
        "event": {"action_id": action["action_id"], "intent_sha256": action["intent_sha256"]},
        "source": {
            **source_claims,
            "kid": source_proof["kid"],
            "committed_at": datetime.utcnow(),
            "claims_sha256": hashlib.sha256(_canonical(source_claims)).hexdigest(),
            "signature_sha256": hashlib.sha256(
                base64.urlsafe_b64decode(source_proof["signature"] + "==")
            ).hexdigest(),
        },
        "session": {"session_id": session.session_id, "scope": session.scope.model_dump(mode="json"),
                    "roe": session.roe, "created_by": owner, "phase": "reconnaissance"},
        "authorization": {
            "status": "active", "revoked_at": None,
            "version": 1, "authorization_id": action["authorization_id"],
            "policy_sha256": verified.policy_digest,
            "canonical_policy": roe_envelope["policy"],
            "signature": roe_envelope["signature"], "kid": roe_envelope["policy"]["key_id"],
        },
        "flow": {"engagement_id": session.session_id, "revision": 0, "status": "running"},
        "task": {"flow_id": action["flow_id"], "subtask_id": action["subtask_id"],
                 "status": "running", "scope_check": True, "approval_required": True,
                 "assigned_agent_id": "worker-browser-current", "started_at": datetime.utcnow(),
                 "completed_at": None,
                 "type": "browser_navigation", "payload": task_payload},
        "subtask": {"execution_task_id": action["task_id"],
                    "flow_id": action["flow_id"], "status": "running",
                    "approval_required": True, "task_type": "browser_navigation"},
        "approval": {"status": "approved", "action_type": "browser_navigation",
                     "target": target, "responded_at": datetime.utcnow(),
                     "operator_id": reviewer,
                     "evidence": pinned_evidence([], task_payload)},
        "owner_control": {"disabled": False}, "reviewer_control": {"disabled": False},
        "lease": {"lease_id": action["lease_id"], "owner_id": action["lease_owner_id"],
                  "state": "dispatched", "expires_at": datetime.utcnow() + timedelta(minutes=3)},
        "reviewer": reviewer,
    }
    pg = FakeReadOnlyPG(rows)
    actions = object.__new__(FlowMCPActionStore)
    actions._sessions = lambda: lambda: pg
    actions._declaration = lambda *_: SimpleNamespace(
        side_effect_class=SideEffectClass.RECON_ACTIVE,
        scope_check=True, requires_approval=True)
    actions.declaration_sha256 = lambda *_: "d" * 64
    return {"readback": BrowserCurrentAuthorityReadback(actions), "pg": pg,
            "rows": rows, "source": source_proof, "evidence": evidence_proof,
            "source_key": source_key, "native_key": native_key, "central_key": central_key}


@pytest.mark.asyncio
async def test_real_signatures_and_read_only_central_current_state(current_case: dict[str, Any]) -> None:
    case = current_case
    proof = await case["readback"].corroborate(case["source"], case["evidence"])
    claims = proof["claims"]
    verified = verify_current_browser_authority(proof, {
        name: claims[name] for name in (
            "request_id", "engagement_id", "flow_id", "task_id",
            "subtask_id", "action_id", "owner_id", "preflight_id",
            "url_sha256", "authorization_sha256", "evidence_attestation_sha256")})
    assert verified == claims
    assert claims["authority_current"] is True
    assert claims["target_effect_verified"] is False
    assert claims["artifact_bytes_verified"] is False
    assert claims["expires_at"] == claims["checked_at"] + 5
    assert len(case["pg"].statements) > 10
    assert case["pg"].statements[0].endswith("READ ONLY")
    assert all(sql.startswith("SELECT ") for sql in case["pg"].statements[1:])
    with pytest.raises(BrowserCurrentAuthorityDenied):
        verify_current_browser_authority(proof, {"request_id": "req-other"})
    with pytest.raises(BrowserCurrentAuthorityDenied):
        verify_current_browser_authority(proof, {
            name: claims[name] for name in (
                "request_id", "engagement_id", "flow_id", "task_id",
                "subtask_id", "action_id", "owner_id", "preflight_id")},
            now=claims["expires_at"])


@pytest.mark.asyncio
@pytest.mark.parametrize("field,new_value", [
    ("action.flow_id", "flow-foreign"),
    ("action.task_id", "task-foreign"),
    ("action.cancel_requested", True),
    ("action.status", "finished"),
    ("source.authorization_sha256", "0" * 64),
    ("source.committed_at", None),
    ("session.phase", "halted"),
    ("authorization.status", "revoked"),
    ("authorization.revoked_at", datetime.utcnow()),
    ("authorization.policy_sha256", "f" * 64),
    ("flow.status", "halted"),
    ("task.status", "cancelled"),
    ("approval.status", "revoked"),
    ("owner_control.disabled", True),
    ("reviewer_control.disabled", True),
    ("lease.state", "cancelled"),
    ("lease.expires_at", datetime.utcnow() - timedelta(seconds=5)),
])
async def test_current_central_revocation_mismatch_or_expiry_denies(
    current_case: dict[str, Any], field: str, new_value: Any
) -> None:
    row, name = field.split(".")
    current_case["rows"][row][name] = new_value
    with pytest.raises(BrowserCurrentAuthorityDenied):
        await current_case["readback"].corroborate(current_case["source"],
                                                   current_case["evidence"])


@pytest.mark.asyncio
async def test_forged_or_stale_provider_and_source_proofs_deny(
    current_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    case = current_case
    for kind, delta in (("source", {"action_id": "action-" + "c" * 32}),
                        ("evidence", {"source_preflight_id": "nbp-" + "d" * 32}),
                        ("evidence", {"issued_at": int(time.time()) - 130})):
        proof = copy.deepcopy(case[kind])
        proof["claims"].update(delta)
        with pytest.raises(BrowserCurrentAuthorityDenied):
            await case["readback"].corroborate(
                proof if kind == "source" else case["source"],
                proof if kind == "evidence" else case["evidence"])

    # A provider possessing its own valid native signature still cannot
    # forge a fresh central authority corroboration signature.
    original = await case["readback"].corroborate(case["source"], case["evidence"])
    forged = _proof(case["native_key"], original["kid"], CURRENT_DOMAIN,
                    original["claims"])
    with pytest.raises(BrowserCurrentAuthorityDenied):
        verify_current_browser_authority(forged, original["claims"])
    monkeypatch.setenv("OSOP_BROWSER_CURRENT_AUTHORITY_PRIVATE_KEY_B64",
                       base64.b64encode(case["native_key"].private_bytes_raw()).decode("ascii"))
    with pytest.raises(BrowserCurrentAuthorityDenied):
        await case["readback"].corroborate(case["source"], case["evidence"])
